# SPDX-License-Identifier: AGPL-3.0-only

import hmac
from datetime import timedelta

from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm
from django.utils import timezone
from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _

from gateway.crypto import encrypt_secret
from gateway.models import Mailbox
from gateway.providers import effective_imap_host, get_provider_preset
from gateway.validators import normalise_authserv_ids


class OwnerCreationForm(UserCreationForm):
    setup_token = forms.CharField(
        widget=forms.PasswordInput(render_value=False),
        label=_("Setup token"),
        help_text=_("Read this one-time bootstrap value from .local/secrets/setup_token."),
    )

    class Meta(UserCreationForm.Meta):
        model = get_user_model()
        fields = ("username",)

    def clean(self):
        cleaned = super().clean()
        supplied = cleaned.get("setup_token", "")
        expected = settings.MAILGATE_SETUP_TOKEN
        if not expected or not hmac.compare_digest(supplied, expected):
            raise forms.ValidationError(_("Invalid setup token."))
        if get_user_model().objects.exists():
            raise forms.ValidationError(_("This installation already has an owner."))
        return cleaned

    def save(self, commit=True):
        user = super().save(commit=False)
        user.is_staff = True
        user.is_superuser = True
        if commit:
            user.save()
        return user


class MailboxForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(render_value=False), min_length=1, max_length=1024, strip=False
    )

    class Meta:
        model = Mailbox
        fields = (
            "name",
            "provider_key",
            "host",
            "port",
            "username",
            "password",
            "trusted_authserv_ids",
            "enabled",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        labels = {
            "name": _("Name"),
            "provider_key": _("Mail provider"),
            "host": _("IMAP host"),
            "port": _("IMAP port"),
            "username": _("Mailbox username"),
            "trusted_authserv_ids": _("Trusted authentication service IDs (advanced)"),
            "enabled": _("Enabled"),
        }
        for field_name, label in labels.items():
            self.fields[field_name].label = label
        self.fields["password"].label = _("Password")
        self.fields["host"].initial = settings.MAILGATE_IMAP_ALLOWED_HOST
        self.fields["trusted_authserv_ids"].help_text = _(
            "Optional comma-separated IDs from the start of your provider's "
            "Authentication-Results header, for example mx.example.test. "
            "This is not necessarily the IMAP host. Leave blank unless the provider "
            "documents the IDs. Matching claims can be forged and never auto-approve mail. "
            "Changes apply only to future messages."
        )
        self.fields["trusted_authserv_ids"].widget.attrs["placeholder"] = (
            "mx.example.test, auth.example.test"
        )
        if self.instance and self.instance.pk:
            self.fields["password"].required = False
            self.fields["password"].label = _("New password")
            self.fields["password"].help_text = _("Leave blank to keep the stored password.")
            for field_name in ("provider_key", "host", "port", "username"):
                self.fields[field_name].disabled = True
                self.fields[field_name].help_text = _(
                    "Mailbox identity cannot be changed after creation; add a new mailbox instead."
                )

    def clean_port(self):
        port = self.cleaned_data["port"]
        if port != 993:
            raise forms.ValidationError(_("MailGate permits encrypted IMAP on port 993 only."))
        return port

    def clean_host(self):
        host = self.cleaned_data["host"].strip().lower().rstrip(".")
        if host != settings.MAILGATE_IMAP_ALLOWED_HOST:
            raise forms.ValidationError(
                format_lazy(
                    _("This installation permits only the IMAP host {host}."),
                    host=settings.MAILGATE_IMAP_ALLOWED_HOST,
                )
            )
        return host

    def clean_trusted_authserv_ids(self):
        try:
            return normalise_authserv_ids(self.cleaned_data["trusted_authserv_ids"])
        except ValueError as exc:
            raise forms.ValidationError(str(exc)) from exc

    def clean(self):
        cleaned = super().clean()
        provider_key = cleaned.get("provider_key")
        if not provider_key:
            return cleaned
        try:
            preset = get_provider_preset(provider_key)
        except ValueError as exc:
            raise forms.ValidationError(str(exc)) from exc
        preset_host = effective_imap_host(preset, settings.MAILGATE_IMAP_ALLOWED_HOST)
        if preset_host != settings.MAILGATE_IMAP_ALLOWED_HOST:
            self.add_error(
                "provider_key",
                _("This provider preset is not enabled by the installation allowlist."),
            )
            return cleaned
        cleaned["host"] = preset_host
        cleaned["port"] = preset.imap_port
        return cleaned

    def save(self, commit=True):
        mailbox = super().save(commit=False)
        password = self.cleaned_data.get("password")
        preset = get_provider_preset(self.cleaned_data["provider_key"])
        mailbox.provider_key = preset.key
        mailbox.preset_version = preset.preset_version
        mailbox.host = effective_imap_host(preset, settings.MAILGATE_IMAP_ALLOWED_HOST)
        mailbox.port = preset.imap_port
        if password:
            mailbox.password_encrypted = encrypt_secret(password)
        if commit:
            mailbox.save()
        return mailbox


class SecurityTestForm(forms.Form):
    mailbox = forms.ModelChoiceField(
        queryset=Mailbox.objects.none(), empty_label=None, label=_("Mailbox")
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["mailbox"].queryset = Mailbox.objects.order_by("name", "pk")

    def clean_mailbox(self):
        mailbox = self.cleaned_data["mailbox"]
        try:
            normalise_authserv_ids(mailbox.trusted_authserv_ids)
        except ValueError as exc:
            raise forms.ValidationError(
                _("Edit this mailbox and correct its authserv IDs.")
            ) from exc
        return mailbox


class MailboxDeleteForm(forms.Form):
    confirmation = forms.CharField(
        max_length=32,
        label=_("Confirmation"),
    )

    def __init__(self, *args, mailbox: Mailbox, **kwargs):
        super().__init__(*args, **kwargs)
        self.mailbox = mailbox
        self.challenge = f"DELETE {mailbox.pk}"
        self.fields["confirmation"].help_text = format_lazy(
            _("Enter {challenge} exactly to confirm local deletion."),
            challenge=self.challenge,
        )

    def clean_confirmation(self):
        value = self.cleaned_data["confirmation"]
        if value != self.challenge:
            raise forms.ValidationError(_("The deletion confirmation does not match."))
        return value


class TokenForm(forms.Form):
    name = forms.CharField(max_length=120, label=_("Name"))
    lifetime_days = forms.IntegerField(
        min_value=0,
        max_value=365,
        initial=90,
        label=_("Lifetime in days"),
        help_text=_("Days until expiry. Use 0 for a token that never expires."),
    )

    def expires_at(self):
        days = self.cleaned_data["lifetime_days"]
        return None if days == 0 else timezone.now() + timedelta(days=days)
