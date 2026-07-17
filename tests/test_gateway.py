# SPDX-License-Identifier: AGPL-3.0-only

import ast
import re
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from compile_translations import read_catalog
from django.contrib.auth import get_user_model
from django.template import Context, Template
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone, translation
from gateway.crypto import decrypt_secret, encrypt_secret
from gateway.models import ApiToken, Attachment, AuditEvent, Mailbox, Message


class TranslationCompilerTests(SimpleTestCase):
    def test_german_catalog_covers_marked_literal_strings(self):
        app_root = Path(__file__).resolve().parents[1] / "app"
        expected = set()
        for path in app_root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "_"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                ):
                    expected.add(node.args[0].value)
        translate_pattern = re.compile(r"{%\s*(?:translate|trans)\s+(['\"])(.*?)\1")
        block_pattern = re.compile(
            r"{%\s*(?:blocktranslate|blocktrans)\b[^%]*%}(.*?){%\s*end(?:blocktranslate|blocktrans)\s*%}",
            re.DOTALL,
        )
        for path in app_root.rglob("*.html"):
            source = path.read_text(encoding="utf-8")
            expected.update(match[1] for match in translate_pattern.findall(source))
            for body in block_pattern.findall(source):
                message = re.sub(
                    r"{{\s*([A-Za-z_][A-Za-z0-9_]*)\s*}}",
                    r"%(\1)s",
                    body.strip(),
                )
                expected.add(message)

        catalog = read_catalog(app_root / "locale/de/LC_MESSAGES/django.po")
        missing = sorted(value for value in expected if value not in catalog)
        self.assertEqual(missing, [])

    def test_fuzzy_entries_are_not_compiled(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "django.po"
            path.write_text(
                'msgid ""\nmsgstr "Content-Type: text/plain; charset=UTF-8\\n"\n\n'
                '#, fuzzy\nmsgid "Old"\nmsgstr "Veraltet"\n\n'
                'msgid "Current"\nmsgstr "Aktuell"\n',
                encoding="utf-8",
            )
            catalog = read_catalog(path)
        self.assertNotIn("Old", catalog)
        self.assertEqual(catalog["Current"], "Aktuell")

    def test_placeholder_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "django.po"
            path.write_text(
                'msgid "Enter {challenge}"\nmsgstr "Eingeben {other}"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "Placeholder mismatch"):
                read_catalog(path)

    def test_machine_values_have_german_display_labels(self):
        source = (
            "{% load gateway_labels %}"
            "{{ signal|signal_label }}|{{ error|error_label }}|"
            "{{ category|category_label }}|{{ auth|auth_label }}"
        )
        with translation.override("de"):
            rendered = Template(source).render(
                Context(
                    {
                        "signal": "processing_error",
                        "error": "empty_message",
                        "category": "unsafe",
                        "auth": "pass",
                    }
                )
            )
        self.assertEqual(
            rendered,
            "Verarbeitungsfehler|Leere Antwort beim Nachrichtenabruf|Unsicher|bestanden",
        )


class CryptoTests(TestCase):
    def test_credentials_are_encrypted_and_round_trip(self):
        ciphertext = encrypt_secret("synthetic-password")
        self.assertNotIn(b"synthetic-password", ciphertext)
        self.assertEqual(decrypt_secret(ciphertext), "synthetic-password")


class OwnerUiTests(TestCase):
    def test_first_owner_can_be_created_only_once(self):
        response = self.client.post(
            reverse("setup-owner"),
            {
                "username": "owner",
                "setup_token": "synthetic-setup-token-not-a-real-secret",
                "password1": "long-synthetic-owner-pass-924!",
                "password2": "long-synthetic-owner-pass-924!",
            },
        )
        self.assertRedirects(response, reverse("mailbox-create"))
        self.client.logout()
        response = self.client.get(reverse("setup-owner"))
        self.assertRedirects(response, reverse("login"))

    def test_dashboard_requires_login(self):
        response = self.client.get(reverse("dashboard"))
        self.assertRedirects(response, f"{reverse('login')}?next=/")

    def test_invalid_setup_token_cannot_create_owner(self):
        response = self.client.post(
            reverse("setup-owner"),
            {
                "username": "attacker",
                "setup_token": "wrong-token",
                "password1": "long-synthetic-owner-pass-924!",
                "password2": "long-synthetic-owner-pass-924!",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(get_user_model().objects.exists())

    def test_authenticated_owner_can_store_encrypted_mailbox(self):
        owner = get_user_model().objects.create_user(username="owner", password="synthetic")
        self.client.force_login(owner)
        response = self.client.post(
            reverse("mailbox-create"),
            {
                "name": "Synthetic",
                "host": "imap.example.test",
                "port": 993,
                "username": "owner@example.test",
                "password": "synthetic-mailbox-password",
                "trusted_authserv_ids": "mx.example.test",
                "enabled": "on",
            },
        )
        self.assertRedirects(response, reverse("dashboard"))
        mailbox = Mailbox.objects.get()
        self.assertNotIn(b"synthetic-mailbox-password", mailbox.password_encrypted)

    def test_owner_can_edit_mailbox_without_replacing_password_or_identity(self):
        owner = get_user_model().objects.create_user(username="owner", password="synthetic")
        self.client.force_login(owner)
        ciphertext = encrypt_secret("existing-synthetic-password")
        mailbox = Mailbox.objects.create(
            name="Before",
            host="imap.example.test",
            port=993,
            username="owner@example.test",
            password_encrypted=ciphertext,
            uid_validity=77,
            last_uid=42,
            last_sync_at=timezone.now(),
        )
        edit_page = self.client.get(reverse("mailbox-edit", args=(mailbox.pk,)))
        self.assertContains(edit_page, "New password")
        self.assertNotContains(edit_page, "existing-synthetic-password")
        self.assertNotContains(edit_page, ciphertext.decode())
        response = self.client.post(
            reverse("mailbox-edit", args=(mailbox.pk,)),
            {
                "name": "After",
                "host": "attacker.example.test",
                "port": 143,
                "username": "attacker@example.test",
                "password": "",
                "trusted_authserv_ids": "mx.example.test",
                "enabled": "on",
            },
        )
        self.assertRedirects(response, reverse("dashboard"))
        mailbox.refresh_from_db()
        self.assertEqual(mailbox.name, "After")
        self.assertEqual(mailbox.host, "imap.example.test")
        self.assertEqual(mailbox.port, 993)
        self.assertEqual(mailbox.username, "owner@example.test")
        self.assertEqual(mailbox.password_encrypted, ciphertext)
        self.assertEqual((mailbox.uid_validity, mailbox.last_uid), (77, 42))

    def test_owner_can_replace_password_without_resetting_imap_identity(self):
        owner = get_user_model().objects.create_user(username="owner", password="synthetic")
        self.client.force_login(owner)
        mailbox = Mailbox.objects.create(
            name="Synthetic",
            host="imap.example.test",
            port=993,
            username="owner@example.test",
            password_encrypted=encrypt_secret("old-synthetic-password"),
            uid_validity=77,
            last_uid=42,
            last_sync_at=timezone.now(),
            last_error_code="authentication_failed",
        )
        response = self.client.post(
            reverse("mailbox-edit", args=(mailbox.pk,)),
            {
                "name": "Synthetic",
                "host": mailbox.host,
                "port": mailbox.port,
                "username": mailbox.username,
                "password": "new-synthetic-password",
                "trusted_authserv_ids": "",
                "enabled": "on",
            },
        )
        self.assertRedirects(response, reverse("dashboard"))
        mailbox.refresh_from_db()
        self.assertEqual(decrypt_secret(mailbox.password_encrypted), "new-synthetic-password")
        self.assertEqual((mailbox.uid_validity, mailbox.last_uid), (77, 42))
        self.assertIsNone(mailbox.last_sync_at)
        self.assertEqual(mailbox.last_error_code, "")
        event = AuditEvent.objects.get(action="mailbox.updated")
        self.assertEqual(event.metadata["changed_fields"], ["password"])
        self.assertNotIn("new-synthetic-password", str(event.metadata))

    def test_prompt_injection_self_test_is_local_and_does_not_create_messages(self):
        owner = get_user_model().objects.create_user(username="owner", password="synthetic")
        self.client.force_login(owner)
        mailbox = Mailbox.objects.create(
            name="Synthetic",
            host="imap.example.test",
            port=993,
            username="owner@example.test",
            password_encrypted=encrypt_secret("synthetic"),
            trusted_authserv_ids="",
            uid_validity=77,
            last_uid=42,
        )
        with (
            patch("imaplib.IMAP4_SSL") as imap,
            patch("smtplib.SMTP") as smtp,
            patch("smtplib.SMTP_SSL") as smtp_ssl,
            patch("socket.create_connection") as socket_connection,
        ):
            response = self.client.post(reverse("security-test"), {"mailbox": mailbox.pk})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "PASS", count=6)
        self.assertContains(response, "does not send email")
        self.assertEqual(response["Cache-Control"], "no-store")
        imap.assert_not_called()
        smtp.assert_not_called()
        smtp_ssl.assert_not_called()
        socket_connection.assert_not_called()
        self.assertFalse(Message.objects.exists())
        self.assertFalse(Attachment.objects.exists())
        mailbox.refresh_from_db()
        self.assertEqual((mailbox.uid_validity, mailbox.last_uid), (77, 42))
        self.assertFalse(AuditEvent.objects.exists())
        results = {str(result.name): result for result in response.context["results"]}
        self.assertEqual(results["Forged authentication claim"].dmarc_claim, "pass")
        self.assertTrue(results["Benign control"].passed)
        self.assertNotIn("prompt_injection_suspected", results["Benign control"].signals)
        pdf_result = results["PDF attachment containment"]
        self.assertTrue(pdf_result.passed)
        self.assertEqual(pdf_result.outcome, "contained")
        self.assertIn("attachment_content_not_inspected", pdf_result.signals)

    def test_authserv_ids_reject_header_injection(self):
        owner = get_user_model().objects.create_user(username="owner", password="synthetic")
        self.client.force_login(owner)
        response = self.client.post(
            reverse("mailbox-create"),
            {
                "name": "Synthetic",
                "host": "imap.example.test",
                "port": 993,
                "username": "owner@example.test",
                "password": "synthetic-mailbox-password",
                "trusted_authserv_ids": "mx.example.test\r\nInjected: value",
                "enabled": "on",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "DNS-style authserv IDs")
        self.assertFalse(Mailbox.objects.exists())

    def test_reactivating_mailbox_clears_stale_status_but_preserves_cursor(self):
        owner = get_user_model().objects.create_user(username="owner", password="synthetic")
        self.client.force_login(owner)
        mailbox = Mailbox.objects.create(
            name="Synthetic",
            host="imap.example.test",
            port=993,
            username="owner@example.test",
            password_encrypted=encrypt_secret("synthetic"),
            enabled=False,
            uid_validity=77,
            last_uid=42,
            last_sync_at=timezone.now(),
            last_error_code="authentication_failed",
        )
        self.assertContains(self.client.get(reverse("dashboard")), "disabled")
        response = self.client.post(
            reverse("mailbox-edit", args=(mailbox.pk,)),
            {
                "name": mailbox.name,
                "host": mailbox.host,
                "port": mailbox.port,
                "username": mailbox.username,
                "password": "",
                "trusted_authserv_ids": "",
                "enabled": "on",
            },
        )
        self.assertRedirects(response, reverse("dashboard"))
        mailbox.refresh_from_db()
        self.assertTrue(mailbox.enabled)
        self.assertIsNone(mailbox.last_sync_at)
        self.assertEqual(mailbox.last_error_code, "")
        self.assertEqual((mailbox.uid_validity, mailbox.last_uid), (77, 42))

    def test_prompt_injection_self_test_requires_login_and_csrf(self):
        mailbox = Mailbox.objects.create(
            name="Synthetic",
            host="imap.example.test",
            port=993,
            username="owner@example.test",
            password_encrypted=encrypt_secret("synthetic"),
        )
        self.assertRedirects(
            self.client.get(reverse("security-test")),
            f"{reverse('login')}?next={reverse('security-test')}",
        )
        owner = get_user_model().objects.create_user(username="owner", password="synthetic")
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(owner)
        response = csrf_client.post(reverse("security-test"), {"mailbox": mailbox.pk})
        self.assertEqual(response.status_code, 403)

    @override_settings(ENVIRONMENT="development", ALLOWED_HOSTS=["127.0.0.1"])
    def test_loopback_null_origin_keeps_token_check_but_is_not_rejected(self):
        client = Client(enforce_csrf_checks=True)
        response = client.get(reverse("setup-owner"), HTTP_HOST="127.0.0.1:8080")
        csrf_token = response.cookies["csrftoken"].value
        response = client.post(
            reverse("setup-owner"),
            {
                "csrfmiddlewaretoken": csrf_token,
                "username": "owner",
                "setup_token": "wrong-token",
                "password1": "long-synthetic-owner-pass-924!",
                "password2": "long-synthetic-owner-pass-924!",
            },
            HTTP_HOST="127.0.0.1:8080",
            HTTP_ORIGIN="null",
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid setup token")
        self.assertFalse(get_user_model().objects.exists())

    @override_settings(ENVIRONMENT="production", ALLOWED_HOSTS=["127.0.0.1"])
    def test_production_rejects_null_origin(self):
        client = Client(enforce_csrf_checks=True)
        response = client.get(reverse("setup-owner"), HTTP_HOST="127.0.0.1:8080")
        csrf_token = response.cookies["csrftoken"].value
        response = client.post(
            reverse("setup-owner"),
            {"csrfmiddlewaretoken": csrf_token},
            HTTP_HOST="127.0.0.1:8080",
            HTTP_ORIGIN="null",
        )
        self.assertEqual(response.status_code, 403)


@override_settings(ROOT_URLCONF="mailgate.api_urls")
class ApiTests(TestCase):
    def setUp(self):
        self.mailbox = Mailbox.objects.create(
            name="Synthetic",
            host="imap.example.test",
            port=993,
            username="owner@example.test",
            password_encrypted=encrypt_secret("synthetic"),
        )
        self.approved = Message.objects.create(
            mailbox=self.mailbox,
            uid_validity=1,
            uid=1,
            sender="safe@example.test",
            subject="Approved",
            sanitized_text="Safe body",
            state=Message.State.APPROVED,
            category="general",
            summary="Safe summary",
            risk=Message.Risk.LOW,
        )
        self.quarantined = Message.objects.create(
            mailbox=self.mailbox,
            uid_validity=1,
            uid=2,
            sender="bad@example.test",
            subject="Quarantined",
            sanitized_text="Hidden",
            state=Message.State.QUARANTINED,
        )
        self.token, self.raw = ApiToken.issue(
            name="test", expires_at=timezone.now() + timedelta(days=1)
        )
        self.auth = {"HTTP_AUTHORIZATION": f"Bearer {self.raw}"}

    def test_list_returns_only_approved_and_minimised_fields(self):
        response = self.client.get(reverse("api-messages"), **self.auth)
        self.assertEqual(response.status_code, 200)
        data = response.json()["items"]
        self.assertEqual([item["subject"] for item in data], ["Approved"])
        self.assertNotIn("text", data[0])
        self.assertNotIn("mailbox", data[0])
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_detail_cannot_enumerate_quarantined_message(self):
        response = self.client.get(
            reverse("api-message-summary", args=(self.quarantined.pk,)), **self.auth
        )
        self.assertEqual(response.status_code, 404)
        self.assertNotContains(response, "Hidden", status_code=404)

    def test_detail_returns_sanitized_text_only(self):
        response = self.client.get(
            reverse("api-message-summary", args=(self.approved.pk,)), **self.auth
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["text"], "Safe body")
        self.assertNotIn("authentication", response.json())

    def test_missing_invalid_expired_and_revoked_tokens_are_rejected(self):
        self.assertEqual(self.client.get(reverse("api-messages")).status_code, 401)
        self.assertEqual(
            self.client.get(
                reverse("api-messages"), HTTP_AUTHORIZATION="Bearer invalid"
            ).status_code,
            401,
        )
        expired_token, expired_raw = ApiToken.issue(
            name="expired", expires_at=timezone.now() - timedelta(seconds=1)
        )
        self.assertFalse(expired_token.active)
        self.assertEqual(
            self.client.get(
                reverse("api-messages"),
                HTTP_AUTHORIZATION=f"Bearer {expired_raw}",
            ).status_code,
            401,
        )
        self.token.revoked_at = timezone.now()
        self.token.save(update_fields=("revoked_at",))
        self.assertEqual(self.client.get(reverse("api-messages"), **self.auth).status_code, 401)

    def test_write_methods_are_rejected_without_state_change(self):
        for method in ("post", "put", "patch", "delete"):
            response = getattr(self.client, method)(reverse("api-messages"), **self.auth)
            self.assertEqual(response.status_code, 405)
        self.assertEqual(Message.objects.filter(state=Message.State.APPROVED).count(), 1)

    def test_non_approved_filter_is_rejected(self):
        response = self.client.get(reverse("api-messages") + "?state=quarantined", **self.auth)
        self.assertEqual(response.status_code, 400)

    def test_access_is_audited_without_raw_token(self):
        self.client.get(reverse("api-categories"), **self.auth)
        event = AuditEvent.objects.get(action="api.read")
        self.assertNotIn(self.raw, str(event.metadata))
        self.assertEqual(event.actor, f"token:{self.token.prefix}")

    def test_unauthorized_responses_are_not_cacheable(self):
        response = self.client.get(reverse("api-messages"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_non_expiring_token_remains_active_until_revoked(self):
        token, raw = ApiToken.issue(name="no-expiry", expires_at=None)
        auth = {"HTTP_AUTHORIZATION": f"Bearer {raw}"}
        self.assertTrue(token.active)
        self.assertEqual(self.client.get(reverse("api-messages"), **auth).status_code, 200)
        token.revoked_at = timezone.now()
        token.save(update_fields=("revoked_at",))
        self.assertFalse(token.active)
        self.assertEqual(self.client.get(reverse("api-messages"), **auth).status_code, 401)


class ManagementUiTests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(username="owner", password="synthetic")
        self.client.force_login(self.owner)

    def test_zero_day_token_never_expires_and_is_labelled(self):
        response = self.client.post(reverse("tokens"), {"name": "Hermes", "lifetime_days": 0})
        self.assertEqual(response.status_code, 200)
        token = ApiToken.objects.get(name="Hermes")
        self.assertIsNone(token.expires_at)
        self.assertTrue(token.active)
        self.assertContains(response, "never expires")
        event = AuditEvent.objects.get(action="token.created")
        self.assertEqual(event.metadata["expiry"], "never")

    def test_token_lifetime_rejects_out_of_range_and_non_integer_values(self):
        for value in (-1, 366, "", "1.5"):
            response = self.client.post(
                reverse("tokens"), {"name": "Invalid", "lifetime_days": value}
            )
            self.assertEqual(response.status_code, 200)
        self.assertFalse(ApiToken.objects.exists())

    def test_mailbox_deletion_is_confirmed_local_and_cascades_only_mail_data(self):
        mailbox = Mailbox.objects.create(
            name="Synthetic",
            host="imap.example.test",
            port=993,
            username="owner@example.test",
            password_encrypted=encrypt_secret("synthetic"),
        )
        message = Message.objects.create(
            mailbox=mailbox,
            uid_validity=1,
            uid=1,
            sender="sender@example.test",
            state=Message.State.QUARANTINED,
        )
        Attachment.objects.create(
            message=message,
            filename="synthetic.pdf",
            content_type="application/pdf",
            size=42,
            sha256="a" * 64,
        )
        global_token, _ = ApiToken.issue(name="global", expires_at=None)

        self.client.get(reverse("mailbox-delete", args=(mailbox.pk,)))
        self.assertTrue(Mailbox.objects.filter(pk=mailbox.pk).exists())
        response = self.client.post(
            reverse("mailbox-delete", args=(mailbox.pk,)),
            {"confirmation": "DELETE wrong"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Mailbox.objects.filter(pk=mailbox.pk).exists())

        response = self.client.post(
            reverse("mailbox-delete", args=(mailbox.pk,)),
            {"confirmation": f"DELETE {mailbox.pk}"},
        )
        self.assertRedirects(response, reverse("dashboard"))
        self.assertFalse(Mailbox.objects.filter(pk=mailbox.pk).exists())
        self.assertFalse(Message.objects.exists())
        self.assertFalse(Attachment.objects.exists())
        self.assertTrue(ApiToken.objects.filter(pk=global_token.pk).exists())
        event = AuditEvent.objects.get(action="mailbox.deleted")
        self.assertEqual(event.metadata["messages_deleted"], 1)
        self.assertEqual(event.metadata["attachments_deleted"], 1)
        self.assertNotIn("owner@example.test", str(event.metadata))

    def test_about_is_public_but_runtime_status_is_owner_only(self):
        Mailbox.objects.create(
            name="Private mailbox name",
            host="private.example.test",
            port=993,
            username="private@example.test",
            password_encrypted=encrypt_secret("synthetic"),
        )
        self.client.logout()
        response = self.client.get(reverse("about"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "How MailGate works")
        self.assertNotContains(response, "Observed local status")
        self.assertNotContains(response, "Private mailbox name")
        self.assertNotContains(response, "private.example.test")
        self.assertEqual(self.client.post(reverse("about")).status_code, 405)

    def test_german_can_be_selected_and_persists_in_cookie(self):
        response = self.client.post(
            reverse("set_language"), {"language": "de", "next": reverse("about")}
        )
        self.assertRedirects(response, reverse("about"))
        self.assertEqual(response.cookies["django_language"].value, "de")
        response = self.client.get(reverse("about"))
        self.assertContains(response, '<html lang="de">', html=False)
        self.assertContains(response, "So funktioniert MailGate")
        mailbox = Mailbox.objects.create(
            name="Synthetic",
            host="imap.example.test",
            port=993,
            username="owner@example.test",
            password_encrypted=encrypt_secret("synthetic"),
        )
        self.assertContains(self.client.get(reverse("mailbox-create")), "Passwort")
        self.assertContains(self.client.get(reverse("security-test")), "Postfach")
        mailbox.delete()

    def test_german_accept_language_works_before_login(self):
        self.client.logout()
        response = self.client.get(reverse("about"), HTTP_ACCEPT_LANGUAGE="de-CH,de;q=0.9")
        self.assertContains(response, "So funktioniert MailGate")

    @override_settings(MAILGATE_WORKER_POLL_INTERVAL_SECONDS=300)
    def test_about_status_uses_worker_interval_and_counts_only_active_tokens(self):
        mailbox = Mailbox.objects.create(
            name="Synthetic",
            host="imap.example.test",
            port=993,
            username="owner@example.test",
            password_encrypted=encrypt_secret("synthetic"),
            last_sync_at=timezone.now() - timedelta(minutes=4),
        )
        ApiToken.issue(name="active", expires_at=None)
        ApiToken.issue(name="expired", expires_at=timezone.now() - timedelta(seconds=1))
        revoked, _ = ApiToken.issue(name="revoked", expires_at=None)
        revoked.revoked_at = timezone.now()
        revoked.save(update_fields=("revoked_at",))

        response = self.client.get(reverse("about"))
        self.assertEqual(response.context["worker_status"], "recent")
        self.assertEqual(response.context["active_token_count"], 1)

        unchecked = Mailbox.objects.create(
            name="Unchecked",
            host="imap2.example.test",
            port=993,
            username="owner2@example.test",
            password_encrypted=encrypt_secret("synthetic"),
        )
        response = self.client.get(reverse("about"))
        self.assertEqual(response.context["worker_status"], "stale")
        unchecked.enabled = False
        unchecked.save(update_fields=("enabled",))

        mailbox.last_sync_at = timezone.now() - timedelta(minutes=11)
        mailbox.save(update_fields=("last_sync_at",))
        response = self.client.get(reverse("about"))
        self.assertEqual(response.context["worker_status"], "stale")

        mailbox.enabled = False
        mailbox.save(update_fields=("enabled",))
        response = self.client.get(reverse("about"))
        self.assertEqual(response.context["worker_status"], "not_observable")
