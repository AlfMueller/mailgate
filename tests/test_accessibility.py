# SPDX-License-Identifier: AGPL-3.0-only

from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import translation
from gateway.crypto import encrypt_secret
from gateway.models import Mailbox, Message
from gateway.providers import GENERIC_IMAPS


class OwnerUiAccessibilityTests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(
            username="owner", password="synthetic-owner-password"
        )
        self.client.force_login(self.owner)
        self.mailbox = Mailbox.objects.create(
            name="Synthetic",
            provider_key=GENERIC_IMAPS,
            host="imap.example.test",
            port=993,
            username="owner@example.test",
            password_encrypted=encrypt_secret("synthetic-mailbox-password"),
        )
        self.message = Message.objects.create(
            mailbox=self.mailbox,
            uid_validity=1,
            uid=1,
            subject="Synthetic detail",
            sanitized_text="Safe synthetic content",
        )

    def test_owner_pages_have_landmarks_skip_link_and_specific_titles(self):
        pages = {
            reverse("dashboard"): "Your private mail gate · MailGate",
            reverse("mailbox-create"): "Connect an IMAP mailbox · MailGate",
            reverse("mailbox-edit", args=(self.mailbox.pk,)): "Mailbox settings · MailGate",
            reverse("security-test"): "Parser/policy adversarial self-test · MailGate",
            reverse("message-list"): "Messages for review · MailGate",
            reverse("message-list") + "?state=approved": "Approved messages · MailGate",
            reverse("message-list") + "?state=rejected": "Rejected messages · MailGate",
            reverse("message-detail", args=(self.message.pk,)): "Synthetic detail · MailGate",
            reverse("tokens"): "Read-only API tokens · MailGate",
            reverse("audit"): "Audit trail · MailGate",
        }
        for url, title in pages.items():
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, f"<title>{title}</title>", html=True)
                self.assertContains(response, 'class="skip-link" href="#main-content"')
                self.assertContains(response, '<nav aria-label="MailGate">', html=False)
                self.assertContains(response, '<main id="main-content" tabindex="-1">', html=False)

    def test_current_page_is_exposed_to_assistive_technology(self):
        response = self.client.get(reverse("audit"))
        self.assertContains(
            response,
            f'<a href="{reverse("audit")}" aria-current="page">',
            html=False,
        )

        response = self.client.get(reverse("message-list") + "?state=approved")
        self.assertContains(response, '<nav class="tabs" aria-labelledby="message-list-title">')
        self.assertContains(response, 'href="?state=approved" aria-current="page"', html=False)

    def test_data_tables_have_captions_and_column_scopes(self):
        response = self.client.get(reverse("audit"))
        self.assertContains(response, '<caption class="visually-hidden">Audit trail</caption>')
        self.assertContains(response, 'scope="col"', count=4)

        response = self.client.get(reverse("message-list"))
        self.assertContains(
            response, '<caption class="visually-hidden">Messages for review</caption>'
        )
        self.assertContains(response, 'scope="col"', count=4)

        response = self.client.post(reverse("security-test"), {"mailbox": self.mailbox.pk})
        self.assertContains(response, '<caption class="visually-hidden">Results</caption>')
        self.assertContains(response, 'scope="col"', count=7)

    def test_flash_messages_use_a_polite_status_region(self):
        response = self.client.post(
            reverse("mailbox-create"),
            {
                "name": "Second synthetic mailbox",
                "provider_key": GENERIC_IMAPS,
                "host": "imap.example.test",
                "port": 993,
                "username": "second@example.test",
                "password": "synthetic-mailbox-password",
                "trusted_authserv_ids": "",
                "enabled": "on",
            },
            follow=True,
        )
        self.assertContains(
            response,
            '<div class="notices" role="status" aria-live="polite" aria-atomic="true">',
            html=False,
        )

    def test_invalid_form_fields_are_identified_and_visually_supported(self):
        response = self.client.post(
            reverse("mailbox-create"),
            {
                "name": "Invalid synthetic mailbox",
                "provider_key": GENERIC_IMAPS,
                "host": "imap.example.test",
                "port": 143,
                "username": "owner@example.test",
                "password": "synthetic-mailbox-password",
                "trusted_authserv_ids": "",
                "enabled": "on",
            },
        )
        self.assertContains(response, 'class="errorlist"')
        self.assertContains(response, 'aria-invalid="true"')
        stylesheet = (
            Path(__file__).resolve().parents[1] / "app/gateway/static/gateway/mailgate.css"
        ).read_text(encoding="utf-8")
        self.assertIn(":focus-visible", stylesheet)
        self.assertIn(".errorlist", stylesheet)
        self.assertIn('input[aria-invalid="true"]', stylesheet)

    def test_all_owner_routes_render_in_german(self):
        self.client.post(reverse("set_language"), {"language": "de", "next": reverse("dashboard")})
        pages = (
            reverse("dashboard"),
            reverse("mailbox-create"),
            reverse("mailbox-edit", args=(self.mailbox.pk,)),
            reverse("security-test"),
            reverse("message-list"),
            reverse("message-detail", args=(self.message.pk,)),
            reverse("tokens"),
            reverse("audit"),
            reverse("about"),
        )
        with translation.override("de"):
            for url in pages:
                with self.subTest(url=url):
                    response = self.client.get(url)
                    self.assertEqual(response.status_code, 200)
                    self.assertContains(response, '<html lang="de">', html=False)
                    self.assertContains(response, "Zum Hauptinhalt springen")
