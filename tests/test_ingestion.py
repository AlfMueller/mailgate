# SPDX-License-Identifier: AGPL-3.0-only

from email.message import EmailMessage
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from gateway.crypto import encrypt_secret
from gateway.ingestion import sync_mailbox
from gateway.mail import MAX_MESSAGE_BYTES
from gateway.models import ApiToken, Attachment, Mailbox, Message

RAW = (
    b"From: Sender <sender@example.test>\r\n"
    b"Subject: Safe\r\n"
    b"Authentication-Results: mx.example.test; "
    b"spf=pass dkim=pass dmarc=pass arc=pass\r\n"
    b"Content-Type: text/plain\r\n\r\nHello"
)


class FakeImap:
    instances = []
    raw = RAW
    reported_size = len(RAW)

    def __init__(self, host, port, timeout, ssl_context):
        self.commands = []
        self.ssl_context = ssl_context
        self.__class__.instances.append(self)

    def login(self, username, password):
        self.commands.append(("login", username))
        return "OK", []

    def select(self, mailbox, readonly=False):
        self.commands.append(("select", mailbox, readonly))
        return "OK", [b"1"]

    def response(self, name):
        return "OK", [b"123"]

    def uid(self, command, *args):
        self.commands.append(("uid", command, *args))
        if command == "SEARCH":
            return "OK", [b"7"]
        if args[-1] == "(RFC822.SIZE)":
            return "OK", [(f"7 (RFC822.SIZE {self.reported_size})".encode(), b"")]
        return "OK", [(b"7 (BODY[] {1})", self.raw), b")"]

    def logout(self):
        self.commands.append(("logout",))


class IngestionTests(TestCase):
    def setUp(self):
        FakeImap.instances.clear()
        FakeImap.raw = RAW
        FakeImap.reported_size = len(RAW)
        self.mailbox = Mailbox.objects.create(
            name="Test",
            host="imap.example.test",
            port=993,
            username="owner@example.test",
            password_encrypted=encrypt_secret("synthetic"),
            trusted_authserv_ids="mx.example.test",
        )

    @patch("gateway.ingestion.imaplib.IMAP4_SSL", FakeImap)
    def test_read_only_peek_and_idempotence(self):
        self.assertEqual(sync_mailbox(self.mailbox), 1)
        self.mailbox.refresh_from_db()
        self.mailbox.last_uid = 0
        self.mailbox.save(update_fields=("last_uid",))
        self.assertEqual(sync_mailbox(self.mailbox), 0)
        self.assertEqual(Message.objects.count(), 1)
        commands = FakeImap.instances[0].commands
        self.assertIn(("select", "INBOX", True), commands)
        self.assertEqual(FakeImap.instances[0].ssl_context.verify_mode.name, "CERT_REQUIRED")
        self.assertTrue(FakeImap.instances[0].ssl_context.check_hostname)
        self.assertIn(("uid", "FETCH", "7", "(RFC822.SIZE)"), commands)
        self.assertIn(("uid", "FETCH", "7", "(BODY.PEEK[])"), commands)
        self.assertFalse(
            any(command[0] in {"store", "move", "delete", "expunge"} for command in commands)
        )

    @patch("gateway.ingestion.imaplib.IMAP4_SSL", FakeImap)
    def test_uid_at_or_below_cursor_is_not_fetched(self):
        self.mailbox.uid_validity = 123
        self.mailbox.last_uid = 7
        self.mailbox.save(update_fields=("uid_validity", "last_uid"))
        self.assertEqual(sync_mailbox(self.mailbox), 0)
        self.assertFalse(
            any(command[1:3] == ("FETCH", "7") for command in FakeImap.instances[0].commands)
        )

    @patch("gateway.ingestion.imaplib.IMAP4_SSL", FakeImap)
    def test_oversized_message_body_is_never_downloaded(self):
        FakeImap.reported_size = MAX_MESSAGE_BYTES + 1
        self.assertEqual(sync_mailbox(self.mailbox), 1)
        commands = FakeImap.instances[0].commands
        self.assertNotIn(("uid", "FETCH", "7", "(BODY.PEEK[])"), commands)
        message = Message.objects.get()
        self.assertEqual(message.state, Message.State.QUARANTINED)
        self.assertEqual(message.signals, ["message_too_large"])

    @patch("gateway.ingestion.imaplib.IMAP4_SSL", FakeImap)
    def test_pdf_injection_bytes_do_not_reach_persistence_or_approved_api(self):
        marker = b"SYNTHETIC_PDF_INJECTION_MARKER"
        fixture = EmailMessage()
        fixture["From"] = "Sender <sender@example.test>"
        fixture["Subject"] = "Synthetic PDF"
        fixture.set_content("Owner-visible safe body")
        fixture.add_attachment(
            b"%PDF-1.4\n" + marker + b"\n%%EOF",
            maintype="application",
            subtype="pdf",
            filename="synthetic.pdf",
        )
        FakeImap.raw = fixture.as_bytes()
        FakeImap.reported_size = len(FakeImap.raw)

        self.assertEqual(sync_mailbox(self.mailbox), 1)
        message = Message.objects.get()
        attachment = Attachment.objects.get(message=message)
        self.assertNotIn(marker.decode(), message.sanitized_text)
        self.assertEqual(attachment.filename, "synthetic.pdf")
        self.assertEqual(attachment.content_type, "application/pdf")

        message.state = Message.State.APPROVED
        message.save(update_fields=("state",))
        _token, raw_token = ApiToken.issue(name="test", expires_at=None)
        response = self.client.get(
            reverse("api-message-summary", args=(message.pk,)),
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(marker, response.content)
        self.assertNotIn("attachments", response.json())
