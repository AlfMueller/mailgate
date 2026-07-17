# SPDX-License-Identifier: AGPL-3.0-only

from email.message import EmailMessage
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings
from django.urls import reverse
from gateway.crypto import encrypt_secret
from gateway.ingestion import EgressIMAP4SSL, MailboxSyncError, sync_mailbox
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
    before_body_fetch = None

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
        if type(self).before_body_fetch is not None:
            type(self).before_body_fetch()
        return "OK", [(b"7 (BODY[] {1})", self.raw), b")"]

    def logout(self):
        self.commands.append(("logout",))


class IngestionTests(TestCase):
    def setUp(self):
        FakeImap.instances.clear()
        FakeImap.raw = RAW
        FakeImap.reported_size = len(RAW)
        FakeImap.before_body_fetch = None
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

    @override_settings(ROOT_URLCONF="mailgate.api_urls")
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

    @patch("gateway.ingestion.imaplib.IMAP4_SSL", FakeImap)
    def test_configuration_change_during_fetch_discards_message_and_cursor(self):
        def change_configuration():
            Mailbox.objects.filter(pk=self.mailbox.pk).update(config_version=2, enabled=False)

        FakeImap.before_body_fetch = change_configuration
        with self.assertRaisesRegex(MailboxSyncError, "configuration_changed"):
            sync_mailbox(self.mailbox)
        self.mailbox.refresh_from_db()
        self.assertFalse(self.mailbox.enabled)
        self.assertEqual(self.mailbox.last_uid, 0)
        self.assertEqual(Message.objects.count(), 0)

    @override_settings(
        MAILGATE_IMAP_ALLOWED_HOST="allowed.example.test",
        MAILGATE_IMAP_EGRESS_ENABLED=False,
    )
    def test_unapproved_imap_destination_is_denied_before_network(self):
        with patch("gateway.ingestion.imaplib.IMAP4_SSL") as connect:
            with self.assertRaisesRegex(MailboxSyncError, "egress_policy_denied"):
                sync_mailbox(self.mailbox)
        connect.assert_not_called()

    @override_settings(
        MAILGATE_IMAP_EGRESS_HOST="imap-egress",
        MAILGATE_IMAP_EGRESS_PORT=10993,
    )
    def test_egress_transport_preserves_mailbox_sni(self):
        context = MagicMock()
        client = object.__new__(EgressIMAP4SSL)
        client.host = "imap.example.test"
        client.ssl_context = context
        raw_socket = object()
        with patch("gateway.ingestion.socket.create_connection", return_value=raw_socket) as dial:
            client._create_socket(7)
        dial.assert_called_once_with(("imap-egress", 10993), 7)
        context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="imap.example.test")
