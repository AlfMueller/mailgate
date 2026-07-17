# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import imaplib
import logging
import re
import socket
import ssl

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from gateway.crypto import decrypt_secret
from gateway.mail import MAX_MESSAGE_BYTES, UnsafeMessage, assess, classify, parse_message
from gateway.models import Attachment, Mailbox, Message, audit

logger = logging.getLogger("mailgate.ingestion")
UIDVALIDITY_RE = re.compile(rb"UIDVALIDITY\s+(\d+)", re.I)


class MailboxSyncError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class EgressIMAP4SSL(imaplib.IMAP4_SSL):
    """Keep end-to-end TLS/SNI for the mailbox while dialing the fixed egress relay."""

    def _create_socket(self, timeout):
        raw_socket = socket.create_connection(
            (settings.MAILGATE_IMAP_EGRESS_HOST, settings.MAILGATE_IMAP_EGRESS_PORT),
            timeout,
        )
        return self.ssl_context.wrap_socket(raw_socket, server_hostname=self.host)


def _open_imap(mailbox: Mailbox, timeout: float):
    if mailbox.host != settings.MAILGATE_IMAP_ALLOWED_HOST or mailbox.port != 993:
        raise MailboxSyncError("egress_policy_denied")
    client_class = EgressIMAP4SSL if settings.MAILGATE_IMAP_EGRESS_ENABLED else imaplib.IMAP4_SSL
    return client_class(
        mailbox.host,
        mailbox.port,
        timeout=timeout,
        ssl_context=ssl.create_default_context(),
    )


def _response_bytes(response) -> bytes:
    if not response:
        return b""
    for item in response:
        if isinstance(item, bytes):
            return item
        if isinstance(item, tuple) and len(item) > 1 and isinstance(item[1], bytes):
            return item[1]
    return b""


def _uidvalidity(client: imaplib.IMAP4_SSL) -> int:
    status, data = client.response("UIDVALIDITY")
    raw = b" ".join(item for item in (data or []) if isinstance(item, bytes))
    match = UIDVALIDITY_RE.search(raw)
    if not match and raw.isdigit():
        return int(raw)
    if not match:
        raise MailboxSyncError("uidvalidity_missing")
    return int(match.group(1))


def _message_size(response) -> int | None:
    headers: list[bytes] = []
    for item in response or []:
        if isinstance(item, bytes):
            headers.append(item)
        elif isinstance(item, tuple) and item and isinstance(item[0], bytes):
            headers.append(item[0])
    match = re.search(rb"RFC822\.SIZE\s+(\d+)", b" ".join(headers), re.I)
    return int(match.group(1)) if match else None


def _store_message(
    mailbox: Mailbox,
    validity: int,
    uid: int,
    raw: bytes = b"",
    *,
    unsafe_reason: str = "",
    expected_config_version: int,
) -> bool:
    trusted = {
        item.strip().lower() for item in mailbox.trusted_authserv_ids.split(",") if item.strip()
    }
    try:
        if unsafe_reason:
            raise UnsafeMessage(unsafe_reason)
        parsed = parse_message(raw, trusted_authserv_ids=trusted)
        risk, state, reasons = assess(parsed)
        category, priority, summary = classify(parsed)
    except UnsafeMessage as exc:
        parsed = None
        risk, state, reasons = "high", "quarantined", [str(exc)]
        category, priority, summary = "unsafe", 1, "Message quarantined because safe parsing failed"
    except Exception:
        logger.warning("Message processing failed mailbox_id=%s uid=%s", mailbox.pk, uid)
        parsed = None
        risk, state, reasons = "high", "quarantined", ["processing_error"]
        category, priority, summary = "unsafe", 1, "Message quarantined because processing failed"
    with transaction.atomic():
        locked_mailbox = (
            Mailbox.objects.select_for_update()
            .filter(
                pk=mailbox.pk,
                enabled=True,
                config_version=expected_config_version,
            )
            .first()
        )
        if locked_mailbox is None:
            raise MailboxSyncError("configuration_changed")
        message, created = Message.objects.get_or_create(
            mailbox=locked_mailbox,
            uid_validity=validity,
            uid=uid,
            defaults={
                "sender": parsed.sender if parsed else "",
                "sender_name": parsed.sender_name if parsed else "",
                "recipients": parsed.recipients if parsed else [],
                "subject": parsed.subject if parsed else "",
                "received_at": parsed.received_at if parsed else None,
                "sanitized_text": parsed.text if parsed else "",
                "links": parsed.links if parsed else [],
                "message_id_hash": parsed.message_id_hash if parsed else "",
                "authentication": parsed.authentication if parsed else {},
                "signals": reasons,
                "risk": risk,
                "state": state,
                "category": category,
                "priority": priority,
                "summary": summary,
                "decided_at": timezone.now(),
            },
        )
        if created and parsed:
            Attachment.objects.bulk_create(
                [Attachment(message=message, **vars(item)) for item in parsed.attachments]
            )
        if created:
            audit(
                actor="worker",
                action="message.ingested",
                obj=message,
                metadata={"state": state, "risk": risk},
            )
        return created


def sync_mailbox(mailbox: Mailbox, *, batch_size: int = 50, timeout: float = 30) -> int:
    if not mailbox.enabled:
        return 0
    expected_config_version = mailbox.config_version
    password = decrypt_secret(mailbox.password_encrypted)
    client = None
    try:
        client = _open_imap(mailbox, timeout)
        status, _ = client.login(mailbox.username, password)
        if status != "OK":
            raise MailboxSyncError("authentication_failed")
        status, _ = client.select("INBOX", readonly=True)
        if status != "OK":
            raise MailboxSyncError("inbox_unavailable")
        validity = _uidvalidity(client)
        if mailbox.uid_validity != validity:
            mailbox.uid_validity = validity
            mailbox.last_uid = 0
        status, values = client.uid("SEARCH", None, f"UID {mailbox.last_uid + 1}:*")
        if status != "OK":
            raise MailboxSyncError("search_failed")
        uids = [
            int(item)
            for item in _response_bytes(values).split()
            if item.isdigit() and int(item) > mailbox.last_uid
        ][:batch_size]
        created = 0
        for uid in uids:
            status, size_response = client.uid("FETCH", str(uid), "(RFC822.SIZE)")
            size = _message_size(size_response)
            if status != "OK" or size is None:
                raise MailboxSyncError("size_unavailable")
            if size > MAX_MESSAGE_BYTES:
                created += int(
                    _store_message(
                        mailbox,
                        validity,
                        uid,
                        unsafe_reason="message_too_large",
                        expected_config_version=expected_config_version,
                    )
                )
                mailbox.last_uid = max(mailbox.last_uid, uid)
                continue
            status, response = client.uid("FETCH", str(uid), "(BODY.PEEK[])")
            if status != "OK":
                raise MailboxSyncError("fetch_failed")
            raw = _response_bytes(response)
            if not raw:
                raise MailboxSyncError("empty_message")
            created += int(
                _store_message(
                    mailbox,
                    validity,
                    uid,
                    raw,
                    expected_config_version=expected_config_version,
                )
            )
            mailbox.last_uid = max(mailbox.last_uid, uid)
        mailbox.last_sync_at = timezone.now()
        mailbox.last_error_code = ""
        updated = Mailbox.objects.filter(
            pk=mailbox.pk,
            enabled=True,
            config_version=expected_config_version,
        ).update(
            uid_validity=mailbox.uid_validity,
            last_uid=mailbox.last_uid,
            last_sync_at=mailbox.last_sync_at,
            last_error_code="",
            updated_at=timezone.now(),
        )
        if updated != 1:
            raise MailboxSyncError("configuration_changed")
        return created
    except (TimeoutError, imaplib.IMAP4.error, OSError, MailboxSyncError) as exc:
        code = exc.code if isinstance(exc, MailboxSyncError) else "connection_failed"
        if code != "configuration_changed":
            Mailbox.objects.filter(
                pk=mailbox.pk,
                enabled=True,
                config_version=expected_config_version,
            ).update(
                last_error_code=code,
                last_sync_at=timezone.now(),
                updated_at=timezone.now(),
            )
        logger.warning("Mailbox sync failed mailbox_id=%s code=%s", mailbox.pk, code)
        raise MailboxSyncError(code) from exc
    finally:
        if client is not None:
            try:
                client.logout()
            except (imaplib.IMAP4.error, OSError):
                pass


def sync_all_mailboxes() -> tuple[int, int]:
    processed = errors = 0
    for mailbox in Mailbox.objects.filter(enabled=True).iterator():
        try:
            processed += sync_mailbox(mailbox)
        except MailboxSyncError:
            errors += 1
        except Exception:
            errors += 1
            logger.exception("Unexpected mailbox sync failure mailbox_id=%s", mailbox.pk)
    return processed, errors
