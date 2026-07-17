# SPDX-License-Identifier: AGPL-3.0-only

import json
from collections.abc import Iterator
from datetime import date, datetime
from typing import Any

from django.contrib.auth import get_user_model
from django.utils import timezone

from gateway.models import ApiToken, Attachment, AuditEvent, Mailbox, Message

EXPORT_SCHEMA = "mailgate.owner.ndjson"
EXPORT_VERSION = 1


def _timestamp(value: datetime | date | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def iter_owner_export(*, exported_at: datetime | None = None) -> Iterator[dict[str, Any]]:
    effective_time = exported_at or timezone.now()
    yield {
        "type": "manifest",
        "schema": EXPORT_SCHEMA,
        "version": EXPORT_VERSION,
        "exported_at": _timestamp(effective_time),
    }

    user_model = get_user_model()
    for owner in user_model.objects.order_by("pk").iterator(chunk_size=500):
        yield {
            "type": "owner",
            "id": owner.pk,
            "username": owner.get_username(),
            "email": owner.email,
            "first_name": owner.first_name,
            "last_name": owner.last_name,
            "is_active": owner.is_active,
            "date_joined": _timestamp(owner.date_joined),
            "last_login": _timestamp(owner.last_login),
        }

    for mailbox in Mailbox.objects.order_by("pk").iterator(chunk_size=500):
        yield {
            "type": "mailbox",
            "id": mailbox.pk,
            "name": mailbox.name,
            "provider_key": mailbox.provider_key,
            "preset_version": mailbox.preset_version,
            "host": mailbox.host,
            "port": mailbox.port,
            "username": mailbox.username,
            "trusted_authserv_ids": mailbox.trusted_authserv_ids,
            "enabled": mailbox.enabled,
            "uid_validity": mailbox.uid_validity,
            "last_uid": mailbox.last_uid,
            "last_sync_at": _timestamp(mailbox.last_sync_at),
            "last_error_code": mailbox.last_error_code,
            "config_version": mailbox.config_version,
            "created_at": _timestamp(mailbox.created_at),
            "updated_at": _timestamp(mailbox.updated_at),
        }

    for message in Message.objects.order_by("pk").iterator(chunk_size=500):
        yield {
            "type": "message",
            "id": str(message.pk),
            "mailbox_id": message.mailbox_id,
            "uid_validity": message.uid_validity,
            "uid": message.uid,
            "message_id_hash": message.message_id_hash,
            "sender": message.sender,
            "sender_name": message.sender_name,
            "recipients": message.recipients,
            "subject": message.subject,
            "received_at": _timestamp(message.received_at),
            "sanitized_text": message.sanitized_text,
            "links": message.links,
            "authentication": message.authentication,
            "signals": message.signals,
            "risk": message.risk,
            "category": message.category,
            "priority": message.priority,
            "summary": message.summary,
            "state": message.state,
            "ingested_at": _timestamp(message.ingested_at),
            "decided_at": _timestamp(message.decided_at),
        }

    for attachment in Attachment.objects.order_by("pk").iterator(chunk_size=500):
        yield {
            "type": "attachment",
            "id": attachment.pk,
            "message_id": str(attachment.message_id),
            "filename": attachment.filename,
            "content_type": attachment.content_type,
            "size": attachment.size,
            "sha256": attachment.sha256,
            "dangerous": attachment.dangerous,
        }

    for token in ApiToken.objects.order_by("pk").iterator(chunk_size=500):
        yield {
            "type": "api_token",
            "id": token.pk,
            "name": token.name,
            "prefix": token.prefix,
            "scope": token.scope,
            "created_at": _timestamp(token.created_at),
            "expires_at": _timestamp(token.expires_at),
            "last_used_at": _timestamp(token.last_used_at),
            "revoked_at": _timestamp(token.revoked_at),
        }

    for event in AuditEvent.objects.order_by("pk").iterator(chunk_size=500):
        yield {
            "type": "audit_event",
            "id": event.pk,
            "actor": event.actor,
            "action": event.action,
            "object_type": event.object_type,
            "object_id": event.object_id,
            "created_at": _timestamp(event.created_at),
        }


def write_owner_export(stream, *, exported_at: datetime | None = None) -> int:
    count = 0
    for record in iter_owner_export(exported_at=exported_at):
        stream.write(
            json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
        )
        count += 1
    return count
