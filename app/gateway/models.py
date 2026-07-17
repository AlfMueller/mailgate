# SPDX-License-Identifier: AGPL-3.0-only

import hashlib
import secrets
import uuid

from django.db import models
from django.utils import timezone


class Mailbox(models.Model):
    name = models.CharField(max_length=120)
    host = models.CharField(max_length=253)
    port = models.PositiveIntegerField(default=993)
    username = models.CharField(max_length=320)
    password_encrypted = models.BinaryField()
    trusted_authserv_ids = models.CharField(
        max_length=500,
        blank=True,
        help_text="Comma-separated Authentication-Results authserv-ids controlled by the provider.",
    )
    enabled = models.BooleanField(default=True)
    uid_validity = models.PositiveBigIntegerField(null=True, blank=True)
    last_uid = models.PositiveBigIntegerField(default=0)
    last_sync_at = models.DateTimeField(null=True, blank=True)
    last_error_code = models.CharField(max_length=80, blank=True)
    config_version = models.PositiveBigIntegerField(default=1, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name


class Message(models.Model):
    class State(models.TextChoices):
        QUARANTINED = "quarantined", "Quarantined"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"

    class Risk(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    mailbox = models.ForeignKey(Mailbox, on_delete=models.CASCADE, related_name="messages")
    uid_validity = models.PositiveBigIntegerField()
    uid = models.PositiveBigIntegerField()
    message_id_hash = models.CharField(max_length=64, blank=True)
    sender = models.CharField(max_length=320, blank=True)
    sender_name = models.CharField(max_length=320, blank=True)
    recipients = models.JSONField(default=list)
    subject = models.CharField(max_length=998, blank=True)
    received_at = models.DateTimeField(null=True, blank=True)
    sanitized_text = models.TextField(blank=True)
    links = models.JSONField(default=list)
    authentication = models.JSONField(default=dict)
    signals = models.JSONField(default=list)
    risk = models.CharField(max_length=10, choices=Risk.choices, default=Risk.MEDIUM)
    category = models.CharField(max_length=80, default="uncategorized")
    priority = models.PositiveSmallIntegerField(default=3)
    summary = models.TextField(blank=True)
    state = models.CharField(max_length=20, choices=State.choices, default=State.QUARANTINED)
    ingested_at = models.DateTimeField(auto_now_add=True)
    decided_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("mailbox", "uid_validity", "uid"), name="unique_imap_message"
            ),
            models.CheckConstraint(
                condition=models.Q(state__in=("quarantined", "approved", "rejected")),
                name="valid_message_state",
            ),
        ]
        indexes = [
            models.Index(fields=("state", "-received_at")),
            models.Index(fields=("category", "state")),
        ]

    def __str__(self) -> str:
        return self.subject or str(self.id)


class Attachment(models.Model):
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name="attachments")
    filename = models.CharField(max_length=255, blank=True)
    content_type = models.CharField(max_length=255, blank=True)
    size = models.PositiveBigIntegerField(default=0)
    sha256 = models.CharField(max_length=64)
    dangerous = models.BooleanField(default=False)


class ApiToken(models.Model):
    name = models.CharField(max_length=120)
    prefix = models.CharField(max_length=16, unique=True)
    token_hash = models.CharField(max_length=64, unique=True)
    scope = models.CharField(max_length=40, default="messages:read:approved", editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    @classmethod
    def issue(cls, *, name: str, expires_at):
        raw = "mg_" + secrets.token_urlsafe(32)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        instance = cls.objects.create(
            name=name,
            prefix=raw[:12],
            token_hash=digest,
            expires_at=expires_at,
        )
        return instance, raw

    @property
    def active(self) -> bool:
        return self.revoked_at is None and (
            self.expires_at is None or self.expires_at > timezone.now()
        )


class ApprovedMessage(models.Model):
    id = models.UUIDField(primary_key=True)
    sender = models.CharField(max_length=320)
    sender_name = models.CharField(max_length=320)
    subject = models.CharField(max_length=998)
    received_at = models.DateTimeField(null=True)
    category = models.CharField(max_length=80)
    priority = models.PositiveSmallIntegerField()
    risk = models.CharField(max_length=10)
    summary = models.TextField()
    sanitized_text = models.TextField()
    links = models.JSONField()
    ingested_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = "mailgate_api_approved_message"


class AuditEvent(models.Model):
    actor = models.CharField(max_length=120)
    action = models.CharField(max_length=120)
    object_type = models.CharField(max_length=80, blank=True)
    object_id = models.CharField(max_length=80, blank=True)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [models.Index(fields=("actor", "action", "-created_at"))]


def audit(*, actor: str, action: str, obj=None, metadata=None) -> None:
    AuditEvent.objects.create(
        actor=actor[:120],
        action=action[:120],
        object_type=obj.__class__.__name__ if obj else "",
        object_id=str(obj.pk)[:80] if obj else "",
        metadata=metadata or {},
    )
