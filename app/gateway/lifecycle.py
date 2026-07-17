# SPDX-License-Identifier: AGPL-3.0-only

from dataclasses import dataclass
from datetime import datetime, timedelta

from django.db import connection, transaction
from django.db.models import Q
from django.db.models.functions import Coalesce
from django.utils import timezone

from gateway.models import ApiToken, AuditEvent, Message, audit


@dataclass(frozen=True)
class RetentionPolicy:
    approved_days: int
    quarantined_days: int
    rejected_days: int
    token_days: int
    audit_days: int

    def __post_init__(self) -> None:
        for field_name, value in vars(self).items():
            if not 0 <= value <= 36_500:
                raise ValueError(f"{field_name} must be between 0 and 36500 days")


def _message_queryset(*, state: str, cutoff: datetime):
    return (
        Message.objects.filter(state=state)
        .annotate(retention_timestamp=Coalesce("decided_at", "ingested_at"))
        .filter(retention_timestamp__lt=cutoff)
    )


def _token_queryset(*, cutoff: datetime):
    return ApiToken.objects.filter(
        Q(revoked_at__lt=cutoff)
        | Q(revoked_at__isnull=True, expires_at__isnull=False, expires_at__lt=cutoff)
    )


def retention_querysets(policy: RetentionPolicy, *, now: datetime):
    return {
        "approved_messages": _message_queryset(
            state=Message.State.APPROVED,
            cutoff=now - timedelta(days=policy.approved_days),
        ),
        "quarantined_messages": _message_queryset(
            state=Message.State.QUARANTINED,
            cutoff=now - timedelta(days=policy.quarantined_days),
        ),
        "rejected_messages": _message_queryset(
            state=Message.State.REJECTED,
            cutoff=now - timedelta(days=policy.rejected_days),
        ),
        "inactive_tokens": _token_queryset(cutoff=now - timedelta(days=policy.token_days)),
        "audit_events": AuditEvent.objects.filter(
            created_at__lt=now - timedelta(days=policy.audit_days)
        ),
    }


def retention_counts(policy: RetentionPolicy, *, now: datetime | None = None) -> dict[str, int]:
    effective_now = now or timezone.now()
    return {
        name: queryset.count()
        for name, queryset in retention_querysets(policy, now=effective_now).items()
    }


def _delete_queryset_in_batches(queryset, *, batch_size: int) -> int:
    deleted = 0
    model = queryset.model
    while True:
        ids = list(queryset.order_by("pk").values_list("pk", flat=True)[:batch_size])
        if not ids:
            return deleted
        locked_ids = list(
            queryset.select_for_update()
            .filter(pk__in=ids)
            .order_by("pk")
            .values_list("pk", flat=True)
        )
        if not locked_ids:
            continue
        model.objects.filter(pk__in=locked_ids).delete()
        deleted += len(locked_ids)


def purge_retention(
    policy: RetentionPolicy,
    *,
    now: datetime | None = None,
    batch_size: int = 500,
) -> dict[str, int]:
    if not 1 <= batch_size <= 10_000:
        raise ValueError("batch_size must be between 1 and 10000")
    effective_now = now or timezone.now()
    with transaction.atomic():
        if connection.vendor == "postgresql":
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(%s)", [4_861_921_208_842_507_777])
        deleted = {
            name: _delete_queryset_in_batches(queryset, batch_size=batch_size)
            for name, queryset in retention_querysets(policy, now=effective_now).items()
        }
        audit(
            actor="system:retention",
            action="retention.purged",
            metadata={"counts": deleted, "policy_days": vars(policy)},
        )
    return deleted
