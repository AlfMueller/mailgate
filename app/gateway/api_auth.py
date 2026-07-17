# SPDX-License-Identifier: AGPL-3.0-only

from datetime import timedelta

from django.db import connection, transaction
from django.utils import timezone

from gateway.models import ApiToken, AuditEvent, audit

RATE_LIMIT_PER_MINUTE = 60


def _orm_authorize(token_hash: str, path: str) -> str:
    """SQLite-only fallback used by unit tests; production uses the DB function."""
    with transaction.atomic():
        try:
            token = ApiToken.objects.select_for_update().get(token_hash=token_hash)
        except ApiToken.DoesNotExist:
            return "unauthorized"
        now = timezone.now()
        if not token.active or token.scope != "messages:read:approved":
            return "unauthorized"
        recent = AuditEvent.objects.filter(
            actor=f"token:{token.prefix}",
            action="api.read",
            created_at__gte=now - timedelta(minutes=1),
        ).count()
        if recent >= RATE_LIMIT_PER_MINUTE:
            return "rate_limited"
        token.last_used_at = now
        token.save(update_fields=("last_used_at",))
        audit(
            actor=f"token:{token.prefix}",
            action="api.read",
            metadata={"path": path},
        )
    return "authorized"


def authorize_api_request(token_hash: str, path: str) -> str:
    if connection.vendor != "postgresql":
        return _orm_authorize(token_hash, path)
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT status FROM public.mailgate_api_authorize(%s, %s)",
            [token_hash, path],
        )
        row = cursor.fetchone()
    return row[0] if row else "unauthorized"
