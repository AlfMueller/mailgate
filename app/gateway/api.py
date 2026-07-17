# SPDX-License-Identifier: AGPL-3.0-only

import hashlib
from datetime import timedelta
from functools import wraps

from django.db import transaction
from django.db.models import Count
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from gateway.models import ApiToken, AuditEvent, Message, audit

RATE_LIMIT_PER_MINUTE = 60


def _error(status: int, code: str):
    return JsonResponse({"error": code}, status=status)


def token_required(view):
    @wraps(view)
    @csrf_exempt
    def wrapped(request, *args, **kwargs):
        if request.method != "GET":
            return _error(405, "method_not_allowed")
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer ") or len(header) > 256:
            return _error(401, "unauthorized")
        digest = hashlib.sha256(header[7:].encode("utf-8")).hexdigest()
        with transaction.atomic():
            try:
                token = ApiToken.objects.select_for_update().get(token_hash=digest)
            except ApiToken.DoesNotExist:
                return _error(401, "unauthorized")
            now = timezone.now()
            if not token.active or token.scope != "messages:read:approved":
                return _error(401, "unauthorized")
            recent = AuditEvent.objects.filter(
                actor=f"token:{token.prefix}",
                action="api.read",
                created_at__gte=now - timedelta(minutes=1),
            ).count()
            if recent >= RATE_LIMIT_PER_MINUTE:
                response = _error(429, "rate_limited")
                response["Retry-After"] = "60"
                return response
            token.last_used_at = now
            token.save(update_fields=("last_used_at",))
            audit(
                actor=f"token:{token.prefix}",
                action="api.read",
                metadata={"path": request.path},
            )
        request.api_token = token
        response = view(request, *args, **kwargs)
        response["Cache-Control"] = "no-store"
        return response

    return wrapped


def _message_json(item: Message, *, detail: bool = False):
    result = {
        "id": str(item.pk),
        "sender": item.sender,
        "sender_name": item.sender_name,
        "subject": item.subject,
        "received_at": item.received_at.isoformat() if item.received_at else None,
        "category": item.category,
        "priority": item.priority,
        "risk": item.risk,
        "summary": item.summary,
    }
    if detail:
        result.update({"text": item.sanitized_text, "links": item.links})
    return result


@token_required
def messages(request):
    if request.GET.get("state", "approved") != "approved":
        return _error(400, "only_approved_state_is_available")
    try:
        limit = min(max(int(request.GET.get("limit", "50")), 1), 100)
    except ValueError:
        return _error(400, "invalid_limit")
    queryset = Message.objects.filter(state=Message.State.APPROVED).order_by(
        "-received_at", "-ingested_at"
    )[:limit]
    return JsonResponse({"items": [_message_json(item) for item in queryset], "limit": limit})


@token_required
def message_summary(request, message_id):
    try:
        item = Message.objects.get(pk=message_id, state=Message.State.APPROVED)
    except (Message.DoesNotExist, ValueError):
        return _error(404, "not_found")
    return JsonResponse(_message_json(item, detail=True))


@token_required
def categories(request):
    items = list(
        Message.objects.filter(state=Message.State.APPROVED)
        .values("category")
        .annotate(count=Count("id"))
        .order_by("category")
    )
    return JsonResponse({"items": items})
