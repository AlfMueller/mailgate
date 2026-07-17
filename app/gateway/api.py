# SPDX-License-Identifier: AGPL-3.0-only

import hashlib
from functools import wraps

from django.db.models import Count
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from gateway.api_auth import authorize_api_request
from gateway.models import ApprovedMessage


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
        status = authorize_api_request(digest, request.path)
        if status == "rate_limited":
            response = _error(429, "rate_limited")
            response["Retry-After"] = "60"
            return response
        if status != "authorized":
            return _error(401, "unauthorized")
        response = view(request, *args, **kwargs)
        response["Cache-Control"] = "no-store"
        return response

    return wrapped


def _message_json(item: ApprovedMessage, *, detail: bool = False):
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
    queryset = ApprovedMessage.objects.order_by("-received_at", "-ingested_at")[:limit]
    return JsonResponse({"items": [_message_json(item) for item in queryset], "limit": limit})


@token_required
def message_summary(request, message_id):
    try:
        item = ApprovedMessage.objects.get(pk=message_id)
    except (ApprovedMessage.DoesNotExist, ValueError):
        return _error(404, "not_found")
    return JsonResponse(_message_json(item, detail=True))


@token_required
def categories(request):
    items = list(
        ApprovedMessage.objects.all()
        .values("category")
        .annotate(count=Count("id"))
        .order_by("category")
    )
    return JsonResponse({"items": items})
