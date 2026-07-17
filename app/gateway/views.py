# SPDX-License-Identifier: AGPL-3.0-only

from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.auth.decorators import login_required
from django.db import connection, transaction
from django.db.models import Max, Q
from django.http import Http404, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from gateway.forms import (
    MailboxDeleteForm,
    MailboxForm,
    OwnerCreationForm,
    SecurityTestForm,
    TokenForm,
)
from gateway.models import ApiToken, Attachment, AuditEvent, Mailbox, Message, audit
from gateway.selftest import run_prompt_injection_suite


@sensitive_post_parameters("setup_token", "password1", "password2")
@require_http_methods(["GET", "POST"])
def setup_owner(request):
    if get_user_model().objects.exists():
        return redirect("login" if not request.user.is_authenticated else "dashboard")
    form = OwnerCreationForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            if connection.vendor == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_advisory_xact_lock(%s)", [0x4D474F574E4552])
            if get_user_model().objects.exists():
                return redirect("login")
            user = form.save()
            audit(actor=user.username, action="owner.created", obj=user)
        login(request, user)
        return redirect("mailbox-create")
    return render(request, "gateway/setup_owner.html", {"form": form})


@login_required
def dashboard(request):
    counts = {
        state: Message.objects.filter(state=state).count() for state, _ in Message.State.choices
    }
    return render(
        request,
        "gateway/dashboard.html",
        {
            "counts": counts,
            "mailboxes": Mailbox.objects.all(),
            "recent": Message.objects.order_by("-received_at", "-ingested_at")[:20],
        },
    )


@login_required
@sensitive_post_parameters("password")
@require_http_methods(["GET", "POST"])
def mailbox_create(request):
    form = MailboxForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        mailbox = form.save()
        audit(actor=request.user.username, action="mailbox.created", obj=mailbox)
        messages.success(
            request, _("Mailbox saved. The worker will test it without changing the mailbox.")
        )
        return redirect("dashboard")
    return render(request, "gateway/mailbox_form.html", {"form": form, "editing": False})


@login_required
@sensitive_post_parameters("password")
@require_http_methods(["GET", "POST"])
def mailbox_edit(request, mailbox_id):
    mailbox = get_object_or_404(Mailbox, pk=mailbox_id)
    form = MailboxForm(request.POST if request.method == "POST" else None, instance=mailbox)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            mailbox = Mailbox.objects.select_for_update().get(pk=mailbox_id)
            was_enabled = mailbox.enabled
            form = MailboxForm(request.POST, instance=mailbox)
            if form.is_valid():
                changed_fields = sorted(form.changed_data)
                mailbox = form.save(commit=False)
                if "password" in changed_fields or (not was_enabled and mailbox.enabled):
                    mailbox.last_sync_at = None
                    mailbox.last_error_code = ""
                mailbox.save()
                audit(
                    actor=request.user.username,
                    action="mailbox.updated",
                    obj=mailbox,
                    metadata={"changed_fields": changed_fields},
                )
                messages.success(
                    request,
                    _(
                        "Mailbox updated. Connection changes will be tested "
                        "read-only by the worker."
                    ),
                )
                return redirect("dashboard")
    return render(
        request,
        "gateway/mailbox_form.html",
        {"form": form, "editing": True, "mailbox": mailbox},
    )


@login_required
@require_http_methods(["GET", "POST"])
def mailbox_delete(request, mailbox_id):
    mailbox = get_object_or_404(Mailbox, pk=mailbox_id)
    form = MailboxDeleteForm(
        request.POST if request.method == "POST" else None,
        mailbox=mailbox,
    )
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            mailbox = Mailbox.objects.select_for_update().get(pk=mailbox_id)
            message_count = mailbox.messages.count()
            attachment_count = Attachment.objects.filter(message__mailbox=mailbox).count()
            audit(
                actor=request.user.username,
                action="mailbox.deleted",
                obj=mailbox,
                metadata={
                    "messages_deleted": message_count,
                    "attachments_deleted": attachment_count,
                },
            )
            mailbox.delete()
        messages.success(
            request,
            _(
                "Mailbox connection and its local MailGate data were deleted. "
                "The remote mailbox was not changed."
            ),
        )
        return redirect("dashboard")
    return render(
        request,
        "gateway/mailbox_delete.html",
        {"form": form, "mailbox": mailbox},
    )


@login_required
@require_http_methods(["GET", "POST"])
def security_test(request):
    results = None
    form = SecurityTestForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        mailbox = form.cleaned_data["mailbox"]
        results = run_prompt_injection_suite(mailbox)
    return render(
        request,
        "gateway/security_test.html",
        {"form": form, "results": results, "has_mailboxes": Mailbox.objects.exists()},
    )


@require_GET
def about(request):
    context = {}
    if request.user.is_authenticated:
        enabled = Mailbox.objects.filter(enabled=True)
        last_worker_check = enabled.aggregate(value=Max("last_sync_at"))["value"]
        stale_before = timezone.now() - timedelta(
            seconds=settings.MAILGATE_WORKER_POLL_INTERVAL_SECONDS * 2 + 10
        )
        if not enabled.exists():
            worker_status = "not_observable"
        elif enabled.filter(
            Q(last_sync_at__isnull=True) | Q(last_sync_at__lt=stale_before)
        ).exists():
            worker_status = "stale"
        else:
            worker_status = "recent"
        active_tokens = ApiToken.objects.filter(revoked_at__isnull=True).filter(
            Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
        )
        context = {
            "last_worker_check": last_worker_check,
            "worker_status": worker_status,
            "message_counts": {
                state: Message.objects.filter(state=state).count()
                for state, _ in Message.State.choices
            },
            "active_token_count": active_tokens.count(),
        }
    return render(request, "gateway/about.html", context)


@login_required
def message_list(request):
    state = request.GET.get("state", Message.State.QUARANTINED)
    if state not in Message.State.values:
        raise Http404
    items = Message.objects.filter(state=state).order_by("-received_at", "-ingested_at")[:200]
    return render(request, "gateway/message_list.html", {"items": items, "state": state})


@login_required
def message_detail(request, message_id):
    item = get_object_or_404(Message.objects.prefetch_related("attachments"), pk=message_id)
    return render(request, "gateway/message_detail.html", {"item": item})


@login_required
@require_POST
def message_decide(request, message_id):
    item = get_object_or_404(Message, pk=message_id)
    decision = request.POST.get("decision")
    if decision not in {Message.State.APPROVED, Message.State.REJECTED}:
        return HttpResponseNotAllowed(["POST"])
    with transaction.atomic():
        item.state = decision
        item.decided_at = timezone.now()
        item.save(update_fields=("state", "decided_at"))
        audit(actor=request.user.username, action=f"message.{decision}", obj=item)
    return redirect("message-detail", message_id=item.pk)


@login_required
@require_http_methods(["GET", "POST"])
def tokens(request):
    raw_token = None
    form = TokenForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        token, raw_token = ApiToken.issue(
            name=form.cleaned_data["name"], expires_at=form.expires_at()
        )
        audit(
            actor=request.user.username,
            action="token.created",
            obj=token,
            metadata={
                "prefix": token.prefix,
                "expiry": "never" if token.expires_at is None else "finite",
            },
        )
        form = TokenForm()
    return render(
        request,
        "gateway/tokens.html",
        {
            "form": form,
            "tokens": ApiToken.objects.order_by("-created_at"),
            "raw_token": raw_token,
        },
    )


@login_required
@require_POST
def token_revoke(request, token_id):
    token = get_object_or_404(ApiToken, pk=token_id)
    if token.revoked_at is None:
        token.revoked_at = timezone.now()
        token.save(update_fields=("revoked_at",))
        audit(
            actor=request.user.username,
            action="token.revoked",
            obj=token,
            metadata={"prefix": token.prefix},
        )
    return redirect("tokens")


@login_required
def audit_log(request):
    return render(request, "gateway/audit.html", {"events": AuditEvent.objects.all()[:250]})
