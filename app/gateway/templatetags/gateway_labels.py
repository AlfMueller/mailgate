# SPDX-License-Identifier: AGPL-3.0-only

from django import template
from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _

register = template.Library()

SIGNALS = {
    "authentication_failure": _("Authentication failed"),
    "independent_dkim_failure": _("Independent DKIM verification failed"),
    "independent_dkim_temperror": _("Independent DKIM verification temporarily unavailable"),
    "independent_dkim_pass": _("Independent DKIM verification passed"),
    "dangerous_attachment": _("Dangerous attachment type"),
    "prompt_injection_suspected": _("Possible prompt injection"),
    "attachment_present": _("Attachment present"),
    "attachment_content_not_inspected": _("Attachment content not inspected"),
    "too_many_attachments": _("Attachment limit exceeded"),
    "too_many_links": _("Link limit exceeded"),
    "too_many_mime_parts": _("MIME part limit exceeded"),
    "text_truncated": _("Text was truncated"),
    "mime_defect": _("Malformed MIME structure"),
    "missing_sender": _("Sender is missing"),
    "unicode_controls": _("Unicode controls made visible"),
    "unicode_controls_in_headers": _("Unicode controls in headers made visible"),
    "unknown_charset": _("Unknown character encoding"),
    "provider_authentication_pass": _("Provider reports authentication passed"),
    "manual_review_required": _("Manual review required"),
    "message_too_large": _("Message size limit exceeded"),
    "processing_error": _("Processing error"),
}

AUTH_VALUES = {
    "pass": _("passed"),
    "fail": _("failed"),
    "unknown": _("unknown"),
    "none": _("none"),
    "neutral": _("neutral"),
    "softfail": _("soft failure"),
    "temperror": _("temporary error"),
    "permerror": _("permanent error"),
}

ERROR_CODES = {
    "authentication_failed": _("Authentication failed"),
    "connection_failed": _("Connection failed"),
    "inbox_unavailable": _("Inbox unavailable"),
    "search_failed": _("Message search failed"),
    "uidvalidity_missing": _("Mailbox identity missing"),
    "size_unavailable": _("Message size unavailable"),
    "fetch_failed": _("Message fetch failed"),
    "processing_error": _("Processing error"),
    "empty_message": _("Empty message response"),
}

CATEGORIES = {
    "general": _("General"),
    "newsletter": _("Newsletter"),
    "finance": _("Finance"),
    "calendar": _("Calendar"),
    "uncategorized": _("Uncategorized"),
    "unsafe": _("Unsafe"),
}

AUDIT_ACTIONS = {
    "owner.created": _("Owner created"),
    "mailbox.created": _("Mailbox created"),
    "mailbox.updated": _("Mailbox updated"),
    "mailbox.deleted": _("Mailbox deleted"),
    "message.ingested": _("Message ingested"),
    "message.approved": _("Message approved"),
    "message.rejected": _("Message rejected"),
    "api.read": _("API read"),
    "token.created": _("Token created"),
    "token.revoked": _("Token revoked"),
}

OBJECT_TYPES = {
    "User": _("Owner"),
    "Mailbox": _("Mailbox"),
    "Message": _("Message"),
    "ApiToken": _("API token"),
}


def _label(mapping, value):
    if value in mapping:
        return mapping[value]
    return format_lazy(_("Technical code: {code}"), code=value)


@register.filter
def signal_label(value):
    return _label(SIGNALS, value)


@register.filter
def auth_label(value):
    return _label(AUTH_VALUES, value)


@register.filter
def error_label(value):
    return _label(ERROR_CODES, value)


@register.filter
def category_label(value):
    return _label(CATEGORIES, value)


@register.filter
def audit_action_label(value):
    return _label(AUDIT_ACTIONS, value)


@register.filter
def object_type_label(value):
    return _label(OBJECT_TYPES, value)
