# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import hashlib
import html
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

from gateway.authentication import DnsTxtResolver, verify_dkim

MAX_MESSAGE_BYTES = 10 * 1024 * 1024
MAX_PARTS = 100
MAX_TEXT_CHARS = 200_000
MAX_ATTACHMENTS = 25
MAX_LINKS = 100
DANGEROUS_EXTENSIONS = {
    ".app",
    ".bat",
    ".cmd",
    ".com",
    ".cpl",
    ".exe",
    ".hta",
    ".js",
    ".jse",
    ".lnk",
    ".msi",
    ".ps1",
    ".scr",
    ".vbs",
    ".vbe",
    ".wsf",
}
URL_RE = re.compile(r"https?://[^\s<>\]\[\"']+", re.IGNORECASE)
CONTROL_NAMES = ("RIGHT-TO-LEFT", "LEFT-TO-RIGHT", "ISOLATE", "OVERRIDE", "EMBEDDING")
PROMPT_INJECTION_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE | re.DOTALL)
    for pattern in (
        r"\b(?:ignore|disregard|forget)\b.{0,80}\b(?:previous|prior|above|system|developer)\b.{0,40}\b(?:instruction|message|prompt)s?\b",
        r"\b(?:system prompt|developer message)\b",
        (
            r"\b(?:reveal|print|show|send|exfiltrate)\b.{0,80}\b"
            r"(?:secret|password|credential|token|api[ -]?key)s?\b"
        ),
        r"\b(?:call|use|invoke|run|execute)\b.{0,40}\b(?:tool|command|shell|terminal|api)s?\b",
        r"\byou are now\b.{0,80}\b(?:assistant|agent|system|administrator)\b",
        r"\bignoriere\b.{0,80}\b(?:vorherige|obige|system|entwickler)[a-zäöüß-]*\b.{0,40}\b(?:anweisung|nachricht|prompt)s?\b",
        (
            r"\b(?:zeige|sende|verrate|extrahiere)\b.{0,80}\b"
            r"(?:geheimnis|passwort|zugangsdaten|token|api[ -]?schlüssel)\b"
        ),
        r"\b(?:führe|starte|verwende)\b.{0,40}\b(?:werkzeug|befehl|shell|terminal|api)\b",
    )
)


class UnsafeMessage(ValueError):
    pass


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "template", "svg", "form", "object", "iframe"}:
            self.skip += 1
        elif tag in {"p", "br", "div", "li", "tr", "h1", "h2", "h3", "h4"}:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "template", "svg", "form", "object", "iframe"} and self.skip:
            self.skip -= 1
        elif tag in {"p", "div", "li", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


@dataclass
class ParsedAttachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    dangerous: bool


@dataclass
class ParsedMessage:
    sender: str = ""
    sender_name: str = ""
    recipients: list[str] = field(default_factory=list)
    subject: str = ""
    received_at: datetime | None = None
    text: str = ""
    links: list[str] = field(default_factory=list)
    attachments: list[ParsedAttachment] = field(default_factory=list)
    message_id_hash: str = ""
    authentication: dict[str, object] = field(default_factory=dict)
    signals: list[str] = field(default_factory=list)


def _safe_header(value, limit: int = 998) -> str:
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


def _visible_controls(value: str) -> tuple[str, bool]:
    found = False
    out: list[str] = []
    for char in value:
        name = unicodedata.name(char, "")
        if char in {"\n", "\t"}:
            out.append(char)
        elif unicodedata.category(char) == "Cf" or any(item in name for item in CONTROL_NAMES):
            found = True
            out.append(f"[UNICODE {name or 'CONTROL'}]")
        elif unicodedata.category(char) == "Cc":
            out.append(" ")
        else:
            out.append(char)
    return "".join(out), found


def _html_to_text(value: str) -> str:
    parser = _TextExtractor()
    parser.feed(value[: MAX_TEXT_CHARS * 2])
    return html.unescape("".join(parser.parts))


def _normalise_url(value: str) -> str | None:
    try:
        parts = urlsplit(value.rstrip(".,;:!?)"))
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        host = parts.hostname.encode("idna").decode("ascii").lower()
        port = f":{parts.port}" if parts.port else ""
        return urlunsplit((parts.scheme.lower(), host + port, parts.path, parts.query, ""))[:2048]
    except (ValueError, UnicodeError):
        return None


def has_prompt_injection_indicators(*values: str) -> bool:
    """Return a conservative signal, never a claim that other content is safe."""
    content = unicodedata.normalize("NFKC", "\n".join(values))
    return any(pattern.search(content) for pattern in PROMPT_INJECTION_PATTERNS)


def parse_authentication_results(values: list[str], trusted_ids: set[str]) -> dict[str, str]:
    result = {item: "unknown" for item in ("spf", "dkim", "dmarc", "arc")}
    result["authserv_id"] = ""
    if not trusted_ids:
        return result
    for value in values:
        authserv = value.split(";", 1)[0].strip().lower()
        if authserv not in trusted_ids:
            continue
        result["authserv_id"] = authserv
        for method in result:
            match = re.search(rf"(?:^|[;\s]){method}=([a-zA-Z_-]+)", value, re.I)
            if match:
                candidate = match.group(1).lower()
                result[method] = (
                    candidate
                    if candidate
                    in {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}
                    else "unknown"
                )
        break
    return result


def parse_message(
    raw: bytes,
    *,
    trusted_authserv_ids: set[str],
    dns_txt_resolver: DnsTxtResolver | None = None,
) -> ParsedMessage:
    if len(raw) > MAX_MESSAGE_BYTES:
        raise UnsafeMessage("message_too_large")
    independent_dkim = verify_dkim(raw, resolver=dns_txt_resolver)
    message = BytesParser(policy=policy.default).parsebytes(raw)
    defects = getattr(message, "defects", ())
    signals = ["mime_defect"] if defects else []
    addresses = getaddresses([str(message.get("From", ""))])
    sender_name, sender = addresses[0] if addresses else ("", "")
    recipients = [
        address
        for _, address in getaddresses([str(message.get("To", "")), str(message.get("Cc", ""))])
    ]
    try:
        received_at = parsedate_to_datetime(str(message.get("Date", "")))
    except (TypeError, ValueError, OverflowError):
        received_at = None
    message_id = _safe_header(message.get("Message-ID"), 998)
    parsed = ParsedMessage(
        sender=_safe_header(sender, 320),
        sender_name=_safe_header(sender_name, 320),
        recipients=[_safe_header(item, 320) for item in recipients[:100]],
        subject=_safe_header(message.get("Subject")),
        received_at=received_at,
        message_id_hash=hashlib.sha256(message_id.encode()).hexdigest() if message_id else "",
        authentication={
            "schema_version": 1,
            "provider_claims": parse_authentication_results(
                message.get_all("Authentication-Results", []), trusted_authserv_ids
            ),
            "independent": {"dkim": independent_dkim},
        },
        signals=signals,
    )
    for field_name in ("sender", "sender_name", "subject"):
        visible, found = _visible_controls(getattr(parsed, field_name))
        setattr(parsed, field_name, visible)
        if found:
            parsed.signals.append("unicode_controls_in_headers")
    visible_recipients: list[str] = []
    for recipient in parsed.recipients:
        visible, found = _visible_controls(recipient)
        visible_recipients.append(visible)
        if found:
            parsed.signals.append("unicode_controls_in_headers")
    parsed.recipients = visible_recipients
    text_parts: list[str] = []
    parts = list(message.walk())
    if len(parts) > MAX_PARTS:
        raise UnsafeMessage("too_many_mime_parts")
    for part in parts:
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        disposition = part.get_content_disposition()
        filename = _safe_header(part.get_filename(), 255)
        if disposition == "attachment" or filename:
            if len(parsed.attachments) >= MAX_ATTACHMENTS:
                raise UnsafeMessage("too_many_attachments")
            suffix = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            content_type = part.get_content_type().lower()
            dangerous = suffix in DANGEROUS_EXTENSIONS or content_type in {
                "application/x-msdownload",
                "application/x-dosexec",
                "application/javascript",
            }
            parsed.attachments.append(
                ParsedAttachment(
                    filename=filename,
                    content_type=content_type,
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    dangerous=dangerous,
                )
            )
            parsed.signals.append("attachment_present")
            parsed.signals.append("attachment_content_not_inspected")
            if dangerous:
                parsed.signals.append("dangerous_attachment")
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            value = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            value = payload.decode("utf-8", errors="replace")
            parsed.signals.append("unknown_charset")
        text_parts.append(_html_to_text(value) if part.get_content_type() == "text/html" else value)
    text = "\n\n".join(text_parts)
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]
        parsed.signals.append("text_truncated")
    text, controls = _visible_controls(text)
    if controls:
        parsed.signals.append("unicode_controls")
    parsed.text = "\n".join(line.rstrip() for line in text.replace("\r", "").splitlines()).strip()
    urls: list[str] = []
    for match in URL_RE.findall(parsed.text):
        normalised = _normalise_url(match)
        if normalised and normalised not in urls:
            urls.append(normalised)
        if len(urls) >= MAX_LINKS:
            parsed.signals.append("too_many_links")
            break
    parsed.links = urls
    if has_prompt_injection_indicators(
        parsed.sender,
        parsed.sender_name,
        parsed.subject,
        parsed.text,
        *parsed.links,
    ):
        parsed.signals.append("prompt_injection_suspected")
    return parsed


def classify(parsed: ParsedMessage) -> tuple[str, int, str]:
    value = f"{parsed.subject}\n{parsed.text[:5000]}".lower()
    if any(word in value for word in ("invoice", "rechnung", "payment", "zahlung")):
        return "finance", 2, "Financial message"
    if any(word in value for word in ("meeting", "termin", "appointment", "calendar")):
        return "calendar", 2, "Calendar-related message"
    if any(word in value for word in ("newsletter", "unsubscribe", "abmelden")):
        return "newsletter", 4, "Newsletter"
    return "general", 3, (parsed.subject or "Message")[:240]


def assess(parsed: ParsedMessage) -> tuple[str, str, list[str]]:
    reasons = list(dict.fromkeys(parsed.signals))
    provider_claims = parsed.authentication.get("provider_claims", {})
    independent_dkim = parsed.authentication.get("independent", {}).get("dkim", {})
    if any(
        provider_claims.get(item) in {"fail", "softfail", "permerror", "temperror"}
        for item in ("dmarc", "dkim", "spf")
    ):
        reasons.append("authentication_failure")
    if independent_dkim.get("result") in {"fail", "permerror"}:
        reasons.append("independent_dkim_failure")
    elif independent_dkim.get("result") == "temperror":
        reasons.append("independent_dkim_temperror")
    if not parsed.sender:
        reasons.append("missing_sender")
    if any(
        signal in reasons
        for signal in (
            "dangerous_attachment",
            "authentication_failure",
            "independent_dkim_failure",
            "prompt_injection_suspected",
        )
    ):
        return "high", "quarantined", reasons
    # Authentication-Results are provider claims carried inside untrusted mail data.
    # Even a complete pass can reduce review urgency, but can never auto-approve.
    if independent_dkim.get("result") == "pass" and not reasons:
        reasons.append("independent_dkim_pass")
        return "low", "quarantined", reasons
    if provider_claims.get("dmarc") == "pass" and not reasons:
        reasons.append("provider_authentication_pass")
        return "low", "quarantined", reasons
    reasons.append("manual_review_required")
    return "medium", "quarantined", list(dict.fromkeys(reasons))
