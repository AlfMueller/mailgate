# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import base64
import json
import os
import re
import time
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from email import policy
from email.parser import BytesParser
from typing import Protocol
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import dkim
import dns.exception
import dns.resolver

MAX_DKIM_SIGNATURES = 5
MAX_DNS_QUERIES = 5
MAX_DNS_TXT_BYTES = 8192
DNS_TIMEOUT_SECONDS = 5.0
DNS_TOTAL_TIMEOUT_SECONDS = 8.0
DKIM_QUERY_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9_-]{1,63}\.)+_domainkey\."
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


class DnsResolutionError(RuntimeError):
    temporary = False


class DnsTemporaryError(DnsResolutionError):
    temporary = True


class DnsTxtResolver(Protocol):
    def resolve_txt(self, name: str, *, timeout: float) -> bytes | None: ...


class SystemDnsTxtResolver:
    """Resolve one bounded TXT record; callers must still constrain allowed names."""

    def __init__(self, resolver: dns.resolver.Resolver | None = None):
        self._resolver = resolver or dns.resolver.Resolver(configure=True)

    def resolve_txt(self, name: str, *, timeout: float) -> bytes | None:
        try:
            answer = self._resolver.resolve(
                name,
                "TXT",
                search=False,
                lifetime=min(max(timeout, 0.1), DNS_TIMEOUT_SECONDS),
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            raise DnsTemporaryError("DNS TXT lookup unavailable") from exc
        except dns.exception.DNSException as exc:
            raise DnsResolutionError("DNS TXT lookup failed") from exc

        records = [b"".join(item.strings) for item in answer]
        if len(records) != 1:
            raise DnsResolutionError("DNS TXT lookup returned an ambiguous answer")
        if len(records[0]) > MAX_DNS_TXT_BYTES:
            raise DnsResolutionError("DNS TXT answer exceeds the size limit")
        return records[0]


class HttpDnsTxtResolver:
    """Use the internal, secret-less DKIM resolver instead of worker internet access."""

    def __init__(self, endpoint: str):
        self.endpoint = endpoint.rstrip("/")

    def resolve_txt(self, name: str, *, timeout: float) -> bytes | None:
        request = Request(  # noqa: S310 -- endpoint is fixed to the internal resolver at startup
            f"{self.endpoint}/resolve?{urlencode({'name': name})}",
            headers={"Accept": "application/json"},
        )
        try:
            with urlopen(request, timeout=min(max(timeout, 0.1), DNS_TIMEOUT_SECONDS)) as response:  # noqa: S310
                if response.status != 200:
                    raise DnsTemporaryError("Internal DKIM resolver returned an error")
                body = response.read(MAX_DNS_TXT_BYTES * 2)
        except (OSError, TimeoutError) as exc:
            raise DnsTemporaryError("Internal DKIM resolver is unavailable") from exc
        try:
            document = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DnsTemporaryError("Internal DKIM resolver returned invalid JSON") from exc
        if not isinstance(document, dict) or set(document) != {"value"}:
            raise DnsTemporaryError("Internal DKIM resolver returned an invalid schema")
        if document["value"] is None:
            return None
        if not isinstance(document["value"], str):
            raise DnsTemporaryError("Internal DKIM resolver returned an invalid value")
        try:
            value = base64.b64decode(document["value"], validate=True)
        except (ValueError, TypeError) as exc:
            raise DnsTemporaryError("Internal DKIM resolver returned invalid encoding") from exc
        if len(value) > MAX_DNS_TXT_BYTES:
            raise DnsResolutionError("DNS TXT answer exceeds the size limit")
        return value


def default_dns_txt_resolver() -> DnsTxtResolver:
    endpoint = os.getenv("MAILGATE_DKIM_RESOLVER_URL", "").strip()
    return HttpDnsTxtResolver(endpoint) if endpoint else SystemDnsTxtResolver()


@dataclass
class _DnsBudget:
    resolver: DnsTxtResolver
    queries: int = 0
    last_error: DnsResolutionError | None = None
    started_at: float = dataclass_field(default_factory=time.monotonic)

    def lookup(self, name: bytes, timeout: int = 5) -> bytes | None:
        self.queries += 1
        if self.queries > MAX_DNS_QUERIES:
            self.last_error = DnsResolutionError("DKIM DNS query limit exceeded")
            return None
        remaining = DNS_TOTAL_TIMEOUT_SECONDS - (time.monotonic() - self.started_at)
        if remaining <= 0:
            self.last_error = DnsTemporaryError("DKIM DNS time budget exceeded")
            return None
        try:
            decoded = name.decode("ascii").lower().rstrip(".")
        except UnicodeDecodeError:
            self.last_error = DnsResolutionError("DKIM DNS name is not ASCII")
            return None
        if not DKIM_QUERY_RE.fullmatch(decoded):
            self.last_error = DnsResolutionError("DKIM DNS name is outside the allowed shape")
            return None
        try:
            value = self.resolver.resolve_txt(
                decoded,
                timeout=min(float(timeout), DNS_TIMEOUT_SECONDS, remaining),
            )
        except DnsResolutionError as exc:
            self.last_error = exc
            return None
        if value is not None and not isinstance(value, bytes):
            self.last_error = DnsResolutionError("DNS TXT resolver returned a non-byte answer")
            return None
        if value is not None and len(value) > MAX_DNS_TXT_BYTES:
            self.last_error = DnsResolutionError("DKIM DNS answer exceeds the size limit")
            return None
        return value


def _signature_metadata(raw: bytes) -> list[dict[str, str]]:
    message = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    values = message.get_all("DKIM-Signature", [])
    metadata = []
    for value in values:
        tags: dict[str, str] = {}
        duplicate = False
        for item in str(value).split(";"):
            if "=" not in item:
                continue
            key, tag_value = item.split("=", 1)
            key = key.strip().lower()
            if key in tags:
                duplicate = True
            tags[key] = tag_value.strip()
        metadata.append(
            {
                "domain": tags.get("d", "")[:253],
                "selector": tags.get("s", "")[:63],
                "result": (
                    "permerror" if duplicate or not tags.get("d") or not tags.get("s") else ""
                ),
            }
        )
    return metadata


def verify_dkim(
    raw: bytes,
    *,
    resolver: DnsTxtResolver | None = None,
) -> dict[str, object]:
    """Verify DKIM against the unchanged wire bytes with bounded, injectable DNS."""

    signatures = _signature_metadata(raw)
    if not signatures:
        return {"result": "none", "signatures": []}
    if len(signatures) > MAX_DKIM_SIGNATURES:
        return {
            "result": "permerror",
            "signatures": signatures[:MAX_DKIM_SIGNATURES],
            "reason": "too_many_signatures",
        }

    budget = _DnsBudget(resolver or default_dns_txt_resolver())
    verifier = dkim.DKIM(raw, timeout=int(DNS_TIMEOUT_SECONDS))
    for index, signature in enumerate(signatures):
        if signature["result"]:
            continue
        budget.last_error = None
        try:
            valid = verifier.verify(idx=index, dnsfunc=budget.lookup)
        except dkim.ValidationError:
            signature["result"] = "fail"
            continue
        except (dkim.DKIMException, ValueError, IndexError):
            signature["result"] = "permerror"
            continue
        if valid:
            signature["result"] = "pass"
        elif budget.last_error is not None:
            signature["result"] = "temperror" if budget.last_error.temporary else "permerror"
        else:
            signature["result"] = "fail"

    results = {str(item["result"]) for item in signatures}
    if "pass" in results:
        result = "pass"
    elif "temperror" in results:
        result = "temperror"
    elif "permerror" in results:
        result = "permerror"
    else:
        result = "fail"
    return {"result": result, "signatures": signatures}
