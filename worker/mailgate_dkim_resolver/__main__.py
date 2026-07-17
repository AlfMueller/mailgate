# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import base64
import json
import os
import re
import threading
import time
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen

import dns.rdata
import dns.rdataclass
import dns.rdatatype

QUERY_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_-]{1,63}\.)+_domainkey\."
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
MAX_RESPONSE_BYTES = 16 * 1024
MAX_TXT_BYTES = 8192
MAX_REQUESTS_PER_MINUTE = 120
REQUEST_TIMES: deque[float] = deque()
RATE_LOCK = threading.Lock()


def _doh_url() -> str:
    value = os.getenv("MAILGATE_DOH_URL", "https://cloudflare-dns.com/dns-query").strip()
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError("MAILGATE_DOH_URL must be one HTTPS endpoint")
    if parsed.query or parsed.fragment:
        raise RuntimeError("MAILGATE_DOH_URL cannot contain a query or fragment")
    return value.rstrip("/")


def _rate_allowed(now: float) -> bool:
    with RATE_LOCK:
        while REQUEST_TIMES and REQUEST_TIMES[0] <= now - 60:
            REQUEST_TIMES.popleft()
        if len(REQUEST_TIMES) >= MAX_REQUESTS_PER_MINUTE:
            return False
        REQUEST_TIMES.append(now)
        return True


def resolve_dkim_txt(name: str, *, endpoint: str, timeout: float = 5.0) -> bytes | None:
    normalized = name.strip().lower().rstrip(".")
    if not QUERY_RE.fullmatch(normalized):
        raise ValueError("Only bounded DKIM TXT names are allowed")
    request = Request(  # noqa: S310 -- _doh_url requires a fixed HTTPS endpoint
        f"{endpoint}?{urlencode({'name': normalized, 'type': 'TXT'})}",
        headers={"Accept": "application/dns-json", "User-Agent": "MailGate-DKIM/1"},
    )
    with urlopen(request, timeout=min(max(timeout, 0.1), 5.0)) as response:  # noqa: S310
        if response.status != HTTPStatus.OK:
            raise OSError("DNS-over-HTTPS resolver returned an error")
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise OSError("DNS-over-HTTPS response exceeds the size limit")
    document = json.loads(body)
    if not isinstance(document, dict) or not isinstance(document.get("Status"), int):
        raise OSError("DNS-over-HTTPS response has an invalid schema")
    if document["Status"] == 3:
        return None
    if document["Status"] != 0:
        raise OSError("DNS-over-HTTPS lookup failed")
    records = []
    for answer in document.get("Answer", []):
        if not isinstance(answer, dict) or answer.get("type") != 16:
            continue
        data = answer.get("data")
        if not isinstance(data, str):
            raise OSError("DNS-over-HTTPS TXT answer is invalid")
        try:
            parsed = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, data)
        except Exception as exc:
            raise OSError("DNS-over-HTTPS TXT answer cannot be parsed") from exc
        records.append(b"".join(parsed.strings))
    if not records:
        return None
    if len(records) != 1 or len(records[0]) > MAX_TXT_BYTES:
        raise OSError("DNS-over-HTTPS TXT answer is ambiguous or too large")
    return records[0]


class Handler(BaseHTTPRequestHandler):
    server_version = "MailGateDKIM/1"

    def _json(self, status: HTTPStatus, document: dict) -> None:
        body = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/health" and not parsed.query:
            self._json(HTTPStatus.OK, {"status": "ok"})
            return
        if parsed.path != "/resolve" or len(self.path) > 600:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        try:
            values = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        except ValueError:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_query"})
            return
        if set(values) != {"name"} or len(values["name"]) != 1:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_query"})
            return
        if not _rate_allowed(time.monotonic()):
            self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "rate_limited"})
            return
        try:
            value = resolve_dkim_txt(values["name"][0], endpoint=self.server.doh_endpoint)
        except ValueError:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_query"})
            return
        except (OSError, TimeoutError, json.JSONDecodeError):
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "resolver_unavailable"})
            return
        encoded = base64.b64encode(value).decode("ascii") if value is not None else None
        self._json(HTTPStatus.OK, {"value": encoded})

    def do_POST(self):
        self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method_not_allowed"})

    def log_message(self, format, *args):
        # Query names are mail metadata and intentionally omitted from logs.
        return


class Server(ThreadingHTTPServer):
    def __init__(self, address, handler, *, doh_endpoint: str):
        super().__init__(address, handler)
        self.doh_endpoint = doh_endpoint


def main() -> None:
    # The container network is the security boundary; no host port is published.
    server = Server(("0.0.0.0", 8053), Handler, doh_endpoint=_doh_url())  # noqa: S104
    server.serve_forever()


if __name__ == "__main__":
    main()
