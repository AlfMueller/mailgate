# SPDX-License-Identifier: AGPL-3.0-only

import base64
import io
import json
from unittest import TestCase, mock

from gateway.authentication import DnsResolutionError, HttpDnsTxtResolver
from mailgate_dkim_resolver.__main__ import resolve_dkim_txt


class _Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class DkimResolverTests(TestCase):
    def test_proxy_accepts_only_dkim_txt_names_and_joins_txt_chunks(self):
        response = {"Status": 0, "Answer": [{"type": 16, "data": '"v=DKIM1; " "p=abc"'}]}
        with mock.patch(
            "mailgate_dkim_resolver.__main__.urlopen",
            return_value=_Response(json.dumps(response).encode()),
        ):
            self.assertEqual(
                resolve_dkim_txt(
                    "selector._domainkey.example.test",
                    endpoint="https://resolver.example.test/dns-query",
                ),
                b"v=DKIM1; p=abc",
            )
        for name in ("example.test", "_dmarc.example.test", "a.example.test", "127.0.0.1"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                resolve_dkim_txt(name, endpoint="https://resolver.example.test/dns-query")

    def test_proxy_rejects_ambiguous_txt_answers(self):
        response = {
            "Status": 0,
            "Answer": [{"type": 16, "data": '"one"'}, {"type": 16, "data": '"two"'}],
        }
        with (
            mock.patch(
                "mailgate_dkim_resolver.__main__.urlopen",
                return_value=_Response(json.dumps(response).encode()),
            ),
            self.assertRaises(OSError),
        ):
            resolve_dkim_txt(
                "selector._domainkey.example.test",
                endpoint="https://resolver.example.test/dns-query",
            )

    def test_worker_http_adapter_validates_schema_and_size(self):
        encoded = base64.b64encode(b"v=DKIM1; p=abc").decode()
        with mock.patch(
            "gateway.authentication.urlopen",
            return_value=_Response(json.dumps({"value": encoded}).encode()),
        ):
            self.assertEqual(
                HttpDnsTxtResolver("http://dkim-resolver:8053").resolve_txt(
                    "selector._domainkey.example.test", timeout=1
                ),
                b"v=DKIM1; p=abc",
            )
        oversized = base64.b64encode(b"x" * 8193).decode()
        with (
            mock.patch(
                "gateway.authentication.urlopen",
                return_value=_Response(json.dumps({"value": oversized}).encode()),
            ),
            self.assertRaises(DnsResolutionError),
        ):
            HttpDnsTxtResolver("http://dkim-resolver:8053").resolve_txt(
                "selector._domainkey.example.test", timeout=1
            )
