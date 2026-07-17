# SPDX-License-Identifier: AGPL-3.0-only

import base64

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import SimpleTestCase
from gateway.authentication import (
    MAX_DKIM_SIGNATURES,
    MAX_DNS_TXT_BYTES,
    DnsTemporaryError,
    verify_dkim,
)
from gateway.mail import assess, parse_message


class MemoryTxtResolver:
    def __init__(self, value: bytes | None):
        self.value = value
        self.names: list[str] = []

    def resolve_txt(self, name: str, *, timeout: float) -> bytes | None:
        self.names.append(name)
        return self.value


class UnavailableTxtResolver:
    def resolve_txt(self, name: str, *, timeout: float) -> bytes | None:
        raise DnsTemporaryError("synthetic timeout")


class DkimVerificationTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.private_key = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        public_der = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        cls.dns_record = b"v=DKIM1; k=rsa; p=" + base64.b64encode(public_der)
        cls.raw = (
            b"From: Sender <sender@example.test>\r\n"
            b"To: owner@example.test\r\n"
            b"Subject: Signed message\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Original body\r\n"
        )
        cls.signed = (
            dkim.sign(
                cls.raw,
                selector=b"mailgate",
                domain=b"example.test",
                privkey=cls.private_key,
                include_headers=[b"from", b"to", b"subject", b"content-type"],
            )
            + cls.raw
        )

    def test_valid_signature_is_verified_on_wire_bytes(self):
        resolver = MemoryTxtResolver(self.dns_record)
        result = verify_dkim(self.signed, resolver=resolver)
        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["signatures"][0]["domain"], "example.test")
        self.assertEqual(result["signatures"][0]["selector"], "mailgate")
        self.assertEqual(resolver.names, ["mailgate._domainkey.example.test"])

    def test_body_tampering_fails_independent_verification(self):
        tampered = self.signed.replace(b"Original body", b"Changed body!", 1)
        result = verify_dkim(tampered, resolver=MemoryTxtResolver(self.dns_record))
        self.assertEqual(result["result"], "fail")

    def test_dns_timeout_is_temporary_and_fail_closed(self):
        result = verify_dkim(self.signed, resolver=UnavailableTxtResolver())
        self.assertEqual(result["result"], "temperror")
        parsed = parse_message(
            self.signed,
            trusted_authserv_ids=set(),
            dns_txt_resolver=UnavailableTxtResolver(),
        )
        self.assertEqual(assess(parsed)[1], "quarantined")
        self.assertIn("independent_dkim_temperror", assess(parsed)[2])

    def test_forged_provider_claim_is_separate_from_independent_result(self):
        forged = self.raw.replace(
            b"Subject: Signed message\r\n",
            b"Subject: Signed message\r\n"
            b"Authentication-Results: mx.example.test; dkim=pass; dmarc=pass\r\n",
        )
        parsed = parse_message(
            forged,
            trusted_authserv_ids={"mx.example.test"},
            dns_txt_resolver=MemoryTxtResolver(self.dns_record),
        )
        self.assertEqual(parsed.authentication["provider_claims"]["dkim"], "pass")
        self.assertEqual(parsed.authentication["independent"]["dkim"]["result"], "none")
        self.assertEqual(assess(parsed)[1], "quarantined")

    def test_invalid_selector_is_rejected_before_dns(self):
        resolver = MemoryTxtResolver(self.dns_record)
        malformed = self.signed.replace(b"s=mailgate", b"s=bad/selector", 1)
        result = verify_dkim(malformed, resolver=resolver)
        self.assertEqual(result["result"], "permerror")
        self.assertEqual(resolver.names, [])

    def test_oversized_dns_answer_is_rejected(self):
        resolver = MemoryTxtResolver(b"x" * (MAX_DNS_TXT_BYTES + 1))
        result = verify_dkim(self.signed, resolver=resolver)
        self.assertEqual(result["result"], "permerror")

    def test_signature_count_is_bounded_without_dns(self):
        header, message = self.signed.split(b"\r\n", 1)
        excessive = b"\r\n".join([header] * (MAX_DKIM_SIGNATURES + 1)) + b"\r\n" + message
        resolver = MemoryTxtResolver(self.dns_record)
        result = verify_dkim(excessive, resolver=resolver)
        self.assertEqual(result["result"], "permerror")
        self.assertEqual(result["reason"], "too_many_signatures")
        self.assertEqual(resolver.names, [])

    def test_valid_signature_does_not_auto_approve(self):
        parsed = parse_message(
            self.signed,
            trusted_authserv_ids=set(),
            dns_txt_resolver=MemoryTxtResolver(self.dns_record),
        )
        self.assertEqual(parsed.authentication["independent"]["dkim"]["result"], "pass")
        self.assertEqual(assess(parsed)[1], "quarantined")
