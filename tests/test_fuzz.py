# SPDX-License-Identifier: AGPL-3.0-only

from django.test import SimpleTestCase
from gateway.ingestion import _message_size, _response_bytes
from gateway.mail import (
    MAX_LINKS,
    MAX_TEXT_CHARS,
    _html_to_text,
    _normalise_url,
    parse_authentication_results,
    parse_message,
)
from gateway.validators import normalise_authserv_ids
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

FUZZ_SETTINGS = settings(
    max_examples=150,
    deadline=None,
    suppress_health_check=(HealthCheck.too_slow,),
)


class FuzzTests(SimpleTestCase):
    @FUZZ_SETTINGS
    @given(st.binary(max_size=16_384))
    def test_message_parser_never_exceeds_output_bounds(self, payload):
        raw = (
            b"From: sender@example.test\r\n"
            b"To: owner@example.test\r\n"
            b"Subject: fuzz\r\n\r\n" + payload
        )
        parsed = parse_message(raw, trusted_authserv_ids=set())
        self.assertLessEqual(len(parsed.text), MAX_TEXT_CHARS)
        self.assertLessEqual(len(parsed.links), MAX_LINKS)
        self.assertEqual(parsed.authentication["independent"]["dkim"]["result"], "none")

    @FUZZ_SETTINGS
    @given(st.text(max_size=20_000))
    def test_html_and_url_normalisation_are_total_and_bounded(self, value):
        self.assertLessEqual(len(_html_to_text(value)), len(value[: MAX_TEXT_CHARS * 2]) * 6)
        result = _normalise_url(value)
        self.assertTrue(
            result is None or (len(result) <= 2048 and result.startswith(("http://", "https://")))
        )

    @FUZZ_SETTINGS
    @given(
        st.lists(st.text(max_size=1000), max_size=20),
        st.sets(st.text(max_size=80), max_size=10),
    )
    def test_authentication_claim_parser_has_closed_result_values(self, values, trusted_ids):
        result = parse_authentication_results(values, trusted_ids)
        self.assertEqual(set(result), {"spf", "dkim", "dmarc", "arc", "authserv_id"})
        allowed = {
            "pass",
            "fail",
            "softfail",
            "neutral",
            "none",
            "temperror",
            "permerror",
            "unknown",
        }
        self.assertTrue(all(result[key] in allowed for key in ("spf", "dkim", "dmarc", "arc")))

    @FUZZ_SETTINGS
    @given(st.text(max_size=1000))
    def test_authserv_normalisation_is_total(self, value):
        try:
            result = normalise_authserv_ids(value)
        except ValueError:
            return
        self.assertLessEqual(len(result), 500)
        self.assertEqual(result, result.lower())

    @FUZZ_SETTINGS
    @given(
        st.recursive(
            st.none() | st.binary(max_size=100),
            lambda child: st.lists(child, max_size=5),
            max_leaves=20,
        )
    )
    def test_imap_response_flattening_is_bounded_and_deterministic(self, value):
        first = _response_bytes(value)
        second = _response_bytes(value)
        self.assertEqual(first, second)
        self.assertIsInstance(first, bytes)

    @FUZZ_SETTINGS
    @given(st.lists(st.binary(max_size=100), max_size=10))
    def test_imap_size_parser_never_returns_negative(self, response):
        result = _message_size(response)
        self.assertTrue(result is None or result >= 0)
