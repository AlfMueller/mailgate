# SPDX-License-Identifier: AGPL-3.0-only

import os
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from mailgate.config import ConfigurationError, get_bool, get_dns_hostname, get_secret


class SecretConfigurationTests(TestCase):
    def test_reads_secret_from_file(self):
        with tempfile.TemporaryDirectory() as directory:
            secret_file = Path(directory) / "secret"
            secret_file.write_text("synthetic-secret-value\n", encoding="utf-8")
            with patch.dict(
                os.environ,
                {"EXAMPLE_SECRET_FILE": str(secret_file)},
                clear=False,
            ):
                self.assertEqual(
                    get_secret("EXAMPLE_SECRET", minimum_length=10),
                    "synthetic-secret-value",
                )

    def test_rejects_ambiguous_secret_sources(self):
        with patch.dict(
            os.environ,
            {"EXAMPLE_SECRET": "direct", "EXAMPLE_SECRET_FILE": "file"},
            clear=False,
        ):
            with self.assertRaises(ConfigurationError):
                get_secret("EXAMPLE_SECRET")

    def test_rejects_short_secret(self):
        with patch.dict(os.environ, {"EXAMPLE_SECRET": "short"}, clear=False):
            with self.assertRaises(ConfigurationError):
                get_secret("EXAMPLE_SECRET", minimum_length=20)


class BooleanConfigurationTests(TestCase):
    def test_accepts_explicit_boolean(self):
        with patch.dict(os.environ, {"EXAMPLE_BOOL": "yes"}, clear=False):
            self.assertTrue(get_bool("EXAMPLE_BOOL"))

    def test_rejects_unknown_boolean(self):
        with patch.dict(os.environ, {"EXAMPLE_BOOL": "perhaps"}, clear=False):
            with self.assertRaises(ConfigurationError):
                get_bool("EXAMPLE_BOOL")


class HostnameConfigurationTests(TestCase):
    def test_normalizes_dns_hostname(self):
        with patch.dict(os.environ, {"EXAMPLE_HOST": "IMAP.Example.Test."}, clear=False):
            self.assertEqual(
                get_dns_hostname("EXAMPLE_HOST", default="unused.example.test"),
                "imap.example.test",
            )

    def test_rejects_ip_wildcard_and_local_names(self):
        for value in ("127.0.0.1", "*.example.test", "localhost", "imap.local", "singlelabel"):
            with self.subTest(value=value):
                with patch.dict(os.environ, {"EXAMPLE_HOST": value}, clear=False):
                    with self.assertRaises(ConfigurationError):
                        get_dns_hostname("EXAMPLE_HOST", default="unused.example.test")
