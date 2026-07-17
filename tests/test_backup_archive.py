# SPDX-License-Identifier: AGPL-3.0-only

import base64
import io
import os
import sys
import tempfile
from pathlib import Path
from unittest import TestCase

from cryptography.fernet import Fernet

from scripts.backup import PrefixedReader
from scripts.backup_archive import (
    BackupArchiveError,
    decrypt_to_temporary,
    encrypt_stream,
    load_backup_key,
)
from scripts.restore import recover_credential_bundle, run_pg_restore, validate_restore_project


class BackupArchiveTests(TestCase):
    def setUp(self):
        self.key = base64.urlsafe_b64decode(Fernet.generate_key())
        self.metadata = {"archive_version": 1, "git_commit": "a" * 40}

    def _archive(self, payload=b"synthetic pg_dump data") -> Path:
        descriptor, name = tempfile.mkstemp(suffix=".mailgate-backup")
        os.close(descriptor)
        path = Path(name)
        with io.BytesIO(payload) as source, path.open("wb") as destination:
            encrypt_stream(source, destination, key=self.key, metadata=self.metadata)
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def test_round_trip_is_authenticated_and_preserves_metadata(self):
        archive = self._archive(b"x" * 2_000_000)
        temporary, metadata = decrypt_to_temporary(archive, key=self.key)
        self.addCleanup(temporary.unlink, missing_ok=True)
        self.assertEqual(temporary.read_bytes(), b"x" * 2_000_000)
        self.assertEqual(metadata, self.metadata)

    def test_ciphertext_tampering_is_rejected_without_plaintext_result(self):
        archive = self._archive()
        value = bytearray(archive.read_bytes())
        value[-20] ^= 1
        archive.write_bytes(value)
        with self.assertRaisesRegex(BackupArchiveError, "authentication failed"):
            decrypt_to_temporary(archive, key=self.key)

    def test_wrong_key_and_truncated_archives_are_rejected(self):
        archive = self._archive()
        with self.assertRaises(BackupArchiveError):
            decrypt_to_temporary(archive, key=os.urandom(32))
        archive.write_bytes(archive.read_bytes()[:20])
        with self.assertRaises(BackupArchiveError):
            decrypt_to_temporary(archive, key=self.key)

    def test_key_file_requires_one_32_byte_urlsafe_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backup_key"
            path.write_bytes(Fernet.generate_key() + b"\n")
            self.assertEqual(len(load_backup_key(path)), 32)
            path.write_text("not-a-key", encoding="ascii")
            with self.assertRaises(BackupArchiveError):
                load_backup_key(path)

    def test_prefixed_reader_never_loses_stream_bytes(self):
        reader = PrefixedReader(b"prefix", io.BytesIO(b"payload"))
        self.assertEqual(reader.read(2), b"pr")
        self.assertEqual(reader.read(7), b"efixpay")
        self.assertEqual(reader.read(), b"load")

    def test_restore_stream_starts_at_the_current_payload_offset(self):
        source = io.BytesIO(b"bundle-prefixPGDMP-synthetic")
        source.seek(len(b"bundle-prefix"))
        command = [
            sys.executable,
            "-c",
            "import sys; raise SystemExit(0 if sys.stdin.buffer.read(5) == b'PGDMP' else 2)",
        ]
        result = run_pg_restore(command, source, repository=Path.cwd())
        self.assertEqual(result.returncode, 0)

    def test_restore_requires_an_explicit_isolated_project(self):
        for project_name in (None, "", "mailgate", "production"):
            with self.subTest(project_name=project_name):
                with self.assertRaises(BackupArchiveError):
                    validate_restore_project(project_name)
        self.assertEqual(
            validate_restore_project("mailgate-restore-drill"), "mailgate-restore-drill"
        )

    def test_credential_recovery_rejects_a_linked_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "destination"
            destination.mkdir()
            linked = root / "linked"
            try:
                linked.symlink_to(destination, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory links are unavailable: {exc}")
            with self.assertRaisesRegex(BackupArchiveError, "must not contain links"):
                recover_credential_bundle({"master_key": "synthetic"}, linked)
