# SPDX-License-Identifier: AGPL-3.0-only

import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from cryptography.fernet import Fernet

SCRIPTS_DIRECTORY = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIRECTORY))

import rotate_credential_keyring as keyring_tool  # noqa: E402
import rotate_postgres_admin_password as postgres_tool  # noqa: E402
import rotation_common  # noqa: E402


def test_hardener(path: Path, mode: int) -> None:
    if os.name != "nt":
        path.chmod(mode)


def write_private(path: Path, value: str, mode: int = 0o444) -> None:
    path.write_text(value + "\n", encoding="utf-8")
    if os.name != "nt":
        path.chmod(mode)


class KeyringHostToolTests(TestCase):
    def secure_directory(self, root: str) -> Path:
        directory = Path(root) / "secrets"
        directory.mkdir()
        if os.name != "nt":
            directory.chmod(0o700)
        return directory

    def test_existing_keyring_gets_new_primary_atomically_and_idempotently(self):
        with tempfile.TemporaryDirectory() as root:
            directory = self.secure_directory(root)
            old_key = Fernet.generate_key().decode("ascii")
            new_key = Fernet.generate_key()
            target = directory / "master_keyring"
            write_private(
                target,
                json.dumps(
                    {"version": 1, "primary": "k1", "keys": {"k1": old_key}},
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )

            changed = keyring_tool.rotate_credential_keyring(
                secrets_directory=directory,
                new_primary_id="k2026q3",
                key_factory=lambda: new_key,
                hardener=test_hardener,
            )
            self.assertTrue(changed)
            document = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(document["primary"], "k2026q3")
            self.assertEqual(document["keys"]["k1"], old_key)
            self.assertEqual(document["keys"]["k2026q3"], new_key.decode("ascii"))
            if os.name != "nt":
                self.assertEqual(target.stat().st_mode & 0o777, 0o444)

            changed = keyring_tool.rotate_credential_keyring(
                secrets_directory=directory,
                new_primary_id="k2026q3",
                key_factory=lambda: self.fail("idempotent preparation generated another key"),
                hardener=test_hardener,
            )
            self.assertFalse(changed)

            changed = keyring_tool.rotate_credential_keyring(
                secrets_directory=directory,
                new_primary_id="k1",
                activate_existing=True,
                key_factory=lambda: self.fail("rollback generated another key"),
                hardener=test_hardener,
            )
            self.assertTrue(changed)
            document = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(document["primary"], "k1")
            self.assertEqual(set(document["keys"]), {"k1", "k2026q3"})

    def test_pre_keyring_installation_imports_legacy_key_without_printing_values(self):
        with tempfile.TemporaryDirectory() as root:
            directory = self.secure_directory(root)
            legacy_key = Fernet.generate_key().decode("ascii")
            new_key = Fernet.generate_key()
            write_private(directory / "master_key", legacy_key)
            output = io.StringIO()
            with (
                patch.object(keyring_tool.Fernet, "generate_key", return_value=new_key),
                patch.object(keyring_tool, "harden_secret_file", test_hardener),
                redirect_stdout(output),
            ):
                keyring_tool.main(
                    [
                        "--secrets-directory",
                        str(directory),
                        "--legacy-key-id",
                        "legacy-k1",
                        "--new-primary-id",
                        "k2",
                    ]
                )

            document = json.loads((directory / "master_keyring").read_text(encoding="utf-8"))
            self.assertEqual(document["keys"]["legacy-k1"], legacy_key)
            self.assertEqual(document["keys"]["k2"], new_key.decode("ascii"))
            self.assertNotIn(legacy_key, output.getvalue())
            self.assertNotIn(new_key.decode("ascii"), output.getvalue())

    def test_invalid_key_id_and_atomic_replace_failure_leave_original_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            directory = self.secure_directory(root)
            old_key = Fernet.generate_key().decode("ascii")
            target = directory / "master_keyring"
            original = json.dumps(
                {"version": 1, "primary": "k1", "keys": {"k1": old_key}},
                separators=(",", ":"),
                sort_keys=True,
            )
            write_private(target, original)

            with self.assertRaises(rotation_common.RotationToolError):
                keyring_tool.rotate_credential_keyring(
                    secrets_directory=directory,
                    new_primary_id="bad key id",
                    hardener=test_hardener,
                )
            self.assertEqual(target.read_text(encoding="utf-8").strip(), original)

            with (
                patch("rotation_common.os.replace", side_effect=OSError("synthetic failure")),
                self.assertRaisesRegex(rotation_common.RotationToolError, "atomically"),
            ):
                keyring_tool.rotate_credential_keyring(
                    secrets_directory=directory,
                    new_primary_id="k2",
                    hardener=test_hardener,
                )
            self.assertEqual(target.read_text(encoding="utf-8").strip(), original)
            self.assertEqual(list(directory.glob(".*.rotation-*")), [])


class FakeDockerRunner:
    def __init__(self, *failed_calls: int):
        self.failed_calls = set(failed_calls)
        self.calls: list[tuple[list[str], str | None]] = []

    def __call__(self, command, standard_input):
        index = len(self.calls)
        self.calls.append((list(command), standard_input))
        return postgres_tool.DockerResult(1 if index in self.failed_calls else 0)


class PostgresAdminRotationTests(TestCase):
    old_value = "old-synthetic-admin-value-123456789"
    new_value = "new-synthetic-admin-value-987654321"

    def secure_installation(self, root: str) -> tuple[Path, Path]:
        repository = Path(root) / "repository"
        repository.mkdir()
        directory = Path(root) / "secrets"
        directory.mkdir()
        if os.name != "nt":
            directory.chmod(0o700)
        write_private(directory / "postgres_password", self.old_value)
        return repository, directory

    def writer(self, path: Path, value: str, mode: int) -> None:
        rotation_common.atomic_write_secret(
            path,
            value,
            mode=mode,
            hardener=test_hardener,
        )

    def rotate(self, repository: Path, directory: Path, runner: FakeDockerRunner) -> None:
        postgres_tool.rotate_postgres_admin_password(
            repository=repository,
            secrets_directory=directory,
            runner=runner,
            docker_executable="docker",
            password_factory=lambda: self.new_value,
            writer=self.writer,
        )

    def assert_values_absent_from_arguments(self, runner: FakeDockerRunner) -> None:
        for command, _standard_input in runner.calls:
            arguments = " ".join(command)
            self.assertNotIn(self.old_value, arguments)
            self.assertNotIn(self.new_value, arguments)

    def test_success_coordinates_role_file_new_login_and_bootstrap(self):
        with tempfile.TemporaryDirectory() as root:
            repository, directory = self.secure_installation(root)
            runner = FakeDockerRunner()
            self.rotate(repository, directory, runner)

            self.assertEqual(
                (directory / "postgres_password").read_text(encoding="utf-8").strip(),
                self.new_value,
            )
            self.assertEqual(len(runner.calls), 5)
            self.assertIn("exec", runner.calls[0][0])
            self.assertIn("SELECT 1", runner.calls[0][1])
            self.assertIn("\\password mailgate_admin", runner.calls[2][0])
            self.assertEqual(runner.calls[2][1], f"{self.new_value}\n{self.new_value}\n")
            self.assertIn("install-db-bootstrap", runner.calls[4][0])
            self.assert_values_absent_from_arguments(runner)

    def test_failed_new_login_rolls_database_and_file_back_then_verifies(self):
        with tempfile.TemporaryDirectory() as root:
            repository, directory = self.secure_installation(root)
            runner = FakeDockerRunner(3)
            with self.assertRaisesRegex(
                rotation_common.RotationToolError,
                "restored and verified",
            ) as raised:
                self.rotate(repository, directory, runner)

            self.assertEqual(
                (directory / "postgres_password").read_text(encoding="utf-8").strip(),
                self.old_value,
            )
            self.assertEqual(len(runner.calls), 6)
            self.assertIn("\\password mailgate_admin", runner.calls[4][0])
            self.assertEqual(runner.calls[4][1], f"{self.old_value}\n{self.old_value}\n")
            self.assertNotIn(self.old_value, str(raised.exception))
            self.assertNotIn(self.new_value, str(raised.exception))
            self.assert_values_absent_from_arguments(runner)

    def test_bootstrap_failure_also_rolls_back(self):
        with tempfile.TemporaryDirectory() as root:
            repository, directory = self.secure_installation(root)
            runner = FakeDockerRunner(4)
            with self.assertRaisesRegex(rotation_common.RotationToolError, "restored and verified"):
                self.rotate(repository, directory, runner)
            self.assertEqual(
                (directory / "postgres_password").read_text(encoding="utf-8").strip(),
                self.old_value,
            )
            self.assertEqual(len(runner.calls), 7)

    def test_secret_file_write_failure_rolls_database_back(self):
        with tempfile.TemporaryDirectory() as root:
            repository, directory = self.secure_installation(root)
            runner = FakeDockerRunner()
            writes = 0

            def fail_first_write(path: Path, value: str, mode: int) -> None:
                nonlocal writes
                writes += 1
                if writes == 1:
                    raise rotation_common.RotationToolError("synthetic file failure")
                self.writer(path, value, mode)

            with self.assertRaisesRegex(rotation_common.RotationToolError, "restored and verified"):
                postgres_tool.rotate_postgres_admin_password(
                    repository=repository,
                    secrets_directory=directory,
                    runner=runner,
                    docker_executable="docker",
                    password_factory=lambda: self.new_value,
                    writer=fail_first_write,
                )
            self.assertEqual(
                (directory / "postgres_password").read_text(encoding="utf-8").strip(),
                self.old_value,
            )
            self.assertEqual(writes, 2)
            self.assertEqual(len(runner.calls), 5)

    def test_preflight_failure_changes_nothing(self):
        with tempfile.TemporaryDirectory() as root:
            repository, directory = self.secure_installation(root)
            runner = FakeDockerRunner(1)
            with self.assertRaisesRegex(rotation_common.RotationToolError, "nothing changed"):
                self.rotate(repository, directory, runner)
            self.assertEqual(
                (directory / "postgres_password").read_text(encoding="utf-8").strip(),
                self.old_value,
            )
            self.assertEqual(len(runner.calls), 2)

    def test_failed_database_rollback_keeps_new_file_when_new_login_still_works(self):
        with tempfile.TemporaryDirectory() as root:
            repository, directory = self.secure_installation(root)
            runner = FakeDockerRunner(3, 4)
            with self.assertRaisesRegex(
                rotation_common.RotationToolError,
                "remain on the new value",
            ):
                self.rotate(repository, directory, runner)
            self.assertEqual(
                (directory / "postgres_password").read_text(encoding="utf-8").strip(),
                self.new_value,
            )
            self.assertEqual(len(runner.calls), 6)
            self.assert_values_absent_from_arguments(runner)
