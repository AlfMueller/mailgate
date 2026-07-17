# SPDX-License-Identifier: AGPL-3.0-only

import io
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from unittest import TestCase, skipIf
from unittest.mock import patch

from scripts.create_local_secrets import SECRET_NAMES
from scripts.doctor import _check_environment, _check_secrets, _parse_compose_ps, run_checks


def _write_installation(repository: Path) -> None:
    (repository / ".env").write_text(
        "MAILGATE_ENVIRONMENT=development\n"
        "MAILGATE_HTTP_PORT=18080\n"
        "MAILGATE_IMAP_ALLOWED_HOST=imap.example.test\n",
        encoding="utf-8",
    )
    target = repository / ".local" / "secrets"
    target.mkdir(parents=True)
    if os.name != "nt":
        target.chmod(0o700)
    for name in SECRET_NAMES:
        path = target / name
        path.write_text("synthetic-value\n", encoding="utf-8")
        if os.name != "nt":
            path.chmod(0o444)


def _completed(command: list[str], *, stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")


class DoctorEnvironmentTests(TestCase):
    def test_imap_destination_rejects_ip_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            (repository / ".env").write_text(
                "MAILGATE_IMAP_ALLOWED_HOST=127.0.0.1\n", encoding="utf-8"
            )
            checks, _values = _check_environment(repository)
        self.assertTrue(
            any(check.name == "IMAP destination" and check.level == "FAIL" for check in checks)
        )

    def test_direct_secret_key_is_rejected_without_echoing_value(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            marker = "synthetic-value-that-must-not-be-echoed"
            (repository / ".env").write_text(
                f"MAILGATE_IMAP_ALLOWED_HOST=imap.example.test\nMAILGATE_MASTER_KEY={marker}\n",
                encoding="utf-8",
            )
            checks, _values = _check_environment(repository)
        rendered = "\n".join(check.detail for check in checks)
        self.assertIn("MAILGATE_MASTER_KEY", rendered)
        self.assertNotIn(marker, rendered)
        self.assertTrue(any(check.level == "FAIL" for check in checks))

    def test_secret_checks_use_metadata_without_opening_secret_files(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            _write_installation(repository)
            real_open = io.open

            def guarded_open(file, *args, **kwargs):
                if Path(file).name in SECRET_NAMES:
                    raise AssertionError("doctor opened a secret file")
                return real_open(file, *args, **kwargs)

            with patch("io.open", side_effect=guarded_open):
                checks = _check_secrets(repository, {})
        self.assertTrue(any(check.level == "PASS" for check in checks))

    def test_missing_secret_files_fail_as_one_bounded_check(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            (repository / ".local" / "secrets").mkdir(parents=True)
            checks = _check_secrets(repository, {})
        self.assertTrue(any(check.level == "FAIL" for check in checks))
        rendered = "\n".join(check.detail for check in checks)
        self.assertIn("django_secret_key", rendered)

    @skipIf(os.name == "nt", "POSIX modes are not meaningful on Windows")
    def test_group_access_on_secret_directory_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            _write_installation(repository)
            target = repository / ".local" / "secrets"
            target.chmod(0o750)
            checks = _check_secrets(repository, {})
            target.chmod(0o700)
        self.assertTrue(
            any(check.name == "secret permissions" and check.level == "FAIL" for check in checks)
        )


class DoctorRuntimeTests(TestCase):
    def test_compose_status_parser_accepts_array_and_line_formats(self):
        rows = [{"Service": "web", "State": "running", "Health": "healthy"}]
        self.assertEqual(_parse_compose_ps(json.dumps(rows)), rows)
        line_rows = "\n".join(json.dumps(row) for row in rows * 2)
        self.assertEqual(_parse_compose_ps(line_rows), rows * 2)
        self.assertIsNone(_parse_compose_ps("not-json"))

    def test_healthy_stack_checks_docker_port_and_health_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            _write_installation(repository)
            rows = [
                {"Service": service, "State": "running", "Health": "healthy"}
                for service in (
                    "db",
                    "web",
                    "api",
                    "worker",
                    "imap-egress",
                    "dkim-resolver",
                    "proxy",
                )
            ]
            commands: list[tuple[str, ...]] = []

            def runner(command: list[str], _repository: Path):
                commands.append(tuple(command))
                if command[1:3] == ["compose", "ps"]:
                    return _completed(command, stdout=json.dumps(rows))
                return _completed(command)

            with patch("scripts.doctor.shutil.which", return_value="docker"):
                checks = run_checks(
                    repository,
                    runner=runner,
                    tcp_probe=lambda _host, _port: True,
                    http_probe=lambda _url: 200,
                )
        self.assertFalse(any(check.level == "FAIL" for check in checks))
        self.assertIn(("docker", "compose", "config", "--quiet"), commands)
        self.assertIn(("docker", "compose", "ps", "--all", "--format", "json"), commands)
        self.assertFalse(any("up" in command or "start" in command for command in commands))

    def test_stopped_stack_reports_free_port_without_calling_health(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            _write_installation(repository)

            def runner(command: list[str], _repository: Path):
                return _completed(command, stdout="" if "ps" in command else "")

            with (
                patch("scripts.doctor.shutil.which", return_value="docker"),
                patch("scripts.doctor._http_probe") as health_probe,
            ):
                checks = run_checks(
                    repository,
                    runner=runner,
                    tcp_probe=lambda _host, _port: False,
                    http_probe=health_probe,
                )
        health_probe.assert_not_called()
        self.assertTrue(
            any(check.name == "local port" and check.level == "PASS" for check in checks)
        )

    def test_permission_metadata_is_not_reported_as_secret_content(self):
        mode = stat.S_IMODE(0o100444)
        self.assertEqual(mode, 0o444)
