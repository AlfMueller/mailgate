#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only installation diagnostics for MailGate.

This helper never opens secret files and never prints configuration values. It
uses filesystem metadata, read-only Docker commands, local TCP probes and the
public health endpoints only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

try:
    from scripts.create_local_secrets import SECRET_NAMES
except ModuleNotFoundError:  # Direct execution places scripts/ on sys.path.
    from create_local_secrets import SECRET_NAMES

EXPECTED_SERVICES = {"db", "web", "api", "worker", "imap-egress", "dkim-resolver", "proxy"}
SAFE_ENV_KEYS = {
    "MAILGATE_ENVIRONMENT",
    "MAILGATE_HTTP_PORT",
    "MAILGATE_IMAP_ALLOWED_HOST",
    "MAILGATE_SECRETS_DIR",
}
DIRECT_SECRET_KEYS = {
    "MAILGATE_SECRET_KEY",
    "MAILGATE_DATABASE_PASSWORD",
    "MAILGATE_MASTER_KEY",
    "MAILGATE_MASTER_KEYRING",
    "MAILGATE_SETUP_TOKEN",
    "MAILGATE_BACKUP_KEY",
    "POSTGRES_PASSWORD",
    "POSTGRES_MIGRATE_PASSWORD",
    "POSTGRES_WEB_PASSWORD",
    "POSTGRES_API_PASSWORD",
    "POSTGRES_WORKER_PASSWORD",
}
HOSTNAME_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)


@dataclass(frozen=True)
class Check:
    level: str
    name: str
    detail: str


CommandRunner = Callable[[list[str], Path], subprocess.CompletedProcess[str]]
TcpProbe = Callable[[str, int], bool]
HttpProbe = Callable[[str], int | None]


def _run_command(command: list[str], repository: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- fixed executable/arguments, never a shell
        command,
        cwd=repository,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )


def _tcp_probe(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _http_probe(url: str) -> int | None:
    request = urllib.request.Request(url, method="GET")  # noqa: S310 -- local HTTP only
    try:
        with urllib.request.urlopen(request, timeout=2) as response:  # noqa: S310
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (OSError, ValueError):
        return None


def _read_safe_env(path: Path) -> tuple[dict[str, str], set[str]]:
    """Read only allowlisted non-secret values and names of forbidden secret keys."""
    values: dict[str, str] = {}
    forbidden: set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            key = key.strip()
            if key in DIRECT_SECRET_KEYS:
                forbidden.add(key)
            if key not in SAFE_ENV_KEYS:
                continue
            value = raw_value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]
            values[key] = value
    return values, forbidden


def _check_environment(repository: Path) -> tuple[list[Check], dict[str, str]]:
    env_path = repository / ".env"
    if not env_path.is_file():
        return [Check("FAIL", "environment", ".env is missing or is not a regular file.")], {}
    try:
        values, forbidden = _read_safe_env(env_path)
    except OSError:
        return [Check("FAIL", "environment", ".env could not be read.")], {}

    checks = [Check("PASS", "environment", ".env is present and readable.")]
    if forbidden:
        checks.append(
            Check(
                "FAIL",
                "environment secrets",
                "Direct secret values are present in .env; use file-backed secrets instead: "
                + ", ".join(sorted(forbidden)),
            )
        )

    environment = values.get("MAILGATE_ENVIRONMENT", "development").lower()
    if environment not in {"development", "test", "production"}:
        checks.append(Check("FAIL", "environment mode", "MAILGATE_ENVIRONMENT is invalid."))
    else:
        checks.append(Check("PASS", "environment mode", "Environment mode is recognized."))

    hostname = values.get("MAILGATE_IMAP_ALLOWED_HOST", "")
    normalized_hostname = hostname.rstrip(".")
    try:
        ipaddress.ip_address(normalized_hostname)
        hostname_is_ip = True
    except ValueError:
        hostname_is_ip = False
    if not normalized_hostname or hostname_is_ip or not HOSTNAME_RE.fullmatch(normalized_hostname):
        checks.append(
            Check("FAIL", "IMAP destination", "A valid DNS hostname is required in .env.")
        )
    elif hostname.lower().endswith((".test", ".invalid", ".example")):
        checks.append(
            Check(
                "WARN",
                "IMAP destination",
                "The configured IMAP destination is a reserved placeholder hostname.",
            )
        )
    else:
        checks.append(Check("PASS", "IMAP destination", "An IMAP DNS hostname is configured."))

    raw_port = values.get("MAILGATE_HTTP_PORT", "8080")
    try:
        port = int(raw_port)
        valid_port = 1 <= port <= 65535
    except ValueError:
        valid_port = False
    if not valid_port:
        checks.append(Check("FAIL", "HTTP port", "MAILGATE_HTTP_PORT is not a valid TCP port."))
    return checks, values


def _secret_directory(repository: Path, env_values: dict[str, str]) -> Path:
    configured = env_values.get("MAILGATE_SECRETS_DIR", "")
    target = Path(configured) if configured else Path(".local/secrets")
    return target if target.is_absolute() else repository / target


def _check_secrets(repository: Path, env_values: dict[str, str]) -> list[Check]:
    target = _secret_directory(repository, env_values)
    try:
        directory_status = target.lstat()
    except OSError:
        return [Check("FAIL", "secret files", "The configured secret directory is missing.")]
    if stat.S_ISLNK(directory_status.st_mode) or not stat.S_ISDIR(directory_status.st_mode):
        return [
            Check(
                "FAIL", "secret files", "The configured secret directory is not a real directory."
            )
        ]

    checks: list[Check] = []
    missing: list[str] = []
    invalid: list[str] = []
    empty: list[str] = []
    modes: list[int] = []
    for name in SECRET_NAMES:
        path = target / name
        try:
            metadata = path.lstat()
        except OSError:
            missing.append(name)
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            invalid.append(name)
            continue
        if metadata.st_size == 0:
            empty.append(name)
        modes.append(stat.S_IMODE(metadata.st_mode))

    if missing:
        checks.append(
            Check(
                "FAIL", "secret files", "Required secret files are missing: " + ", ".join(missing)
            )
        )
    if invalid:
        checks.append(
            Check(
                "FAIL",
                "secret files",
                "Secret paths must be regular files, not links: " + ", ".join(invalid),
            )
        )
    if empty:
        checks.append(
            Check("FAIL", "secret files", "Secret files must not be empty: " + ", ".join(empty))
        )
    if not (missing or invalid or empty):
        checks.append(
            Check("PASS", "secret files", "All required non-empty secret files are present.")
        )

    if os.name == "nt":
        checks.append(
            Check(
                "WARN",
                "secret permissions",
                "Windows ACLs cannot be verified here; confirm owner-only directory "
                "access manually.",
            )
        )
    else:
        directory_mode = stat.S_IMODE(directory_status.st_mode)
        if directory_mode & 0o077:
            checks.append(
                Check(
                    "FAIL",
                    "secret permissions",
                    "The secret directory grants access beyond its owner; expected mode 0700.",
                )
            )
        elif any(mode & 0o022 for mode in modes):
            checks.append(
                Check(
                    "FAIL",
                    "secret permissions",
                    "At least one secret file is writable by group or other users.",
                )
            )
        elif modes and any(mode != 0o444 for mode in modes):
            checks.append(
                Check(
                    "WARN",
                    "secret permissions",
                    "Secret file modes differ from 0444 and may be unreadable by UID 10001.",
                )
            )
        else:
            checks.append(
                Check(
                    "PASS",
                    "secret permissions",
                    "Secret directory and file modes match the Compose boundary.",
                )
            )
    return checks


def _parse_compose_ps(output: str) -> list[dict[str, object]] | None:
    stripped = output.strip()
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        rows: list[dict[str, object]] = []
        try:
            for line in stripped.splitlines():
                item = json.loads(line)
                if not isinstance(item, dict):
                    return None
                rows.append(item)
            return rows
        except json.JSONDecodeError:
            return None
    return None


def _check_docker(
    repository: Path,
    runner: CommandRunner,
) -> tuple[list[Check], list[dict[str, object]]]:
    if shutil.which("docker") is None:
        return [Check("FAIL", "Docker", "The docker command is not available in PATH.")], []

    checks: list[Check] = []
    try:
        docker_version = runner(["docker", "--version"], repository)
        compose_version = runner(["docker", "compose", "version"], repository)
    except (OSError, subprocess.SubprocessError):
        return [Check("FAIL", "Docker", "Docker could not be queried safely.")], []
    if docker_version.returncode != 0:
        checks.append(Check("FAIL", "Docker", "The Docker client is not usable."))
        return checks, []
    checks.append(Check("PASS", "Docker", "The Docker client is available."))
    if compose_version.returncode != 0:
        checks.append(Check("FAIL", "Docker Compose", "The Compose plugin is not usable."))
        return checks, []
    checks.append(Check("PASS", "Docker Compose", "The Compose plugin is available."))

    try:
        config = runner(["docker", "compose", "config", "--quiet"], repository)
    except (OSError, subprocess.SubprocessError):
        checks.append(
            Check("FAIL", "Compose config", "Compose configuration could not be checked.")
        )
        return checks, []
    if config.returncode == 0:
        checks.append(Check("PASS", "Compose config", "Compose configuration is valid."))
    else:
        checks.append(Check("FAIL", "Compose config", "Compose configuration is invalid."))

    try:
        ps = runner(["docker", "compose", "ps", "--all", "--format", "json"], repository)
    except (OSError, subprocess.SubprocessError):
        checks.append(Check("FAIL", "stack status", "Compose service status could not be queried."))
        return checks, []
    if ps.returncode != 0:
        checks.append(Check("FAIL", "stack status", "Compose service status could not be queried."))
        return checks, []
    rows = _parse_compose_ps(ps.stdout)
    if rows is None:
        checks.append(Check("FAIL", "stack status", "Compose returned an unknown status format."))
        return checks, []
    if not rows:
        checks.append(Check("WARN", "stack status", "No Compose services are currently present."))
        return checks, []

    by_service = {str(row.get("Service", "")): row for row in rows if row.get("Service")}
    missing = sorted(EXPECTED_SERVICES - by_service.keys())
    unhealthy: list[str] = []
    for service in sorted(EXPECTED_SERVICES & by_service.keys()):
        row = by_service[service]
        state = str(row.get("State", "")).lower()
        status_value = str(row.get("Status", "")).lower()
        health = str(row.get("Health", "")).lower()
        if state != "running" and not status_value.startswith("up"):
            unhealthy.append(service)
        elif health and health != "healthy":
            unhealthy.append(service)
    if missing:
        checks.append(
            Check("FAIL", "stack status", "Required services are absent: " + ", ".join(missing))
        )
    if unhealthy:
        checks.append(
            Check(
                "FAIL", "stack status", "Required services are not healthy: " + ", ".join(unhealthy)
            )
        )
    if not (missing or unhealthy):
        checks.append(Check("PASS", "stack status", "All required services are running."))
    return checks, rows


def run_checks(
    repository: Path,
    *,
    runner: CommandRunner = _run_command,
    tcp_probe: TcpProbe = _tcp_probe,
    http_probe: HttpProbe = _http_probe,
) -> list[Check]:
    repository = repository.resolve()
    checks, env_values = _check_environment(repository)
    checks.extend(_check_secrets(repository, env_values))
    docker_checks, services = _check_docker(repository, runner)
    checks.extend(docker_checks)

    try:
        port = int(env_values.get("MAILGATE_HTTP_PORT", "8080"))
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        return checks
    listening = tcp_probe("127.0.0.1", port)
    if services and listening:
        checks.append(Check("PASS", "local port", "The MailGate HTTP port accepts local TCP."))
        for endpoint in ("live", "ready"):
            status_code = http_probe(f"http://127.0.0.1:{port}/health/{endpoint}")
            if status_code == 200:
                checks.append(
                    Check(
                        "PASS", f"health {endpoint}", f"The {endpoint} endpoint returned HTTP 200."
                    )
                )
            else:
                checks.append(
                    Check("FAIL", f"health {endpoint}", f"The {endpoint} endpoint is not healthy.")
                )
    elif services:
        checks.append(
            Check(
                "FAIL", "local port", "Compose services exist but the HTTP port is not reachable."
            )
        )
    elif listening:
        checks.append(
            Check(
                "WARN", "local port", "The configured port is occupied outside this Compose stack."
            )
        )
    else:
        checks.append(Check("PASS", "local port", "The configured port is available for startup."))
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run read-only MailGate installation diagnostics")
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="MailGate repository root (defaults to the script's repository)",
    )
    args = parser.parse_args(argv)
    checks = run_checks(args.repository)
    for check in checks:
        print(f"[{check.level}] {check.name}: {check.detail}")
    failures = sum(check.level == "FAIL" for check in checks)
    warnings = sum(check.level == "WARN" for check in checks)
    print(f"Summary: {failures} failure(s), {warnings} warning(s).")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
