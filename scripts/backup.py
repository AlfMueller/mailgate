#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

try:
    from scripts.backup_archive import BackupArchiveError, encrypt_stream, load_backup_key
except ImportError:  # Direct invocation from the scripts directory.
    from backup_archive import BackupArchiveError, encrypt_stream, load_backup_key

PAYLOAD_MAGIC = b"MAILGATE-PGDUMP\x00"
MAX_CREDENTIAL_BUNDLE_BYTES = 64 * 1024


class PrefixedReader:
    def __init__(self, prefix: bytes, source):
        self.prefix = io.BytesIO(prefix)
        self.source = source

    def read(self, size: int = -1) -> bytes:
        first = self.prefix.read(size)
        if size < 0:
            return first + self.source.read()
        return first + self.source.read(size - len(first))


def credential_bundle(secrets_dir: Path) -> bytes:
    values = {}
    for name in ("master_key", "master_keyring"):
        path = secrets_dir / name
        if path.is_file():
            try:
                values[name] = path.read_text(encoding="ascii").strip()
            except (OSError, UnicodeError) as exc:
                raise BackupArchiveError("Unable to read the credential key bundle") from exc
    if "master_key" not in values and "master_keyring" not in values:
        raise BackupArchiveError("Credential master key or keyring is missing")
    encoded = json.dumps(values, separators=(",", ":"), sort_keys=True).encode("ascii")
    if len(encoded) > MAX_CREDENTIAL_BUNDLE_BYTES:
        raise BackupArchiveError("Credential key bundle is unexpectedly large")
    return PAYLOAD_MAGIC + len(encoded).to_bytes(4, "big") + encoded


def _docker_command(project_name: str | None, *arguments: str) -> list[str]:
    executable = shutil.which("docker")
    if not executable:
        raise BackupArchiveError("Docker CLI was not found")
    command = [executable, "compose"]
    if project_name:
        command.extend(("--project-name", project_name))
    command.extend(arguments)
    return command


def _git_commit(repository: Path) -> str:
    executable = shutil.which("git")
    if not executable:
        return "unknown"
    result = subprocess.run(  # noqa: S603
        [executable, "rev-parse", "HEAD"],
        cwd=repository,
        capture_output=True,
        check=False,
        text=True,
    )
    value = result.stdout.strip().lower()
    return value if result.returncode == 0 and len(value) == 40 else "unknown"


def create_backup(*, output: Path, secrets_dir: Path, project_name: str | None) -> dict:
    if output.exists():
        raise BackupArchiveError("Refusing to overwrite an existing backup")
    output.parent.mkdir(parents=True, exist_ok=True)
    key = load_backup_key(secrets_dir / "backup_key")
    payload_prefix = credential_bundle(secrets_dir)
    repository = Path(__file__).resolve().parents[1]
    metadata = {
        "archive_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "database": os.getenv("MAILGATE_DATABASE_NAME", "mailgate"),
        "git_commit": _git_commit(repository),
        "includes_credential_key_bundle": True,
        "project_name": project_name or "mailgate",
    }
    command = _docker_command(
        project_name,
        "exec",
        "-T",
        "db",
        "pg_dump",
        "--username=mailgate_admin",
        f"--dbname={metadata['database']}",
        "--format=custom",
        "--no-owner",
        "--no-acl",
    )
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temp_name)
    if os.name != "nt":
        temporary.chmod(0o600)
    process = None
    try:
        with os.fdopen(descriptor, "wb") as destination:
            process = subprocess.Popen(  # noqa: S603
                command,
                cwd=repository,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            assert process.stdout is not None
            encrypt_stream(
                PrefixedReader(payload_prefix, process.stdout),
                destination,
                key=key,
                metadata=metadata,
            )
        return_code = process.wait()
        if return_code != 0:
            raise BackupArchiveError("pg_dump failed; no backup was published")
        os.replace(temporary, output)
        return metadata
    except Exception:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create an authenticated encrypted MailGate backup"
    )
    parser.add_argument("output", type=Path)
    parser.add_argument("--project-name")
    parser.add_argument("--secrets-dir", type=Path, default=Path(".local/secrets"))
    arguments = parser.parse_args()
    try:
        metadata = create_backup(
            output=arguments.output.resolve(),
            secrets_dir=arguments.secrets_dir.resolve(),
            project_name=arguments.project_name,
        )
    except BackupArchiveError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(metadata, sort_keys=True))
    print(f"Encrypted backup created: {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
