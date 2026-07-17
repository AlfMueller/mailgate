#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from scripts.backup import MAX_CREDENTIAL_BUNDLE_BYTES, PAYLOAD_MAGIC
    from scripts.backup_archive import BackupArchiveError, decrypt_to_temporary, load_backup_key
except ImportError:  # Direct invocation from the scripts directory.
    from backup import MAX_CREDENTIAL_BUNDLE_BYTES, PAYLOAD_MAGIC
    from backup_archive import BackupArchiveError, decrypt_to_temporary, load_backup_key


def read_credential_bundle(source) -> dict[str, str]:
    if source.read(len(PAYLOAD_MAGIC)) != PAYLOAD_MAGIC:
        raise BackupArchiveError("Encrypted payload is not a MailGate PostgreSQL backup")
    size_bytes = source.read(4)
    if len(size_bytes) != 4:
        raise BackupArchiveError("Encrypted backup payload is truncated")
    size = int.from_bytes(size_bytes, "big")
    if not 1 <= size <= MAX_CREDENTIAL_BUNDLE_BYTES:
        raise BackupArchiveError("Credential key bundle has an invalid size")
    try:
        bundle = json.loads(source.read(size))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupArchiveError("Credential key bundle is invalid") from exc
    if (
        not isinstance(bundle, dict)
        or not bundle
        or not set(bundle).issubset({"master_key", "master_keyring"})
        or any(not isinstance(value, str) or not value for value in bundle.values())
    ):
        raise BackupArchiveError("Credential key bundle has an invalid schema")
    return bundle


def recover_credential_bundle(bundle: dict[str, str], target: Path) -> None:
    target = target.absolute()
    for candidate in (target, *target.parents):
        if not candidate.exists():
            continue
        status = candidate.lstat()
        is_junction = getattr(candidate, "is_junction", lambda: False)()
        if stat.S_ISLNK(status.st_mode) or is_junction:
            raise BackupArchiveError("Credential recovery path must not contain links")
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise BackupArchiveError("Credential recovery directory must be empty")
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        target.chmod(0o700)
    created: list[Path] = []
    try:
        for name, value in bundle.items():
            path = target / name
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags, 0o600)
            created.append(path)
            with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as destination:
                destination.write(value)
                destination.write("\n")
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def run_pg_restore(command: list[str], source, *, repository: Path) -> subprocess.CompletedProcess:
    """Stream from the current payload offset without relying on inherited file position."""
    with tempfile.TemporaryFile() as error_output:
        process = subprocess.Popen(  # noqa: S603
            command,
            cwd=repository,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=error_output,
        )
        assert process.stdin is not None
        try:
            while chunk := source.read(1024 * 1024):
                process.stdin.write(chunk)
        except BrokenPipeError:
            pass
        finally:
            process.stdin.close()
        return_code = process.wait()
        error_output.seek(0)
        error = error_output.read(4096)
    return subprocess.CompletedProcess(command, return_code, stdout=b"", stderr=error)


def _docker_command(project_name: str | None, *arguments: str) -> list[str]:
    executable = shutil.which("docker")
    if not executable:
        raise BackupArchiveError("Docker CLI was not found")
    command = [executable, "compose"]
    if project_name:
        command.extend(("--project-name", project_name))
    command.extend(arguments)
    return command


def validate_restore_project(project_name: str | None) -> str:
    if not project_name:
        raise BackupArchiveError("An explicit isolated --project-name is required")
    if project_name == "mailgate" or "restore" not in project_name:
        raise BackupArchiveError(
            "Restore project name must be non-production and contain 'restore'"
        )
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,62}", project_name):
        raise BackupArchiveError("Restore project name contains unsupported characters")
    return project_name


def restore_backup(
    *,
    archive: Path,
    secrets_dir: Path,
    project_name: str | None,
    confirmation: str,
    credential_output_dir: Path | None = None,
) -> dict:
    project_name = validate_restore_project(project_name)
    expected = f"RESTORE {project_name}"
    if confirmation != expected:
        raise BackupArchiveError(f"Confirmation must be exactly: {expected}")
    key = load_backup_key(secrets_dir / "backup_key")
    temporary, metadata = decrypt_to_temporary(archive, key=key)
    repository = Path(__file__).resolve().parents[1]
    database = os.getenv("MAILGATE_DATABASE_NAME", "mailgate")
    command = _docker_command(
        project_name,
        "exec",
        "-T",
        "db",
        "pg_restore",
        "--username=mailgate_admin",
        f"--dbname={database}",
        "--role=mailgate_migrate",
        "--clean",
        "--if-exists",
        "--no-owner",
        "--no-acl",
        "--exit-on-error",
    )
    try:
        with temporary.open("rb") as source:
            bundle = read_credential_bundle(source)
            result = run_pg_restore(command, source, repository=repository)
        if result.returncode != 0:
            raise BackupArchiveError(
                "pg_restore failed; inspect the isolated database service locally"
            )
        if credential_output_dir is not None:
            recover_credential_bundle(bundle, credential_output_dir)
        return metadata
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Restore a verified encrypted MailGate backup into a stopped, isolated stack"
    )
    parser.add_argument("archive", type=Path)
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--secrets-dir", type=Path, default=Path(".local/secrets"))
    parser.add_argument(
        "--credential-output-dir",
        type=Path,
        help="Optional new empty directory for the recovered credential key bundle.",
    )
    arguments = parser.parse_args()
    try:
        metadata = restore_backup(
            archive=arguments.archive.resolve(),
            secrets_dir=arguments.secrets_dir.resolve(),
            project_name=arguments.project_name,
            confirmation=arguments.confirm,
            credential_output_dir=(
                arguments.credential_output_dir.absolute()
                if arguments.credential_output_dir
                else None
            ),
        )
    except BackupArchiveError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("Restore completed from authenticated archive metadata:")
    print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
