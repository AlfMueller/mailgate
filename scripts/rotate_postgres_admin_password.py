#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only

import argparse
import re
import secrets
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from rotation_common import (
    FileHardener,
    RotationToolError,
    atomic_write_secret,
    container_secret_mode,
    exclusive_rotation_lock,
    harden_secret_file,
    read_secret,
    require_secure_directory,
)

DATABASE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")


@dataclass(frozen=True)
class DockerResult:
    returncode: int


DockerRunner = Callable[[Sequence[str], str | None], DockerResult]
SecretWriter = Callable[[Path, str, int], None]


def subprocess_docker_runner(command: Sequence[str], standard_input: str | None) -> DockerResult:
    try:
        result = subprocess.run(  # noqa: S603 -- executable is resolved, arguments are fixed.
            list(command),
            input=standard_input,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=180,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RotationToolError("A Docker Compose operation could not be executed") from exc
    return DockerResult(result.returncode)


def _password_prompt_input(value: str) -> str:
    return f"{value}\n{value}\n"


def _require_success(
    runner: DockerRunner,
    command: Sequence[str],
    *,
    standard_input: str | None,
    stage: str,
) -> None:
    if runner(command, standard_input).returncode != 0:
        raise RotationToolError(stage)


def _compose_base(
    *,
    docker: str,
    repository: Path,
    compose_files: Sequence[Path],
    project_name: str | None,
) -> list[str]:
    command = [docker, "compose", "--project-directory", str(repository)]
    for compose_file in compose_files:
        command.extend(("--file", str(compose_file.resolve())))
    if project_name:
        command.extend(("--project-name", project_name))
    return command


def _local_admin_command(base: Sequence[str], database_name: str) -> list[str]:
    return list(base) + [
        "exec",
        "-T",
        "db",
        "psql",
        "--no-psqlrc",
        "--quiet",
        "--set",
        "ON_ERROR_STOP=1",
        "--username",
        "mailgate_admin",
        "--dbname",
        database_name,
    ]


def _local_password_command(base: Sequence[str], database_name: str) -> list[str]:
    return _local_admin_command(base, database_name) + [
        "--command",
        "SET password_encryption = 'scram-sha-256'",
        "--command",
        "\\password mailgate_admin",
    ]


def _tcp_probe_command(base: Sequence[str]) -> list[str]:
    probe = (
        'export PGPASSWORD="$(cat /run/secrets/postgres_password)"; '
        'test -n "$PGPASSWORD"; '
        'exec psql --host=db --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" '
        "--no-psqlrc --quiet --tuples-only --no-align --command='SELECT 1'"
    )
    return list(base) + [
        "run",
        "--no-deps",
        "--rm",
        "--entrypoint",
        "sh",
        "db",
        "-ceu",
        probe,
    ]


def _validate_password(value: str) -> str:
    if not 16 <= len(value) <= 1024 or any(ord(character) < 32 for character in value):
        raise RotationToolError("The PostgreSQL admin secret is malformed")
    return value


def rotate_postgres_admin_password(
    *,
    repository: Path,
    secrets_directory: Path,
    runner: DockerRunner,
    docker_executable: str,
    compose_files: Sequence[Path] = (),
    project_name: str | None = None,
    database_name: str = "mailgate",
    password_factory: Callable[[], str] = lambda: secrets.token_urlsafe(48),
    writer: SecretWriter | None = None,
    hardener: FileHardener = harden_secret_file,
) -> None:
    repository = repository.resolve()
    if not repository.is_dir():
        raise RotationToolError("The repository directory is unavailable")
    if not DATABASE_NAME_RE.fullmatch(database_name):
        raise RotationToolError("The database name is invalid")
    directory = require_secure_directory(secrets_directory)
    secret_path = directory / "postgres_password"
    write_secret = writer or (
        lambda path, value, file_mode: atomic_write_secret(
            path, value, mode=file_mode, hardener=hardener
        )
    )
    base = _compose_base(
        docker=docker_executable,
        repository=repository,
        compose_files=compose_files,
        project_name=project_name,
    )
    local_admin = _local_admin_command(base, database_name)
    local_password = _local_password_command(base, database_name)
    tcp_probe = _tcp_probe_command(base)
    bootstrap = list(base) + ["run", "--no-deps", "--rm", "install-db-bootstrap"]

    with exclusive_rotation_lock(directory, ".postgres-admin.rotation.lock"):
        old_password, mode = read_secret(secret_path, maximum_bytes=4096)
        mode = container_secret_mode(mode)
        old_password = _validate_password(old_password)
        new_password = _validate_password(password_factory())
        if new_password == old_password:
            raise RotationToolError("The password generator did not produce a new value")
        _require_success(
            runner,
            local_admin,
            standard_input="SELECT 1;\n",
            stage="The local PostgreSQL recovery channel is unavailable; nothing changed",
        )
        _require_success(
            runner,
            tcp_probe,
            standard_input=None,
            stage="The current admin secret does not authenticate; nothing changed",
        )

        database_change_attempted = False
        try:
            database_change_attempted = True
            _require_success(
                runner,
                local_password,
                standard_input=_password_prompt_input(new_password),
                stage="PostgreSQL rejected the admin-role update",
            )
            write_secret(secret_path, new_password, mode)
            _require_success(
                runner,
                tcp_probe,
                standard_input=None,
                stage="The rotated admin secret failed connection verification",
            )
            _require_success(
                runner,
                bootstrap,
                standard_input=None,
                stage="The database-role bootstrap failed after admin rotation",
            )
        except BaseException as original_error:
            if not database_change_attempted:
                if isinstance(original_error, RotationToolError):
                    raise
                raise RotationToolError(
                    "Admin rotation failed before changing PostgreSQL"
                ) from original_error

            try:
                _require_success(
                    runner,
                    local_password,
                    standard_input=_password_prompt_input(old_password),
                    stage="PostgreSQL rejected the admin-password rollback",
                )
            except BaseException as rollback_error:
                aligned = False
                alignment_error = None
                try:
                    write_secret(secret_path, new_password, mode)
                    _require_success(
                        runner,
                        tcp_probe,
                        standard_input=None,
                        stage="The retained rotated secret did not authenticate",
                    )
                    aligned = True
                except BaseException as exc:
                    alignment_error = exc
                if aligned:
                    raise RotationToolError(
                        "Rollback failed; PostgreSQL and the secret file remain on the new value. "
                        "Keep services stopped and rerun bootstrap after inspection"
                    ) from rollback_error
                raise RotationToolError(
                    "Rollback failed and database/file alignment could not be verified; "
                    "manual recovery through the local database channel is required"
                ) from alignment_error

            try:
                write_secret(secret_path, old_password, mode)
                _require_success(
                    runner,
                    tcp_probe,
                    standard_input=None,
                    stage="The restored previous admin secret failed verification",
                )
            except BaseException as rollback_error:
                raise RotationToolError(
                    "PostgreSQL was rolled back but the previous secret file could not be "
                    "restored and verified; manual recovery is required"
                ) from rollback_error
            raise RotationToolError(
                "Admin rotation failed; PostgreSQL and the secret file were restored and verified"
            ) from original_error


def build_parser() -> argparse.ArgumentParser:
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Rotate the PostgreSQL admin password without exposing it in process arguments."
    )
    parser.add_argument("--repository", type=Path, default=repository)
    parser.add_argument(
        "--secrets-directory",
        type=Path,
        default=repository / ".local" / "secrets",
    )
    parser.add_argument("--compose-file", type=Path, action="append", default=[])
    parser.add_argument("--project-name")
    parser.add_argument("--database-name", default="mailgate")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    docker = shutil.which("docker")
    if not docker:
        raise SystemExit("PostgreSQL admin rotation failed: Docker is unavailable")
    try:
        rotate_postgres_admin_password(
            repository=args.repository,
            secrets_directory=args.secrets_directory,
            runner=subprocess_docker_runner,
            docker_executable=docker,
            compose_files=args.compose_file,
            project_name=args.project_name,
            database_name=args.database_name,
        )
    except RotationToolError as exc:
        raise SystemExit(f"PostgreSQL admin rotation failed: {exc}") from exc
    print(
        "PostgreSQL admin role, secret file, new connection and role bootstrap were verified; "
        "no password was printed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
