#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only

import json
import os
import secrets
from pathlib import Path

SECRET_NAMES = (
    "django_secret_key",
    "postgres_password",
    "postgres_migrate_password",
    "postgres_web_password",
    "postgres_api_password",
    "postgres_worker_password",
    "api_django_secret_key",
    "master_key",
    "master_keyring",
    "backup_key",
    "setup_token",
)


def create_secret(path: Path, length: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(secrets.token_urlsafe(length))
        handle.write("\n")
    make_container_readable(path)


def make_container_readable(path: Path) -> None:
    if os.name != "nt":
        # Compose file-backed secrets retain host ownership. The secret directory
        # remains owner-only (0700); files need read permission for UID 10001.
        path.chmod(0o444)


def create_fernet_key(path: Path) -> None:
    import base64

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"))
        handle.write("\n")
    make_container_readable(path)


def create_credential_keyring(path: Path) -> None:
    import base64

    document = {
        "version": 1,
        "primary": "k1",
        "keys": {
            "k1": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
        },
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, separators=(",", ":"), sort_keys=True)
        handle.write("\n")
    make_container_readable(path)


def main() -> int:
    repository = Path(__file__).resolve().parents[1]
    target = repository / ".local" / "secrets"
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        target.chmod(0o700)

    invalid = [
        name for name in SECRET_NAMES if (target / name).exists() and not (target / name).is_file()
    ]
    if invalid:
        raise SystemExit("Refusing non-file secret path(s): " + ", ".join(invalid))

    for name in SECRET_NAMES:
        path = target / name
        if path.is_file():
            make_container_readable(path)

    missing = [name for name in SECRET_NAMES if not (target / name).exists()]
    if not missing:
        raise SystemExit("All local secret files already exist; nothing was changed")

    if "django_secret_key" in missing:
        create_secret(target / "django_secret_key", 64)
    if "postgres_password" in missing:
        create_secret(target / "postgres_password", 48)
    for name in (
        "postgres_migrate_password",
        "postgres_web_password",
        "postgres_api_password",
        "postgres_worker_password",
        "api_django_secret_key",
    ):
        if name in missing:
            create_secret(target / name, 48)
    if "master_key" in missing:
        # Legacy fallback for existing installations during migration to the keyring.
        create_fernet_key(target / "master_key")
    if "master_keyring" in missing:
        create_credential_keyring(target / "master_keyring")
    if "backup_key" in missing:
        # Independent from the credential keyring and never mounted into runtime services.
        create_fernet_key(target / "backup_key")
    if "setup_token" in missing:
        create_secret(target / "setup_token", 32)
    print(f"Created missing local secret files in {target}; existing files were unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
