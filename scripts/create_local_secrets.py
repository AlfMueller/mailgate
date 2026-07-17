#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only

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
    "setup_token",
)


def create_secret(path: Path, length: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(secrets.token_urlsafe(length))
        handle.write("\n")


def main() -> int:
    repository = Path(__file__).resolve().parents[1]
    target = repository / ".local" / "secrets"
    target.mkdir(mode=0o700, parents=True, exist_ok=True)

    invalid = [
        name for name in SECRET_NAMES if (target / name).exists() and not (target / name).is_file()
    ]
    if invalid:
        raise SystemExit("Refusing non-file secret path(s): " + ", ".join(invalid))

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
        # Fernet-compatible, URL-safe 32-byte key, independent from Django.
        import base64

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(target / "master_key", flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"))
            handle.write("\n")
    if "setup_token" in missing:
        create_secret(target / "setup_token", 32)
    print(f"Created missing local secret files in {target}; existing files were unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
