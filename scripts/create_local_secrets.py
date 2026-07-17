#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only

import os
import secrets
from pathlib import Path

SECRET_NAMES = ("django_secret_key", "postgres_password")


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

    existing = [name for name in SECRET_NAMES if (target / name).exists()]
    if existing:
        names = ", ".join(existing)
        raise SystemExit(f"Refusing to overwrite existing secret file(s): {names}")

    create_secret(target / "django_secret_key", 64)
    create_secret(target / "postgres_password", 48)
    print(f"Created local secret files in {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
