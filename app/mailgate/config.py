# SPDX-License-Identifier: AGPL-3.0-only

import os
from collections.abc import Iterable
from pathlib import Path


class ConfigurationError(RuntimeError):
    """Raised when security-relevant configuration is missing or ambiguous."""


def get_bool(name: str, *, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default

    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be a boolean value")


def get_list(name: str, *, default: Iterable[str] = ()) -> list[str]:
    raw = os.getenv(name)
    if raw is None:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def get_secret(name: str, *, minimum_length: int = 1) -> str:
    direct_value = os.getenv(name)
    file_name = os.getenv(f"{name}_FILE")

    if direct_value is not None and file_name is not None:
        raise ConfigurationError(f"Set either {name} or {name}_FILE, not both")

    if file_name is not None:
        try:
            value = Path(file_name).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigurationError(f"Unable to read {name}_FILE") from exc
    elif direct_value is not None:
        value = direct_value.strip()
    else:
        raise ConfigurationError(f"Set {name}_FILE (preferred) or {name}")

    if len(value) < minimum_length:
        raise ConfigurationError(
            f"{name} must contain at least {minimum_length} characters"
        )
    return value
