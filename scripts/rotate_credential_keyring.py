#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only

import argparse
import json
import re
from collections.abc import Callable
from pathlib import Path

from cryptography.fernet import Fernet
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

KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAXIMUM_KEYS = 32


def _reject_duplicate_keys(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise RotationToolError("The existing keyring contains duplicate fields")
        document[key] = value
    return document


def _validate_key_id(value: str) -> str:
    if not KEY_ID_RE.fullmatch(value):
        raise RotationToolError(
            "Key IDs must be 1-64 ASCII letters, digits, dots, underscores or hyphens"
        )
    return value


def _validate_fernet_key(value: str) -> str:
    try:
        Fernet(value.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise RotationToolError("The keyring contains an invalid Fernet key") from exc
    return value


def _load_keyring(path: Path) -> tuple[dict, int]:
    raw, mode = read_secret(path)
    try:
        document = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise RotationToolError("The existing credential keyring is not valid JSON") from exc
    if not isinstance(document, dict) or set(document) != {"version", "primary", "keys"}:
        raise RotationToolError("The existing credential keyring has an unsupported shape")
    if document["version"] != 1:
        raise RotationToolError("The existing credential keyring version is unsupported")
    primary = document["primary"]
    keys = document["keys"]
    if not isinstance(primary, str):
        raise RotationToolError("The existing credential keyring primary is invalid")
    _validate_key_id(primary)
    if not isinstance(keys, dict) or not keys or len(keys) > MAXIMUM_KEYS:
        raise RotationToolError("The existing credential keyring key count is invalid")
    for key_id, value in keys.items():
        if not isinstance(key_id, str) or not isinstance(value, str):
            raise RotationToolError("The existing credential keyring contains invalid entries")
        _validate_key_id(key_id)
        _validate_fernet_key(value)
    if primary not in keys:
        raise RotationToolError("The existing credential keyring primary key is unavailable")
    return document, mode


def rotate_credential_keyring(
    *,
    secrets_directory: Path,
    new_primary_id: str,
    legacy_key_id: str | None = None,
    activate_existing: bool = False,
    key_factory: Callable[[], bytes] | None = None,
    hardener: FileHardener = harden_secret_file,
) -> bool:
    directory = require_secure_directory(secrets_directory)
    new_primary_id = _validate_key_id(new_primary_id)
    target = directory / "master_keyring"

    with exclusive_rotation_lock(directory, ".credential-keyring.rotation.lock"):
        if target.exists() or target.is_symlink():
            document, mode = _load_keyring(target)
            mode = container_secret_mode(mode)
            if new_primary_id in document["keys"]:
                if document["primary"] == new_primary_id:
                    return False
                if not activate_existing:
                    raise RotationToolError(
                        "The requested key ID already exists; use --activate-existing-id "
                        "for an intentional rollback"
                    )
                document["primary"] = new_primary_id
                serialized = json.dumps(document, separators=(",", ":"), sort_keys=True)
                atomic_write_secret(target, serialized, mode=mode, hardener=hardener)
                verified, _mode = _load_keyring(target)
                if verified != document:
                    raise RotationToolError(
                        "The atomically written credential keyring failed verification"
                    )
                return True
        else:
            if activate_existing:
                raise RotationToolError("Cannot activate an existing key before a keyring exists")
            if legacy_key_id is None:
                raise RotationToolError(
                    "--legacy-key-id is required when converting an installation without a keyring"
                )
            legacy_key_id = _validate_key_id(legacy_key_id)
            if legacy_key_id == new_primary_id:
                raise RotationToolError("The legacy and new primary key IDs must differ")
            legacy_value, mode = read_secret(directory / "master_key")
            document = {
                "version": 1,
                "primary": legacy_key_id,
                "keys": {legacy_key_id: _validate_fernet_key(legacy_value)},
            }
            mode = container_secret_mode(mode)

        if len(document["keys"]) >= MAXIMUM_KEYS:
            raise RotationToolError(
                "The keyring limit was reached; retire a verified old key first"
            )
        generated = (key_factory or Fernet.generate_key)()
        try:
            generated_value = generated.decode("ascii")
        except (AttributeError, UnicodeDecodeError) as exc:
            raise RotationToolError("The Fernet key generator returned invalid data") from exc
        document["keys"][new_primary_id] = _validate_fernet_key(generated_value)
        document["primary"] = new_primary_id
        serialized = json.dumps(document, separators=(",", ":"), sort_keys=True)
        atomic_write_secret(target, serialized, mode=mode, hardener=hardener)

        verified, _mode = _load_keyring(target)
        if verified != document:
            raise RotationToolError("The atomically written credential keyring failed verification")
    return True


def build_parser() -> argparse.ArgumentParser:
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Atomically add and activate a generated Fernet key without printing it."
    )
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--new-primary-id")
    operation.add_argument(
        "--activate-existing-id",
        help="Atomically reactivate a retained key, for example during rollback.",
    )
    parser.add_argument(
        "--legacy-key-id",
        help="Required only when importing a pre-keyring master_key installation.",
    )
    parser.add_argument(
        "--secrets-directory",
        type=Path,
        default=repository / ".local" / "secrets",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    primary_id = args.new_primary_id or args.activate_existing_id
    try:
        changed = rotate_credential_keyring(
            secrets_directory=args.secrets_directory,
            new_primary_id=primary_id,
            legacy_key_id=args.legacy_key_id,
            activate_existing=args.activate_existing_id is not None,
        )
    except RotationToolError as exc:
        raise SystemExit(f"Keyring rotation preparation failed: {exc}") from exc
    if changed:
        print(f"Credential keyring primary is now {primary_id}; no key value was printed.")
    else:
        print(f"Credential keyring primary was already {primary_id}; nothing changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
