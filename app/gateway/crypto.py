# SPDX-License-Identifier: AGPL-3.0-only

import json
import re
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from mailgate.config import ConfigurationError


class CredentialDecryptionError(RuntimeError):
    pass


TOKEN_PREFIX = b"mgk1:"
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError(f"Duplicate keyring field: {key}")
        result[key] = value
    return result


def _make_fernet(value: str, *, description: str) -> Fernet:
    try:
        return Fernet(value.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise ConfigurationError(f"{description} is not a valid Fernet key") from exc


@dataclass(frozen=True)
class CredentialKeyring:
    primary_id: str | None
    keys: dict[str, Fernet]
    legacy_keys: tuple[Fernet, ...]

    @classmethod
    def from_settings(cls) -> "CredentialKeyring":
        raw_keyring = getattr(settings, "MAILGATE_MASTER_KEYRING", "")
        legacy_value = getattr(settings, "MAILGATE_MASTER_KEY", "")
        if not raw_keyring:
            if not legacy_value:
                raise ConfigurationError("No mailbox credential encryption key is configured")
            legacy = _make_fernet(legacy_value, description="MAILGATE_MASTER_KEY")
            return cls(primary_id=None, keys={}, legacy_keys=(legacy,))

        try:
            document = json.loads(raw_keyring, object_pairs_hook=_reject_duplicate_keys)
        except json.JSONDecodeError as exc:
            raise ConfigurationError("MAILGATE_MASTER_KEYRING must be valid JSON") from exc
        if not isinstance(document, dict) or set(document) != {"version", "primary", "keys"}:
            raise ConfigurationError(
                "MAILGATE_MASTER_KEYRING must contain exactly version, primary and keys"
            )
        if document["version"] != 1:
            raise ConfigurationError("Unsupported MAILGATE_MASTER_KEYRING version")
        primary = document["primary"]
        values = document["keys"]
        if not isinstance(primary, str) or not KEY_ID_RE.fullmatch(primary):
            raise ConfigurationError("MAILGATE_MASTER_KEYRING primary is not a valid key ID")
        if not isinstance(values, dict) or not values:
            raise ConfigurationError("MAILGATE_MASTER_KEYRING keys must be a non-empty object")

        keys = {}
        for key_id, value in values.items():
            if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id):
                raise ConfigurationError("MAILGATE_MASTER_KEYRING contains an invalid key ID")
            if not isinstance(value, str):
                raise ConfigurationError(f"Fernet key {key_id} must be a string")
            keys[key_id] = _make_fernet(value, description=f"Fernet key {key_id}")
        if primary not in keys:
            raise ConfigurationError("MAILGATE_MASTER_KEYRING primary is absent from keys")

        legacy_keys = list(keys.values())
        if legacy_value:
            legacy_keys.append(_make_fernet(legacy_value, description="MAILGATE_MASTER_KEY"))
        return cls(primary_id=primary, keys=keys, legacy_keys=tuple(legacy_keys))

    def encrypt(self, value: bytes) -> bytes:
        if self.primary_id is None:
            return self.legacy_keys[0].encrypt(value)
        token = self.keys[self.primary_id].encrypt(value)
        return TOKEN_PREFIX + self.primary_id.encode("ascii") + b":" + token

    def decrypt(self, value: bytes) -> bytes:
        key_id, token = self.identify(value)
        if key_id is not None:
            fernet = self.keys.get(key_id)
            if fernet is None:
                raise CredentialDecryptionError(
                    f"Stored credential references unavailable key ID {key_id}"
                )
            try:
                return fernet.decrypt(token)
            except InvalidToken as exc:
                raise CredentialDecryptionError("Stored credential cannot be decrypted") from exc

        for fernet in self.legacy_keys:
            try:
                return fernet.decrypt(token)
            except InvalidToken:
                continue
        raise CredentialDecryptionError("Stored credential cannot be decrypted")

    def identify(self, value: bytes) -> tuple[str | None, bytes]:
        if not value.startswith(TOKEN_PREFIX):
            return None, value
        parts = value.split(b":", 2)
        if len(parts) != 3:
            raise CredentialDecryptionError("Stored credential has an invalid keyring envelope")
        try:
            key_id = parts[1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise CredentialDecryptionError("Stored credential has an invalid key ID") from exc
        if not KEY_ID_RE.fullmatch(key_id) or not parts[2]:
            raise CredentialDecryptionError("Stored credential has an invalid keyring envelope")
        return key_id, parts[2]

    def uses_primary(self, value: bytes) -> bool:
        key_id, _token = self.identify(value)
        if self.primary_id is None:
            return key_id is None
        return key_id == self.primary_id


def credential_keyring() -> CredentialKeyring:
    return CredentialKeyring.from_settings()


def encrypt_secret(value: str) -> bytes:
    return credential_keyring().encrypt(value.encode("utf-8"))


def decrypt_secret(value: bytes) -> str:
    try:
        return credential_keyring().decrypt(bytes(value)).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CredentialDecryptionError("Stored credential cannot be decrypted") from exc


def reencrypt_secret(value: bytes) -> tuple[bytes, bool]:
    keyring = credential_keyring()
    plaintext = keyring.decrypt(bytes(value))
    if keyring.uses_primary(bytes(value)):
        return bytes(value), False
    rotated = keyring.encrypt(plaintext)
    if keyring.decrypt(rotated) != plaintext:
        raise CredentialDecryptionError("Rotated credential failed verification")
    return rotated, True
