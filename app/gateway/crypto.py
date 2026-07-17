# SPDX-License-Identifier: AGPL-3.0-only

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


class CredentialDecryptionError(RuntimeError):
    pass


def _fernet() -> Fernet:
    return Fernet(settings.MAILGATE_MASTER_KEY.encode("ascii"))


def encrypt_secret(value: str) -> bytes:
    return _fernet().encrypt(value.encode("utf-8"))


def decrypt_secret(value: bytes) -> str:
    try:
        return _fernet().decrypt(bytes(value)).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise CredentialDecryptionError("Stored credential cannot be decrypted") from exc
