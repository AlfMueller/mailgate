#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only

"""Authenticated streaming archive format used by MailGate database backups."""

from __future__ import annotations

import base64
import json
import os
import struct
import tempfile
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"MAILGATE-BACKUP\x00"
VERSION = 1
NONCE_BYTES = 12
TAG_BYTES = 16
MAX_METADATA_BYTES = 64 * 1024
CHUNK_BYTES = 1024 * 1024


class BackupArchiveError(RuntimeError):
    pass


def load_backup_key(path: Path) -> bytes:
    try:
        encoded = path.read_text(encoding="ascii").strip()
        key = base64.urlsafe_b64decode(encoded.encode("ascii"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise BackupArchiveError("Unable to read a valid backup key") from exc
    if len(key) != 32:
        raise BackupArchiveError("Backup key must be one URL-safe base64-encoded 32-byte key")
    return key


def _metadata_bytes(metadata: dict) -> bytes:
    try:
        value = json.dumps(
            metadata,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BackupArchiveError("Backup metadata is not valid JSON") from exc
    if not value or len(value) > MAX_METADATA_BYTES:
        raise BackupArchiveError("Backup metadata has an invalid size")
    return value


def encrypt_stream(source: BinaryIO, destination: BinaryIO, *, key: bytes, metadata: dict) -> None:
    if len(key) != 32:
        raise BackupArchiveError("Backup encryption key must contain 32 bytes")
    nonce = os.urandom(NONCE_BYTES)
    encoded_metadata = _metadata_bytes(metadata)
    header = MAGIC + bytes((VERSION,)) + nonce + struct.pack(">I", len(encoded_metadata))
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header + encoded_metadata)
    destination.write(header)
    destination.write(encoded_metadata)
    while chunk := source.read(CHUNK_BYTES):
        destination.write(encryptor.update(chunk))
    destination.write(encryptor.finalize())
    destination.write(encryptor.tag)


def decrypt_to_temporary(archive: Path, *, key: bytes) -> tuple[Path, dict]:
    if len(key) != 32:
        raise BackupArchiveError("Backup decryption key must contain 32 bytes")
    temporary_path: Path | None = None
    completed = False
    try:
        with archive.open("rb") as source:
            fixed_size = len(MAGIC) + 1 + NONCE_BYTES + 4
            header = source.read(fixed_size)
            if len(header) != fixed_size or not header.startswith(MAGIC):
                raise BackupArchiveError("Not a MailGate backup archive")
            version = header[len(MAGIC)]
            if version != VERSION:
                raise BackupArchiveError("Unsupported MailGate backup version")
            nonce_start = len(MAGIC) + 1
            nonce = header[nonce_start : nonce_start + NONCE_BYTES]
            metadata_size = struct.unpack(">I", header[-4:])[0]
            if not 1 <= metadata_size <= MAX_METADATA_BYTES:
                raise BackupArchiveError("Backup metadata has an invalid size")
            encoded_metadata = source.read(metadata_size)
            if len(encoded_metadata) != metadata_size:
                raise BackupArchiveError("Backup archive is truncated")
            try:
                metadata = json.loads(encoded_metadata)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BackupArchiveError("Backup metadata is invalid") from exc
            if not isinstance(metadata, dict):
                raise BackupArchiveError("Backup metadata must be an object")

            ciphertext_start = fixed_size + metadata_size
            archive_size = archive.stat().st_size
            ciphertext_size = archive_size - ciphertext_start - TAG_BYTES
            if ciphertext_size < 1:
                raise BackupArchiveError("Backup archive has no encrypted payload")
            source.seek(archive_size - TAG_BYTES)
            tag = source.read(TAG_BYTES)
            source.seek(ciphertext_start)

            descriptor, temp_name = tempfile.mkstemp(prefix="mailgate-restore-", suffix=".dump")
            temporary_path = Path(temp_name)
            if os.name != "nt":
                temporary_path.chmod(0o600)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(header + encoded_metadata)
            remaining = ciphertext_size
            with os.fdopen(descriptor, "wb") as destination:
                while remaining:
                    chunk = source.read(min(CHUNK_BYTES, remaining))
                    if not chunk:
                        raise BackupArchiveError("Backup archive is truncated")
                    remaining -= len(chunk)
                    destination.write(decryptor.update(chunk))
                destination.write(decryptor.finalize())
            completed = True
            return temporary_path, metadata
    except InvalidTag as exc:
        raise BackupArchiveError("Backup authentication failed") from exc
    except OSError as exc:
        raise BackupArchiveError("Unable to read or decrypt the backup archive") from exc
    finally:
        if temporary_path is not None and not completed:
            temporary_path.unlink(missing_ok=True)
