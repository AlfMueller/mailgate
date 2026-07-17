#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only

import getpass
import os
import secrets
import shutil
import stat
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path


class RotationToolError(RuntimeError):
    """A content-minimal operational error safe to show to an operator."""


FileHardener = Callable[[Path, int], None]


def container_secret_mode(existing_mode: int) -> int:
    """Keep bind-mounted secrets readable only through the owner-only parent boundary."""
    return existing_mode if os.name == "nt" else 0o444


def require_secure_directory(path: Path) -> Path:
    directory = path.expanduser().absolute()
    try:
        status = directory.lstat()
    except OSError as exc:
        raise RotationToolError("The secret directory is unavailable") from exc
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        raise RotationToolError("The secret directory must be a real directory")
    if os.name != "nt":
        if status.st_uid != os.getuid() or stat.S_IMODE(status.st_mode) & 0o077:
            raise RotationToolError("The secret directory must be owner-only (0700)")
    return directory


def _windows_identity() -> str:
    username = os.environ.get("USERNAME") or getpass.getuser()
    domain = os.environ.get("USERDOMAIN", "").strip()
    return f"{domain}\\{username}" if domain else username


def harden_secret_file(path: Path, mode: int) -> None:
    if os.name != "nt":
        path.chmod(mode)
        if stat.S_IMODE(path.stat().st_mode) != mode:
            raise RotationToolError("Unable to apply restrictive secret-file permissions")
        return

    icacls = shutil.which("icacls")
    if not icacls:
        raise RotationToolError("Windows ACL hardening is unavailable")
    result = subprocess.run(  # noqa: S603 -- absolute system utility, fixed arguments.
        [
            icacls,
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"{_windows_identity()}:(F)",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise RotationToolError("Unable to apply an owner-only Windows ACL")


def read_secret(path: Path, *, maximum_bytes: int = 65_536) -> tuple[str, int]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RotationToolError("A required secret file is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RotationToolError("A required secret path is not a private regular file")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RotationToolError("A secret file changed while it was being opened")
        data = os.read(descriptor, maximum_bytes + 1)
    except OSError as exc:
        raise RotationToolError("Unable to read a required secret file") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(data) > maximum_bytes:
        raise RotationToolError("A secret file exceeds the supported size limit")
    try:
        value = data.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise RotationToolError("A secret file is not valid UTF-8") from exc
    if not value or "\x00" in value:
        raise RotationToolError("A secret file is empty or malformed")
    return value, stat.S_IMODE(before.st_mode)


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_secret(
    path: Path,
    value: str,
    *,
    mode: int,
    hardener: FileHardener = harden_secret_file,
) -> None:
    directory = require_secure_directory(path.parent)
    target = directory / path.name
    if target.exists() or target.is_symlink():
        try:
            status = target.lstat()
        except OSError as exc:
            raise RotationToolError("Unable to inspect the existing secret file") from exc
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise RotationToolError("Refusing to replace a non-private secret path")

    temporary = directory / f".{target.name}.rotation-{secrets.token_hex(12)}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = None
            stream.write(value)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        hardener(temporary, mode)
        os.replace(temporary, target)
        _fsync_directory(directory)
    except RotationToolError:
        raise
    except OSError as exc:
        raise RotationToolError("Unable to replace the secret file atomically") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError as exc:
            raise RotationToolError("Unable to remove a temporary secret file") from exc


@contextmanager
def exclusive_rotation_lock(directory: Path, name: str) -> Iterator[None]:
    secure_directory = require_secure_directory(directory)
    lock_path = secure_directory / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except FileExistsError as exc:
        raise RotationToolError(
            "Another rotation is active; inspect and remove a stale lock only after verification"
        ) from exc
    except OSError as exc:
        raise RotationToolError("Unable to acquire the rotation lock") from exc
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        yield
    finally:
        os.close(descriptor)
        try:
            lock_path.unlink()
        except OSError as exc:
            raise RotationToolError("Unable to release the rotation lock") from exc
