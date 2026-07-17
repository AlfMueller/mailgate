# SPDX-License-Identifier: AGPL-3.0-only
"""Strictly synthetic, read-only TLS IMAP server for integration and E2E tests."""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import re
import shlex
import socket
import ssl
import threading
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path
from typing import BinaryIO

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HOSTNAME = "imap.example.test"
USERNAME = "owner@example.test"
UID_VALIDITY = 20260717
MESSAGE_UID = 1
CERTIFICATE_PATH = Path("/tmp/synthetic-imap-cert.pem")  # noqa: S108 -- isolated tmpfs
KEY_PATH = Path("/tmp/synthetic-imap-key.pem")  # noqa: S108 -- isolated tmpfs
MAX_COMMAND_BYTES = 16_384
MUTATING_COMMANDS = {
    "APPEND",
    "CHECK",
    "CLOSE",
    "COPY",
    "CREATE",
    "DELETE",
    "EXPUNGE",
    "MOVE",
    "RENAME",
    "STORE",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
}
TAG_RE = re.compile(r"^[A-Za-z0-9]+$")


def synthetic_message() -> bytes:
    message = EmailMessage()
    message["From"] = "Synthetic Sender <safe-sender@example.test>"
    message["To"] = USERNAME
    message["Subject"] = "MailGate E2E synthetic message"
    message["Date"] = "Fri, 17 Jul 2026 18:00:00 +0000"
    message["Message-ID"] = "<mailgate-e2e-1@example.test>"
    message.set_content("This is a synthetic MailGate browser E2E message.")
    return message.as_bytes(policy=SMTP)


SYNTHETIC_MESSAGE = synthetic_message()


def create_certificate(
    certificate_path: Path = CERTIFICATE_PATH,
    key_path: Path = KEY_PATH,
) -> None:
    certificate_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=4))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(HOSTNAME), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    certificate_path.chmod(0o444)
    key_path.chmod(0o600)


def _send(stream: BinaryIO, value: str | bytes) -> None:
    payload = value.encode("ascii") if isinstance(value, str) else value
    stream.write(payload)
    stream.flush()


def _tagged(stream: BinaryIO, tag: str, status: str, message: str) -> None:
    _send(stream, f"{tag} {status} {message}\r\n")


def _parse_command(raw_line: bytes) -> list[str]:
    try:
        decoded = raw_line.decode("utf-8", errors="strict").rstrip("\r\n")
        return shlex.split(decoded, posix=True)
    except (UnicodeDecodeError, ValueError):
        return []


def _print_mutation(message: str) -> None:
    print(message, flush=True)


def _select_read_only(stream: BinaryIO, tag: str) -> None:
    _send(stream, "* FLAGS (\\Seen)\r\n")
    _send(stream, "* 1 EXISTS\r\n")
    _send(stream, "* 0 RECENT\r\n")
    _send(stream, f"* OK [UIDVALIDITY {UID_VALIDITY}] synthetic mailbox identity\r\n")
    _send(stream, f"* OK [UIDNEXT {MESSAGE_UID + 1}] next synthetic UID\r\n")
    _tagged(stream, tag, "OK", "[READ-ONLY] INBOX selected without mutation")


def _uid_search(stream: BinaryIO, tag: str, arguments: list[str]) -> None:
    expression = " ".join(arguments)
    match = re.search(r"(?:^|\s)UID\s+(\d+):\*(?:\s|$)", expression, re.IGNORECASE)
    if match is None:
        _tagged(stream, tag, "BAD", "Only bounded UID range searches are supported")
        return
    lower_bound = int(match.group(1))
    value = str(MESSAGE_UID) if lower_bound <= MESSAGE_UID else ""
    _send(stream, f"* SEARCH {value}\r\n" if value else "* SEARCH\r\n")
    _tagged(stream, tag, "OK", "UID SEARCH completed")


def _uid_fetch(stream: BinaryIO, tag: str, arguments: list[str]) -> None:
    if len(arguments) < 2 or arguments[0] != str(MESSAGE_UID):
        _tagged(stream, tag, "OK", "UID FETCH completed with no matching message")
        return
    attributes = " ".join(arguments[1:]).upper()
    if "RFC822.SIZE" in attributes and "BODY.PEEK[]" not in attributes:
        _send(
            stream,
            f"* 1 FETCH (UID {MESSAGE_UID} RFC822.SIZE {len(SYNTHETIC_MESSAGE)})\r\n",
        )
        _tagged(stream, tag, "OK", "UID FETCH size completed")
        return
    if "BODY.PEEK[]" in attributes:
        _send(
            stream,
            f"* 1 FETCH (UID {MESSAGE_UID} BODY[] {{{len(SYNTHETIC_MESSAGE)}}}\r\n",
        )
        _send(stream, SYNTHETIC_MESSAGE)
        _send(stream, ")\r\n")
        _tagged(stream, tag, "OK", "UID FETCH body completed without setting flags")
        return
    _tagged(stream, tag, "BAD", "Only RFC822.SIZE and BODY.PEEK[] are supported")


def handle_client(
    connection: socket.socket,
    *,
    mutation_logger=_print_mutation,
) -> None:
    state = "not_authenticated"
    try:
        with connection, connection.makefile("rwb", buffering=0) as stream:
            _send(stream, "* OK [CAPABILITY IMAP4rev1] synthetic MailGate integration server\r\n")
            while True:
                raw_line = stream.readline(MAX_COMMAND_BYTES + 1)
                if not raw_line:
                    return
                if len(raw_line) > MAX_COMMAND_BYTES or not raw_line.endswith(b"\n"):
                    _send(stream, "* BAD command exceeds fixture limits\r\n")
                    return
                parts = _parse_command(raw_line)
                if len(parts) < 2 or not TAG_RE.fullmatch(parts[0]):
                    _send(stream, "* BAD malformed command\r\n")
                    continue
                tag, command = parts[0], parts[1].upper()
                arguments = parts[2:]

                if command in MUTATING_COMMANDS:
                    mutation_logger(f"MUTATION_ATTEMPT command={command}")
                    _tagged(stream, tag, "NO", "Read-only fixture rejects mailbox mutation")
                    continue
                if command == "CAPABILITY":
                    _send(stream, "* CAPABILITY IMAP4rev1\r\n")
                    _tagged(stream, tag, "OK", "CAPABILITY completed")
                elif command == "NOOP":
                    _tagged(stream, tag, "OK", "NOOP completed")
                elif command == "LOGIN":
                    if len(arguments) != 2 or arguments[0] != USERNAME or not arguments[1]:
                        _tagged(stream, tag, "NO", "Synthetic credentials rejected")
                    else:
                        state = "authenticated"
                        _tagged(stream, tag, "OK", "LOGIN completed")
                elif command in {"EXAMINE", "SELECT"}:
                    if state == "not_authenticated":
                        _tagged(stream, tag, "NO", "Authenticate first")
                    elif len(arguments) != 1 or arguments[0].upper() != "INBOX":
                        _tagged(stream, tag, "NO", "Only INBOX is available")
                    else:
                        state = "selected"
                        _select_read_only(stream, tag)
                elif command == "UID":
                    if state != "selected" or not arguments:
                        _tagged(stream, tag, "NO", "Select INBOX read-only first")
                        continue
                    subcommand = arguments[0].upper()
                    if subcommand in MUTATING_COMMANDS:
                        mutation_logger(f"MUTATION_ATTEMPT command=UID_{subcommand}")
                        _tagged(stream, tag, "NO", "Read-only fixture rejects UID mutation")
                    elif subcommand == "SEARCH":
                        _uid_search(stream, tag, arguments[1:])
                    elif subcommand == "FETCH":
                        _uid_fetch(stream, tag, arguments[1:])
                    else:
                        _tagged(stream, tag, "BAD", "Unsupported read-only UID command")
                elif command == "LOGOUT":
                    _send(stream, "* BYE synthetic session closed\r\n")
                    _tagged(stream, tag, "OK", "LOGOUT completed")
                    return
                else:
                    _tagged(stream, tag, "BAD", "Unsupported command")
    except (BrokenPipeError, ConnectionError, OSError):
        return


def serve(certificate_path: Path, key_path: Path, *, port: int = 993) -> None:
    create_certificate(certificate_path, key_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate_path, key_path)
    # The integration-only container is attached solely to the relay upstream network.
    with socket.create_server(("0.0.0.0", port)) as listener:  # noqa: S104
        while True:
            connection, _address = listener.accept()
            try:
                tls_connection = context.wrap_socket(connection, server_side=True)
            except (OSError, ssl.SSLError):
                connection.close()
                continue
            thread = threading.Thread(target=handle_client, args=(tls_connection,), daemon=True)
            thread.start()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate-path", type=Path, default=CERTIFICATE_PATH)
    parser.add_argument("--key-path", type=Path, default=KEY_PATH)
    parser.add_argument("--port", type=int, default=993)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not 1 <= args.port <= 65535:
        raise SystemExit("port must be between 1 and 65535")
    serve(args.certificate_path, args.key_path, port=args.port)


if __name__ == "__main__":
    main()
