# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic TLS IMAP greeting server used only by the Compose integration profile."""

from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HOSTNAME = "imap.example.test"
CERTIFICATE_PATH = Path("/tmp/synthetic-imap-cert.pem")  # noqa: S108 -- isolated tmpfs
KEY_PATH = Path("/tmp/synthetic-imap-key.pem")  # noqa: S108 -- isolated tmpfs


def create_certificate() -> None:
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
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(HOSTNAME), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    CERTIFICATE_PATH.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def main() -> None:
    create_certificate()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(CERTIFICATE_PATH, KEY_PATH)
    # The integration-only container is attached solely to the relay upstream network.
    with socket.create_server(("0.0.0.0", 993)) as listener:  # noqa: S104
        while True:
            connection, _address = listener.accept()
            try:
                with context.wrap_socket(connection, server_side=True) as tls_connection:
                    tls_connection.sendall(b"* OK synthetic MailGate integration server\r\n")
            except (OSError, ssl.SSLError):
                connection.close()


if __name__ == "__main__":
    main()
