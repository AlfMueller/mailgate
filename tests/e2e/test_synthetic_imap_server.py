# SPDX-License-Identifier: AGPL-3.0-only

import socket
import threading
from unittest import TestCase

from scripts.synthetic_imap_server import SYNTHETIC_MESSAGE, handle_client


class SyntheticImapServerTests(TestCase):
    def setUp(self):
        self.server_socket, self.client_socket = socket.socketpair()
        self.mutations: list[str] = []
        self.thread = threading.Thread(
            target=handle_client,
            args=(self.server_socket,),
            kwargs={"mutation_logger": self.mutations.append},
            daemon=True,
        )
        self.thread.start()
        self.stream = self.client_socket.makefile("rwb", buffering=0)
        self.assertTrue(self.stream.readline().startswith(b"* OK"))

    def tearDown(self):
        self.stream.close()
        self.client_socket.close()
        self.thread.join(timeout=2)

    def command(self, value: bytes, tag: bytes) -> list[bytes]:
        self.stream.write(value + b"\r\n")
        lines = []
        while True:
            line = self.stream.readline()
            self.assertTrue(line, "synthetic server closed before tagged response")
            lines.append(line)
            if line.startswith(tag + b" "):
                return lines

    def test_read_only_imap_flow_and_mutation_rejection(self):
        self.assertIn(b"A1 OK", b"".join(self.command(b"A1 CAPABILITY", b"A1")))
        self.assertIn(
            b"A2 OK",
            b"".join(
                self.command(
                    b'A2 LOGIN "owner@example.test" "synthetic-password"',
                    b"A2",
                )
            ),
        )
        selected = b"".join(self.command(b'A3 EXAMINE "INBOX"', b"A3"))
        self.assertIn(b"UIDVALIDITY 20260717", selected)
        self.assertIn(b"[READ-ONLY]", selected)

        searched = b"".join(self.command(b"A4 UID SEARCH UID 1:*", b"A4"))
        self.assertIn(b"* SEARCH 1", searched)
        sized = b"".join(self.command(b"A5 UID FETCH 1 (RFC822.SIZE)", b"A5"))
        self.assertIn(f"RFC822.SIZE {len(SYNTHETIC_MESSAGE)}".encode(), sized)

        self.stream.write(b"A6 UID FETCH 1 (BODY.PEEK[])\r\n")
        literal_header = self.stream.readline()
        self.assertIn(f"{{{len(SYNTHETIC_MESSAGE)}}}".encode(), literal_header)
        self.assertEqual(self.stream.read(len(SYNTHETIC_MESSAGE)), SYNTHETIC_MESSAGE)
        self.assertEqual(self.stream.readline(), b")\r\n")
        self.assertTrue(self.stream.readline().startswith(b"A6 OK"))

        rejected = b"".join(self.command(b"A7 UID STORE 1 +FLAGS (\\Seen)", b"A7"))
        self.assertIn(b"A7 NO", rejected)
        self.assertEqual(self.mutations, ["MUTATION_ATTEMPT command=UID_STORE"])
        self.assertIn(b"A8 OK", b"".join(self.command(b"A8 LOGOUT", b"A8")))

    def test_select_is_also_forced_read_only(self):
        self.command(b'A1 LOGIN "owner@example.test" "synthetic-password"', b"A1")
        selected = b"".join(self.command(b'A2 SELECT "INBOX"', b"A2"))
        self.assertIn(b"[READ-ONLY]", selected)
        rejected = b"".join(self.command(b"A3 EXPUNGE", b"A3"))
        self.assertIn(b"A3 NO", rejected)
        self.assertEqual(self.mutations, ["MUTATION_ATTEMPT command=EXPUNGE"])
        self.command(b"A4 LOGOUT", b"A4")
