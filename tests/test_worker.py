# SPDX-License-Identifier: AGPL-3.0-only

from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from django.test import SimpleTestCase
from mailgate_worker import __main__ as worker_main


class WorkerCliTests(SimpleTestCase):
    def test_help_does_not_initialize_django_or_require_secrets(self):
        output = StringIO()
        with (
            patch("sys.argv", ["mailgate_worker", "--help"]),
            patch.object(worker_main.django, "setup") as django_setup,
            redirect_stdout(output),
            self.assertRaises(SystemExit) as exit_context,
        ):
            worker_main.main()
        self.assertEqual(exit_context.exception.code, 0)
        self.assertIn("MailGate read-only ingestion worker", output.getvalue())
        django_setup.assert_not_called()
