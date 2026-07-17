# SPDX-License-Identifier: AGPL-3.0-only

import os
import tempfile
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction

from gateway.owner_export import write_owner_export


class Command(BaseCommand):
    help = "Write a versioned owner-data NDJSON export without credentials or token hashes."

    def add_arguments(self, parser):
        parser.add_argument(
            "--output",
            required=True,
            help="New output file, or '-' for NDJSON on standard output.",
        )

    def _write_records(self, stream) -> int:
        with transaction.atomic():
            if connection.vendor == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            return write_owner_export(stream)

    def handle(self, *args, **options):
        output = options["output"]
        if output == "-":
            self._write_records(self.stdout)
            return

        target = Path(output).expanduser().resolve()
        if target.exists():
            raise CommandError("Refusing to overwrite an existing export file")
        if not target.parent.is_dir():
            raise CommandError("Export parent directory does not exist")

        temporary_path = None
        try:
            descriptor, name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
            temporary_path = Path(name)
            if os.name != "nt":
                os.chmod(temporary_path, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                count = self._write_records(stream)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary_path, target)
            except FileExistsError as exc:
                raise CommandError("Refusing to overwrite an existing export file") from exc
            except OSError as exc:
                raise CommandError("Unable to publish export atomically") from exc
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

        self.stdout.write(self.style.SUCCESS(f"Exported {count} record(s) to {target}."))
