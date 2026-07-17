# SPDX-License-Identifier: AGPL-3.0-only

import json

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from gateway.lifecycle import RetentionPolicy, purge_retention, retention_counts


class Command(BaseCommand):
    help = "Preview or apply bounded retention for messages, inactive tokens and audit events."

    def add_arguments(self, parser):
        parser.add_argument("--approved-days", type=int, default=365)
        parser.add_argument("--quarantined-days", type=int, default=30)
        parser.add_argument("--rejected-days", type=int, default=30)
        parser.add_argument("--token-days", type=int, default=30)
        parser.add_argument("--audit-days", type=int, default=365)
        parser.add_argument("--batch-size", type=int, default=500)
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Delete eligible records. Without this flag the command is a dry run.",
        )

    def handle(self, *args, **options):
        try:
            policy = RetentionPolicy(
                approved_days=options["approved_days"],
                quarantined_days=options["quarantined_days"],
                rejected_days=options["rejected_days"],
                token_days=options["token_days"],
                audit_days=options["audit_days"],
            )
            now = timezone.now()
            if options["apply"]:
                counts = purge_retention(policy, now=now, batch_size=options["batch_size"])
                mode = "applied"
            else:
                counts = retention_counts(policy, now=now)
                mode = "dry-run"
        except ValueError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(
            json.dumps(
                {"mode": mode, "counts": counts, "policy_days": vars(policy)},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
