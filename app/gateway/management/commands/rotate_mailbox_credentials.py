# SPDX-License-Identifier: AGPL-3.0-only

from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from mailgate.config import ConfigurationError

from gateway.crypto import CredentialDecryptionError, credential_keyring, reencrypt_secret
from gateway.models import Mailbox, audit

ROTATION_LOCK_ID = 4_861_921_208_842_507_776


class Command(BaseCommand):
    help = "Re-encrypt mailbox credentials with the configured primary Fernet key."

    def handle(self, *args, **options):
        try:
            keyring = credential_keyring()
        except ConfigurationError as exc:
            raise CommandError("Mailbox credential keyring configuration is invalid") from exc
        if keyring.primary_id is None:
            raise CommandError(
                "A versioned MAILGATE_MASTER_KEYRING with a primary key is required for rotation"
            )

        rotated = 0
        verified = 0
        try:
            with transaction.atomic():
                if connection.vendor == "postgresql":
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT pg_advisory_xact_lock(%s)", [ROTATION_LOCK_ID])
                for mailbox in Mailbox.objects.select_for_update().order_by("pk"):
                    ciphertext, changed = reencrypt_secret(mailbox.password_encrypted)
                    verified += 1
                    if not changed:
                        continue
                    mailbox.password_encrypted = ciphertext
                    mailbox.config_version += 1
                    mailbox.save(
                        update_fields=("password_encrypted", "config_version", "updated_at")
                    )
                    rotated += 1
                audit(
                    actor="system:key-rotation",
                    action="credentials.rotated",
                    metadata={
                        "primary_key_id": keyring.primary_id,
                        "rotated": rotated,
                        "verified": verified,
                    },
                )
        except CredentialDecryptionError as exc:
            raise CommandError(
                "Credential rotation failed verification; the transaction was rolled back"
            ) from exc

        self.stdout.write(
            self.style.SUCCESS(
                f"Verified {verified} mailbox credential(s); rotated {rotated} "
                f"to key {keyring.primary_id}."
            )
        )
