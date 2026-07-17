# SPDX-License-Identifier: AGPL-3.0-only

from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from mailgate.config import ConfigurationError

from gateway.crypto import CredentialDecryptionError, credential_keyring
from gateway.models import Mailbox

from .rotate_mailbox_credentials import ROTATION_LOCK_ID


class Command(BaseCommand):
    help = "Verify that every stored mailbox credential can be decrypted."

    def handle(self, *args, **options):
        try:
            keyring = credential_keyring()
        except ConfigurationError as exc:
            raise CommandError("Mailbox credential keyring configuration is invalid") from exc
        verified = 0
        try:
            with transaction.atomic():
                if connection.vendor == "postgresql":
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT pg_advisory_xact_lock(%s)", [ROTATION_LOCK_ID])
                for ciphertext in (
                    Mailbox.objects.select_for_update()
                    .order_by("pk")
                    .values_list("password_encrypted", flat=True)
                ):
                    keyring.decrypt(bytes(ciphertext))
                    verified += 1
        except CredentialDecryptionError as exc:
            raise CommandError("Credential verification failed") from exc
        self.stdout.write(self.style.SUCCESS(f"Verified {verified} mailbox credential(s)."))
