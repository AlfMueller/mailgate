# SPDX-License-Identifier: AGPL-3.0-only

import io
import json
import os
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings
from django.utils import timezone
from gateway import lifecycle
from gateway.crypto import CredentialDecryptionError, decrypt_secret, encrypt_secret
from gateway.lifecycle import RetentionPolicy
from gateway.models import ApiToken, Attachment, AuditEvent, Mailbox, Message
from mailgate.config import ConfigurationError


def keyring_json(*, primary: str, keys: dict[str, bytes]) -> str:
    return json.dumps(
        {
            "version": 1,
            "primary": primary,
            "keys": {key_id: key.decode("ascii") for key_id, key in keys.items()},
        }
    )


class KeyringRotationTests(TestCase):
    def setUp(self):
        self.old_key = Fernet.generate_key()
        self.new_key = Fernet.generate_key()
        self.keyring = keyring_json(
            primary="current-2026-07",
            keys={"current-2026-07": self.new_key, "previous-2026-06": self.old_key},
        )

    def legacy_ciphertext(self, plaintext: str) -> bytes:
        with override_settings(
            MAILGATE_MASTER_KEY=self.old_key.decode("ascii"),
            MAILGATE_MASTER_KEYRING="",
        ):
            return encrypt_secret(plaintext)

    def test_versioned_keyring_reads_legacy_and_writes_primary_envelope(self):
        legacy = self.legacy_ciphertext("synthetic-credential")
        self.assertFalse(legacy.startswith(b"mgk1:"))
        with override_settings(
            MAILGATE_MASTER_KEY=self.old_key.decode("ascii"),
            MAILGATE_MASTER_KEYRING=self.keyring,
        ):
            self.assertEqual(decrypt_secret(legacy), "synthetic-credential")
            current = encrypt_secret("synthetic-credential")
            self.assertTrue(current.startswith(b"mgk1:current-2026-07:"))
            self.assertEqual(decrypt_secret(current), "synthetic-credential")

    def test_rotation_is_verified_locked_and_idempotent(self):
        original = self.legacy_ciphertext("synthetic-credential")
        mailbox = Mailbox.objects.create(
            name="Synthetic",
            host="imap.example.test",
            username="owner@example.test",
            password_encrypted=original,
        )
        output = io.StringIO()
        settings = {
            "MAILGATE_MASTER_KEY": self.old_key.decode("ascii"),
            "MAILGATE_MASTER_KEYRING": self.keyring,
        }
        with override_settings(**settings):
            call_command("rotate_mailbox_credentials", stdout=output)
            mailbox.refresh_from_db()
            rotated = bytes(mailbox.password_encrypted)
            self.assertTrue(rotated.startswith(b"mgk1:current-2026-07:"))
            self.assertEqual(decrypt_secret(rotated), "synthetic-credential")
            self.assertEqual(mailbox.config_version, 2)

            second_output = io.StringIO()
            call_command("rotate_mailbox_credentials", stdout=second_output)
            mailbox.refresh_from_db()
            self.assertEqual(bytes(mailbox.password_encrypted), rotated)
            self.assertEqual(mailbox.config_version, 2)
            self.assertIn("rotated 0", second_output.getvalue())
            call_command("verify_mailbox_credentials", stdout=io.StringIO())

        events = AuditEvent.objects.filter(action="credentials.rotated").order_by("pk")
        self.assertEqual(events.count(), 2)
        self.assertEqual(events.first().metadata["rotated"], 1)
        self.assertNotIn("synthetic-credential", str(events.first().metadata))

    def test_failed_partial_rotation_rolls_everything_back(self):
        valid_original = self.legacy_ciphertext("synthetic-credential")
        valid = Mailbox.objects.create(
            name="First",
            host="imap.example.test",
            username="first@example.test",
            password_encrypted=valid_original,
        )
        invalid = Mailbox.objects.create(
            name="Second",
            host="imap.example.test",
            username="second@example.test",
            password_encrypted=b"not-a-fernet-token",
        )
        with override_settings(
            MAILGATE_MASTER_KEY=self.old_key.decode("ascii"),
            MAILGATE_MASTER_KEYRING=self.keyring,
        ):
            with self.assertRaisesRegex(CommandError, "rolled back"):
                call_command("rotate_mailbox_credentials", stdout=io.StringIO())
            with self.assertRaisesRegex(CommandError, "verification failed"):
                call_command("verify_mailbox_credentials", stdout=io.StringIO())

        valid.refresh_from_db()
        invalid.refresh_from_db()
        self.assertEqual(bytes(valid.password_encrypted), valid_original)
        self.assertEqual(bytes(invalid.password_encrypted), b"not-a-fernet-token")
        self.assertEqual(valid.config_version, 1)
        self.assertFalse(AuditEvent.objects.filter(action="credentials.rotated").exists())

    def test_unknown_versioned_key_and_invalid_keyring_fail_closed(self):
        unavailable = b"mgk1:retired:" + Fernet(self.old_key).encrypt(b"synthetic")
        with override_settings(MAILGATE_MASTER_KEY="", MAILGATE_MASTER_KEYRING=self.keyring):
            with self.assertRaisesRegex(CredentialDecryptionError, "unavailable key ID"):
                decrypt_secret(unavailable)

        duplicate = (
            '{"version":1,"primary":"one","keys":{"one":"'
            + self.old_key.decode("ascii")
            + '","one":"'
            + self.new_key.decode("ascii")
            + '"}}'
        )
        with override_settings(MAILGATE_MASTER_KEY="", MAILGATE_MASTER_KEYRING=duplicate):
            with self.assertRaisesRegex(ConfigurationError, "Duplicate keyring field"):
                encrypt_secret("synthetic")


class RetentionTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.mailbox = Mailbox.objects.create(
            name="Synthetic",
            host="imap.example.test",
            username="owner@example.test",
            password_encrypted=encrypt_secret("synthetic"),
            uid_validity=77,
            last_uid=900,
        )
        self.policy = RetentionPolicy(
            approved_days=90,
            quarantined_days=30,
            rejected_days=60,
            token_days=10,
            audit_days=120,
        )

    def message(self, *, uid: int, state: str, age_days: int) -> Message:
        item = Message.objects.create(
            mailbox=self.mailbox,
            uid_validity=77,
            uid=uid,
            state=state,
            subject=f"Synthetic {uid}",
        )
        Message.objects.filter(pk=item.pk).update(
            ingested_at=self.now - timedelta(days=age_days),
            decided_at=self.now - timedelta(days=age_days),
        )
        item.refresh_from_db()
        return item

    def test_dry_run_and_apply_use_independent_periods_and_keep_imap_cursor(self):
        approved_kept = self.message(uid=1, state=Message.State.APPROVED, age_days=45)
        approved_purged = self.message(uid=2, state=Message.State.APPROVED, age_days=100)
        quarantined_purged = self.message(uid=3, state=Message.State.QUARANTINED, age_days=45)
        rejected_kept = self.message(uid=4, state=Message.State.REJECTED, age_days=45)
        self.message(uid=5, state=Message.State.REJECTED, age_days=70)
        attachment = Attachment.objects.create(
            message=quarantined_purged,
            filename="synthetic.txt",
            content_type="text/plain",
            size=9,
            sha256="a" * 64,
        )

        active, _ = ApiToken.issue(name="active", expires_at=None)
        expired, _ = ApiToken.issue(name="expired", expires_at=self.now - timedelta(days=20))
        revoked, _ = ApiToken.issue(name="revoked", expires_at=None)
        revoked.revoked_at = self.now - timedelta(days=20)
        revoked.save(update_fields=("revoked_at",))
        recently_revoked, _ = ApiToken.issue(
            name="recently-revoked", expires_at=self.now - timedelta(days=20)
        )
        recently_revoked.revoked_at = self.now - timedelta(days=2)
        recently_revoked.save(update_fields=("revoked_at",))

        old_event = AuditEvent.objects.create(actor="test", action="old")
        AuditEvent.objects.filter(pk=old_event.pk).update(created_at=self.now - timedelta(days=130))
        recent_event = AuditEvent.objects.create(actor="test", action="recent")

        dry_output = io.StringIO()
        call_command(
            "purge_retention",
            approved_days=90,
            quarantined_days=30,
            rejected_days=60,
            token_days=10,
            audit_days=120,
            stdout=dry_output,
        )
        dry_result = json.loads(dry_output.getvalue())
        self.assertEqual(dry_result["mode"], "dry-run")
        self.assertEqual(dry_result["counts"]["approved_messages"], 1)
        self.assertEqual(dry_result["counts"]["quarantined_messages"], 1)
        self.assertEqual(dry_result["counts"]["rejected_messages"], 1)
        self.assertEqual(dry_result["counts"]["inactive_tokens"], 2)
        self.assertEqual(dry_result["counts"]["audit_events"], 1)
        self.assertTrue(Message.objects.filter(pk=approved_purged.pk).exists())

        apply_output = io.StringIO()
        call_command(
            "purge_retention",
            approved_days=90,
            quarantined_days=30,
            rejected_days=60,
            token_days=10,
            audit_days=120,
            batch_size=1,
            apply=True,
            stdout=apply_output,
        )
        self.assertEqual(json.loads(apply_output.getvalue())["mode"], "applied")
        self.assertEqual(
            set(Message.objects.values_list("pk", flat=True)),
            {approved_kept.pk, rejected_kept.pk},
        )
        self.assertFalse(Attachment.objects.filter(pk=attachment.pk).exists())
        self.assertEqual(
            set(ApiToken.objects.values_list("pk", flat=True)),
            {active.pk, recently_revoked.pk},
        )
        self.assertFalse(AuditEvent.objects.filter(pk=old_event.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(pk=recent_event.pk).exists())
        purge_event = AuditEvent.objects.get(action="retention.purged")
        self.assertEqual(purge_event.metadata["counts"]["inactive_tokens"], 2)
        self.mailbox.refresh_from_db()
        self.assertEqual((self.mailbox.uid_validity, self.mailbox.last_uid), (77, 900))

    def test_invalid_policy_and_batch_size_are_rejected_without_deletion(self):
        item = self.message(uid=1, state=Message.State.QUARANTINED, age_days=100)
        with self.assertRaises(CommandError):
            call_command("purge_retention", quarantined_days=-1, apply=True)
        with self.assertRaises(CommandError):
            call_command("purge_retention", batch_size=0, apply=True)
        self.assertTrue(Message.objects.filter(pk=item.pk).exists())

    def test_apply_rolls_back_all_batches_when_a_later_category_fails(self):
        approved = self.message(uid=1, state=Message.State.APPROVED, age_days=100)
        quarantined = self.message(uid=2, state=Message.State.QUARANTINED, age_days=40)
        original_delete = lifecycle._delete_queryset_in_batches
        calls = 0

        def fail_after_first_category(queryset, *, batch_size):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("synthetic retention failure")
            return original_delete(queryset, batch_size=batch_size)

        with (
            patch(
                "gateway.lifecycle._delete_queryset_in_batches",
                side_effect=fail_after_first_category,
            ),
            self.assertRaisesRegex(RuntimeError, "synthetic retention failure"),
        ):
            call_command(
                "purge_retention",
                approved_days=90,
                quarantined_days=30,
                rejected_days=60,
                token_days=10,
                audit_days=120,
                apply=True,
                stdout=io.StringIO(),
            )

        self.assertTrue(Message.objects.filter(pk=approved.pk).exists())
        self.assertTrue(Message.objects.filter(pk=quarantined.pk).exists())
        self.assertFalse(AuditEvent.objects.filter(action="retention.purged").exists())


class OwnerExportTests(TestCase):
    def setUp(self):
        self.synthetic_owner_value = "synthetic-owner-password"
        self.owner = get_user_model().objects.create_user(
            username="owner",
            email="owner@example.test",
            password=self.synthetic_owner_value,
        )
        self.synthetic_mailbox_value = "synthetic-mailbox-credential"
        self.mailbox = Mailbox.objects.create(
            name="Synthetic",
            host="imap.example.test",
            username="owner@example.test",
            password_encrypted=encrypt_secret(self.synthetic_mailbox_value),
        )
        self.message = Message.objects.create(
            mailbox=self.mailbox,
            uid_validity=1,
            uid=1,
            sender="sender@example.test",
            recipients=["owner@example.test"],
            subject="Synthetic export",
            sanitized_text="Safe exported text",
            state=Message.State.APPROVED,
        )
        Attachment.objects.create(
            message=self.message,
            filename="synthetic.txt",
            content_type="text/plain",
            size=10,
            sha256="b" * 64,
        )
        self.token, self.raw_token = ApiToken.issue(name="Hermes", expires_at=None)
        AuditEvent.objects.create(
            actor="test",
            action="synthetic",
            metadata={"password": "must-not-be-exported"},
        )

    def test_stdout_export_is_versioned_complete_and_omits_secret_material(self):
        output = io.StringIO()
        call_command("export_owner_data", output="-", stdout=output)
        serialized = output.getvalue()
        records = [json.loads(line) for line in serialized.splitlines()]

        self.assertEqual(records[0]["schema"], "mailgate.owner.ndjson")
        self.assertEqual(records[0]["version"], 1)
        self.assertEqual(
            {record["type"] for record in records},
            {"manifest", "owner", "mailbox", "message", "attachment", "api_token", "audit_event"},
        )
        self.assertIn("Safe exported text", serialized)
        mailbox_record = next(record for record in records if record["type"] == "mailbox")
        self.assertEqual(mailbox_record["provider_key"], "generic_imaps")
        self.assertEqual(mailbox_record["preset_version"], 1)
        self.assertNotIn(self.synthetic_owner_value, serialized)
        self.assertNotIn(self.synthetic_mailbox_value, serialized)
        self.assertNotIn(self.raw_token, serialized)
        self.assertNotIn(self.token.token_hash, serialized)
        self.assertNotIn("must-not-be-exported", serialized)
        for record in records:
            self.assertNotIn("password", record)
            self.assertNotIn("password_encrypted", record)
            self.assertNotIn("token_hash", record)
            if record["type"] == "audit_event":
                self.assertNotIn("metadata", record)

    def test_file_export_is_private_atomic_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "owner.ndjson"
            call_command("export_owner_data", output=str(target), stdout=io.StringIO())
            self.assertTrue(target.is_file())
            records = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(records[0]["version"], 1)
            if os.name != "nt":
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            original = target.read_bytes()
            with self.assertRaisesRegex(CommandError, "overwrite"):
                call_command("export_owner_data", output=str(target), stdout=io.StringIO())
            self.assertEqual(target.read_bytes(), original)
