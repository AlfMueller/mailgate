# SPDX-License-Identifier: AGPL-3.0-only

from django.db import migrations, models

AUTH_METHODS = ("spf", "dkim", "dmarc", "arc")


def migrate_authentication_schema(apps, schema_editor):
    Message = apps.get_model("gateway", "Message")
    pending = []
    for message in Message.objects.all().only("id", "authentication").iterator(chunk_size=500):
        current = message.authentication or {}
        if not isinstance(current, dict):
            current = {}
        if current.get("schema_version") == 1:
            continue
        claims = {method: current.get(method, "unknown") for method in AUTH_METHODS}
        claims["authserv_id"] = current.get("authserv_id", "")
        message.authentication = {
            "schema_version": 1,
            "provider_claims": claims,
            "independent": {"dkim": {"result": "none", "signatures": []}},
        }
        pending.append(message)
        if len(pending) == 500:
            Message.objects.bulk_update(pending, ("authentication",), batch_size=500)
            pending.clear()
    if pending:
        Message.objects.bulk_update(pending, ("authentication",), batch_size=500)


def restore_flat_authentication(apps, schema_editor):
    Message = apps.get_model("gateway", "Message")
    pending = []
    for message in Message.objects.all().only("id", "authentication").iterator(chunk_size=500):
        current = message.authentication or {}
        if not isinstance(current, dict):
            current = {}
        if current.get("schema_version") != 1:
            continue
        claims = current.get("provider_claims", {})
        message.authentication = {method: claims.get(method, "unknown") for method in AUTH_METHODS}
        pending.append(message)
        if len(pending) == 500:
            Message.objects.bulk_update(pending, ("authentication",), batch_size=500)
            pending.clear()
    if pending:
        Message.objects.bulk_update(pending, ("authentication",), batch_size=500)


def update_mailbox_version_trigger(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute(
        """
        CREATE OR REPLACE FUNCTION public.mailgate_bump_mailbox_config_version()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $$
        BEGIN
            IF ROW(
                NEW.provider_key,
                NEW.preset_version,
                NEW.host,
                NEW.port,
                NEW.username,
                NEW.password_encrypted,
                NEW.trusted_authserv_ids,
                NEW.enabled
            ) IS DISTINCT FROM ROW(
                OLD.provider_key,
                OLD.preset_version,
                OLD.host,
                OLD.port,
                OLD.username,
                OLD.password_encrypted,
                OLD.trusted_authserv_ids,
                OLD.enabled
            ) THEN
                NEW.config_version := OLD.config_version + 1;
            ELSE
                NEW.config_version := OLD.config_version;
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    )


def restore_mailbox_version_trigger(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute(
        """
        CREATE OR REPLACE FUNCTION public.mailgate_bump_mailbox_config_version()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $$
        BEGIN
            IF ROW(
                NEW.host,
                NEW.port,
                NEW.username,
                NEW.password_encrypted,
                NEW.trusted_authserv_ids,
                NEW.enabled
            ) IS DISTINCT FROM ROW(
                OLD.host,
                OLD.port,
                OLD.username,
                OLD.password_encrypted,
                OLD.trusted_authserv_ids,
                OLD.enabled
            ) THEN
                NEW.config_version := OLD.config_version + 1;
            ELSE
                NEW.config_version := OLD.config_version;
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    )


class Migration(migrations.Migration):
    dependencies = [("gateway", "0004_api_boundary_and_mailbox_version")]

    operations = [
        migrations.AddField(
            model_name="mailbox",
            name="provider_key",
            field=models.CharField(
                choices=[("generic_imaps", "Generic IMAPS"), ("hostpoint", "Hostpoint")],
                default="generic_imaps",
                max_length=32,
            ),
        ),
        migrations.AddField(
            model_name="mailbox",
            name="preset_version",
            field=models.PositiveSmallIntegerField(default=1, editable=False),
        ),
        migrations.RunPython(migrate_authentication_schema, restore_flat_authentication),
        migrations.RunPython(update_mailbox_version_trigger, restore_mailbox_version_trigger),
    ]
