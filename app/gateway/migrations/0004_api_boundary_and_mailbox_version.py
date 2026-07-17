# SPDX-License-Identifier: AGPL-3.0-only
# ruff: noqa: S608 -- the only interpolated identifier is a quoted module constant.

from django.db import migrations, models

VIEW_NAME = "mailgate_api_approved_message"


def create_security_boundaries(apps, schema_editor):
    quoted_view = schema_editor.quote_name(VIEW_NAME)
    view_sql = f"""
        CREATE VIEW {quoted_view} AS
        SELECT
            id,
            sender,
            sender_name,
            subject,
            received_at,
            category,
            priority,
            risk,
            summary,
            sanitized_text,
            links,
            ingested_at
        FROM gateway_message
        WHERE state = 'approved'
        """
    schema_editor.execute(view_sql)
    if schema_editor.connection.vendor != "postgresql":
        return
    schema_editor.execute(
        """
        ALTER VIEW public.mailgate_api_approved_message
          SET (security_barrier = true);

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

        CREATE TRIGGER mailgate_mailbox_config_version
        BEFORE UPDATE ON public.gateway_mailbox
        FOR EACH ROW EXECUTE FUNCTION public.mailgate_bump_mailbox_config_version();

        CREATE OR REPLACE FUNCTION public.mailgate_api_authorize(
            p_token_hash text,
            p_path text
        )
        RETURNS TABLE(status text)
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $$
        DECLARE
            v_prefix text;
            v_now timestamptz := clock_timestamp();
            v_recent integer;
        BEGIN
            IF p_token_hash !~ '^[0-9a-f]{64}$' OR length(p_path) > 2048 THEN
                RETURN QUERY SELECT 'unauthorized'::text;
                RETURN;
            END IF;

            SELECT prefix
              INTO v_prefix
              FROM public.gateway_apitoken
             WHERE token_hash = p_token_hash
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > v_now)
               AND scope = 'messages:read:approved'
             FOR UPDATE;

            IF NOT FOUND THEN
                RETURN QUERY SELECT 'unauthorized'::text;
                RETURN;
            END IF;

            SELECT count(*)
              INTO v_recent
              FROM public.gateway_auditevent
             WHERE actor = 'token:' || v_prefix
               AND action = 'api.read'
               AND created_at >= v_now - interval '1 minute';

            IF v_recent >= 60 THEN
                RETURN QUERY SELECT 'rate_limited'::text;
                RETURN;
            END IF;

            UPDATE public.gateway_apitoken
               SET last_used_at = v_now
             WHERE token_hash = p_token_hash;

            INSERT INTO public.gateway_auditevent
                (actor, action, object_type, object_id, metadata, created_at)
            VALUES
                (
                    'token:' || v_prefix,
                    'api.read',
                    '',
                    '',
                    jsonb_build_object('path', p_path),
                    v_now
                );

            RETURN QUERY SELECT 'authorized'::text;
        END;
        $$;

        REVOKE ALL ON FUNCTION public.mailgate_api_authorize(text, text) FROM PUBLIC;
        """
    )


def drop_security_boundaries(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(
            """
            DROP FUNCTION IF EXISTS public.mailgate_api_authorize(text, text);
            DROP TRIGGER IF EXISTS mailgate_mailbox_config_version
              ON public.gateway_mailbox;
            DROP FUNCTION IF EXISTS public.mailgate_bump_mailbox_config_version();
            """
        )
    schema_editor.execute(f"DROP VIEW IF EXISTS {schema_editor.quote_name(VIEW_NAME)}")


class Migration(migrations.Migration):
    dependencies = [("gateway", "0003_alter_apitoken_expires_at")]

    operations = [
        migrations.AddField(
            model_name="mailbox",
            name="config_version",
            field=models.PositiveBigIntegerField(default=1, editable=False),
        ),
        migrations.CreateModel(
            name="ApprovedMessage",
            fields=[
                ("id", models.UUIDField(primary_key=True, serialize=False)),
                ("sender", models.CharField(max_length=320)),
                ("sender_name", models.CharField(max_length=320)),
                ("subject", models.CharField(max_length=998)),
                ("received_at", models.DateTimeField(null=True)),
                ("category", models.CharField(max_length=80)),
                ("priority", models.PositiveSmallIntegerField()),
                ("risk", models.CharField(max_length=10)),
                ("summary", models.TextField()),
                ("sanitized_text", models.TextField()),
                ("links", models.JSONField()),
                ("ingested_at", models.DateTimeField()),
            ],
            options={
                "db_table": VIEW_NAME,
                "managed": False,
            },
        ),
        migrations.RunPython(create_security_boundaries, drop_security_boundaries),
    ]
