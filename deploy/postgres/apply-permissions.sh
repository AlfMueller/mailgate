#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM mailgate_api;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM mailgate_api;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM mailgate_api;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

GRANT SELECT ON mailgate_api_approved_message TO mailgate_api;
GRANT EXECUTE ON FUNCTION mailgate_api_authorize(text, text) TO mailgate_api;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM mailgate_worker;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM mailgate_worker;

GRANT SELECT ON gateway_mailbox TO mailgate_worker;
GRANT UPDATE (uid_validity, last_uid, last_sync_at, last_error_code, updated_at)
  ON gateway_mailbox TO mailgate_worker;
GRANT SELECT, INSERT ON gateway_message TO mailgate_worker;
GRANT SELECT, INSERT ON gateway_attachment TO mailgate_worker;
GRANT INSERT ON gateway_auditevent TO mailgate_worker;
-- Django uses INSERT ... RETURNING id for AutoField models. PostgreSQL requires
-- SELECT on the returned column even though the worker never reads audit rows.
GRANT SELECT (id) ON gateway_auditevent TO mailgate_worker;
GRANT USAGE, SELECT ON gateway_attachment_id_seq, gateway_auditevent_id_seq
  TO mailgate_worker;

DO $$
BEGIN
  IF has_table_privilege('mailgate_api', 'gateway_message', 'SELECT')
     OR has_table_privilege('mailgate_api', 'gateway_mailbox', 'SELECT')
     OR has_table_privilege('mailgate_api', 'gateway_attachment', 'SELECT')
     OR has_table_privilege('mailgate_api', 'gateway_apitoken', 'SELECT')
     OR has_table_privilege('mailgate_api', 'gateway_auditevent', 'SELECT') THEN
    RAISE EXCEPTION 'mailgate_api has forbidden base-table access';
  END IF;
  IF NOT has_table_privilege(
      'mailgate_api', 'mailgate_api_approved_message', 'SELECT'
  ) THEN
    RAISE EXCEPTION 'mailgate_api cannot read approved-only view';
  END IF;
  IF NOT has_function_privilege(
      'mailgate_api', 'mailgate_api_authorize(text,text)', 'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'mailgate_api cannot execute authorization function';
  END IF;
  IF has_function_privilege(
      'mailgate_worker', 'mailgate_api_authorize(text,text)', 'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'authorization function leaked outside the API role';
  END IF;
  IF has_function_privilege(
      'mailgate_api', 'mailgate_force_worker_quarantine()', 'EXECUTE'
  ) OR has_function_privilege(
      'mailgate_api', 'mailgate_bump_mailbox_config_version()', 'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'mailgate_api can execute an unapproved function';
  END IF;
  IF has_table_privilege('mailgate_worker', 'gateway_apitoken', 'SELECT')
     OR has_table_privilege('mailgate_worker', 'auth_user', 'SELECT') THEN
    RAISE EXCEPTION 'mailgate_worker has forbidden credential access';
  END IF;
END;
$$;

-- Fail the one-shot permissions job if the least-privilege audit grant is not
-- sufficient for Django's INSERT ... RETURNING behavior. The row is rolled back.
BEGIN;
SET LOCAL ROLE mailgate_worker;
INSERT INTO gateway_auditevent
  (actor, action, object_type, object_id, metadata, created_at)
VALUES
  ('permission-check', 'permission-check', '', '', '{}'::jsonb, CURRENT_TIMESTAMP)
RETURNING id;
ROLLBACK;

BEGIN;
INSERT INTO gateway_mailbox
  (name, provider_key, preset_version, host, port, username, password_encrypted,
   trusted_authserv_ids, enabled, last_uid, last_error_code, config_version,
   created_at, updated_at)
VALUES
  ('permission-check-worker-role', 'generic_imaps', 1, 'imap.example.test', 993,
   'owner@example.test', decode('00', 'hex'), '', true, 0, '', 1,
   CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
SET LOCAL ROLE mailgate_worker;
UPDATE gateway_mailbox
   SET last_uid = 1
 WHERE name = 'permission-check-worker-role';
SELECT 1 / CASE WHEN config_version = 1 THEN 1 ELSE 0 END
  FROM gateway_mailbox
 WHERE name = 'permission-check-worker-role';
ROLLBACK;

BEGIN;
SET LOCAL ROLE mailgate_api;
SELECT count(*) FROM mailgate_api_approved_message;
SELECT status FROM mailgate_api_authorize(repeat('0', 64), '/permission-check');
ROLLBACK;

-- Exercise the real PostgreSQL authorization function, including expiry,
-- revocation, fixed scope, rate limiting, last-use update, and minimal audit.
BEGIN;
INSERT INTO gateway_apitoken
  (name, prefix, token_hash, scope, created_at, expires_at, last_used_at, revoked_at)
VALUES
  ('permission-valid', 'validcheck', repeat('a', 64), 'messages:read:approved',
   CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + interval '1 day', NULL, NULL),
  ('permission-expired', 'expiredcheck', repeat('b', 64), 'messages:read:approved',
   CURRENT_TIMESTAMP, CURRENT_TIMESTAMP - interval '1 day', NULL, NULL),
  ('permission-revoked', 'revokedcheck', repeat('c', 64), 'messages:read:approved',
   CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + interval '1 day', NULL, CURRENT_TIMESTAMP),
  ('permission-rate', 'ratecheck', repeat('d', 64), 'messages:read:approved',
   CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + interval '1 day', NULL, NULL),
  ('permission-scope', 'scopecheck', repeat('e', 64), 'forbidden',
   CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + interval '1 day', NULL, NULL);
INSERT INTO gateway_auditevent
  (actor, action, object_type, object_id, metadata, created_at)
SELECT 'token:ratecheck', 'api.read', '', '', '{}'::jsonb, CURRENT_TIMESTAMP
  FROM generate_series(1, 60);

SET LOCAL ROLE mailgate_api;
SELECT 1 / CASE WHEN status = 'authorized' THEN 1 ELSE 0 END
  FROM mailgate_api_authorize(repeat('a', 64), '/api/v1/messages');
SELECT 1 / CASE WHEN status = 'unauthorized' THEN 1 ELSE 0 END
  FROM mailgate_api_authorize(repeat('b', 64), '/api/v1/messages');
SELECT 1 / CASE WHEN status = 'unauthorized' THEN 1 ELSE 0 END
  FROM mailgate_api_authorize(repeat('c', 64), '/api/v1/messages');
SELECT 1 / CASE WHEN status = 'rate_limited' THEN 1 ELSE 0 END
  FROM mailgate_api_authorize(repeat('d', 64), '/api/v1/messages');
SELECT 1 / CASE WHEN status = 'unauthorized' THEN 1 ELSE 0 END
  FROM mailgate_api_authorize(repeat('e', 64), '/api/v1/messages');
RESET ROLE;

DO $$
BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM gateway_apitoken
       WHERE prefix = 'validcheck' AND last_used_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'authorization did not update last_used_at';
  END IF;
  IF 1 <> (
      SELECT count(*) FROM gateway_auditevent
       WHERE actor = 'token:validcheck'
         AND action = 'api.read'
         AND metadata = '{"path": "/api/v1/messages"}'::jsonb
  ) THEN
    RAISE EXCEPTION 'authorization audit is missing or not content-minimal';
  END IF;
END;
$$;
ROLLBACK;

-- Prove that security-relevant mailbox edits advance the persisted version,
-- while ordinary worker cursor/status updates do not. Synthetic row is rolled back.
BEGIN;
DO $$
DECLARE
  v_id bigint;
  v_version bigint;
BEGIN
  INSERT INTO gateway_mailbox
    (name, provider_key, preset_version, host, port, username, password_encrypted,
     trusted_authserv_ids, enabled, last_uid, last_error_code, config_version,
     created_at, updated_at)
  VALUES
    ('permission-check', 'generic_imaps', 1, 'imap.example.test', 993,
     'owner@example.test', decode('00', 'hex'), '', true, 0, '', 1,
     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  RETURNING id INTO v_id;

  UPDATE gateway_mailbox SET last_uid = 1 WHERE id = v_id
  RETURNING config_version INTO v_version;
  IF v_version <> 1 THEN
    RAISE EXCEPTION 'worker status update unexpectedly advanced config_version';
  END IF;

  UPDATE gateway_mailbox SET enabled = false WHERE id = v_id
  RETURNING config_version INTO v_version;
  IF v_version <> 2 THEN
    RAISE EXCEPTION 'security edit did not advance config_version';
  END IF;
END;
$$;
ROLLBACK;
SQL
