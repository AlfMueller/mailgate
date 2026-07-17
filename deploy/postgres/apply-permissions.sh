#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
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
SQL
