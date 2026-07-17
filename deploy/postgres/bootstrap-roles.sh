#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

psql --set=ON_ERROR_STOP=1 \
  --set=db_name="$POSTGRES_DB" \
  --set=migrate_password="$(cat /run/secrets/postgres_migrate_password)" \
  --set=web_password="$(cat /run/secrets/postgres_web_password)" \
  --set=worker_password="$(cat /run/secrets/postgres_worker_password)" \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
SELECT 'CREATE ROLE mailgate_migrate LOGIN' WHERE NOT EXISTS
  (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mailgate_migrate')\gexec
SELECT 'CREATE ROLE mailgate_web LOGIN' WHERE NOT EXISTS
  (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mailgate_web')\gexec
SELECT 'CREATE ROLE mailgate_worker LOGIN' WHERE NOT EXISTS
  (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mailgate_worker')\gexec

ALTER ROLE mailgate_migrate WITH PASSWORD :'migrate_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
ALTER ROLE mailgate_web WITH PASSWORD :'web_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
ALTER ROLE mailgate_worker WITH PASSWORD :'worker_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

GRANT CONNECT ON DATABASE :"db_name" TO mailgate_migrate, mailgate_web, mailgate_worker;
GRANT USAGE, CREATE ON SCHEMA public TO mailgate_migrate;
GRANT USAGE ON SCHEMA public TO mailgate_web, mailgate_worker;

ALTER DEFAULT PRIVILEGES FOR ROLE mailgate_migrate IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO mailgate_web;
ALTER DEFAULT PRIVILEGES FOR ROLE mailgate_migrate IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO mailgate_web;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO mailgate_web;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mailgate_web;
SQL
