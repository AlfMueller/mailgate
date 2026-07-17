# SPDX-License-Identifier: AGPL-3.0-only
"""Destructive-only-to-synthetic PostgreSQL integration checks for the CI profile."""

from __future__ import annotations

import os
import threading
import time
import uuid
from pathlib import Path

import psycopg
from psycopg.errors import InsufficientPrivilege


def connection():
    return psycopg.connect(
        host=os.environ["PGHOST"],
        dbname=os.environ["PGDATABASE"],
        user=os.environ["PGUSER"],
        password=Path(os.environ["PGPASSWORD_FILE"]).read_text(encoding="utf-8").strip(),
    )


def create_mailbox(database, name: str) -> int:
    with database.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO gateway_mailbox
              (name, host, port, username, password_encrypted, trusted_authserv_ids,
               enabled, last_uid, last_error_code, config_version, created_at, updated_at)
            VALUES
              (%s, 'imap.example.test', 993, 'owner@example.test', decode('00','hex'),
               '', true, 0, '', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING id
            """,
            [name],
        )
        return cursor.fetchone()[0]


def set_role(database, role: str) -> None:
    with database.cursor() as cursor:
        cursor.execute(f"SET ROLE {role}")  # noqa: S608 -- role is a fixed test constant.


def assert_worker_cannot_change_message(message_id) -> None:
    for statement in (
        "UPDATE gateway_message SET state='approved' WHERE id=%s",
        "DELETE FROM gateway_message WHERE id=%s",
    ):
        with connection() as worker:
            set_role(worker, "mailgate_worker")
            try:
                with worker.cursor() as cursor:
                    cursor.execute(statement, [message_id])
            except InsufficientPrivilege:
                worker.rollback()
            else:
                raise AssertionError("worker unexpectedly changed an existing message")


def main() -> None:
    marker = uuid.uuid4().hex
    mailbox_ids: list[int] = []
    with connection() as admin:
        try:
            # Configuration commits first: every old-version worker status write must lose.
            first_id = create_mailbox(admin, f"race-config-first-{marker}")
            mailbox_ids.append(first_id)
            admin.commit()
            with admin.cursor() as cursor:
                cursor.execute(
                    "UPDATE gateway_mailbox SET password_encrypted=decode('01','hex') WHERE id=%s",
                    [first_id],
                )
            admin.commit()
            with connection() as worker:
                set_role(worker, "mailgate_worker")
                with worker.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE gateway_mailbox SET last_error_code='stale'
                         WHERE id=%s AND enabled=true AND config_version=1
                        """,
                        [first_id],
                    )
                    assert cursor.rowcount == 0

            # Worker row lock commits first: the configuration edit must wait, then bump.
            second_id = create_mailbox(admin, f"race-worker-first-{marker}")
            mailbox_ids.append(second_id)
            admin.commit()
            worker = connection()
            set_role(worker, "mailgate_worker")
            locked = worker.execute(
                """
                SELECT id FROM gateway_mailbox
                 WHERE id=%s AND enabled=true AND config_version=1
                 FOR UPDATE
                """,
                [second_id],
            ).fetchone()
            assert locked == (second_id,)

            edit_started = threading.Event()
            edit_finished = threading.Event()
            edit_errors: list[BaseException] = []

            def edit_configuration() -> None:
                try:
                    with connection() as web:
                        set_role(web, "mailgate_web")
                        edit_started.set()
                        web.execute(
                            """
                            UPDATE gateway_mailbox
                               SET password_encrypted=decode('02','hex')
                             WHERE id=%s
                            """,
                            [second_id],
                        )
                except BaseException as exc:  # pragma: no cover - reported in parent thread
                    edit_errors.append(exc)
                finally:
                    edit_finished.set()

            thread = threading.Thread(target=edit_configuration, daemon=True)
            thread.start()
            assert edit_started.wait(2)
            time.sleep(0.2)
            assert not edit_finished.is_set(), "configuration edit did not wait for worker lock"
            result = worker.execute(
                """
                UPDATE gateway_mailbox SET last_uid=1
                 WHERE id=%s AND enabled=true AND config_version=1
                """,
                [second_id],
            )
            assert result.rowcount == 1
            worker.commit()
            worker.close()
            assert edit_finished.wait(5)
            thread.join(timeout=1)
            if edit_errors:
                raise edit_errors[0]
            version = admin.execute(
                "SELECT config_version FROM gateway_mailbox WHERE id=%s", [second_id]
            ).fetchone()[0]
            assert version == 2

            # The real worker role's insert trigger must force quarantine and medium risk.
            message_id = uuid.uuid4()
            with connection() as worker:
                set_role(worker, "mailgate_worker")
                state, risk = worker.execute(
                    """
                    INSERT INTO gateway_message
                      (id, mailbox_id, uid_validity, uid, message_id_hash, sender,
                       sender_name, recipients, subject, sanitized_text, links,
                       authentication, signals, risk, category, priority, summary,
                       state, ingested_at, decided_at)
                    VALUES
                      (%s, %s, 1, 1, '', '', '', '[]'::jsonb, 'synthetic', '',
                       '[]'::jsonb, '{}'::jsonb, '[]'::jsonb, 'low', 'test', 3, '',
                       'approved', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    RETURNING state, risk
                    """,
                    [message_id, second_id],
                ).fetchone()
                assert (state, risk) == ("quarantined", "medium")
            assert_worker_cannot_change_message(message_id)
        finally:
            admin.rollback()
            with admin.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM gateway_message WHERE mailbox_id = ANY(%s)", [mailbox_ids]
                )
                cursor.execute("DELETE FROM gateway_mailbox WHERE id = ANY(%s)", [mailbox_ids])
            admin.commit()

    print("POSTGRES_BOUNDARIES_OK")


if __name__ == "__main__":
    main()
