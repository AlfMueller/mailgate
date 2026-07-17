# SPDX-License-Identifier: AGPL-3.0-only

import argparse
import logging
import os
import signal
import threading

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mailgate.settings")

import django  # noqa: E402
from django.conf import settings  # noqa: E402
from django.db import DatabaseError, close_old_connections, connection  # noqa: E402

logger = logging.getLogger("mailgate.worker")
stop_event = threading.Event()


def check_database() -> bool:
    close_old_connections()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except DatabaseError:
        logger.error("Worker database check failed")
        return False
    return True


def request_stop(_signum, _frame) -> None:
    stop_event.set()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the MailGate read-only ingestion worker")
    parser.add_argument(
        "--check-once",
        action="store_true",
        help="check database readiness once and exit",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    django.setup()
    from gateway.ingestion import sync_all_mailboxes

    if args.check_once:
        return 0 if check_database() else 1
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    logger.info("MailGate read-only ingestion worker started")
    while not stop_event.is_set():
        if check_database():
            processed, errors = sync_all_mailboxes()
            logger.info("Mailbox sync cycle complete processed=%s errors=%s", processed, errors)
        stop_event.wait(settings.MAILGATE_WORKER_POLL_INTERVAL_SECONDS)
    logger.info("MailGate worker stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
