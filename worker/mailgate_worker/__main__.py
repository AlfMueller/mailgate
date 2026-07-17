# SPDX-License-Identifier: AGPL-3.0-only

import argparse
import logging
import os
import signal
import threading

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mailgate.settings")

import django  # noqa: E402
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
    parser = argparse.ArgumentParser(description="Run the MailGate worker foundation")
    parser.add_argument(
        "--check-once",
        action="store_true",
        help="check database readiness once and exit",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=30.0,
        help="seconds between foundation readiness checks",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    django.setup()

    if args.check_once:
        return 0 if check_database() else 1
    if args.poll_interval < 1:
        raise SystemExit("--poll-interval must be at least 1 second")

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    logger.info("MailGate worker foundation started; mail ingestion is not enabled")
    while not stop_event.is_set():
        check_database()
        stop_event.wait(args.poll_interval)
    logger.info("MailGate worker stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
