# SPDX-License-Identifier: AGPL-3.0-only

import os

os.environ.setdefault("MAILGATE_ENVIRONMENT", "test")
os.environ.setdefault("MAILGATE_DATABASE_ENGINE", "sqlite")
if "MAILGATE_SECRET_KEY" not in os.environ and "MAILGATE_SECRET_KEY_FILE" not in os.environ:
    os.environ["MAILGATE_SECRET_KEY"] = "test-only-" + ("x" * 64)
os.environ.setdefault("MAILGATE_ALLOWED_HOSTS", "testserver,localhost")

from mailgate.settings import *  # noqa: F403,E402

DATABASES["default"]["NAME"] = ":memory:"  # noqa: F405
