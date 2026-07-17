# SPDX-License-Identifier: AGPL-3.0-only

import os

os.environ.setdefault("MAILGATE_ENVIRONMENT", "test")
os.environ.setdefault("MAILGATE_DATABASE_ENGINE", "sqlite")
if "MAILGATE_SECRET_KEY" not in os.environ and "MAILGATE_SECRET_KEY_FILE" not in os.environ:
    os.environ["MAILGATE_SECRET_KEY"] = "test-only-" + ("x" * 64)
os.environ.setdefault("MAILGATE_ALLOWED_HOSTS", "testserver,localhost")
if "MAILGATE_MASTER_KEY" not in os.environ and "MAILGATE_MASTER_KEY_FILE" not in os.environ:
    os.environ["MAILGATE_MASTER_KEY"] = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
if "MAILGATE_SETUP_TOKEN" not in os.environ and "MAILGATE_SETUP_TOKEN_FILE" not in os.environ:
    os.environ["MAILGATE_SETUP_TOKEN"] = "synthetic-setup-token-not-a-real-secret"

from mailgate.settings import *  # noqa: F403,E402

DATABASES["default"]["NAME"] = ":memory:"  # noqa: F405
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
STORAGES["staticfiles"] = {  # noqa: F405
    "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"
}
