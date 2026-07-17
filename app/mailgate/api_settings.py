# SPDX-License-Identifier: AGPL-3.0-only

import os
from pathlib import Path

from mailgate.config import ConfigurationError, get_list, get_secret

BASE_DIR = Path(__file__).resolve().parents[2]
ENVIRONMENT = os.getenv("MAILGATE_ENVIRONMENT", "production").strip().lower()
SECRET_KEY = get_secret("MAILGATE_SECRET_KEY", minimum_length=50)
DEBUG = False
ALLOWED_HOSTS = get_list("MAILGATE_ALLOWED_HOSTS", default=("localhost", "127.0.0.1", "[::1]"))

INSTALLED_APPS = ["gateway"]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "mailgate.middleware.SecurityHeadersMiddleware",
]
ROOT_URLCONF = "mailgate.api_urls"
TEMPLATES = []
WSGI_APPLICATION = "mailgate.api_wsgi.application"

database_engine = os.getenv("MAILGATE_DATABASE_ENGINE", "postgresql").strip().lower()
if database_engine == "sqlite":
    if ENVIRONMENT != "test":
        raise ConfigurationError("The API process permits SQLite only in tests")
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": os.getenv("MAILGATE_SQLITE_PATH", ":memory:"),
        }
    }
elif database_engine == "postgresql":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "HOST": os.getenv("MAILGATE_DATABASE_HOST", "db"),
            "PORT": os.getenv("MAILGATE_DATABASE_PORT", "5432"),
            "NAME": os.getenv("MAILGATE_DATABASE_NAME", "mailgate"),
            "USER": os.getenv("MAILGATE_DATABASE_USER", "mailgate_api"),
            "PASSWORD": get_secret("MAILGATE_DATABASE_PASSWORD", minimum_length=16),
            "CONN_MAX_AGE": 60,
            "CONN_HEALTH_CHECKS": True,
        }
    }
else:
    raise ConfigurationError("MAILGATE_DATABASE_ENGINE must be postgresql or sqlite")

LANGUAGE_CODE = "en"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "no-referrer"
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
X_FRAME_OPTIONS = "DENY"

if ENVIRONMENT not in {"development", "test", "production"}:
    raise ConfigurationError("MAILGATE_ENVIRONMENT must be development, test, or production")
if ENVIRONMENT == "production" and any(host == "*" for host in ALLOWED_HOSTS):
    raise ConfigurationError("Wildcard hosts are forbidden in production")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "mailgate": {
            "format": "{asctime} {levelname} {name}: {message}",
            "style": "{",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "mailgate",
        }
    },
    "root": {"handlers": ["console"], "level": "INFO"},
}

# Explicitly unused in this process. Reading these secrets here would break the
# API/owner trust boundary.
MAILGATE_API_PROCESS = True
