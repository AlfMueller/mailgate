# SPDX-License-Identifier: AGPL-3.0-only

import os
from pathlib import Path

from mailgate.config import ConfigurationError, get_bool, get_list, get_secret

BASE_DIR = Path(__file__).resolve().parents[2]

ENVIRONMENT = os.getenv("MAILGATE_ENVIRONMENT", "production").strip().lower()
SECRET_KEY = get_secret("MAILGATE_SECRET_KEY", minimum_length=50)
DEBUG = get_bool("MAILGATE_DEBUG", default=False)
ALLOWED_HOSTS = get_list("MAILGATE_ALLOWED_HOSTS", default=("localhost", "127.0.0.1", "[::1]"))
CSRF_TRUSTED_ORIGINS = get_list("MAILGATE_CSRF_TRUSTED_ORIGINS")

INSTALLED_APPS = [
    "gateway",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "mailgate.middleware.LocalNullOriginMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "mailgate.middleware.SecurityHeadersMiddleware",
]

ROOT_URLCONF = "mailgate.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "app" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    }
]
WSGI_APPLICATION = "mailgate.wsgi.application"
ASGI_APPLICATION = "mailgate.asgi.application"

database_engine = os.getenv("MAILGATE_DATABASE_ENGINE", "postgresql").strip().lower()
if database_engine == "sqlite":
    if ENVIRONMENT not in {"development", "test"}:
        raise ConfigurationError("SQLite is allowed only in development or tests")
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": os.getenv("MAILGATE_SQLITE_PATH", str(BASE_DIR / "mailgate.sqlite3")),
        }
    }
elif database_engine == "postgresql":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "HOST": os.getenv("MAILGATE_DATABASE_HOST", "db"),
            "PORT": os.getenv("MAILGATE_DATABASE_PORT", "5432"),
            "NAME": os.getenv("MAILGATE_DATABASE_NAME", "mailgate"),
            "USER": os.getenv("MAILGATE_DATABASE_USER", "mailgate"),
            "PASSWORD": get_secret("MAILGATE_DATABASE_PASSWORD", minimum_length=16),
            "CONN_MAX_AGE": 60,
            "CONN_HEALTH_CHECKS": True,
        }
    }
else:
    raise ConfigurationError("MAILGATE_DATABASE_ENGINE must be postgresql or sqlite")

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = os.getenv("MAILGATE_LANGUAGE_CODE", "en").strip().lower()
LANGUAGES = (("en", "English"), ("de", "Deutsch"))
if LANGUAGE_CODE not in {code for code, _name in LANGUAGES}:
    raise ConfigurationError("MAILGATE_LANGUAGE_CODE must be en or de")
LOCALE_PATHS = [BASE_DIR / "app" / "locale"]
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
LANGUAGE_COOKIE_HTTPONLY = True
LANGUAGE_COOKIE_SAMESITE = "Lax"

try:
    MAILGATE_WORKER_POLL_INTERVAL_SECONDS = float(
        os.getenv("MAILGATE_WORKER_POLL_INTERVAL_SECONDS", "30")
    )
except ValueError as exc:
    raise ConfigurationError("MAILGATE_WORKER_POLL_INTERVAL_SECONDS must be a number") from exc
if not 1 <= MAILGATE_WORKER_POLL_INTERVAL_SECONDS <= 86_400:
    raise ConfigurationError("MAILGATE_WORKER_POLL_INTERVAL_SECONDS must be between 1 and 86400")

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"

MAILGATE_MASTER_KEY = get_secret("MAILGATE_MASTER_KEY", minimum_length=44)
if (
    os.getenv("MAILGATE_SETUP_TOKEN") is not None
    or os.getenv("MAILGATE_SETUP_TOKEN_FILE") is not None
):
    MAILGATE_SETUP_TOKEN = get_secret("MAILGATE_SETUP_TOKEN", minimum_length=32)
else:
    MAILGATE_SETUP_TOKEN = ""

SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "no-referrer"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"
X_FRAME_OPTIONS = "DENY"

HTTPS_ONLY = get_bool("MAILGATE_HTTPS_ONLY", default=False)
SECURE_SSL_REDIRECT = HTTPS_ONLY
SESSION_COOKIE_SECURE = HTTPS_ONLY
CSRF_COOKIE_SECURE = HTTPS_ONLY
LANGUAGE_COOKIE_SECURE = HTTPS_ONLY
SECURE_HSTS_SECONDS = 31_536_000 if HTTPS_ONLY else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = HTTPS_ONLY
SECURE_HSTS_PRELOAD = False

if get_bool("MAILGATE_TRUST_PROXY_HEADERS", default=False):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

if ENVIRONMENT == "production" and not HTTPS_ONLY:
    raise ConfigurationError("MAILGATE_HTTPS_ONLY must be enabled in production")
if ENVIRONMENT == "production" and DEBUG:
    raise ConfigurationError("MAILGATE_DEBUG must be disabled in production")
if ENVIRONMENT == "production" and any(host == "*" for host in ALLOWED_HOSTS):
    raise ConfigurationError("Wildcard hosts are forbidden in production")
if ENVIRONMENT not in {"development", "test", "production"}:
    raise ConfigurationError("MAILGATE_ENVIRONMENT must be development, test, or production")

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
