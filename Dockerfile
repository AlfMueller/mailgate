# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS caddy-builder

ENV CGO_ENABLED=0

RUN GOBIN=/out go install github.com/caddyserver/caddy/v2/cmd/caddy@v2.11.4 \
    && test -x /out/caddy

FROM python:3.14.6-slim-bookworm@sha256:86f975aca15cf04a40b399eebede9aea7c82eae084d1f1a0a6ef6bcaae871a30

ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/mailgate/app:/opt/mailgate/worker \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid "${APP_GID}" mailgate \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --no-create-home --shell /usr/sbin/nologin mailgate \
    && mkdir -p /config /data /etc/caddy \
    && chown "${APP_UID}:${APP_GID}" /config /data

WORKDIR /opt/mailgate

COPY requirements.lock ./requirements.lock
RUN python -m pip install --require-hashes --requirement requirements.lock

COPY app ./app
COPY worker ./worker
COPY LICENSE README.md ./
COPY --from=caddy-builder /out/caddy /usr/local/bin/caddy

RUN export MAILGATE_ENVIRONMENT=test \
    MAILGATE_DATABASE_ENGINE=sqlite \
    MAILGATE_SECRET_KEY=test-only-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
    MAILGATE_MASTER_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
    && python app/compile_translations.py \
    && python app/manage.py collectstatic --noinput

USER mailgate:mailgate

EXPOSE 80 443 8000 8080

CMD ["gunicorn", "--bind=0.0.0.0:8000", "--workers=2", "--threads=2", "--no-control-socket", "--limit-request-line=2048", "--limit-request-fields=50", "--limit-request-field_size=4096", "--header-map=refuse", "--access-logfile=-", "--access-logformat=%(h)s %(t)s \"%(m)s %(U)s %(H)s\" %(s)s %(b)s", "--error-logfile=-", "mailgate.wsgi:application"]
