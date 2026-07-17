# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM python:3.13.14-slim-bookworm@sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64

ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/mailgate/app:/opt/mailgate/worker \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid "${APP_GID}" mailgate \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --no-create-home --shell /usr/sbin/nologin mailgate

WORKDIR /opt/mailgate

COPY requirements.lock ./requirements.lock
RUN python -m pip install --require-hashes --requirement requirements.lock

COPY app ./app
COPY worker ./worker
COPY LICENSE README.md ./

USER mailgate:mailgate

EXPOSE 8000

CMD ["gunicorn", "--bind=0.0.0.0:8000", "--workers=2", "--threads=2", "--no-control-socket", "--limit-request-line=2048", "--limit-request-fields=50", "--limit-request-field_size=4096", "--header-map=refuse", "--access-logfile=-", "--access-logformat=%(h)s %(t)s \"%(m)s %(U)s %(H)s\" %(s)s %(b)s", "--error-logfile=-", "mailgate.wsgi:application"]
