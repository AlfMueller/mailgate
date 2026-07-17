#!/bin/sh
set -eu

host="${MAILGATE_IMAP_ALLOWED_HOST:-}"
case "$host" in
  ""|*[^a-z0-9.-]*|.*|*..*|*.|-*|*-|localhost|*.local)
    echo "MAILGATE_IMAP_ALLOWED_HOST must be one lowercase public DNS hostname" >&2
    exit 1
    ;;
esac

case "$host" in
  *.*) ;;
  *)
    echo "MAILGATE_IMAP_ALLOWED_HOST must contain a dot" >&2
    exit 1
    ;;
esac

sed "s/@ALLOWED_HOST@/$host/g" \
  /etc/mailgate/haproxy.cfg.template > /tmp/haproxy.cfg
haproxy -c -f /tmp/haproxy.cfg
