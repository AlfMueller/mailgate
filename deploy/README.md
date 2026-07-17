# Deployment configurations

- `Caddyfile` serves the loopback-only development stack over HTTP on port 8080.
- `Caddyfile.production` is used by `compose.production.yaml`, binds ports 80/443, and lets Caddy obtain certificates for `MAILGATE_DOMAIN`.

The production override is a release-candidate evaluation path, not a v1 production endorsement. Review `docs/release-gates.md` before exposing any real mailbox.
