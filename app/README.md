# Web Application

The first implementation foundation lives here:

- `manage.py` provides Django management commands;
- `mailgate/settings.py` reads explicit, file-backed secrets and database settings;
- `mailgate/health.py` exposes content-minimal liveness and readiness endpoints;
- `mailgate/middleware.py` applies restrictive response security headers.

The web process has no IMAP or SMTP code and receives no mailbox credentials. The Compose deployment attaches it only to internal application and database networks. A separate, unprivileged Caddy proxy publishes the current HTTP endpoint on loopback.
