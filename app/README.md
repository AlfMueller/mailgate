# Web application

`mailgate/` contains fail-closed Django configuration, health endpoints and response hardening.
`gateway/` contains encrypted mailbox configuration, message/audit/token models, the owner UI,
bounded mail processing and the GET-only approved-message API. The owner UI and API use separate
settings, URL configurations, processes, secrets and PostgreSQL roles.

The web container has no worker egress network and no SMTP implementation. It receives the master
key so the owner can store mailbox credentials, while the password is never rendered again. The
owner can rotate a stored password without resetting the IMAP identity or UID cursor. Host, port,
and username remain immutable after ingestion to keep historical messages bound to one source.
The local adversarial self-test uses fixed synthetic fixtures and performs no network or message
store mutation. The API role can read only an approved-message security-barrier view and use one
constrained authorization function; it cannot read application base tables.
