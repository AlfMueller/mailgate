# Mail worker

The worker periodically reads enabled mailboxes using certificate-verified IMAPS. It requests a
read-only `INBOX` selection and fetches with `BODY.PEEK[]`; it has no SMTP implementation and
never stores, moves, flags, or deletes provider mail.

Messages are bounded, parsed and reduced to safe text, normalized links and attachment metadata.
Provider authentication claims are recorded but never auto-approve a message. Failures are logged
only by mailbox ID and stable error code. The database role cannot access owner accounts, sessions,
or API tokens and cannot update message approval state.

The worker is the only application process attached to `worker_egress`. Destination-enforced egress
allowlisting remains a release gate.
