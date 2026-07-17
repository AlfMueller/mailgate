# Mail worker

The worker periodically reads enabled mailboxes using certificate-verified IMAPS. It requests a
read-only `INBOX` selection and fetches with `BODY.PEEK[]`; it has no SMTP implementation and
never stores, moves, flags, or deletes provider mail.

Messages are bounded, parsed and reduced to safe text, normalized links and attachment metadata.
Provider authentication claims are recorded but never auto-approve a message. Failures are logged
only by mailbox ID and stable error code. The database role cannot access owner accounts, sessions,
or API tokens and cannot update message approval state.

The worker has only internal database and IMAP-relay networks. It cannot connect directly to the
internet. The hardened `imap-egress` relay accepts end-to-end TLS only for the installation's exact
operator-approved hostname and forwards that traffic only to port 993.
