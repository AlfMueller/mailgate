# Hostpoint preset

The `hostpoint` preset fixes the incoming connection to `imap.mail.hostpoint.ch` on encrypted IMAPS
port 993. The installation-level `MAILGATE_IMAP_ALLOWED_HOST` must contain the same host; the browser
cannot override that allowlist.

Hostpoint publicly documents the IMAP hostname and port, but MailGate does not guess an
`Authentication-Results` `authserv-id`. Leave the advanced field empty unless the receiving
infrastructure's exact behavior has been verified from provider documentation and synthetic-header
tests. Provider SPF, DKIM, DMARC, ARC, and spam fields remain claims and never auto-approve mail.

MailGate independently verifies DKIM signatures against the unchanged message bytes. SPF cannot be
reconstructed reliably from an IMAP copy because the original SMTP client IP, HELO, and envelope
sender are not authoritative inputs at this boundary. ARC likewise requires an explicitly trusted
sealer before it can affect policy; V1 exposes the provider claim but does not treat it as independent
authorization.

The preset does not configure SMTP. MailGate never sends, moves, flags, or deletes remote mail.
