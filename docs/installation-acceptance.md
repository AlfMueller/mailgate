# Independent 15-minute installation acceptance

This is a human release gate, not a maintainer smoke test. The participant must not have worked on
MailGate and may use only the public README and linked documentation. Use a fresh supported Linux VM,
an isolated synthetic/test mailbox, invented message content, and a timer.

## Success path

Start the timer when the participant opens the README. They must independently:

1. run the doctor and generate local secrets;
2. configure the one allowed IMAPS hostname;
3. start Compose and reach a healthy UI;
4. create the single owner with the setup token;
5. add the isolated mailbox and observe a successful read-only worker check;
6. review and approve one synthetic harmless message;
7. issue a finite-lived agent token and read that approved message through the private API;
8. confirm a quarantined message is not visible to the API.

Stop the timer at the successful approved-only API response. The result passes only at 15:00 or less,
without maintainer intervention or bypassing a security boundary.

Record total and per-step time, commands attempted, errors, unclear wording, help requested, and the
participant's operating-system/Docker versions. Do not record hostnames, usernames, addresses,
tokens, setup values, screenshots containing personal data, or message content. File an aggregated
report using the template below and correct every blocking documentation defect before repeating
with a fresh participant.
