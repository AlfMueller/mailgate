# Mail provider documentation

MailGate ships an explicit provider registry. A preset supplies only documented connection defaults;
it never makes a provider claim trustworthy and never guesses an `authserv-id`.

- [Hostpoint](hostpoint.md)
- [Generic IMAPS](generic-imaps.md)

Every example uses reserved domains, invented addresses and synthetic credentials unless it points
only to public provider documentation. Add providers through a small, reviewed registry change plus
tests and a documentation page; do not accept arbitrary hosts from browser input.
