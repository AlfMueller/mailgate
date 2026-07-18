# Automatisierungsplan für die öffentliche V1

## Ziel und Messung

MailGate soll nach einer kurzen Lern- und Beobachtungsphase 70–80% der **geeigneten** Nachrichten
automatisch freigeben. Manuell geprüft werden hauptsächlich Ausnahmen, Unsicherheit und echte
Warnsignale. Die Quote wird nicht durch lockere Schwellen erzwungen, sondern im isolierten
28-Tage-Pilot gemessen.

```text
Automatisierungsquote = korrekt automatisch freigegebene geeignete Nachrichten
                       / alle geeigneten Nachrichten
```

Nicht in den Nenner gehören synthetische Angriffstests, Parserfehler, abgeschnittene oder zu große
Nachrichten und Inhalte, für die keine sichere Repräsentation erzeugt werden konnte. Zusätzlich
werden Fehlfreigaben, unnötige Quarantäne, Entscheidungsdauer und manueller Aufwand getrennt
ausgewiesen. „80%“ darf niemals durch das Ausblenden schlechter Ergebnisse erreicht werden.

## Was noch gebaut werden muss

### 1. Verlässliche Signale und Absenderausrichtung

- DKIM-Signaturdomain und `From`-Domain unabhängig auswerten und Alignment speichern;
- Identitätsabweichungen zwischen `From`, `Sender` und `Reply-To` als feste Reason Codes erfassen;
- unsichtbaren Text, Unicode-Steuerzeichen, Homographen, verdächtige URLs und gefährliche
  Anhangstypen deterministisch erkennen;
- Provider-Header weiterhin nur als nicht verifizierte Zusatzsignale behandeln;
- alle Scanner strikt begrenzen: Eingabegröße, Laufzeit, Speicher, Netzwerk und Ausgabeformat.

### 2. Austauschbare Scanner-Schicht

- internes, versioniertes Scanner-Interface mit `safe`, `suspicious`, `unknown` und Reason Codes;
- standardmäßig lokaler Scanner-Sidecar ohne Internetzugriff, mit gepinntem Modell und Modell-SBOM;
- Auswahl eines aktiv gepflegten lokalen Modells anhand der MailGate-Benchmarks, Lizenz,
  Ressourcenbedarf, Deutsch/Englisch und reproduzierbarer Modellherkunft;
- Microsoft LLMail-Inject als gepinnter Testdatensatz mit Herkunft, Lizenzprüfung und Checksummen;
- Azure AI Content Safety Prompt Shields nur als ausdrücklich aktivierbarer Zusatzscanner;
- das archivierte Protect-AI-Projekt LLM Guard nur als Funktionsreferenz und Vergleichsbasis, nicht
  als ungeprüfte Produktionsabhängigkeit verwenden.

### 3. Versionierte Freigabepolicy

Die Policy benötigt vier Betriebsarten:

- **Manuell:** heutiges Verhalten, jede Nachricht wird geprüft;
- **Schattenmodus:** MailGate empfiehlt eine Entscheidung, ändert den Status aber nicht;
- **Ausgewogen:** eindeutig risikoarme Nachrichten werden automatisch freigegeben;
- **Benutzerdefiniert:** zusätzliche Regeln, ohne die harten Sperren umgehen zu können.

Automatische Freigabe setzt mindestens voraus:

- erfolgreiches Parsing und Sanitizing ohne Kürzung oder Fehler;
- unabhängiges, zum sichtbaren Absender ausgerichtetes DKIM `pass`;
- keine Prompt-Injection-, Identitäts-, Link-, Unicode- oder gefährlichen Anhangssignale;
- erfolgreiche Scannerentscheidung ohne Timeout oder Widerspruch;
- keine globale, postfachbezogene oder absenderbezogene Sperre.

Fehlende Signale, Scannerfehler und Widersprüche führen immer zu `needs_review`. Es gibt keine
automatische Ablehnung. Manuell gepflegte Vertrauensregeln dürfen positive Evidenz ergänzen, aber
niemals eine harte Sperre überschreiben.

### 4. Datenmodell, Audit und Oberfläche

- `ApprovalPolicy` mit Modus, Schwellen, Policy-Version und Kill Switch;
- unveränderliche `MessageDecision`-Historie mit `manual`, `shadow` oder `automatic`;
- Scanner- und Policy-Version, Konfigurationsversion und maschinenlesbare Reason Codes speichern;
- Einstellungsseite mit verständlichen Profilen und Vorschau auf die letzten Entscheidungen;
- Queue für Ausnahmen, Mehrfachauswahl und schnelle Korrektur;
- Stichprobenansicht für automatisch freigegebene Nachrichten;
- Dashboard für Automatisierungsquote, Fehlfreigaben, unnötige Quarantäne und Scannerfehler;
- keine Mailtexte, Adressen, Modellprompts oder Tokens in Metriken und Auditlogs.

### 5. Hermes- und MCP-Aktionsgrenzen

MailGate selbst bleibt vollständig read-only. Für Hermes wird zusätzlich ein optionales
Guardrail-Paket bereitgestellt:

- MailGate-Ausgaben als `untrusted_email_data` kennzeichnen;
- nach Einfluss solcher Daten mutierende Toolaufrufe standardmäßig blockieren oder eine echte
  Benutzerbestätigung verlangen;
- Versand an unbekannte Empfänger, Weitergabe von Geheimnissen, Aufruf mailgelieferter URLs,
  Dateiänderungen, Löschen und Shellzugriffe deterministisch sperren;
- Referenzregeln und Integrationstests für Invariant Guardrails beziehungsweise einen kompatiblen
  lokalen MCP/LLM-Gateway bereitstellen;
- Guardrails nie als Ersatz für die fehlenden MailGate-Schreibwerkzeuge darstellen.

### 6. Tests und Pilot

- LLMail-Inject-Fälle sowie sichtbare, versteckte, deutsche und Unicode-Angriffe ausführen;
- einen datenschutzfreien benignen Mailkorpus gegen Übererkennung testen;
- Policy-Grenzen mit Property-, Mutation-, Integrations- und Browser-E2E-Tests prüfen;
- Scanner-Ausfall, Timeout, Versionswechsel und widersprüchliche Ergebnisse erzwingen;
- die ersten 100 automatisch vorgeschlagenen beziehungsweise freigegebenen Nachrichten vollständig
  manuell kontrollieren, danach mindestens 10% zufällig auditieren;
- bei einer sicherheitskritischen Fehlfreigabe Automation sofort deaktivieren, Ursache dokumentieren,
  Regressionstest ergänzen und den betroffenen Pilotzeitraum neu starten.

## Umsetzungsphasen

| Phase | Ergebnis | Definition of Done |
| --- | --- | --- |
| A | Benchmark und Signalmodell | LLMail-Inject und benigner Korpus reproduzierbar; Metriken und Lizenzen dokumentiert |
| B | Scanner-Sidecar | lokal, ohne Egress, ressourcenbegrenzt, gepinnt, ausfallsicher und SBOM-erfasst |
| C | Schattenmodus | Empfehlungen und Gründe sichtbar; Status bleibt garantiert unverändert |
| D | Begrenzte Auto-Freigabe | nur harte Low-Risk-Policy; Kill Switch, Audit und Rollback getestet |
| E | Hermes-Guardrails | Referenzpolicy blockiert mutierende Aktionen aus mailbeeinflussten Abläufen |
| F | 28-Tage-Pilot | 70–80% korrekte Automation geeigneter Nachrichten mit signiertem Abschlussbericht |

## Freigabekriterien

- Automatisierungsquote im stabilen Pilotfenster: **mindestens 70%, Zielkorridor 70–80%**;
- sicherheitskritische Fehlfreigaben im Pilot und bekannten Angriffskorpus: **0**;
- bestätigte Fehlfreigaben insgesamt: **höchstens 1%** der auditierten Auto-Freigaben;
- manuelle Stichprobe: erste 100 vollständig, danach mindestens 10% zufällig;
- unapproved API exposure, Mailbox-Mutation oder Attachment-Byte-Exposure: **0**;
- jeder automatische Statuswechsel ist reproduzierbar aus versionierter Policy und Reason Codes;
- lokaler Betrieb bleibt ohne Cloudkonto, Telemetrie oder Weitergabe von Mailinhalten möglich.

Diese Ziele sind Abnahmekriterien für den Pilot, keine Behauptung, Prompt Injection vollständig zu
erkennen. Wird der 70%-Wert nur durch unsichere Schwellen erreicht, gilt die Phase als nicht bestanden.

## Referenzen

- [Microsoft LLMail-Inject](https://github.com/microsoft/llmail-inject-challenge)
- [Azure AI Content Safety Prompt Shields](https://learn.microsoft.com/azure/ai-services/content-safety/concepts/jailbreak-detection)
- [Invariant Guardrails](https://github.com/invariantlabs-ai/invariant)
- [Protect AI LLM Guard – archivierte Referenz](https://github.com/protectai/llm-guard)
