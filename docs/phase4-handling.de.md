# ModSecurity-nginx: Phase-4-Handling (Deutsch)

## Zweck dieses Dokuments

Dieses Dokument beschreibt die im aktuellen Code implementierte Phase-4-Behandlung im nginx-Modul, inklusive:

- technischer Grenzen bei bereits gesendeten Headern,
- Verhalten der Modi `minimal`, `safe`, `strict`,
- Content-Type-Scoping,
- Logging (`modsecurity_phase4_log`) und Sicherheitsaspekte,
- Abgrenzung zwischen **Produktionskonfiguration** und **Test-/Demo-Verhalten**.

Es werden nur Aussagen getroffen, die durch den aktuellen Repository-Stand belegt sind.

---

## 1) Hintergrund: Request- vs. Response-Phasen

ModSecurity-Regeln laufen in unterschiedlichen Phasen der Transaktion.

- Frühe Phasen (z. B. Request-Phasen) treffen Entscheidungen, bevor eine Antwort gesendet wird.
- `phase:4` gehört zur **Response-Body-Verarbeitung**.

Das ist ein zentraler Unterschied: In `phase:4` kann nginx bereits begonnen haben, Header und/oder Body zu senden.

### Warum ist das relevant?

Wenn eine Regel in `phase:4` eine Intervention wie `deny` oder `redirect` auslöst, ist ein sauberer Wechsel auf neuen HTTP-Status nur möglich, solange Header noch nicht final gesendet wurden.

---

## 2) Was `phase:4` praktisch bedeutet

`phase:4`-Regeln prüfen den Antwortinhalt (Response-Body). Das ist nützlich, wenn Sicherheitskriterien erst am Antwortinhalt erkennbar sind.

Gleichzeitig erzeugt es eine harte technische Grenze:

- **Vor Header-Versand**: Status/Redirect kann noch sauber gesetzt werden.
- **Nach Header-Versand**: Status/Redirect lässt sich nicht zuverlässig „nachträglich“ korrigieren.

Daher existiert im Modul ein dediziertes Handling für späte Interventionen.

---

## 3) Warum Header in `phase:4` bereits gesendet sein können

In nginx werden Antworten als Stream verarbeitet. Je nach Upstream-, Filter- und Buffering-Verhalten kann der Header bereits auf dem Socket sein, bevor die vollständige Body-Prüfung abgeschlossen ist.

Folge: Ein in `phase:4` erkanntes `status:403` oder `redirect:302` kann nicht garantiert als sauberer HTTP-Status beim Client landen.

> Keine falsche Garantie: `phase:4` kann nach gesendeten Headern keinen sauberen HTTP-Status mehr garantieren.

---

## 4) Neue Directives im Modul

## `modsecurity_phase4_mode`

Konfiguriert das Verhalten bei Phase-4-Interventionen.

Unterstützte Werte:

- `minimal`
- `safe`
- `strict`

Ungültige Werte führen zu Konfigurationsfehlern.

## `modsecurity_phase4_content_types_file`

Lädt erlaubte/gescopte Content-Types aus einer Datei.

- eine Zeile pro Typ,
- Kommentare mit `#`,
- Einträge werden validiert,
- Wildcards (`*`) sind nicht erlaubt.

Wenn nicht gesetzt, nutzt das Modul Default-Typen.

## `modsecurity_phase4_log`

Aktiviert dediziertes JSON-Line-Logging für Phase-4-Ereignisse.

---

## 5) Modusverhalten (`minimal`, `safe`, `strict`)

## `minimal`

Ziel: möglichst wenig Eingriff in laufende Responses.

Bei Intervention nach gesendeten Headern:

- Aktion wird auf `log_only` degradiert,
- keine erzwungene Verbindungsbeendigung.

Sinnvoll, wenn Stabilität und vollständige Antwortauslieferung Vorrang haben.

## `safe`

Ziel: konservativer Produktionsstandard (Default-Merge-Verhalten im Modul).

Bei Intervention nach gesendeten Headern:

- ebenfalls `log_only`.

Sinnvoll als Standardmodus, wenn Phase-4-Transparenz gewünscht ist, aber Verbindungsabbrüche vermieden werden sollen.

## `strict`

Ziel: strengere Reaktion, wenn keine saubere Statusänderung mehr möglich ist.

Bei Intervention nach gesendeten Headern:

- `connection_abort`.

### Risiken von `strict`

- Kann aktive Verbindungen abbrechen.
- Liefert nicht garantiert einen „schönen“ HTTP-Fehlerstatus beim Client.
- Kann je nach Client/Proxy als Transportfehler statt als 4xx/3xx sichtbar werden.

`strict` ist daher nur sinnvoll, wenn diese Nebenwirkungen betrieblich akzeptabel sind.

---

## 6) Verhalten nach Header-Status

## Header noch **nicht** gesendet

Wenn eine Intervention vor Header-Versand finalisiert wird, bleibt normaler Deny-/Statuspfad möglich (im Code als `deny_status` geloggt).

## Header bereits gesendet

- `minimal`: `log_only`
- `safe`: `log_only`
- `strict`: `connection_abort`

Das ist eine bewusste Degradierung, um keine falschen Status-Garantien vorzutäuschen.

---

## 7) Warum **kein globales Response-Body-Buffering** genutzt wird

Ein globales Buffering aller Responses würde zwar den Eingriffszeitpunkt verschieben, bringt aber technische und betriebliche Kosten:

- zusätzlicher Speicher- und Latenz-Overhead,
- größere Komplexität für allgemeine Response-Pfade,
- Risiko unbeabsichtigter Nebenwirkungen auf Durchsatz/Stabilität.

Der aktuelle Ansatz versucht stattdessen, late Interventionen transparent und kontrolliert zu behandeln (`log_only` oder `connection_abort`).

---

## 8) Warum kein `ngx_chain_t`-Reordering/Rewriting genutzt wird

Das Modul implementiert **keine** künstliche Reordering-Logik auf bereits laufenden Body-Ketten, um nachträglich „doch noch“ andere Header-/Statussemantik zu erzwingen.

Begründung:

- hohe Komplexität,
- erhöhte Fehleranfälligkeit,
- schwierige Garantien über korrektes Verhalten in allen Filter-/Upstream-Kombinationen.

Die dokumentierte Degradierung ist technisch robuster als scheinbar harte, aber unsichere Nachkorrekturen.

---

## 9) Content-Type-Scoping: Bedeutung und sichere Nutzung

`modsecurity_phase4_content_types_file` begrenzt Phase-4-Sonderbehandlung auf definierte MIME-Typen.

Wenn `Content-Type` fehlt oder nicht im Scope liegt:

- Ereignis wird als `log_only` dokumentiert,
- Grund ist typischerweise `content_type_missing` oder `content_type_not_in_scope`.

### Warum wichtig?

- reduziert Nebeneffekte auf nicht-zielgerichtete Antworttypen,
- macht Verhalten vorhersagbarer,
- zwingt zu expliziter Auswahl relevanter Content-Typen.

---

## 10) Logging-Format und Sicherheitsgrenzen

Mit `modsecurity_phase4_log` schreibt das Modul JSON-Zeilen, u. a. mit:

- `event` (`phase4_intervention`)
- `uri`, `method`
- `response_status`, `waf_status`
- `content_type`
- `header_sent`
- `mode`
- `wanted_action`, `actual_action`
- `reason`
- `intervention`
- `rule_id`

Zusätzlich kann im nginx `error.log` ein Hinweis erscheinen (insbesondere im `strict`-Pfad bei Headern, die schon gesendet wurden).

### Sicherheitsgrenze im Logging

Die Tests prüfen explizit, dass keine Response-Body-Inhalte in das Phase-4-Log „durchrutschen“.

---

## 11) Produktionsbeispiele

Allgemeine (nicht testpfadgebundene) Beispielkonfigurationen:

- `docs/examples/phase4-minimal.conf`
- `docs/examples/phase4-safe.conf`
- `docs/examples/phase4-strict.conf`
- `docs/examples/phase4-content-types.conf`

Diese Beispiele nutzen `http`/`server`/`location /` und keine test-spezifischen `/phase4`-Pfade.

---

## 12) Test-/Demo-Verhalten (klar getrennt)

Im Repository existieren Testfälle mit `/phase4`-Pfaden, z. B. in:

- `tests/modsecurity.t`
- `tests/modsecurity-proxy.t`
- `tests/modsecurity-h2.t`
- `tests/modsecurity-proxy-h2.t`
- `tests/modsecurity-phase4-*.t`

Diese Pfade sind **Testkontext** und nicht als allgemeine Produktionskonfiguration gedacht.

---

## 13) Bekannte Grenzen / keine falschen Versprechen

- `phase:4` kann **nicht garantieren**, dass ein gewünschter 301/302/401/403-Status nach Header-Versand noch sauber beim Client ankommt.
- Bei späten Interventionen ist nur degradierte Behandlung möglich (`log_only` oder `connection_abort`).
- `strict` bedeutet nicht „garantierter 403“, sondern kann Verbindungsabbruch bedeuten.

---

## 14) Betriebsleitfaden (kurz)

1. Harte Block-/Redirect-Entscheidungen möglichst in frühere Phasen legen.
2. `safe` als Ausgangspunkt verwenden, wenn keine klare Notwendigkeit für `strict` besteht.
3. `strict` nur einsetzen, wenn Abbrüche tolerierbar und beobachtbar sind.
4. `modsecurity_phase4_log` aktivieren und auf `actual_action`/`reason` auswerten.
5. Content-Type-Liste eng halten und regelmäßig prüfen.

