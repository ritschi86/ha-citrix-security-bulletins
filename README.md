# Citrix Security Bulletins für Home Assistant

[![KI-generiert](https://img.shields.io/badge/Code-100%25%20KI--generiert-8A2BE2)](#-ki-generiert)
[![HACS Custom](https://img.shields.io/badge/HACS-Custom-41BDF5)](https://hacs.xyz)
[![Lizenz: MIT](https://img.shields.io/badge/Lizenz-MIT-blue)](LICENSE)

Custom Integration, die neue **Citrix NetScaler Security Bulletins** (CTX-Artikel) erkennt und in Home Assistant bereitstellt.

> [!NOTE]
> **Reine KI-Integration:** Der gesamte Code dieser Integration wurde von einer KI geschrieben, ohne manuelle Code-Änderungen. Details siehe [KI-generiert](#-ki-generiert).

## Datenquelle

Citrix bietet keinen offiziellen maschinenlesbaren Feed mehr an (der frühere RSS-Feed liefert keine Daten mehr, offiziell gibt es nur E-Mail-Alerts). Die Integration nutzt deshalb die offizielle **NVD CVE API 2.0** des NIST:

- Abfrage per CPE: `citrix:netscaler_application_delivery_controller` und `citrix:netscaler_gateway`
- Die CVEs werden anhand der Herstellerreferenz (z. B. `CTX696300`) zu **Bulletins gruppiert**, so wie Citrix sie veröffentlicht.
- Erst kompletter Abruf, danach stündlich nur noch Änderungen (`lastModStartDate`), lokal zwischengespeichert.
- Hinweis: Die NVD übernimmt neue CVEs meist innerhalb weniger Stunden nach der Citrix-Veröffentlichung.

## Entitäten

| Entität | Beschreibung |
|---|---|
| Sensor **Neuestes Bulletin** | State = CTX-ID des neuesten Bulletins. Attribute: `title`, `url` (Citrix-Artikel), `nvd_urls`, `severity`, `cvss_score`, `cves`, `products`, `published`, `known_exploited` (CISA KEV), `description`, `recent_bulletins` |
| Sensor **CVSS-Score** | Höchster CVSS-Basiswert des neuesten Bulletins (Zahl, mit Verlauf) |
| Sensor **Schweregrad** | Kritisch / Hoch / Mittel / Niedrig |
| Sensor **Artikel-URL** | Direkter Link zum Citrix-Artikel, z. B. `https://support.citrix.com/external/article/CTX697096` |
| Sensor **NIST-NVD-URL** | NVD-Seite der CVE mit dem höchsten Score, z. B. `https://nvd.nist.gov/vuln/detail/CVE-2026-88771`; alle CVE-Links im Attribut `nvd_urls` |
| Event **Neues Bulletin** | Event-Typ `new_bulletin` mit denselben Daten – feuert einmal pro neu erkanntem Bulletin |

Die genaue Entity-ID siehst du unter *Geräte & Dienste → Citrix Security Bulletins*; im Beispiel unten ggf. anpassen.

Beim allerersten Abruf (und nach einer Änderung der Produktauswahl) werden **keine** Events ausgelöst – vorhandene Bulletins gelten als bekannt.

## Installation

**HACS:** HACS → Integrationen → ⋮ → Benutzerdefinierte Repositories → `https://github.com/ritschi86/ha-citrix-security-bulletins`, Kategorie *Integration* → installieren → Home Assistant neu starten.

**Manuell:** `custom_components/citrix_security_bulletins` nach `/config/custom_components/` kopieren und neu starten.

Dann: *Einstellungen → Geräte & Dienste → Integration hinzufügen → Citrix Security Bulletins*.

Ein [NVD-API-Schlüssel](https://nvd.nist.gov/developers/request-an-api-key) ist optional (ohne: 5 Anfragen/30 s, mit: 50 Anfragen/30 s).

**Optionen:** Produkte auswählen (NetScaler ADC, NetScaler Gateway). **Neu konfigurieren:** API-Schlüssel ändern.

## Beispiel-Automation

```yaml
alias: Citrix Security Bulletin melden
triggers:
  - trigger: state
    entity_id: event.citrix_security_bulletins_neues_bulletin
    not_from: unavailable
conditions:
  - condition: template
    value_template: "{{ trigger.to_state.attributes.event_type == 'new_bulletin' }}"
actions:
  - action: notify.notify
    data:
      title: >-
        Citrix {{ trigger.to_state.attributes.severity }}:
        {{ trigger.to_state.attributes.bulletin_id }}
      message: >-
        {{ trigger.to_state.attributes.title }}
        (CVSS {{ trigger.to_state.attributes.cvss_score }}{{ ', aktiv ausgenutzt!' if trigger.to_state.attributes.known_exploited }})
        {{ trigger.to_state.attributes.url }}
```


Eine fertige Automation für eine **kritische iPhone-Nachricht** (ab Schweregrad Hoch) mit Buttons zum Citrix-Artikel und zur NIST NVD liegt in [`examples/automation_iphone_kritisch.yaml`](examples/automation_iphone_kritisch.yaml).

## 🤖 KI-generiert

Diese Integration ist ein reines KI-Projekt. **Sämtliche Dateien** – Python-Code, Config Flow, Übersetzungen, Tests, Beispiel-Automation, GitHub-Workflow und diese README – wurden von **Claude (Anthropic)** erstellt. Es gab **keine manuellen Code-Änderungen**.

| Rolle | Aufgabe |
|---|---|
| **KI (Claude)** | Recherche der Datenquelle, Architektur, gesamter Code, Fehleranalyse und -behebung, Dokumentation |
| **Mensch (Maintainer)** | Anforderungen vorgeben, Entscheidungen treffen, in Home Assistant testen, Fehlermeldungen zurückmelden, auf GitHub veröffentlichen |

Grundlage waren ausschließlich die offiziellen Dokumentationen von Home Assistant, der Home Assistant Companion App und der NIST NVD API.

> [!IMPORTANT]
> Die Integration wird ohne Gewähr bereitgestellt (siehe [Lizenz](LICENSE)). Sie ersetzt keine offiziellen Citrix-Benachrichtigungen – für sicherheitskritische Umgebungen zusätzlich die [Citrix-Security-Alerts](https://support.citrix.com/user/alerts) abonnieren.

## Lizenz

[MIT](LICENSE)
