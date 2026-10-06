# Citrix Security Bulletins für Home Assistant

Custom Integration, die neue **Citrix NetScaler Security Bulletins** (CTX-Artikel) erkennt und in Home Assistant bereitstellt.

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


## Lizenz

[MIT](LICENSE)
