"""Tests for the HA-independent parsing/grouping logic (run with: python -m pytest tests)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types

PKG_DIR = Path(__file__).parents[1] / "custom_components" / "citrix_security_bulletins"
PKG = "citrix_security_bulletins"

# Load const/models without executing the package __init__ (which needs Home Assistant).
sys.modules.setdefault(PKG, types.ModuleType(PKG)).__path__ = [str(PKG_DIR)]
for name in ("const", "models"):
    spec = importlib.util.spec_from_file_location(f"{PKG}.{name}", PKG_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

models = sys.modules[f"{PKG}.models"]


def nvd_item(cve_id, published, ctx=None, v4=None, v31=None, kev=False, status="Analyzed", tags=None):
    metrics = {}
    if v4:
        metrics["cvssMetricV40"] = [
            {"source": "secure@citrix.com", "type": "Secondary",
             "cvssData": {"version": "4.0", "baseScore": v4[0], "baseSeverity": v4[1], "vectorString": "CVSS:4.0/AV:N"}}
        ]
    if v31:
        metrics["cvssMetricV31"] = [
            {"source": "nvd@nist.gov", "type": "Primary",
             "cvssData": {"version": "3.1", "baseScore": v31[0], "baseSeverity": v31[1], "vectorString": "CVSS:3.1/AV:N"}}
        ]
    refs = [{"url": "https://labs.example.com/" + cve_id, "source": "x", "tags": ["Exploit"]}]
    if ctx:
        refs.append({
            "url": f"https://support.citrix.com/support-home/kbsearch/article?articleNumber={ctx}",
            "source": "secure@citrix.com",
            "tags": tags if tags is not None else ["Vendor Advisory"],
        })
    cve = {
        "id": cve_id, "published": published, "lastModified": published, "vulnStatus": status,
        "descriptions": [{"lang": "es", "value": "es"}, {"lang": "en", "value": f"Desc {cve_id}"}],
        "metrics": metrics, "references": refs,
    }
    if kev:
        cve["cisaExploitAdd"] = "2026-09-28"
    return {"cve": cve}


def test_parse_prefers_v4_and_extracts_ctx():
    cve = models.parse_cve(
        nvd_item("CVE-2026-1", "2026-09-27T15:15:10.123", "CTX697096", v4=(9.3, "CRITICAL"), v31=(7.5, "HIGH"), kev=True),
        "netscaler_adc",
    )
    assert cve.cvss_score == 9.3 and cve.severity == "CRITICAL" and cve.cvss_version == "4.0"
    assert cve.bulletin_id == "CTX697096" and "articleNumber=CTX697096" in cve.bulletin_url
    assert cve.known_exploited and cve.description == "Desc CVE-2026-1"
    assert cve.published.tzinfo is not None


def test_rejected_and_ctx_without_vendor_tag():
    assert models.parse_cve(nvd_item("CVE-2026-9", "2026-01-01T00:00:00", status="Rejected"), "x") is None
    cve = models.parse_cve(nvd_item("CVE-2026-8", "2026-01-01T00:00:00", "ctx123456", tags=[]), "x")
    assert cve.bulletin_id == "CTX123456"


def test_grouping_and_roundtrip():
    items = [
        nvd_item("CVE-2026-88771", "2026-09-27T15:00:00", "CTX697096", v4=(9.5, "CRITICAL")),
        nvd_item("CVE-2026-88772", "2026-09-27T15:01:00", "CTX697096", v4=(7.0, "HIGH")),
        nvd_item("CVE-2026-3055", "2026-03-23T10:00:00", "CTX696300", v4=(9.3, "CRITICAL"), kev=True),
        nvd_item("CVE-2026-5000", "2026-05-01T10:00:00", None, v31=(5.3, "MEDIUM")),
    ]
    cves = {}
    for item in items:
        for product in ("netscaler_adc", "netscaler_gateway"):
            parsed = models.parse_cve(item, product)
            if parsed.cve_id in cves:
                parsed.products |= cves[parsed.cve_id].products
            cves[parsed.cve_id] = parsed

    # Storage roundtrip
    cves = {k: models.Cve.from_dict(v.to_dict()) for k, v in cves.items()}

    bulletins = models.group_bulletins(cves)
    assert [b.bulletin_id for b in bulletins] == ["CTX697096", "CVE-2026-5000", "CTX696300"]
    latest = bulletins[0]
    assert latest.cve_ids == ["CVE-2026-88771", "CVE-2026-88772"]
    assert latest.severity == "CRITICAL" and latest.cvss_score == 9.5
    assert latest.title == (
        "NetScaler ADC and NetScaler Gateway Security Bulletin for CVE-2026-88771 and CVE-2026-88772"
    )
    assert latest.url == "https://support.citrix.com/external/article/CTX697096"
    assert bulletins[1].url == "https://nvd.nist.gov/vuln/detail/CVE-2026-5000"
    assert bulletins[2].known_exploited
    data = latest.as_event_data()
    assert data["products"] == ["NetScaler ADC", "NetScaler Gateway"]
    assert data["published"].startswith("2026-09-27T15:00:00")
