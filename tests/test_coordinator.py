"""Coordinator tests with minimal Home Assistant / aiohttp stubs.

Run: python -m pytest tests  (or execute this file directly)
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import importlib.util
from pathlib import Path
import sys
import types

PKG_DIR = Path(__file__).parents[1] / "custom_components" / "citrix_security_bulletins"
PKG = "citrix_security_bulletins"
NOW = datetime(2026, 10, 9, 8, 0, tzinfo=UTC)


def _module(name: str, **attrs) -> types.ModuleType:
    mod = sys.modules.get(name) or types.ModuleType(name)
    for key, value in attrs.items():
        setattr(mod, key, value)
    sys.modules[name] = mod
    return mod


class _Generic:
    def __class_getitem__(cls, item):
        return cls


class _Coordinator(_Generic):
    def __init__(self, hass, logger, *, config_entry, name, update_interval):
        self.hass = hass
        self.config_entry = config_entry


class _Store(_Generic):
    data: dict | None = None
    saved: dict | None = None

    def __init__(self, hass, version, key):
        pass

    async def async_load(self):
        return _Store.data

    async def async_save(self, data):
        _Store.saved = data


class _HAError(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args)


def _install_stubs() -> None:
    _module("aiohttp", ClientError=Exception, ClientSession=object, ClientTimeout=lambda **kw: None)
    _module("yarl", URL=lambda url, encoded=False: url)
    _module("homeassistant")
    _module("homeassistant.config_entries", ConfigEntry=_Generic)
    _module("homeassistant.core", HomeAssistant=object)
    _module("homeassistant.exceptions", ConfigEntryAuthFailed=_HAError)
    _module("homeassistant.helpers")
    _module("homeassistant.helpers.storage", Store=_Store)
    _module(
        "homeassistant.helpers.update_coordinator",
        DataUpdateCoordinator=_Coordinator,
        UpdateFailed=_HAError,
    )
    dt = types.SimpleNamespace(utcnow=lambda: NOW)
    _module("homeassistant.util", dt=dt)
    sys.modules.setdefault(PKG, types.ModuleType(PKG)).__path__ = [str(PKG_DIR)]
    for name in ("const", "models", "api", "coordinator"):
        spec = importlib.util.spec_from_file_location(f"{PKG}.{name}", PKG_DIR / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)


_install_stubs()
const = sys.modules[f"{PKG}.const"]
coordinator_mod = sys.modules[f"{PKG}.coordinator"]


def item(cve_id, published, ctx, description, status="Received"):
    return {
        "cve": {
            "id": cve_id,
            "sourceIdentifier": const.NETSCALER_CNA_SOURCE,
            "published": published,
            "lastModified": published,
            "vulnStatus": status,
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {
                "cvssMetricV40": [
                    {
                        "source": const.NETSCALER_CNA_SOURCE,
                        "type": "Secondary",
                        "cvssData": {"baseScore": 9.5, "baseSeverity": "CRITICAL"},
                    }
                ]
            },
            "references": [
                {
                    "url": f"https://support.citrix.com/support-home/kbsearch/article?articleNumber={ctx}",
                    "source": const.NETSCALER_CNA_SOURCE,
                }
            ],
        }
    }


# Freshly published, not yet analysed by NVD: no CPE, no product named.
NEW = item(
    "CVE-2026-107406",
    "2026-10-08T22:17:26.847",
    "CTX697191",
    "Memory overflow vulnerability leading to Remote Code Execution or Denial of "
    "Service when NetScaler is configured as a SAML SP or SAML IdP",
)
KNOWN = item(
    "CVE-2026-88771", "2026-09-27T15:00:00", "CTX697096",
    "Vulnerability in NetScaler ADC and NetScaler Gateway", status="Analyzed",
)
OLD = item(
    "CVE-2023-3519", "2023-07-19T18:15:00", "CTX561482",
    "Unauthenticated remote code execution", status="Analyzed",
)
CONSOLE = item(
    "CVE-2026-50000", "2026-10-08T10:00:00", "CTX697000",
    "Privilege escalation in NetScaler Console", status="Received",
)


class FakeClient:
    def __init__(self):
        self.calls = []

    async def async_get_cves(self, cpe_match=None, last_mod_start=None,
                             last_mod_end=None, source_identifier=None):
        self.calls.append((cpe_match, source_identifier, last_mod_start))
        if source_identifier == const.NETSCALER_CNA_SOURCE:
            return [NEW, KNOWN, OLD, CONSOLE]
        return [KNOWN]  # CPE queries only know the analysed record


def run(stored):
    _Store.data = stored
    entry = types.SimpleNamespace(
        options={const.CONF_PRODUCTS: const.DEFAULT_PRODUCTS}, entry_id="e1"
    )
    client = FakeClient()
    coord = coordinator_mod.CitrixBulletinCoordinator(None, entry, client)

    async def go():
        await coord._async_setup()
        return await coord._async_update_data()

    return asyncio.run(go()), client


def test_missed_bulletin_is_reported_after_update():
    # Cache of the previous version (no schema), CTX697096 already reported.
    stored = {
        "products": const.DEFAULT_PRODUCTS,
        "last_sync": (NOW - timedelta(hours=1)).isoformat(),
        "baseline_done": True,
        "seen": ["CTX697096", "CTX561482"],
        "cves": {},
    }
    data, client = run(stored)
    assert [b.bulletin_id for b in data.new_bulletins] == ["CTX697191"]
    new = data.new_bulletins[0]
    assert new.products == ["netscaler_adc", "netscaler_gateway"]
    assert new.url == "https://support.citrix.com/external/article/CTX697191"
    assert data.bulletins[0].bulletin_id == "CTX697191"
    # Console-only CVE is not monitored.
    assert all(b.bulletin_id != "CTX697000" for b in data.bulletins)
    # Full re-sync (no date range) and the CNA query was used.
    assert any(src == const.NETSCALER_CNA_SOURCE for _, src, _ in client.calls)
    assert all(start is None for _, _, start in client.calls)
    assert _Store.saved["schema"] == const.CACHE_SCHEMA
    assert "CVE-2026-107406" in _Store.saved["seen"]


def test_no_flood_for_old_bulletins_after_resync():
    stored = {
        "products": const.DEFAULT_PRODUCTS,
        "last_sync": (NOW - timedelta(hours=1)).isoformat(),
        "baseline_done": True,
        "seen": ["CTX697096"],  # CTX561482 (2023) never reported before
        "cves": {},
    }
    data, _ = run(stored)
    assert [b.bulletin_id for b in data.new_bulletins] == ["CTX697191"]


def test_first_run_reports_nothing():
    data, _ = run(None)
    assert data.new_bulletins == []
    assert len(data.bulletins) == 3


def test_incremental_run_reports_nothing_twice():
    _, _ = run(None)
    stored = dict(_Store.saved)
    data, client = run(stored)
    assert data.new_bulletins == []
    assert all(start is not None for _, _, start in client.calls)


if __name__ == "__main__":
    for name, func in list(globals().items()):
        if name.startswith("test_"):
            func()
            print("PASS", name)
