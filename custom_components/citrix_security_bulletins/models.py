"""Data models and NVD parsing for the Citrix Security Bulletins integration.

This module has no Home Assistant dependencies so it can be unit tested on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import re
from typing import Any

from .const import NVD_DETAIL_URL, PRODUCT_NAMES

# Citrix knowledge base / security bulletin IDs, e.g. CTX696300.
_CTX_RE = re.compile(r"\b(CTX\d{5,7})\b", re.IGNORECASE)
_VENDOR_HOSTS = ("citrix.com", "netscaler.com", "cloud.com")

_SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def parse_nvd_datetime(value: str | None) -> datetime | None:
    """Parse an NVD timestamp (UTC, without offset) into an aware datetime."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


@dataclass(slots=True)
class Cve:
    """A single CVE relevant for one or more configured products."""

    cve_id: str
    published: datetime
    last_modified: datetime
    description: str
    cvss_score: float | None
    severity: str | None
    cvss_version: str | None
    cvss_vector: str | None
    known_exploited: bool
    bulletin_id: str | None
    bulletin_url: str | None
    products: set[str] = field(default_factory=set)

    @property
    def nvd_url(self) -> str:
        """Return the NVD detail page."""
        return NVD_DETAIL_URL.format(cve_id=self.cve_id)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for the storage cache."""
        return {
            "cve_id": self.cve_id,
            "published": self.published.isoformat(),
            "last_modified": self.last_modified.isoformat(),
            "description": self.description,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "cvss_version": self.cvss_version,
            "cvss_vector": self.cvss_vector,
            "known_exploited": self.known_exploited,
            "bulletin_id": self.bulletin_id,
            "bulletin_url": self.bulletin_url,
            "products": sorted(self.products),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Cve:
        """Deserialize from the storage cache."""
        return cls(
            cve_id=data["cve_id"],
            published=datetime.fromisoformat(data["published"]),
            last_modified=datetime.fromisoformat(data["last_modified"]),
            description=data.get("description", ""),
            cvss_score=data.get("cvss_score"),
            severity=data.get("severity"),
            cvss_version=data.get("cvss_version"),
            cvss_vector=data.get("cvss_vector"),
            known_exploited=data.get("known_exploited", False),
            bulletin_id=data.get("bulletin_id"),
            bulletin_url=data.get("bulletin_url"),
            products=set(data.get("products", [])),
        )


@dataclass(slots=True)
class Bulletin:
    """A Citrix security bulletin (CTX article) grouping one or more CVEs."""

    bulletin_id: str
    url: str
    cves: list[Cve]

    @property
    def cve_ids(self) -> list[str]:
        """Return the sorted CVE IDs."""
        return sorted(cve.cve_id for cve in self.cves)

    @property
    def products(self) -> list[str]:
        """Return the affected product keys."""
        return sorted({product for cve in self.cves for product in cve.products})

    @property
    def product_names(self) -> list[str]:
        """Return human readable product names."""
        return [PRODUCT_NAMES.get(product, product) for product in self.products]

    @property
    def published(self) -> datetime:
        """Return the earliest publication date of the contained CVEs."""
        return min(cve.published for cve in self.cves)

    @property
    def last_modified(self) -> datetime:
        """Return the latest modification date of the contained CVEs."""
        return max(cve.last_modified for cve in self.cves)

    @property
    def cvss_score(self) -> float | None:
        """Return the highest CVSS base score."""
        scores = [cve.cvss_score for cve in self.cves if cve.cvss_score is not None]
        return max(scores) if scores else None

    @property
    def severity(self) -> str | None:
        """Return the highest severity."""
        severities = [cve.severity for cve in self.cves if cve.severity]
        if not severities:
            return None
        return max(severities, key=lambda sev: _SEVERITY_ORDER.get(sev, -1))

    @property
    def known_exploited(self) -> bool:
        """Return True if CISA lists any contained CVE as known exploited."""
        return any(cve.known_exploited for cve in self.cves)

    @property
    def title(self) -> str:
        """Return a title in the style Citrix uses for its bulletins."""
        ids = self.cve_ids
        if len(ids) > 1:
            cve_part = f"{', '.join(ids[:-1])} and {ids[-1]}"
        else:
            cve_part = ids[0]
        return f"{' and '.join(self.product_names)} Security Bulletin for {cve_part}"

    def as_event_data(self) -> dict[str, Any]:
        """Return the data attached to events and sensor attributes."""
        return {
            "bulletin_id": self.bulletin_id,
            "title": self.title,
            "url": self.url,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cves": self.cve_ids,
            "products": self.product_names,
            "published": self.published.isoformat(),
            "last_modified": self.last_modified.isoformat(),
            "known_exploited": self.known_exploited,
        }


def _pick_metric(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None, str | None]:
    """Pick the best available CVSS metric (v4.0 > v3.1 > v3.0 > v2)."""
    for key, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries: list[dict[str, Any]] = metrics.get(key) or []
        if not entries:
            continue
        # Prefer the primary (NVD) score, otherwise the CNA score (NetScaler/Citrix).
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return (
            data.get("baseScore"),
            severity.upper() if severity else None,
            version,
            data.get("vectorString"),
        )
    return None, None, None, None


def _find_bulletin(references: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    """Find the Citrix CTX bulletin referenced by a CVE."""
    fallback: tuple[str | None, str | None] = (None, None)
    for ref in references:
        url: str = ref.get("url", "")
        if not any(host in url.lower() for host in _VENDOR_HOSTS):
            continue
        if match := _CTX_RE.search(url):
            result = (match.group(1).upper(), url)
            if "Vendor Advisory" in (ref.get("tags") or []):
                return result
            if fallback == (None, None):
                fallback = result
    return fallback


def parse_cve(item: dict[str, Any], product: str) -> Cve | None:
    """Parse one entry of the NVD 'vulnerabilities' list."""
    cve: dict[str, Any] = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id or cve.get("vulnStatus") == "Rejected":
        return None
    published = parse_nvd_datetime(cve.get("published"))
    last_modified = parse_nvd_datetime(cve.get("lastModified")) or published
    if published is None or last_modified is None:
        return None

    description = next(
        (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    score, severity, version, vector = _pick_metric(cve.get("metrics", {}))
    bulletin_id, bulletin_url = _find_bulletin(cve.get("references", []))

    return Cve(
        cve_id=cve_id,
        published=published,
        last_modified=last_modified,
        description=description,
        cvss_score=score,
        severity=severity,
        cvss_version=version,
        cvss_vector=vector,
        known_exploited=bool(cve.get("cisaExploitAdd")),
        bulletin_id=bulletin_id,
        bulletin_url=bulletin_url,
        products={product},
    )


def group_bulletins(cves: dict[str, Cve]) -> list[Bulletin]:
    """Group CVEs into bulletins, newest first.

    CVEs without a CTX reference become their own pseudo bulletin (ID = CVE ID).
    """
    groups: dict[str, list[Cve]] = {}
    urls: dict[str, str] = {}
    for cve in cves.values():
        key = cve.bulletin_id or cve.cve_id
        groups.setdefault(key, []).append(cve)
        if key not in urls:
            urls[key] = cve.bulletin_url or cve.nvd_url

    bulletins = [Bulletin(bulletin_id=key, url=urls[key], cves=items) for key, items in groups.items()]
    bulletins.sort(key=lambda b: (b.published, b.bulletin_id), reverse=True)
    return bulletins
