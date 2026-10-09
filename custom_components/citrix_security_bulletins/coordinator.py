"""DataUpdateCoordinator for the Citrix Security Bulletins integration."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import NvdAuthError, NvdClient, NvdError
from .const import (
    CACHE_SCHEMA,
    CONF_PRODUCTS,
    DEFAULT_PRODUCTS,
    DOMAIN,
    MAX_EVENT_AGE,
    NETSCALER_CNA_SOURCE,
    NVD_MAX_RANGE,
    PRODUCT_CPES,
    STORAGE_KEY,
    STORAGE_VERSION,
    UPDATE_INTERVAL,
)
from .models import (
    Bulletin,
    Cve,
    detect_products,
    english_description,
    group_bulletins,
    parse_cve,
)

_LOGGER = logging.getLogger(__name__)

# Overlap for incremental syncs so nothing slips through at the boundaries.
_SYNC_OVERLAP = timedelta(hours=2)

type CitrixConfigEntry = ConfigEntry[CitrixBulletinCoordinator]


@dataclass(slots=True)
class CitrixBulletinData:
    """Data provided by the coordinator."""

    bulletins: list[Bulletin]
    new_bulletins: list[Bulletin] = field(default_factory=list)
    last_sync: datetime | None = None


class CitrixBulletinCoordinator(DataUpdateCoordinator[CitrixBulletinData]):
    """Fetch Citrix security bulletins from the NVD and detect new ones."""

    config_entry: CitrixConfigEntry

    def __init__(
        self, hass: HomeAssistant, config_entry: CitrixConfigEntry, client: NvdClient
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            config_entry=config_entry,
            name=DOMAIN,
            update_interval=UPDATE_INTERVAL,
        )
        self.client = client
        self.products: list[str] = list(
            config_entry.options.get(CONF_PRODUCTS, DEFAULT_PRODUCTS)
        )
        self._store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, f"{STORAGE_KEY}.{config_entry.entry_id}"
        )
        self._cves: dict[str, Cve] = {}
        self._seen: set[str] = set()
        self._last_sync: datetime | None = None
        self._baseline_done = False

    async def _async_setup(self) -> None:
        """Load the persisted cache."""
        stored = await self._store.async_load()
        if not stored:
            return
        if sorted(stored.get("products", [])) != sorted(self.products):
            # Product selection changed: start fresh, without firing events
            # for bulletins of newly selected products.
            _LOGGER.debug("Product selection changed, discarding cache")
            return
        try:
            self._seen = set(stored.get("seen", []))
            self._baseline_done = bool(stored.get("baseline_done"))
            if stored.get("schema") != CACHE_SCHEMA:
                # Queries changed: full re-sync, but keep the reported bulletins
                # so bulletins missed by the old queries are reported now.
                _LOGGER.info("Cache schema changed, performing a full re-sync")
                return
            self._cves = {
                cve_id: Cve.from_dict(data) for cve_id, data in stored["cves"].items()
            }
            last_sync = stored.get("last_sync")
            self._last_sync = datetime.fromisoformat(last_sync) if last_sync else None
        except (KeyError, TypeError, ValueError) as err:
            _LOGGER.warning("Ignoring invalid cache: %s", err)
            self._cves, self._seen, self._last_sync = {}, set(), None
            self._baseline_done = False

    async def _async_update_data(self) -> CitrixBulletinData:
        """Fetch new/changed CVEs from the NVD and build bulletins."""
        now = dt_util.utcnow()
        incremental = (
            self._last_sync is not None
            and bool(self._cves)
            and now - (self._last_sync - _SYNC_OVERLAP) < NVD_MAX_RANGE
        )

        start: datetime | None = None
        cves: dict[str, Cve] = {}
        if incremental and self._last_sync is not None:
            start = self._last_sync - _SYNC_OVERLAP
            # Copy so a failed update leaves the cache untouched.
            cves = {k: replace(v, products=set(v.products)) for k, v in self._cves.items()}

        try:
            end = now if start else None
            # 1) NetScaler CNA records: available as soon as NetScaler publishes,
            #    before NVD analysts add CPE data.
            items = await self.client.async_get_cves(
                source_identifier=NETSCALER_CNA_SOURCE,
                last_mod_start=start,
                last_mod_end=end,
            )
            self._merge(cves, items, None, self.products)
            # 2) CPE matches: analysed records, including other CNAs (e.g. Citrix).
            for product in self.products:
                items = await self.client.async_get_cves(
                    PRODUCT_CPES[product], last_mod_start=start, last_mod_end=end
                )
                self._merge(cves, items, product, self.products)
        except NvdAuthError as err:
            raise ConfigEntryAuthFailed(
                translation_domain=DOMAIN, translation_key="invalid_api_key"
            ) from err
        except NvdError as err:
            raise UpdateFailed(
                translation_domain=DOMAIN,
                translation_key="update_failed",
                translation_placeholders={"error": str(err)},
            ) from err

        self._cves = cves
        self._last_sync = now
        bulletins = group_bulletins(cves)
        # Remember bulletin IDs and CVE IDs, so a CVE first reported without CTX
        # reference is not reported again once NVD adds the reference.
        current_ids = {b.bulletin_id for b in bulletins} | set(cves)

        new_bulletins: list[Bulletin] = []
        if self._baseline_done:
            # Oldest first, so events fire in chronological order.
            new_bulletins = [
                b
                for b in reversed(bulletins)
                if b.bulletin_id not in self._seen
                and not any(cve_id in self._seen for cve_id in b.cve_ids)
                and now - b.published <= MAX_EVENT_AGE
            ]
        self._seen |= current_ids
        self._baseline_done = True

        await self._store.async_save(
            {
                "schema": CACHE_SCHEMA,
                "products": self.products,
                "last_sync": now.isoformat(),
                "baseline_done": True,
                "seen": sorted(self._seen),
                "cves": {cve_id: cve.to_dict() for cve_id, cve in cves.items()},
            }
        )

        return CitrixBulletinData(
            bulletins=bulletins, new_bulletins=new_bulletins, last_sync=now
        )

    @staticmethod
    def _merge(
        cves: dict[str, Cve],
        items: list[dict[str, Any]],
        product: str | None,
        selected: list[str],
    ) -> None:
        """Merge NVD results into the CVE dict.

        product: the product of a CPE query, or None for the CNA query
        (products are then derived from the description).
        """
        for item in items:
            cve_id = item.get("cve", {}).get("id")
            if product is None:
                products = detect_products(english_description(item), selected)
            else:
                products = {product}
            parsed = parse_cve(item, products) if products else None
            if parsed is None:
                # Rejected, unparsable or not relevant for this query.
                if cve_id in cves:
                    if product is not None:
                        cves[cve_id].products.discard(product)
                    elif item.get("cve", {}).get("vulnStatus") == "Rejected":
                        cves[cve_id].products.clear()
                    if not cves[cve_id].products:
                        del cves[cve_id]
                continue
            if (existing := cves.get(parsed.cve_id)) is not None:
                parsed.products |= existing.products
            cves[parsed.cve_id] = parsed
