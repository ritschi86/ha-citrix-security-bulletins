"""Sensor platform for the Citrix Security Bulletins integration."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import RECENT_BULLETINS
from .coordinator import CitrixConfigEntry
from .entity import CitrixBulletinEntity

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CitrixConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the sensor platform."""
    async_add_entities([LatestBulletinSensor(entry.runtime_data)])


class LatestBulletinSensor(CitrixBulletinEntity, SensorEntity):
    """Shows the most recent Citrix security bulletin (CTX ID)."""

    # Large/volatile attributes are not written to the recorder database.
    _unrecorded_attributes = frozenset({"description", "recent_bulletins"})

    def __init__(self, coordinator) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, "latest_bulletin")

    @property
    def native_value(self) -> str | None:
        """Return the ID of the latest bulletin."""
        bulletins = self.coordinator.data.bulletins
        return bulletins[0].bulletin_id if bulletins else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return details of the latest bulletin."""
        data = self.coordinator.data
        if not data.bulletins:
            return {"last_sync": data.last_sync.isoformat() if data.last_sync else None}
        latest = data.bulletins[0]
        return {
            **latest.as_event_data(),
            "description": " ".join(
                f"{cve.cve_id}: {cve.description}" for cve in latest.cves
            )[:2000],
            "recent_bulletins": [
                {
                    "bulletin_id": b.bulletin_id,
                    "title": b.title,
                    "severity": b.severity,
                    "published": b.published.isoformat(),
                    "url": b.url,
                }
                for b in data.bulletins[:RECENT_BULLETINS]
            ],
            "last_sync": data.last_sync.isoformat() if data.last_sync else None,
        }
