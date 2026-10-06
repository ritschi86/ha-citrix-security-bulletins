"""Sensor platform for the Citrix Security Bulletins integration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import RECENT_BULLETINS, SEVERITY_LEVELS
from .coordinator import CitrixBulletinCoordinator, CitrixConfigEntry
from .entity import CitrixBulletinEntity
from .models import Bulletin

PARALLEL_UPDATES = 0


@dataclass(frozen=True, kw_only=True)
class CitrixSensorEntityDescription(SensorEntityDescription):
    """Describes a sensor derived from the latest bulletin."""

    value_fn: Callable[[Bulletin], str | float | None]


SENSORS: tuple[CitrixSensorEntityDescription, ...] = (
    CitrixSensorEntityDescription(
        key="cvss_score",
        translation_key="cvss_score",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        value_fn=lambda b: b.cvss_score,
    ),
    CitrixSensorEntityDescription(
        key="severity",
        translation_key="severity",
        device_class=SensorDeviceClass.ENUM,
        options=SEVERITY_LEVELS,
        value_fn=lambda b: b.severity.lower() if b.severity else None,
    ),
    CitrixSensorEntityDescription(
        key="article_url",
        translation_key="article_url",
        value_fn=lambda b: b.url,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CitrixConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the sensor platform."""
    coordinator = entry.runtime_data
    async_add_entities(
        [
            LatestBulletinSensor(coordinator),
            *(CitrixBulletinSensor(coordinator, description) for description in SENSORS),
        ]
    )


class LatestBulletinSensor(CitrixBulletinEntity, SensorEntity):
    """Shows the most recent Citrix security bulletin (CTX ID)."""

    # Large/volatile attributes are not written to the recorder database.
    _unrecorded_attributes = frozenset({"description", "recent_bulletins", "nvd_urls"})

    def __init__(self, coordinator: CitrixBulletinCoordinator) -> None:
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
                    "cvss_score": b.cvss_score,
                    "published": b.published.isoformat(),
                    "url": b.url,
                }
                for b in data.bulletins[:RECENT_BULLETINS]
            ],
            "last_sync": data.last_sync.isoformat() if data.last_sync else None,
        }


class CitrixBulletinSensor(CitrixBulletinEntity, SensorEntity):
    """A single value of the latest bulletin (score, severity, URL)."""

    entity_description: CitrixSensorEntityDescription

    def __init__(
        self,
        coordinator: CitrixBulletinCoordinator,
        description: CitrixSensorEntityDescription,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> str | float | None:
        """Return the value for the latest bulletin."""
        bulletins = self.coordinator.data.bulletins
        return self.entity_description.value_fn(bulletins[0]) if bulletins else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Reference the bulletin the value belongs to."""
        bulletins = self.coordinator.data.bulletins
        return {"bulletin_id": bulletins[0].bulletin_id} if bulletins else None
