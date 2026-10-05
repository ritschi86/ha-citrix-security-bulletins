"""Base entity for the Citrix Security Bulletins integration."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import CitrixBulletinCoordinator


class CitrixBulletinEntity(CoordinatorEntity[CitrixBulletinCoordinator]):
    """Common base for all entities."""

    _attr_has_entity_name = True
    _attr_attribution = "Data provided by the NIST National Vulnerability Database (NVD)"

    def __init__(self, coordinator: CitrixBulletinCoordinator, key: str) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.entry_id}_{key}"
        self._attr_translation_key = key
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Citrix Security Bulletins",
            manufacturer="Cloud Software Group (Citrix)",
            model="NetScaler Security Bulletins",
            entry_type=DeviceEntryType.SERVICE,
            configuration_url="https://support.citrix.com/user/alerts",
        )
