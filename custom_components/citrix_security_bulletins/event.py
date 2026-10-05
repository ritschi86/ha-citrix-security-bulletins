"""Event platform for the Citrix Security Bulletins integration."""

from __future__ import annotations

from homeassistant.components.event import EventEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import EVENT_TYPE_NEW_BULLETIN
from .coordinator import CitrixConfigEntry
from .entity import CitrixBulletinEntity

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CitrixConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the event platform."""
    async_add_entities([NewBulletinEvent(entry.runtime_data)])


class NewBulletinEvent(CitrixBulletinEntity, EventEntity):
    """Fires when a new Citrix security bulletin is published."""

    _attr_event_types = [EVENT_TYPE_NEW_BULLETIN]

    def __init__(self, coordinator) -> None:
        """Initialize the event entity."""
        super().__init__(coordinator, "new_bulletin")

    async def async_added_to_hass(self) -> None:
        """Fire events detected by the initial refresh (e.g. after a restart)."""
        await super().async_added_to_hass()
        self._fire_new_bulletins()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle fresh coordinator data."""
        if not self._fire_new_bulletins():
            # Only availability may have changed.
            self.async_write_ha_state()

    @callback
    def _fire_new_bulletins(self) -> bool:
        """Fire one event per newly detected bulletin."""
        new_bulletins = self.coordinator.data.new_bulletins
        for bulletin in new_bulletins:
            self._trigger_event(EVENT_TYPE_NEW_BULLETIN, bulletin.as_event_data())
            self.async_write_ha_state()
        return bool(new_bulletins)
