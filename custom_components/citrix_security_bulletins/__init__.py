"""The Citrix Security Bulletins integration."""

from __future__ import annotations

from homeassistant.const import CONF_API_KEY, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.storage import Store

from .api import NvdClient
from .const import STORAGE_KEY, STORAGE_VERSION
from .coordinator import CitrixBulletinCoordinator, CitrixConfigEntry

PLATFORMS: list[Platform] = [Platform.EVENT, Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: CitrixConfigEntry) -> bool:
    """Set up Citrix Security Bulletins from a config entry."""
    client = NvdClient(async_get_clientsession(hass), entry.data.get(CONF_API_KEY))
    coordinator = CitrixBulletinCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: CitrixConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_entry(hass: HomeAssistant, entry: CitrixConfigEntry) -> None:
    """Remove the persisted cache when the entry is deleted."""
    await Store(hass, STORAGE_VERSION, f"{STORAGE_KEY}.{entry.entry_id}").async_remove()
