"""Config flow for the Citrix Security Bulletins integration."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlowWithReload,
)
from homeassistant.const import CONF_API_KEY
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .api import NvdAuthError, NvdClient, NvdError
from .const import CONF_PRODUCTS, DEFAULT_PRODUCTS, DOMAIN, PRODUCT_CPES

_LOGGER = logging.getLogger(__name__)

NVD_API_KEY_URL = "https://nvd.nist.gov/developers/request-an-api-key"

API_KEY_SCHEMA = vol.Schema(
    {
        vol.Optional(CONF_API_KEY): TextSelector(
            TextSelectorConfig(type=TextSelectorType.PASSWORD)
        )
    }
)

OPTIONS_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_PRODUCTS, default=DEFAULT_PRODUCTS): SelectSelector(
            SelectSelectorConfig(
                options=list(PRODUCT_CPES),
                multiple=True,
                mode=SelectSelectorMode.LIST,
                translation_key=CONF_PRODUCTS,
            )
        )
    }
)


class CitrixSecurityBulletinsConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow."""

    VERSION = 1

    async def _async_validate(self, api_key: str | None) -> dict[str, str]:
        """Validate connectivity and the optional API key."""
        session = async_get_clientsession(self.hass)
        try:
            await NvdClient(session, api_key).async_validate()
        except NvdAuthError:
            # NVD answers some malformed requests with "Invalid apiKey" as well.
            # Only blame the key if the same request works without it.
            try:
                await NvdClient(session).async_validate()
            except NvdError as err:
                _LOGGER.warning("NVD not reachable without API key either: %s", err)
                return {"base": "cannot_connect"}
            return {CONF_API_KEY: "invalid_api_key"}
        except NvdError as err:
            _LOGGER.warning("NVD validation failed: %s", err)
            return {"base": "cannot_connect"}
        except Exception:
            _LOGGER.exception("Unexpected exception")
            return {"base": "unknown"}
        return {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            api_key = (user_input.get(CONF_API_KEY) or "").strip() or None
            errors = await self._async_validate(api_key)
            if not errors:
                return self.async_create_entry(
                    title="Citrix Security Bulletins",
                    data={CONF_API_KEY: api_key} if api_key else {},
                    options={CONF_PRODUCTS: DEFAULT_PRODUCTS},
                )
        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(API_KEY_SCHEMA, user_input),
            errors=errors,
            description_placeholders={"nvd_url": NVD_API_KEY_URL},
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Change the API key."""
        errors: dict[str, str] = {}
        entry = self._get_reconfigure_entry()
        if user_input is not None:
            api_key = (user_input.get(CONF_API_KEY) or "").strip() or None
            errors = await self._async_validate(api_key)
            if not errors:
                return self.async_update_reload_and_abort(
                    entry, data={CONF_API_KEY: api_key} if api_key else {}
                )
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=self.add_suggested_values_to_schema(
                API_KEY_SCHEMA, user_input or entry.data
            ),
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Start reauthentication when the API key was rejected."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for a new (or no) API key."""
        errors: dict[str, str] = {}
        if user_input is not None:
            api_key = (user_input.get(CONF_API_KEY) or "").strip() or None
            errors = await self._async_validate(api_key)
            if not errors:
                return self.async_update_reload_and_abort(
                    self._get_reauth_entry(),
                    data={CONF_API_KEY: api_key} if api_key else {},
                )
        return self.async_show_form(
            step_id="reauth_confirm", data_schema=API_KEY_SCHEMA, errors=errors
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlowHandler:
        """Create the options flow."""
        return OptionsFlowHandler()


class OptionsFlowHandler(OptionsFlowWithReload):
    """Select the products to monitor."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the options."""
        errors: dict[str, str] = {}
        if user_input is not None:
            if user_input.get(CONF_PRODUCTS):
                return self.async_create_entry(data=user_input)
            errors[CONF_PRODUCTS] = "no_products"
        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(
                OPTIONS_SCHEMA, user_input or self.config_entry.options
            ),
            errors=errors,
        )
