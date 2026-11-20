"""Config flow: log in with e-mail and password (or paste a session cookie)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import aiohttp
import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.selector import (
    BooleanSelector,
    EntitySelector,
    EntitySelectorConfig,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .api import (
    TechemAuthError,
    TechemClient,
    TechemError,
    TechemInteractionRequired,
    login,
    parse_cookies,
)
from .const import CONF_COOKIES, CONF_VALVES, CONF_WEATHER, DOMAIN

CREDENTIALS_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): TextSelector(
            TextSelectorConfig(type=TextSelectorType.EMAIL, autocomplete="username")
        ),
        vol.Required(CONF_PASSWORD): TextSelector(
            TextSelectorConfig(type=TextSelectorType.PASSWORD, autocomplete="current-password")
        ),
    }
)
PASSWORD_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_PASSWORD): TextSelector(
            TextSelectorConfig(type=TextSelectorType.PASSWORD, autocomplete="current-password")
        )
    }
)
COOKIE_SCHEMA = vol.Schema({vol.Required("cookie"): TextSelector(TextSelectorConfig(multiline=True))})


class TechemConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return TechemOptionsFlow()

    async def _login(self, username: str, password: str) -> dict[str, str]:
        """Log in with credentials; needs its own real cookie jar."""
        session = async_create_clientsession(self.hass, cookie_jar=aiohttp.CookieJar())
        return await login(session, username, password)

    async def _validate(self, cookies: dict[str, str]) -> tuple[str, dict[str, str]]:
        """Confirm the cookies work; return the account id and the rolled cookies."""
        client = TechemClient(
            async_create_clientsession(self.hass, cookie_jar=aiohttp.DummyCookieJar()), cookies
        )
        user = await client.session_user()
        await client.units()
        return user, client.cookies

    # --- initial setup ----------------------------------------------------------

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        return self.async_show_menu(step_id="user", menu_options=["credentials", "cookie"])

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input:
            try:
                cookies = await self._login(user_input[CONF_USERNAME], user_input[CONF_PASSWORD])
                user, cookies = await self._validate(cookies)
            except TechemInteractionRequired:
                errors["base"] = "interaction_required"
            except TechemAuthError:
                errors["base"] = "invalid_auth"
            except (TechemError, aiohttp.ClientError, TimeoutError):
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(user)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title="Techem",
                    data={
                        CONF_COOKIES: cookies,
                        CONF_USERNAME: user_input[CONF_USERNAME],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                    },
                )
        return self.async_show_form(
            step_id="credentials", data_schema=CREDENTIALS_SCHEMA, errors=errors
        )

    async def async_step_cookie(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input:
            cookies = parse_cookies(user_input["cookie"])
            if not cookies:
                errors["base"] = "bad_cookie"
            else:
                try:
                    user, cookies = await self._validate(cookies)
                except TechemAuthError:
                    errors["base"] = "invalid_auth"
                except (TechemError, aiohttp.ClientError, TimeoutError):
                    errors["base"] = "cannot_connect"
                else:
                    await self.async_set_unique_id(user)
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(title="Techem", data={CONF_COOKIES: cookies})
        return self.async_show_form(step_id="cookie", data_schema=COOKIE_SCHEMA, errors=errors)

    # --- reauth -----------------------------------------------------------------

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        username = entry.data.get(CONF_USERNAME)
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                if username:
                    cookies = await self._login(username, user_input[CONF_PASSWORD])
                else:
                    cookies = parse_cookies(user_input["cookie"])
                    if not cookies:
                        errors["base"] = "bad_cookie"
                if not errors:
                    user, cookies = await self._validate(cookies)
            except TechemInteractionRequired:
                errors["base"] = "interaction_required"
            except TechemAuthError:
                errors["base"] = "invalid_auth"
            except (TechemError, aiohttp.ClientError, TimeoutError):
                errors["base"] = "cannot_connect"
            else:
                if not errors:
                    await self.async_set_unique_id(user)
                    self._abort_if_unique_id_mismatch()
                    data = {**entry.data, CONF_COOKIES: cookies}
                    if username:
                        data[CONF_PASSWORD] = user_input[CONF_PASSWORD]
                    return self.async_update_reload_and_abort(entry, data=data)
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=PASSWORD_SCHEMA if username else COOKIE_SCHEMA,
            errors=errors,
            description_placeholders={"email": username or ""},
        )


class TechemOptionsFlow(OptionsFlow):
    """Model inputs: radiator valves and whether to fetch weather from Open-Meteo."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data=user_input)
        opts = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Optional(CONF_WEATHER, default=opts.get(CONF_WEATHER, True)): BooleanSelector(),
                vol.Optional(CONF_VALVES, default=opts.get(CONF_VALVES, [])): EntitySelector(
                    EntitySelectorConfig(domain="sensor", multiple=True)
                ),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
