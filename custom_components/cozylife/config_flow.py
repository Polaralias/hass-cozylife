"""Config flow for the CozyLife integration."""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_NAME
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import network, selector
from homeassistant.helpers.translation import async_get_translations

from .const import (
    CONF_AREA,
    CONF_LIGHT_POLL_INTERVAL,
    CONF_SWITCH_POLL_INTERVAL,
    DEFAULT_LIGHT_POLL_INTERVAL,
    DEFAULT_SWITCH_POLL_INTERVAL,
    DOMAIN,
)
from .helpers import (
    normalize_area_value,
    prepare_area_value_for_storage,
    resolve_area_id,
)
from .discovery import discover_devices

DEFAULT_START_IP = "192.168.0.0"
DEFAULT_END_IP = "192.168.0.255"

_LOGGER = logging.getLogger(__name__)


def _coerce_ip(value: str) -> str:
    """Validate and normalise an IPv4 address string."""

    try:
        return str(ipaddress.ip_address(value))
    except ValueError as err:
        raise vol.Invalid("invalid_ip") from err


TIMEOUT_VALIDATOR = vol.All(vol.Coerce(float), vol.Range(min=0.05, max=10.0))
POLL_INTERVAL_VALIDATOR = vol.All(vol.Coerce(float), vol.Range(min=5.0, max=600.0))

class CozyLifeConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the CozyLife config flow."""

    VERSION = 1

    def __init__(self) -> None:
        self._discovered_devices: list[dict[str, Any]] = []
        self._available_devices: list[dict[str, Any]] = []
        self._scan_settings: dict[str, Any] = {}
        self._auto_scan_ranges: list[tuple[str, str]] = []
        self._device_type_labels: dict[str, str] | None = None
        self._pending_devices: list[dict[str, Any]] = []
        self._device_wizard_index: int = 0
        self._device_wizard_results: list[dict[str, Any]] = []

    async def _async_get_device_type_labels(self) -> dict[str, str]:
        """Return translated labels for device types."""

        if self._device_type_labels is not None:
            return self._device_type_labels

        language = self.hass.config.language or "en"
        translations = await async_get_translations(
            self.hass, language, "component", {DOMAIN}
        )

        prefix = f"component.{DOMAIN}.config.labels.device_type."
        labels = {
            "light": translations.get(f"{prefix}light", "Light"),
            "switch": translations.get(f"{prefix}switch", "Switch"),
            "unknown": translations.get(f"{prefix}unknown", "Device"),
        }

        self._device_type_labels = labels
        return labels

    def _build_ip_selector(self) -> selector.TextSelector:
        """Return a text selector configured for IP input."""

        return selector.TextSelector(
            selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
        )

    def _build_timeout_selector(self) -> selector.NumberSelector:
        """Return a number selector for timeouts."""

        return selector.NumberSelector(
            selector.NumberSelectorConfig(
                min=0.05,
                max=10.0,
                step=0.05,
                mode=selector.NumberSelectorMode.BOX,
            )
        )

    async def _async_get_auto_scan_ranges(self) -> list[tuple[str, str]]:
        """Return the automatically detected scan ranges for the host network."""

        if self._auto_scan_ranges:
            return self._auto_scan_ranges

        ranges: list[tuple[str, str]] = []

        try:
            adapters = await network.async_get_adapters(self.hass)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Unable to determine network adapters: %s", err)
            adapters = []

        seen: set[tuple[str, str]] = set()

        for adapter in adapters:
            if not adapter.get("enabled", True):
                continue

            for ipv4_data in adapter.get("ipv4", []):
                if ipv4_data.get("scope") not in (None, "global"):
                    continue

                address = ipv4_data.get("address")
                netmask = ipv4_data.get("netmask")

                if not address or not netmask:
                    continue

                try:
                    interface = ipaddress.IPv4Interface(f"{address}/{netmask}")
                except ValueError:
                    continue

                network_details = interface.network

                start = str(network_details.network_address)
                end = str(network_details.broadcast_address)

                if (start, end) in seen:
                    continue

                seen.add((start, end))
                ranges.append((start, end))

        self._auto_scan_ranges = ranges
        return self._auto_scan_ranges

    async def async_step_user(
        self, user_input: Mapping[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step initiated by the user."""

        errors: dict[str, str] = {}

        if user_input is None:
            self._discovered_devices = []
            self._available_devices = []
            self._pending_devices = []
            self._device_wizard_index = 0
            self._device_wizard_results = []

        detected_auto_ranges = await self._async_get_auto_scan_ranges()
        effective_auto_ranges = (
            detected_auto_ranges
            if detected_auto_ranges
            else [(DEFAULT_START_IP, DEFAULT_END_IP)]
        )

        suggested_start = (
            user_input.get("start_ip")
            if user_input and "start_ip" in user_input
            else effective_auto_ranges[0][0]
        )
        suggested_end = (
            user_input.get("end_ip")
            if user_input and "end_ip" in user_input
            else effective_auto_ranges[0][1]
        )
        suggested_timeout = (
            user_input.get("timeout")
            if user_input and "timeout" in user_input
            else 0.3
        )

        use_custom_range = bool(user_input and user_input.get("use_custom_range"))
        if (
            not use_custom_range
            and user_input is not None
            and (user_input.get("start_ip") or user_input.get("end_ip"))
        ):
            # Treat manual IP input as opting into custom mode even if the
            # toggle was not explicitly enabled.
            use_custom_range = True

        show_manual_fields = use_custom_range

        if user_input is not None:
            try:
                timeout = TIMEOUT_VALIDATOR(user_input.get("timeout", 0.3))
            except vol.Invalid:
                errors["timeout"] = "invalid_timeout"
                timeout = 0.3
            else:
                suggested_timeout = timeout

            ranges_to_scan: list[tuple[str, str]] = []

            if use_custom_range:
                start_ip = user_input.get("start_ip", "")
                end_ip = user_input.get("end_ip", "")

                if not start_ip or not end_ip:
                    errors["base"] = "manual_range_required"
                else:
                    try:
                        start_ip = _coerce_ip(start_ip)
                    except vol.Invalid:
                        errors["start_ip"] = "invalid_ip"

                    try:
                        end_ip = _coerce_ip(end_ip)
                    except vol.Invalid:
                        errors["end_ip"] = "invalid_ip"

                    if not errors and int(ipaddress.ip_address(start_ip)) > int(
                        ipaddress.ip_address(end_ip)
                    ):
                        errors["end_ip"] = "range_order"

                    if not errors:
                        ranges_to_scan = [(start_ip, end_ip)]
            else:
                ranges_to_scan = effective_auto_ranges

            if not errors and ranges_to_scan:
                seen_devices: set[str] = set()
                discovered_devices: list[dict[str, Any]] = []
                any_devices_found = False

                for start_ip, end_ip in ranges_to_scan:
                    devices = await self.hass.async_add_executor_job(
                        discover_devices, start_ip, end_ip, timeout
                    )

                    for category, items in devices.items():
                        if items:
                            any_devices_found = True

                        for device in items:
                            device_id = device.get("did")
                            if not device_id or device_id in seen_devices:
                                continue

                            seen_devices.add(device_id)
                            discovered_devices.append(device)

                if not any_devices_found:
                    errors["base"] = "no_devices_found"
                else:
                    existing_entries: dict[str, config_entries.ConfigEntry] = {}

                    for entry in self._async_current_entries():
                        identifiers: set[str] = set()

                        if entry.unique_id:
                            identifiers.add(entry.unique_id)

                        data = entry.data

                        device_info = data.get("device")
                        if isinstance(device_info, Mapping):
                            device_id = device_info.get("did")
                            if isinstance(device_id, str):
                                identifiers.add(device_id)

                        devices_value = data.get("devices")
                        if isinstance(devices_value, list):
                            for device_entry in devices_value:
                                if not isinstance(device_entry, Mapping):
                                    continue

                                payload = device_entry.get("device")
                                if isinstance(payload, Mapping):
                                    device_id = payload.get("did")
                                else:
                                    device_id = device_entry.get("did")

                                if isinstance(device_id, str):
                                    identifiers.add(device_id)
                        elif isinstance(devices_value, Mapping):
                            for device_entry in devices_value.values():
                                if isinstance(device_entry, list):
                                    candidate_items = device_entry
                                else:
                                    candidate_items = [device_entry]

                                for item in candidate_items:
                                    if not isinstance(item, Mapping):
                                        continue

                                    device_id = item.get("did")
                                    if isinstance(device_id, str):
                                        identifiers.add(device_id)

                        for identifier in identifiers:
                            existing_entries.setdefault(identifier, entry)

                    enriched_devices: list[dict[str, Any]] = []
                    for device in discovered_devices:
                        device_id = device.get("did")
                        configured_entry = (
                            existing_entries.get(device_id) if device_id else None
                        )

                        enriched_devices.append(
                            {
                                **device,
                                "configured": configured_entry is not None,
                                "configured_entry_title": (
                                    configured_entry.title if configured_entry else None
                                ),
                            }
                        )

                    self._scan_settings = {
                        "mode": "custom" if use_custom_range else "auto",
                        "ranges": ranges_to_scan,
                        "timeout": timeout,
                    }

                    self._discovered_devices = sorted(
                        enriched_devices,
                        key=lambda item: (
                            item.get("configured", False),
                            item.get("type", ""),
                            item.get("dmn") or "",
                            item.get("ip") or "",
                        ),
                    )

                    self._available_devices = [
                        device
                        for device in self._discovered_devices
                        if not device.get("configured")
                    ]

                    self._pending_devices = list(self._available_devices)
                    self._device_wizard_index = 0
                    self._device_wizard_results = []

                    return await self.async_step_device()

        description_default_start = (
            suggested_start if suggested_start else effective_auto_ranges[0][0]
        )
        description_default_end = (
            suggested_end if suggested_end else effective_auto_ranges[0][1]
        )

        placeholders = {
            "auto": ", ".join(
                f"{start} – {end}" for start, end in detected_auto_ranges
            )
            if detected_auto_ranges
            else f"{DEFAULT_START_IP} – {DEFAULT_END_IP}",
            "protocol": "a TCP probe on port 5555",
            "default_range": f"{description_default_start} – {description_default_end}",
        }

        schema = self._build_user_schema(
            show_manual_fields,
            suggested_start,
            suggested_end,
            suggested_timeout,
            use_custom_range,
        )

        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(
                schema,
                user_input or {},
            ),
            errors=errors,
            description_placeholders=placeholders,
        )

    def _build_user_schema(
        self,
        show_manual_fields: bool,
        suggested_start: str,
        suggested_end: str,
        suggested_timeout: float,
        use_custom_range: bool,
    ) -> vol.Schema:
        """Construct the dynamic schema for the user step."""

        schema_fields: dict[Any, Any] = {
            vol.Required("use_custom_range", default=use_custom_range): selector.BooleanSelector(),
        }

        if show_manual_fields:
            schema_fields.update(
                {
                    vol.Required("start_ip", default=suggested_start): self._build_ip_selector(),
                    vol.Required("end_ip", default=suggested_end): self._build_ip_selector(),
                }
            )

        schema_fields[vol.Required("timeout", default=suggested_timeout)] = (
            self._build_timeout_selector()
        )

        return vol.Schema(schema_fields)

    async def async_step_device(
        self, user_input: Mapping[str, Any] | None = None
    ) -> FlowResult:
        """Guide the user through configuring each discovered device."""

        errors: dict[str, str] = {}

        if not self._discovered_devices:
            return self.async_abort(reason="no_devices_found")

        type_labels = await self._async_get_device_type_labels()

        summary_lines: list[str] = []
        for device in self._discovered_devices:
            label_type = type_labels.get(
                device.get("type"),
                type_labels["unknown"],
            )
            model = device.get("dmn") or type_labels["unknown"]
            label = f"{label_type}: {model} ({device['ip']})"

            configured_title = device.get("configured_entry_title")
            if device.get("configured"):
                status = (
                    f"Configured as \"{configured_title}\""
                    if configured_title
                    else "Configured"
                )
            else:
                status = "Not configured"

            summary_lines.append(f"• {label} — {status}")

        summary_text = "\n".join(summary_lines)

        if not self._available_devices:
            if user_input is not None:
                return self.async_abort(reason="all_devices_configured")

            return self.async_show_form(
                step_id="device",
                data_schema=vol.Schema({}),
                errors={"base": "all_devices_configured"},
                description_placeholders={
                    "device_overview": summary_text,
                },
            )

        if not self._pending_devices:
            self._pending_devices = list(self._available_devices)
            self._device_wizard_index = 0
            self._device_wizard_results = []

        if self._device_wizard_index >= len(self._pending_devices):
            return await self._async_finish_device_wizard()

        current_device = self._pending_devices[self._device_wizard_index]

        if user_input is not None:
            name_input = (user_input.get(CONF_NAME) or "").strip()
            area_input = prepare_area_value_for_storage(
                self.hass, user_input.get(CONF_AREA)
            )

            device_payload = {
                key: value
                for key, value in current_device.items()
                if key not in {"configured", "configured_entry_title"}
            }

            self._device_wizard_results.append(
                {
                    "device": device_payload,
                    CONF_NAME: name_input or None,
                    CONF_AREA: area_input or None,
                }
            )
            self._device_wizard_index += 1

            if self._device_wizard_index >= len(self._pending_devices):
                return await self._async_finish_device_wizard()

            return await self.async_step_device()

        default_name = current_device.get("dmn") or current_device.get("did") or ""

        schema = vol.Schema(
            {
                vol.Optional(CONF_NAME, default=default_name): selector.TextSelector(),
                vol.Optional(CONF_AREA): selector.AreaSelector(),
            }
        )

        sanitized_input: dict[str, Any]
        if user_input is None:
            sanitized_input = {}
        else:
            sanitized_input = dict(user_input)
            if sanitized_input.get(CONF_NAME) is None:
                sanitized_input.pop(CONF_NAME, None)
            if not sanitized_input.get(CONF_AREA):
                sanitized_input.pop(CONF_AREA, None)

        label_type = type_labels.get(
            current_device.get("type"),
            type_labels["unknown"],
        )
        model = current_device.get("dmn") or type_labels["unknown"]
        current_label = f"{label_type}: {model} ({current_device['ip']})"
        progress = f"{self._device_wizard_index + 1} / {len(self._pending_devices)}"

        return self.async_show_form(
            step_id="device",
            data_schema=self.add_suggested_values_to_schema(
                schema,
                sanitized_input,
            ),
            errors=errors,
            description_placeholders={
                "device_overview": summary_text,
                "current_device": current_label,
                "progress": progress,
            },
        )

    async def _async_finish_device_wizard(self) -> FlowResult:
        """Create config entries for the collected device details."""

        if not self._device_wizard_results:
            return self.async_abort(reason="no_devices_found")

        timeout = self._scan_settings.get("timeout", 0.3)

        if len(self._device_wizard_results) == 1:
            device_entry = self._device_wizard_results[0]
            device_payload = dict(device_entry.get("device", {}))
            name_value = device_entry.get(CONF_NAME)
            area_value = device_entry.get(CONF_AREA)

            title = (
                name_value
                or device_payload.get("dmn")
                or device_payload.get("did")
                or "CozyLife device"
            )

            data = {
                "device": device_payload,
                "timeout": timeout,
            }

            if name_value:
                data[CONF_NAME] = name_value
            if area_value:
                data[CONF_AREA] = area_value

            unique_id = device_payload.get("did")
            if unique_id:
                await self.async_set_unique_id(unique_id)
                self._abort_if_unique_id_configured()

            return self.async_create_entry(title=title, data=data)

        devices_payload: list[dict[str, Any]] = []
        for device_entry in self._device_wizard_results:
            device_payload = dict(device_entry.get("device", {}))
            item: dict[str, Any] = {"device": device_payload}
            if device_entry.get(CONF_NAME):
                item[CONF_NAME] = device_entry[CONF_NAME]
            if device_entry.get(CONF_AREA):
                item[CONF_AREA] = device_entry[CONF_AREA]
            devices_payload.append(item)

        title = f"{len(devices_payload)} CozyLife devices"
        data: dict[str, Any] = {
            "devices": devices_payload,
            "timeout": timeout,
        }

        if self._scan_settings:
            data["scan_settings"] = self._scan_settings

        return self.async_create_entry(title=title, data=data)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> config_entries.OptionsFlow:
        """Return the options flow handler."""

        return CozyLifeOptionsFlow(config_entry)


class CozyLifeOptionsFlow(config_entries.OptionsFlow):
    """Handle options for the CozyLife integration."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self.config_entry = config_entry
        self._multi_devices: list[dict[str, Any]] = []
        self._multi_results: list[dict[str, Any]] = []
        self._multi_index: int = 0
        self._multi_timeout: float = 0.3
        self._multi_initialized = False
        self._light_poll_interval: float = float(
            config_entry.options.get(
                CONF_LIGHT_POLL_INTERVAL, DEFAULT_LIGHT_POLL_INTERVAL
            )
        )
        self._switch_poll_interval: float = float(
            config_entry.options.get(
                CONF_SWITCH_POLL_INTERVAL, DEFAULT_SWITCH_POLL_INTERVAL
            )
        )
        self._multi_light_poll_interval: float = self._light_poll_interval
        self._multi_switch_poll_interval: float = self._switch_poll_interval

    def _build_ip_selector(self) -> selector.TextSelector:
        """Return a text selector configured for IP input."""

        return selector.TextSelector(
            selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
        )

    def _build_timeout_selector(self) -> selector.NumberSelector:
        """Return a number selector for timeouts."""

        return selector.NumberSelector(
            selector.NumberSelectorConfig(
                min=0.05,
                max=10.0,
                step=0.05,
                mode=selector.NumberSelectorMode.BOX,
            )
        )

    def _build_poll_interval_selector(self) -> selector.NumberSelector:
        """Return a number selector for polling intervals."""

        return selector.NumberSelector(
            selector.NumberSelectorConfig(
                min=5,
                max=600,
                step=5,
                mode=selector.NumberSelectorMode.BOX,
            )
        )

    async def async_step_init(
        self, user_input: Mapping[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options for the integration."""

        errors: dict[str, str] = {}

        data = self.config_entry.data

        if isinstance(data.get("devices"), list):
            return await self._async_step_multi(user_input)

        if "device" not in data:
            return await self._async_step_legacy(user_input)

        device = data.get("device", {})

        if user_input is not None:
            ip_value = user_input.get("ip", "")
            timeout_value = user_input.get("timeout")
            name_value = (user_input.get(CONF_NAME) or "").strip()
            area_value = prepare_area_value_for_storage(
                self.hass, user_input.get(CONF_AREA)
            )
            light_poll_input = user_input.get(
                CONF_LIGHT_POLL_INTERVAL, self._light_poll_interval
            )
            switch_poll_input = user_input.get(
                CONF_SWITCH_POLL_INTERVAL, self._switch_poll_interval
            )

            try:
                ip_value = _coerce_ip(ip_value)
            except vol.Invalid:
                errors["ip"] = "invalid_ip"

            try:
                timeout_value = float(timeout_value)
            except (TypeError, ValueError):
                errors["timeout"] = "invalid_timeout"
            else:
                if not 0.05 <= timeout_value <= 10.0:
                    errors["timeout"] = "invalid_timeout"

            try:
                light_poll_value = POLL_INTERVAL_VALIDATOR(light_poll_input)
            except vol.Invalid:
                errors[CONF_LIGHT_POLL_INTERVAL] = "invalid_poll_interval"
                light_poll_value = None
            else:
                light_poll_value = float(light_poll_value)

            try:
                switch_poll_value = POLL_INTERVAL_VALIDATOR(switch_poll_input)
            except vol.Invalid:
                errors[CONF_SWITCH_POLL_INTERVAL] = "invalid_poll_interval"
                switch_poll_value = None
            else:
                switch_poll_value = float(switch_poll_value)

            if not errors:
                updated_device = {**device, "ip": ip_value}
                updated_data = {
                    **data,
                    "device": updated_device,
                    "timeout": timeout_value,
                    CONF_NAME: name_value or None,
                    CONF_AREA: area_value or None,
                }

                if "location" in updated_data:
                    updated_data.pop("location", None)
                if "name" in updated_data and CONF_NAME in updated_data:
                    updated_data.pop("name", None)

                options_data = {
                    **self.config_entry.options,
                    CONF_LIGHT_POLL_INTERVAL: int(light_poll_value),
                    CONF_SWITCH_POLL_INTERVAL: int(switch_poll_value),
                }

                self.hass.config_entries.async_update_entry(
                    self.config_entry, data=updated_data
                )
                await self.hass.config_entries.async_reload(
                    self.config_entry.entry_id
                )
                return self.async_create_entry(title="", data=options_data)

        suggested_name = (
            data.get(CONF_NAME)
            or data.get("name")
            or device.get("dmn")
            or device.get("did")
        )
        raw_area = data.get(CONF_AREA) or data.get("location") or None
        suggested_area = resolve_area_id(self.hass, raw_area)
        suggested_ip = device.get("ip", "")
        suggested_timeout = data.get("timeout", 0.3)

        area_field: Any
        if suggested_area is None:
            area_field = vol.Optional(CONF_AREA)
        else:
            area_field = vol.Optional(CONF_AREA, default=suggested_area)

        options_schema = vol.Schema(
            {
                vol.Required("ip", default=suggested_ip): self._build_ip_selector(),
                vol.Required("timeout", default=suggested_timeout): self._build_timeout_selector(),
                vol.Required(
                    CONF_LIGHT_POLL_INTERVAL, default=self._light_poll_interval
                ): self._build_poll_interval_selector(),
                vol.Required(
                    CONF_SWITCH_POLL_INTERVAL, default=self._switch_poll_interval
                ): self._build_poll_interval_selector(),
                vol.Optional(CONF_NAME, default=suggested_name or ""): selector.TextSelector(),
                area_field: selector.AreaSelector(),
            }
        )

        sanitized_input: dict[str, Any]
        if user_input is None:
            sanitized_input = {}
        else:
            sanitized_input = dict(user_input)
            if sanitized_input.get(CONF_NAME) is None:
                sanitized_input.pop(CONF_NAME, None)
            if not sanitized_input.get(CONF_AREA):
                sanitized_input.pop(CONF_AREA, None)

        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(
                options_schema, sanitized_input
            ),
            errors=errors,
        )

    async def _async_step_multi(
        self, user_input: Mapping[str, Any] | None
    ) -> FlowResult:
        """Handle options updates for multi-device entries."""

        errors: dict[str, str] = {}

        if not self._multi_initialized:
            data = self.config_entry.data
            self._multi_devices = [dict(device) for device in data.get("devices", [])]
            self._multi_results = []
            self._multi_index = 0
            self._multi_timeout = data.get("timeout", 0.3)
            self._multi_light_poll_interval = self._light_poll_interval
            self._multi_switch_poll_interval = self._switch_poll_interval
            self._multi_initialized = True

        if not self._multi_devices:
            return self.async_abort(reason="no_devices_found")

        if self._multi_index < len(self._multi_devices):
            device_entry = self._multi_devices[self._multi_index]
            device_info = dict(device_entry.get("device", {}))
            current_ip = device_info.get("ip", "")
            suggested_name = (
                device_entry.get(CONF_NAME)
                or device_info.get("dmn")
                or device_info.get("did")
                or ""
            )
            raw_area = device_entry.get(CONF_AREA) or device_info.get("location")
            suggested_area = resolve_area_id(self.hass, raw_area)

            if user_input is not None:
                ip_value = user_input.get("ip", current_ip)
                name_value = (user_input.get(CONF_NAME) or "").strip()
                area_input = prepare_area_value_for_storage(
                    self.hass, user_input.get(CONF_AREA)
                )

                try:
                    ip_value = _coerce_ip(ip_value)
                except vol.Invalid:
                    errors["ip"] = "invalid_ip"

                if not errors:
                    updated_device = {**device_info, "ip": ip_value}
                    result_entry: dict[str, Any] = {"device": updated_device}
                    if name_value:
                        result_entry[CONF_NAME] = name_value
                    if area_input:
                        result_entry[CONF_AREA] = area_input
                    self._multi_results.append(result_entry)
                    self._multi_index += 1
                    return await self._async_step_multi(None)

            schema_fields: dict[Any, Any] = {
                vol.Required("ip", default=current_ip): self._build_ip_selector(),
                vol.Optional(CONF_NAME, default=suggested_name): selector.TextSelector(),
            }

            if suggested_area is None:
                area_field = vol.Optional(CONF_AREA)
            else:
                area_field = vol.Optional(CONF_AREA, default=suggested_area)

            schema_fields[area_field] = selector.AreaSelector()
            schema = vol.Schema(schema_fields)

            sanitized_input: dict[str, Any]
            if user_input is None:
                sanitized_input = {}
            else:
                sanitized_input = dict(user_input)
                if sanitized_input.get(CONF_NAME) is None:
                    sanitized_input.pop(CONF_NAME, None)
                if not sanitized_input.get(CONF_AREA):
                    sanitized_input.pop(CONF_AREA, None)

            device_label = (
                device_info.get("dmn")
                or device_info.get("did")
                or device_info.get("ip")
                or "device"
            )
            progress = f"{self._multi_index + 1} / {len(self._multi_devices)}"

            return self.async_show_form(
                step_id="init",
                data_schema=self.add_suggested_values_to_schema(
                    schema, sanitized_input
                ),
                errors=errors,
                description_placeholders={
                    "progress": progress,
                    "current_device": device_label,
                },
            )

        if user_input is not None:
            try:
                timeout_value = float(user_input.get("timeout"))
            except (TypeError, ValueError):
                errors["timeout"] = "invalid_timeout"
            else:
                if not 0.05 <= timeout_value <= 10.0:
                    errors["timeout"] = "invalid_timeout"

            try:
                light_poll_value = POLL_INTERVAL_VALIDATOR(
                    user_input.get(
                        CONF_LIGHT_POLL_INTERVAL, self._multi_light_poll_interval
                    )
                )
            except vol.Invalid:
                errors[CONF_LIGHT_POLL_INTERVAL] = "invalid_poll_interval"
                light_poll_value = None

            try:
                switch_poll_value = POLL_INTERVAL_VALIDATOR(
                    user_input.get(
                        CONF_SWITCH_POLL_INTERVAL, self._multi_switch_poll_interval
                    )
                )
            except vol.Invalid:
                errors[CONF_SWITCH_POLL_INTERVAL] = "invalid_poll_interval"
                switch_poll_value = None

            if not errors:
                updated_devices: list[dict[str, Any]] = []

                for result in self._multi_results:
                    device_payload = dict(result.get("device", {}))
                    entry_payload: dict[str, Any] = {"device": device_payload}
                    if result.get(CONF_NAME):
                        entry_payload[CONF_NAME] = result[CONF_NAME]
                    if result.get(CONF_AREA):
                        entry_payload[CONF_AREA] = result[CONF_AREA]
                    updated_devices.append(entry_payload)

                new_data = {
                    **self.config_entry.data,
                    "devices": updated_devices,
                    "timeout": timeout_value,
                }

                options_data = {
                    **self.config_entry.options,
                    CONF_LIGHT_POLL_INTERVAL: int(light_poll_value),
                    CONF_SWITCH_POLL_INTERVAL: int(switch_poll_value),
                }

                self.hass.config_entries.async_update_entry(
                    self.config_entry, data=new_data
                )
                await self.hass.config_entries.async_reload(
                    self.config_entry.entry_id
                )
                return self.async_create_entry(title="", data=options_data)

        timeout_selector = self._build_timeout_selector()
        poll_selector = self._build_poll_interval_selector()
        schema = vol.Schema(
            {
                vol.Required("timeout", default=self._multi_timeout): timeout_selector,
                vol.Required(
                    CONF_LIGHT_POLL_INTERVAL, default=self._multi_light_poll_interval
                ): poll_selector,
                vol.Required(
                    CONF_SWITCH_POLL_INTERVAL,
                    default=self._multi_switch_poll_interval,
                ): poll_selector,
            }
        )

        sanitized_input = {} if user_input is None else dict(user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(schema, sanitized_input),
            errors=errors,
        )

    async def _async_step_legacy(
        self, user_input: Mapping[str, Any] | None
    ) -> FlowResult:
        """Handle options for legacy search-based entries."""

        errors: dict[str, str] = {}
        timeout_selector = self._build_timeout_selector()
        ip_selector = self._build_ip_selector()
        poll_selector = self._build_poll_interval_selector()

        if user_input is not None:
            start_ip = user_input.get("start_ip", "")
            end_ip = user_input.get("end_ip", "")

            try:
                start_ip = _coerce_ip(start_ip)
            except vol.Invalid:
                errors["start_ip"] = "invalid_ip"

            try:
                end_ip = _coerce_ip(end_ip)
            except vol.Invalid:
                errors["end_ip"] = "invalid_ip"

            if not errors and int(ipaddress.ip_address(start_ip)) > int(
                ipaddress.ip_address(end_ip)
            ):
                errors["end_ip"] = "range_order"

            timeout_value = user_input.get("timeout")
            if timeout_value is None:
                timeout_value = self.config_entry.data.get("timeout", 0.3)

            if not errors:
                timeout = float(timeout_value)

                try:
                    light_poll_value = POLL_INTERVAL_VALIDATOR(
                        user_input.get(
                            CONF_LIGHT_POLL_INTERVAL, self._light_poll_interval
                        )
                    )
                except vol.Invalid:
                    errors[CONF_LIGHT_POLL_INTERVAL] = "invalid_poll_interval"
                    light_poll_value = None

                try:
                    switch_poll_value = POLL_INTERVAL_VALIDATOR(
                        user_input.get(
                            CONF_SWITCH_POLL_INTERVAL, self._switch_poll_interval
                        )
                    )
                except vol.Invalid:
                    errors[CONF_SWITCH_POLL_INTERVAL] = "invalid_poll_interval"
                    switch_poll_value = None

            if not errors:
                devices = await self.hass.async_add_executor_job(
                    discover_devices, start_ip, end_ip, timeout
                )

                if not any(devices.values()):
                    errors["base"] = "no_devices_found"
                else:
                    data = {
                        "start_ip": start_ip,
                        "end_ip": end_ip,
                        "timeout": timeout,
                        "devices": devices,
                    }
                    options_data = {
                        **self.config_entry.options,
                        CONF_LIGHT_POLL_INTERVAL: int(light_poll_value),
                        CONF_SWITCH_POLL_INTERVAL: int(switch_poll_value),
                    }
                    self.hass.config_entries.async_update_entry(
                        self.config_entry, data=data
                    )
                    await self.hass.config_entries.async_reload(
                        self.config_entry.entry_id
                    )
                    return self.async_create_entry(title="", data=options_data)

        current = self.config_entry.data
        suggested = {
            "start_ip": current.get("start_ip"),
            "end_ip": current.get("end_ip"),
            "timeout": current.get("timeout", 0.3),
        }

        legacy_schema = vol.Schema(
            {
                vol.Required("start_ip", default=suggested["start_ip"]): ip_selector,
                vol.Required("end_ip", default=suggested["end_ip"]): ip_selector,
                vol.Required("timeout", default=suggested["timeout"]): timeout_selector,
                vol.Required(
                    CONF_LIGHT_POLL_INTERVAL, default=self._light_poll_interval
                ): poll_selector,
                vol.Required(
                    CONF_SWITCH_POLL_INTERVAL, default=self._switch_poll_interval
                ): poll_selector,
            }
        )

        return self.async_show_form(
            step_id="init",
            data_schema=legacy_schema,
            errors=errors,
        )
