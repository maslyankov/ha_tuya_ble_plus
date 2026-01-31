"""The Tuya BLE integration."""
from __future__ import annotations

import logging

from bleak_retry_connector import BLEAK_RETRY_EXCEPTIONS as BLEAK_EXCEPTIONS, get_device
from bleak import BleakScanner

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth.match import ADDRESS, BluetoothCallbackMatcher
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady

from .tuya_ble import TuyaBLEDevice

from .cloud import HASSTuyaBLEDeviceManager
from .const import DOMAIN
from .devices import TuyaBLECoordinator, TuyaBLEData, get_device_product_info

PLATFORMS: list[Platform] = [
    Platform.BUTTON,
    Platform.CLIMATE,
    Platform.NUMBER,
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.LIGHT,
    Platform.SELECT,
    Platform.SWITCH,
    Platform.TEXT,
]

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Tuya BLE from a config entry."""
    address: str = entry.data[CONF_ADDRESS].upper()
    ble_device = None
    advertised_connectable = False

    # Try to get connectable device first
    ble_device = bluetooth.async_ble_device_from_address(hass, address, True)
    if ble_device:
        advertised_connectable = True
        _LOGGER.debug("Device %s found as connectable", address)

    # If not found as connectable, try non-connectable (some devices advertise this way)
    if not ble_device:
        service_info = bluetooth.async_last_service_info(hass, address, connectable=False)
        if service_info:
            ble_device = service_info.device
            _LOGGER.info(
                "Device %s is advertising as non-connectable. "
                "Will attempt connection anyway - many devices are still "
                "connectable despite this flag.",
                address
            )

    # Last resort: try bleak directly
    if not ble_device:
        try:
            ble_device = await get_device(address)
            advertised_connectable = True  # If bleak found it, assume connectable
            _LOGGER.debug("Device %s found via bleak directly", address)
        except Exception as ex:
            _LOGGER.debug("Failed to get device via bleak: %s", ex)

    if not ble_device:
        raise ConfigEntryNotReady(
            f"Could not find Tuya BLE device with address {address}"
        )
    manager = HASSTuyaBLEDeviceManager(hass, entry.options.copy())
    device = TuyaBLEDevice(manager, ble_device)
    await device.initialize()
    product_info = get_device_product_info(device)

    coordinator = TuyaBLECoordinator(hass, device)

    # Always attempt to connect, regardless of advertised connectable status.
    # The BLE "connectable" flag is advisory - many devices (especially battery-powered
    # ones like Fingerbot Touch) advertise as non-connectable but still accept connections.
    _LOGGER.debug(
        "Device %s: attempting initial connection (advertised_connectable=%s, category=%s)",
        address,
        advertised_connectable,
        device.category,
    )
    hass.add_job(device.update())

    @callback
    def _async_update_ble(
        service_info: bluetooth.BluetoothServiceInfoBleak,
        change: bluetooth.BluetoothChange,
    ) -> None:
        """Update from a ble callback."""
        device.set_ble_device_and_advertisement_data(
            service_info.device, service_info.advertisement
        )

        # For battery-powered devices (category "kg"), always try to connect when
        # we receive ANY advertisement - they may only advertise briefly when awake.
        # The "connectable" flag is advisory and often incorrect for these devices.
        is_battery_device = device.category == "kg"

        if service_info.connectable:
            _LOGGER.debug(
                "Device %s is advertising as connectable, triggering update",
                address
            )
            hass.add_job(device.update())
        elif is_battery_device:
            # Battery device advertising as non-connectable - try anyway!
            # These devices often advertise briefly when woken and may accept
            # connections even when advertising as non-connectable.
            _LOGGER.info(
                "Device %s (battery-powered) received advertisement (RSSI: %s), "
                "attempting connection despite non-connectable flag",
                address,
                service_info.rssi,
            )
            hass.add_job(device.update())
        else:
            _LOGGER.debug(
                "Device %s received non-connectable advertisement (RSSI: %s)",
                address,
                service_info.rssi,
            )

    entry.async_on_unload(
        bluetooth.async_register_callback(
            hass,
            _async_update_ble,
            BluetoothCallbackMatcher({ADDRESS: address}),
            bluetooth.BluetoothScanningMode.ACTIVE,
        )
    )

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = TuyaBLEData(
        entry.title,
        device,
        product_info,
        manager,
        coordinator,
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    async def _async_stop(event: Event) -> None:
        """Close the connection."""
        await device.stop()

    entry.async_on_unload(
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _async_stop)
    )
    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
    if entry.title != data.title:
        await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        data: TuyaBLEData = hass.data[DOMAIN].pop(entry.entry_id)
        await data.device.stop()

    return unload_ok
