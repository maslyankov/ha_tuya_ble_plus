# Tuya BLE Plus - Home Assistant Integration

## Overview

This integration supports Tuya devices locally connected via BLE.

**Tuya BLE Plus** is a fork of the original `ha_tuya_ble` integration with added features:
- **Manual MAC address entry** - Add devices by MAC address, bypassing Bluetooth auto-discovery
- **Support for non-connectable devices** - Works with devices that advertise as non-connectable (like Fingerbot Touch)
- **Can run alongside the original integration** - Different domain name (`tuya_ble_plus`) allows both integrations to coexist

It includes support for **Fingerbot Touch** (product_id 'bs3ubslo') and is primarily maintained for use with Fingerbots.

## Installation

Place the `custom_components/tuya_ble_plus` folder in your Home Assistant configuration directory (or add its contents to an existing `custom_components` folder).

**Note:** This integration uses the domain `tuya_ble_plus` so it can be installed alongside the original `tuya_ble` integration.

## Usage

### Adding Devices

1. Go to **Settings** → **Devices & Services** → **+ Add Integration**
2. Search for **"Tuya BLE Plus"**
3. Choose one of:
   - **Auto-discover devices** - Automatically find nearby Tuya BLE devices
   - **Manual MAC address entry** - Enter the device MAC address manually (useful for devices that advertise as non-connectable)

### Finding Your Device's MAC Address

If your device doesn't appear in auto-discovery:
1. Go to **Settings** → **Devices & Services** → **Bluetooth**
2. Look for your device in the list of discovered Bluetooth devices
3. The MAC address will be shown (e.g., `DC:23:51:5E:23:CB`)

### Tuya Cloud Credentials

The integration works locally, but requires device ID and encryption key from Tuya IoT cloud for initial setup.
To obtain the credentials, please refer to the official Tuya integration [documentation](https://www.home-assistant.io/integrations/tuya/).

## Non-Connectable Devices

Some Tuya BLE devices (like Fingerbot Touch) advertise as **non-connectable** to save battery. For these devices:

1. The integration will set up successfully but show the device as "unavailable"
2. **Touch/interact with the device physically** to wake it up
3. The device will briefly advertise as connectable
4. The integration will automatically detect this and connect

You'll see log messages like:
```
Device DC:23:51:5E:23:CB is advertising as non-connectable. 
Touch/interact with the device physically to wake it up...
```

## Battery Saving Mode

These devices usually enter sleep mode after 5 minutes of inactivity.
To prevent battery drain, automatic reconnection is disabled.
The connection will reestablish automatically when:
- An action is triggered (potentially introducing a slight delay)
- You physically interact with the device
- You use the reconnect/reload buttons in Home Assistant

## Supported Devices

### Fingerbots (category_id 'szjqr')
- Fingerbot (product_ids 'ltak7e1p', 'y6kttvd6', 'yrnk7mnn', 'nvr2rocq', 'bnt7wajf', 'rvdceqjh', '5xhbk964') - Original device, CR2 battery
- Adaprox Fingerbot (product_id 'y6kttvd6') - Built-in battery with USB-C charging
- Fingerbot Plus (product_ids 'blliqpsj', 'ndvkgsrm', 'yiihr7zh', 'neq16kgd') - Has sensor button for manual control
- CubeTouch 1s (product_id '3yqdo5yt') - Built-in battery with USB-C charging
- CubeTouch II (product_id 'xhf790if') - Built-in battery with USB-C charging

### Fingerbots (category_id 'kg')
- Fingerbot Plus (product_ids 'mknd4lci', 'riecov42')
- Fingerbot Switch Robot (product_id '4ctjfrzq')
- **Fingerbot Touch** (product_id 'bs3ubslo') - 2-channel touch switch

### Temperature and Humidity Sensors (category_id 'wsdcg')
- Soil moisture sensor (product_id 'ojzlzzsw')
- Soil Thermo-Hygrometer (product_id 'tv6peegl')

### CO2 Sensors (category_id 'co2bj')
- CO2 Detector (product_id '59s19z5m')

### Smart Locks (category_id 'ms')
- Smart Lock (product_ids 'ludzroix', 'isk2p555', 'gumrixyt', 'uamrw6h3')
- TEKXDD Fingerprint Smart Lock (product_id 'okkyfgfs')

### Climate (category_id 'wk')
- Thermostatic Radiator Valve (product_ids 'drlajpqc', 'nhj2j7su', 'zmachryv')

### Smart Water Devices
- Smart water bottle (category 'znhsb', product_id 'cdlandip')
- Smart Water Valve (category 'sfkzq', product_id 'nxquc5lb')

### Irrigation (category_id 'ggq')
- Irrigation computer (product_id '6pahkcau')
- 2-outlet irrigation computer SGW02 (product_id 'hfgdqhho')

### Lights (category_id 'dd')
- LGB102 Magic Strip Lights (product_id 'nvfrtxlq')
- Most light products should be supported as the Light class tries to get device description from the cloud

### Smart Bulbs (category_id 'dj')
- SSG Smart 9W (product_id 'u4h3jtqr')

## Credits

- Original HASS component by [@PlusPlus-ua](https://github.com/PlusPlus-ua/ha_tuya_ble)
- Forked from [@pascalgoedeke](https://github.com/pascalgoedeke/ha_tuya_ble) with light support by @airy10 and @patriot1889
- Inspired by code of [@redphx](https://github.com/redphx/poc-tuya-ble-fingerbot)

## Support

If you encounter issues:
1. Check that your device's MAC address is correct
2. Ensure the device is registered in the Tuya app
3. For non-connectable devices, try touching/interacting with the device
4. Check Home Assistant logs for detailed error messages

## Support the Original Developer

_The following is from the original developer:_

I am working on this integration in Ukraine. Our country was subjected to brutal aggression by Russia. The war still continues. The capital of Ukraine - Kyiv, where I live, and many other cities and villages are constantly under threat of rocket attacks. Our air defense forces are doing wonders, but they also need support.

<p align="center">
  <a href="https://www.buymeacoffee.com/3PaK6lXr4l"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy me an air defense"></a>
</p>
