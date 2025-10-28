# Tigo CCA to the Home Assistant MQTT bridge

This is Python3 service to act as bridge between the Tigo CCA gateway tapping device implemented using [taptap](https://github.com/litinoveweedle/taptap) project and the [Home Assistant MQTT integration](https://www.home-assistant.io/integrations/mqtt/). It provides completely local access to the data provided by your Tigo installation (as alternative to using Tigo Cloud). This software reads data from `taptap` binary and push them into HA integrated MQTT broker as a sensors values. It can be also used for other project compatible with the HomeAssistant MQTT integrations (like for example OpenHab).

It supports HA MQTT auto [discovery](https://www.home-assistant.io/integrations/mqtt/#mqtt-discovery) feature (both new device type as well as older per entity type for HA < 2024.12.0 or OpenHab) to provide for easy integration with the Home Assistant.

If you are looking for seamlessly integrated solution for HomeAssistant please check my [HomeAssistant addons repository](https://github.com/litinoveweedle/hassio-addons), where I provide this software packaged as Hassio addon.

## To make it work you need to:
- Get taptap binary, either compile it from [source](https://github.com/litinoveweedle/taptap), or check [my builds](https://github.com/litinoveweedle/taptap/releases). Please do not use original [taptap project](https://github.com/willglynn/taptap) as it is not compatible with the latest advance features (like modules barcodes discovery etc.)
- You will need Modbus to Ethernet or Modbus to USB converter, connected to Tigo CCA [as described](https://github.com/willglynn/taptap?tab=readme-ov-file#connecting).
- Install appropriate Python3 libraries - see `requirements.txt`.
- Rename config file example `config.ini.example` to `config.ini`.
- Configure your installation in the `config.ini` file, check inline comments for explanation.


## Provided data/entities:

- for each Tigo optimizer (node)
  - sensor: 
    - voltage_in ( "class": "voltage", "unit": "V" )
    - voltage_out ( "class": "voltage", "unit": "V" )
    - current ( "class": "current", "unit": "A" )
    - voltage_in ( "class": "voltage", "unit": "V" )
    - power ( "class": "power", "unit": "W" )
    - temperature ( "class": "temperature", "unit": "°C" )
    - duty_cycle ( "class": "power_factor", "unit": "%" )
    - rssi ( "class": "signal_strength", "unit": "dB"  )
    - timestamp ("class": "timestamp", "unit": None )    # time node was last seen on the bus
    - node_serial ("class": None, "unit": None )        # Tigo optimizer serial number
  
- statistic data for all optimizers (nodes) connected to the Tigo CCA:
  - sensor:
    - voltage_in_max
    - voltage_in_min
    - voltage_in_avg
    - voltage_out_min
    - voltage_out_max
    - voltage_out_avg
    - current_min
    - current_max
    - current_avg
    - duty_cycle_min
    - duty_cycle_max
    - duty_cycle_avg
    - temperature_min
    - temperature_max
    - temperature_avg
    - rssi_min
    - rssi_max
    - rssi_avg


## Reporting issues:
Before reporting any issue please check that you have running taptap binary which can intercept messages in the `observe` mode! There is hight chance, that you problem would be related to the configuration of the converter (especially Ethernet ones).
