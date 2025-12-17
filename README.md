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

- Node data for each Tigo optimizer (node)
  - sensor: 
    - voltage_in ( "class": "voltage", "unit": "V" )
    - voltage_out ( "class": "voltage", "unit": "V" )
    - current_in ( "class": "current", "unit": "A" )
    - current_out ( "class": "current", "unit": "A" )
    - power ( "class": "power", "unit": "W" )
    - temperature ( "class": "temperature", "unit": "°C" )
    - duty_cycle ( "class": "power_factor", "unit": "%" )
    - rssi ( "class": "signal_strength", "unit": "dB"  )
    - energy_daily ( "class": "energy", "unit": "kWh"  )
    - timestamp ("class": "timestamp", "unit": None )    # time node was last seen on the bus
    - node_serial ("class": None, "unit": None )        # Tigo optimizer serial number
    - gateway_address ("class": None, "unit": None )    # Tigo gateway address


- Single string / no string defined:
  - Total statistic for all Tigo optimizers:
    - sensor:
      - voltage_in_max
      - voltage_in_min
      - voltage_in_avg
      - voltage_in_sum
      - voltage_out_min
      - voltage_out_max
      - voltage_out_avg
      - voltage_out_sum
      - current_in_min
      - current_in_max
      - current_in_avg
      - current_out_min
      - current_out_max
      - current_out_avg
      - power_max
      - power_min
      - power_avg
      - power_sum
      - temperature_min
      - temperature_max
      - temperature_avg
      - duty_cycle_min
      - duty_cycle_max
      - duty_cycle_avg
      - rssi_min
      - rssi_max
      - rssi_avg
      - energy_daily
      - nodes_total
      - nodes_online
      - nodes_identified

- Multiple strings defined
  - String statistics for string connected Tigo Optimizers:
    - sensor:
      - voltage_in_max
      - voltage_in_min
      - voltage_in_avg
      - voltage_in_sum
      - voltage_out_min
      - voltage_out_max
      - voltage_out_avg
      - voltage_out_sum
      - current_in_min
      - current_in_max
      - current_in_avg
      - current_out_min
      - current_out_max
      - current_out_avg
      - power_max
      - power_min
      - power_avg
      - power_sum
      - temperature_min
      - temperature_max
      - temperature_avg
      - duty_cycle_min
      - duty_cycle_max
      - duty_cycle_avg
      - energy_daily
      - nodes_total
      - nodes_online
      - nodes_identified

  - Total statistic for all Tigo optimizers:
    - sensor:
      - power_sum
      - rssi_min
      - rssi_max
      - rssi_avg
      - energy_daily
      - nodes_total
      - nodes_online
      - nodes_identified




## Reporting issues:
Before reporting any issue please check that you can get running [taptap binary](https://github.com/litinoveweedle/taptap/) which can intercept messages in the `observe` mode! There is high chance, that you problem could be related to the configuration of the converter (especially Ethernet ones).

If you are note able to get outputs in the taptap `observe` mode, but you are getting messages in the lower layer modes like `peek-bytes`, `peek-frames` and/or `peek-activity` there is a high chance, that there is incompatibility of the taptap with the current Tigo Gateway protocol. The know versions of the Tigo GW firmware compatible with the taptap are 3.9.0-ct, 4.0.1-ct, 4.0.3-ct. Update your firmware using Tigo application if you are on the older version. If you are on the newer firmware version please [report the issue](https://github.com/willglynn/taptap/issues) together with taptap binary messages captures.
