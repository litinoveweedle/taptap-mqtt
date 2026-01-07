# Taptap-MQTT Bridge Development Guide

## Project Overview

This is a Python3 bridge service that reads data from Tigo solar optimizer hardware via the `taptap` binary and publishes sensor data to MQTT for Home Assistant integration. It provides local access to Tigo installation data as an alternative to Tigo Cloud.

**Key Architecture:**
- Single-file Python application ([taptap-mqtt.py](../taptap-mqtt.py))
- External dependency on `taptap` binary (separate project) for Modbus communication
- MQTT client for publishing sensor data and HomeAssistant MQTT discovery
- Persistent state management via JSON files for node topology and runtime state

## Core Data Flow

1. **Initialization Phase:**
   - Parse [config.ini](../config.ini.example) for MQTT, taptap binary path, module definitions
   - Spawn `taptap` subprocess in observe mode with JSON output
   - Connect to MQTT broker and publish LWT (Last Will Testament)
   - Send MQTT discovery messages for HomeAssistant auto-configuration

2. **Runtime Loop:**
   - Read JSON events from `taptap` stdout: `infrastructure_report` (node topology) and `power_report` (telemetry)
   - Cache power reports per node until update interval expires
   - Calculate statistics: node sensors, per-string aggregates, overall stats
   - Publish to MQTT topics: `{prefix}/{name}/state` and per-entity discovery topics

3. **Node Identification:**
   - Nodes are defined by triplets: `STRING:NAME:SERIAL` in `MODULES` config
   - Serial numbers may be unknown initially; service logs unidentified serials for discovery
   - State persisted to `STATE_FILE` for fast topology initialization on restart

## Configuration Patterns

**Module Definition Format:**
```ini
MODULES = A:01:A-AAAAAAA, A:02:A-BAAAAAA, B:03:B-CAAAAAA
# STRING (optional) : NAME (required) : SERIAL (optional)
```

- **STRING**: Groups nodes into strings for aggregated statistics (requires 2+ strings)
- **NAME**: User-defined identifier for each optimizer node
- **SERIAL**: Barcode from physical device (format: `X-XXXXXXX`). If omitted, service will discover and log unknowns

**Availability Control:** The `HA` section has granular `*_AVAILABILITY_ONLINE` and `*_AVAILABILITY_IDENTIFIED` flags to control when HomeAssistant entities show "unavailable" based on node online status or serial identification.

## Key Data Structures

### `sensors` Dictionary (lines 58-226)
Defines all sensor types with metadata for HomeAssistant discovery:
- `type_node`: Node-level sensors (`"value"`, `"daily"`, `"node"`)
- `type_string`: Per-string aggregate sensors (`"min"`, `"max"`, `"avg"`, `"sum"`, `"count"`)
- `type_stat`: Overall statistics sensors
- `avail_online_key`/`avail_ident_key`: Availability dependency keys

### `state` Global Dictionary
Runtime telemetry organized as:
```python
state = {
    "nodes": {
        "A01": {"voltage_in": 45.2, "power": 320, "state_online": "online", ...},
        ...
    },
    "stats": {
        "A": {"power_sum": 1200, ...},  # Per-string stats
        "overall": {"power_sum": 2400, ...}  # Total stats
    }
}
```

## Critical Functions

- **`taptap_conf()`**: Parse `MODULES` config into `nodes`, `strings`, `gateways` dicts
- **`taptap_tele()`**: Main loop reading taptap JSON events, updating state, managing cache
- **`taptap_infrastructure_event(data)`**: Process node enumeration, assign node_ids to configured names
- **`taptap_power_event(data, now)`**: Validate and cache power telemetry per node
- **`taptap_discovery(mode)`**: Publish HomeAssistant MQTT discovery (device-based or legacy per-entity)
- **`reset_sensor_integral(type, dt)`**: Determine if integral sensors (daily/weekly energy) should reset
- **`update_stats_tele(sensor, node_name, value)`**: Aggregate node data into string/overall statistics

## HomeAssistant Discovery Modes

**Device-Based (default, HA >= 2024.12):** Single discovery message per device with all sensors.
**Legacy (OpenHab or HA < 2024.12):** Separate discovery message per sensor entity.

Toggle via `DISCOVERY_LEGACY = true/false` in config.

## Development Workflows

**Running Locally:**
```bash
# Install dependencies
pip install -r requirements.txt

# Copy and configure
cp config.ini.example config.ini
# Edit config.ini with your MQTT broker, taptap path, module serials

# Run (reads config.ini by default, or specify path)
python3 taptap-mqtt.py [path/to/config.ini]
```

**Testing Without Hardware:** Requires `taptap` binary outputting valid JSON. No mock mode exists.

**Debugging:**
- Set `LOG_LEVEL = debug` in `[TAPTAP]` section for verbose output
- Check `STATE_FILE` (default `./taptap.json`) for persisted node topology
- Monitor `RUN_FILE` timestamp updates to verify main loop execution

## Error Handling & Recovery

- `MAX_ERROR`: Retry count for recoverable errors (`MqttError`, `AppError`). Set `0` for unlimited retries.
- On `MqttError`: Cleanup MQTT client, wait 10s, reconnect
- On `AppError`: Cleanup taptap subprocess, wait 10s, restart
- On `KeyboardInterrupt`/`SystemExit`: Graceful shutdown, log unidentified nodes, remove `RUN_FILE`

## External Dependencies

- **`taptap` binary**: Must be from [litinoveweedle/taptap](https://github.com/litinoveweedle/taptap) fork (not original willglynn/taptap). Supports `observe` mode with JSON event output for infrastructure and power reports.
- **Modbus Hardware**: Requires Modbus-to-Ethernet or Modbus-to-USB converter connected to Tigo CCA gateway.

## Common Pitfalls

- **Unknown serials logged repeatedly:** Normal if serials not configured. Serials may only emit during nighttime. Wait 24hrs for full discovery.
- **No power reports:** Check taptap can run in `observe` mode standalone. Verify Modbus converter config (especially Ethernet converters).
- **Discovery not working:** Ensure `DISCOVERY_PREFIX` matches HA MQTT discovery prefix (default `homeassistant`). Check `BIRTH_TOPIC` subscription.
- **Integral sensors not resetting:** Verify system timezone is correct; `reset_sensor_integral()` uses local time midnight boundaries.
