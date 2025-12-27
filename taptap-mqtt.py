#! /usr/bin/python3

import paho.mqtt.client as mqtt
import configparser
import hashlib
import json
import time
import uptime
import os
import sys
import uuid
import re
import subprocess
import traceback
from dateutil import tz
from datetime import datetime
from pathlib import Path


# Define user-defined exception
class AppError(Exception):
    "Raised on application error"

    pass


class MqttError(Exception):
    "Raised on MQTT connection failure"

    pass


def logging(level: str, message) -> None:
    if level in log_levels and log_levels[level] >= log_level:
        print("[" + str(datetime.now()) + "] " + level.upper() + ":", message)


# Global variables
log_level = 1
log_levels = {
    "error": 3,
    "warning": 2,
    "info": 1,
    "debug": 0,
}

state = {"time": 0, "uptime": 0, "nodes": {}, "stats": {}}
sensors = {
    "voltage_in": {
        "state_class": "measurement",
        "device_class": "voltage",
        "unit": "V",
        "precision": 2,
        "avail_online_key": "state_online",
        "avail_ident_key": "state_identified",
        "type_node": {"value": "voltage_in"},
        "type_string": ["min", "max", "avg", "sum"],
        "type_stat": [],
    },
    "voltage_out": {
        "state_class": "measurement",
        "device_class": "voltage",
        "unit": "V",
        "precision": 2,
        "avail_online_key": "state_online",
        "avail_ident_key": "state_identified",
        "type_node": {"value": "voltage_out"},
        "type_string": ["min", "max", "avg", "sum"],
        "type_stat": [],
    },
    "current_in": {
        "state_class": "measurement",
        "device_class": "current",
        "unit": "A",
        "precision": 2,
        "avail_online_key": "state_online",
        "avail_ident_key": "state_identified",
        "type_node": {"value": "current_in"},
        "type_string": ["min", "max", "avg"],
        "type_stat": [],
    },
    "current_out": {
        "state_class": "measurement",
        "device_class": "current",
        "unit": "A",
        "precision": 2,
        "avail_online_key": "state_online",
        "avail_ident_key": "state_identified",
        "type_node": {"value": "current_out"},
        "type_string": ["min", "max", "avg"],
        "type_stat": [],
    },
    "power": {
        "state_class": "measurement",
        "device_class": "power",
        "unit": "W",
        "precision": 0,
        "avail_online_key": "state_online",
        "avail_ident_key": "state_identified",
        "type_node": {"value": "power"},
        "type_string": ["min", "max", "avg", "sum"],
        "type_stat": ["sum"],
    },
    "temperature": {
        "state_class": "measurement",
        "device_class": "temperature",
        "unit": "°C",
        "precision": 1,
        "avail_online_key": "state_online",
        "avail_ident_key": "state_identified",
        "type_node": {"value": "temperature"},
        "type_string": ["min", "max", "avg"],
        "type_stat": [],
    },
    "duty_cycle": {
        "state_class": "measurement",
        "device_class": "power_factor",
        "unit": "%",
        "precision": 2,
        "avail_online_key": "state_online",
        "avail_ident_key": "state_identified",
        "type_node": {"value": "duty_cycle"},
        "type_string": ["min", "max", "avg"],
        "type_stat": [],
    },
    "rssi": {
        "state_class": "measurement",
        "device_class": "signal_strength",
        "unit": "dB",
        "precision": 0,
        "avail_online_key": "state_online",
        "avail_ident_key": "state_identified",
        "type_node": {"value": "rssi"},
        "type_string": [],
        "type_stat": ["min", "max", "avg"],
    },
    "energy": {
        "state_class": "total_increasing",
        "device_class": "energy",
        "unit": "kWh",
        "precision": 2,
        "scale": 0.000000278,
        "avail_online_key": "",
        "avail_ident_key": "state_identified",
        "type_node": {"daily": "power"},
        "type_string": ["daily"],
        "type_stat": ["daily"],
    },
    "timestamp": {
        "state_class": "measurement",
        "device_class": "timestamp",
        "unit": None,
        "precision": None,
        "avail_online_key": "state_init",
        "avail_ident_key": "",
        "type_node": {"value": "timestamp"},
        "type_string": [],
        "type_stat": [],
    },
    "node_serial": {
        "state_class": "measurement",
        "device_class": None,
        "unit": None,
        "precision": None,
        "avail_online_key": "",
        "avail_ident_key": "",
        "type_node": {"node": "node_serial"},
        "type_string": [],
        "type_stat": [],
    },
    "gateway_address": {
        "state_class": "measurement",
        "device_class": None,
        "unit": None,
        "precision": None,
        "avail_online_key": "",
        "avail_ident_key": "",
        "type_node": {"node": "gateway_address"},
        "type_string": [],
        "type_stat": [],
    },
    "nodes_total": {
        "state_class": "measurement",
        "device_class": None,
        "unit": None,
        "precision": None,
        "avail_online_key": "",
        "avail_ident_key": "",
        "type_node": {},
        "type_string": ["count"],
        "type_stat": ["count"],
    },
    "nodes_online": {
        "state_class": "measurement",
        "device_class": None,
        "unit": None,
        "precision": None,
        "avail_online_key": "",
        "avail_ident_key": "",
        "type_node": {},
        "type_string": ["count"],
        "type_stat": ["count"],
    },
    "nodes_identified": {
        "state_class": "measurement",
        "device_class": None,
        "unit": None,
        "precision": None,
        "avail_online_key": "",
        "avail_ident_key": "",
        "type_node": {},
        "type_string": ["count"],
        "type_stat": ["count"],
    },
}

config_validation = {
    "MQTT": {
        "SERVER": r"^(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})|((([a-z0-9][a-z0-9\-]*[a-z0-9])|[a-z0-9]+\.)*([a-z]+|xn\-\-[a-z0-9]+)\.?)$",
        "PORT": r"^\d+$",
        "QOS": r"^[0-2]$",
        "TIMEOUT": r"^\d+$",
        "USER?": r".+",
        "PASS?": r".+",
    },
    "TAPTAP": {
        "LOG_LEVEL": r"[error|warning|info|debug]",
        "BINARY": r"^(\.{0,2}\/)*(\w+\/)*taptap$",
        "SERIAL?": r"^\/dev\/tty\w+$",
        "ADDRESS?": r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$",
        "PORT": r"^\d+$",
        "MODULES": r"^(\s*(\w+)?\s*\:\s*(\w+)\s*\:\s*([0-9A-Z]\-[0-9A-Z]{7})?\s*)?(\s*\,\s*(\w+)?\s*\:\s*(\w+)\s*\:\s*([0-9A-Z]\-[0-9A-Z]{7})?\s*)*$",
        "TOPIC_PREFIX": r"^(\w+)(\/\w+)*",
        "TOPIC_NAME": r"^(\w+)$",
        "TIMEOUT": r"^\d+$",
        "UPDATE": r"^\d+$",
        "STATE_FILE": r"^(\.{0,2}\/)?(\w+\/)*([\.\w]+)$",
    },
    "HA": {
        "DISCOVERY_PREFIX": r"^(\w+)(\/\w+)*",
        "DISCOVERY_LEGACY": r"^(true|false)$",
        "BIRTH_TOPIC": r"^(\w+)(\/\w+)*",
        "NODES_AVAILABILITY_ONLINE": r"^(true|false)$",
        "NODES_AVAILABILITY_IDENTIFIED": r"^(true|false)$",
        "STRINGS_AVAILABILITY_ONLINE": r"^(true|false)$",
        "STRINGS_AVAILABILITY_IDENTIFIED": r"^(true|false)$",
        "STATS_AVAILABILITY_ONLINE": r"^(true|false)$",
        "STATS_AVAILABILITY_IDENTIFIED": r"^(true|false)$",
        "NODES_SENSORS_RECORDER?": r"^(\s*\w+\s*)?(\,\s*\w+\s*)*$",
        "STRINGS_SENSORS_RECORDER?": r"^(\s*\w+\s*)?(\,\s*\w+\s*)*$",
        "STATS_SENSORS_RECORDER?": r"^(\s*\w+\s*)?(\,\s*\w+\s*)*$",
    },
    "RUNTIME": {
        "MAX_ERROR": r"^\d+$",
        "RUN_FILE?": r"^(\.{0,2}\/)?(\w+\/)*([\.\w]+)$",
    },
}

# Read config
logging("debug", "Processing config")
config = configparser.ConfigParser()
if len(sys.argv) > 1 and sys.argv[1] and Path(sys.argv[1]).is_file():
    logging("info", "Reading config file: " + sys.argv[1])
    config.read(sys.argv[1])
elif Path("config.ini").is_file():
    logging("info", "Reading default config file: ./config.ini")
    config.read("config.ini")
else:
    logging("info", "No valid configuration file found/specified")
    exit(1)

logging("debug", f"Config data:")
logging("debug", {section: dict(config[section]) for section in config.sections()})

for section in config_validation:
    if not section in config.sections():
        logging("error", "Missing config section: " + section)
        exit(1)
    for param1 in config_validation[section]:
        optional = False
        param2 = param1
        if param1[-1:] == "?":
            param2 = param1[:-1]
            optional = True

        if not param2 in config[section] or config[section][param2] is None:
            logging("error", "Missing config parameter: " + param2)
            exit(1)
        elif config_validation[section][param1] and not re.match(
            config_validation[section][param1], config[section][param2]
        ):
            if not (optional and not config[section][param2]):
                logging("error", "Invalid config entry: " + section + "/" + param2)
                exit(1)

if config["TAPTAP"]["LOG_LEVEL"] and config["TAPTAP"]["LOG_LEVEL"] in log_levels:
    log_level = log_levels[config["TAPTAP"]["LOG_LEVEL"]]

if not Path(config["TAPTAP"]["BINARY"]).is_file():
    logging("error", "TAPTAP BINARY doesn't exists!")
    exit(1)

if (
    (not config["TAPTAP"]["SERIAL"] and not config["TAPTAP"]["ADDRESS"])
    or (config["TAPTAP"]["SERIAL"] and config["TAPTAP"]["ADDRESS"])
    or (config["TAPTAP"]["ADDRESS"] and not config["TAPTAP"]["PORT"])
):
    logging("error", "Either TAPTAP SERIAL or ADDRESS and PORT shall be set!")
    exit(1)

# Init nodes dictionaries
# Dict of node names -> node string, serial, getaway, node id
nodes = {}
# Dict of nodes ids -> node names
nodes_ids = {}
# Dict string_name -> nodes cout
strings = {}
# Dict gateway id -> getway address
gateways = {}
# Bool if all nodes have serials configured
nodes_configured = True

# Power Reports cache
cache = {}

# Init discovery struct
discovery = {}

# Init MQTT topics
lwt_topic = (
    config["TAPTAP"]["TOPIC_PREFIX"] + "/" + config["TAPTAP"]["TOPIC_NAME"] + "/lwt"
)
state_topic = (
    config["TAPTAP"]["TOPIC_PREFIX"] + "/" + config["TAPTAP"]["TOPIC_NAME"] + "/state"
)
attributes_topic = (
    config["TAPTAP"]["TOPIC_PREFIX"]
    + "/"
    + config["TAPTAP"]["TOPIC_NAME"]
    + "/attributes"
)

logging("debug", f"Configured nodes: {nodes.keys()}")


def taptap_conf() -> None:
    logging("debug", "Into taptap_conf")
    global nodes
    global strings
    global nodes_configured
    global cache
    nodes_serials = set()

    entries = list(map(str.strip, config["TAPTAP"]["MODULES"].split(",")))

    if not entries:
        logging("error", f"Modules are not configured!")
        exit(1)

    for entry in entries:
        parsed = re.search(
            r"^\s*(\w+)?\s*\:\s*(\w+)\s*\:\s*([0-9A-Z]\-[0-9A-Z]{7})?\s*$", entry
        )
        if parsed:
            node_string = parsed.group(1)
            node_name = parsed.group(2)
            node_serial = parsed.group(3)
            node_name_short = node_name

            if node_string is not None:
                if node_string == "overall":
                    logging("error", f"Reserved node string name: {node_string}!")
                    exit(1)

                node_name = node_string + node_name
                if node_string not in strings:
                    strings[node_string] = 0
                else:
                    strings[node_string] += 1

            if node_name in nodes.keys():
                logging("error", f"Duplicite node name: {node_name}!")
                exit(1)

            if node_serial is not None:
                if node_serial in nodes_serials:
                    logging("error", f"Duplicite node serial: {node_serial}!")
                    exit(1)
                nodes_serials.add(node_serial)
            else:
                nodes_configured = False

            nodes[node_name] = {
                "node_id": None,
                "string_name": node_string,
                "node_name": node_name,
                "node_name_short": node_name_short,
                "node_serial": node_serial,
                "gateway_id": None,
                "gateway_address": None,
            }
        else:
            logging("error", f"Invalid MODULES_SERIALS entry: {entry}")
            exit(1)

    if len(strings.keys()) == 0:
        logging("debug", f"Strings are not configured, strings statistics are inactive")
    elif len(strings.keys()) == 1:
        logging(
            "warning",
            f"Only single string is configured, strings statistics are inactive.",
        )
        strings = {}
    else:
        logging(
            "debug",
            f"{len(strings.keys())} strings are is configured, strings statistics are enabled.",
        )

    # Init cache struct
    cache = dict.fromkeys(nodes.keys(), {})


def taptap_tele() -> None:
    logging("debug", "Into taptap_tele")
    global last_tele
    global taptap
    global state
    global cache
    now = time.time()

    # Check taptap process is alive
    if not taptap or not taptap.stdout or taptap.poll() is not None:
        logging("error", "TapTap process is not running!")
        raise AppError("TapTap process is not running!")

    while True:
        line = taptap.stdout.readline()
        if not line:
            break
        elif time.time() - now > int(config["TAPTAP"]["UPDATE"]) - 1:
            logging("warning", f"Slow run detected reading taptap messages!")
            taptap.stdout.truncate()
            break

        try:
            data = json.loads(line)
        except json.JSONDecodeError as error:
            logging("warning", f"Can't parse json: {error}")
            logging("debug", line)
            continue

        if "event_type" not in data.keys():
            logging("warning", "Unknown taptap event type")
            logging("debug", data)
            continue

        if data["event_type"] == "infrastructure_report":
            logging("debug", "Received infrastructure_report event")
            logging("debug", data)
            if taptap_infrastructure_event(data):
                # Infrastructure Event processed
                logging("debug", "Successfully processed infrastructure event")
                logging("debug", data)
                logging("info", "Nodes were enumerated, flushing message cache")
                cache = dict.fromkeys(nodes.keys(), {})
        elif data["event_type"] == "power_report":
            logging("debug", "Received power_report event")
            logging("debug", data)
            if taptap_power_event(data, now):
                # Power Report processed
                cache[nodes_ids[str(data["node_id"])]][data["tmstp"]] = data
                logging("debug", "Successfully processed power event")
                logging("debug", data)
        else:
            logging("warning", "Unknown taptap event type")
            logging("debug", data)
            continue

    if last_tele + int(config["TAPTAP"]["UPDATE"]) < now:
        dt = {
            "last": datetime.fromtimestamp(last_tele, tz.tzlocal()),
            "now": datetime.fromtimestamp(now, tz.tzlocal()),
        }

        # Reset statistic values
        if "overall" not in state["stats"]:
            state["stats"]["overall"] = {}
        if strings:
            for string_name in strings.keys():
                if string_name not in state["stats"]:
                    state["stats"][string_name] = {}
                for sensor in sensors.keys():
                    for type in sensors[sensor]["type_string"]:
                        reset_stat_sensor(sensor, type, dt, state["stats"][string_name])
                state["stats"][string_name]["nodes_total"]["count"] = strings[
                    string_name
                ]
            for sensor in sensors.keys():
                for type in sensors[sensor]["type_stat"]:
                    reset_stat_sensor(sensor, type, dt, state["stats"]["overall"])
        else:
            for sensor in sensors.keys():
                for type in sensors[sensor]["type_string"]:
                    reset_stat_sensor(sensor, type, dt, state["stats"]["overall"])
        state["stats"]["overall"]["nodes_total"]["count"] = len(nodes.keys())

        for node_name in nodes.keys():
            if node_name not in state["nodes"]:
                # Node was not yet seen on the bus, need to init its state topic
                state["nodes"][node_name] = {
                    "state_online": "offline",
                    "state_init": "offline",
                    "tmstp": 0,
                }
            for sensor in sensors.keys():
                if sensors[sensor]["type_node"]:
                    type = list(sensors[sensor]["type_node"])[0]
                    reset_node_sensor(sensor, type, dt, state["nodes"][node_name])

            if nodes[node_name]["node_id"] is None:
                # not yet received any message from this node
                logging("debug", f"Node {node_name} not yet seen on the bus")
                continue

            node_id = nodes[node_name]["node_id"]

            # Set identified state
            if nodes[node_name]["node_serial"] is not None:
                state["nodes"][node_name]["state_identified"] = "online"
                state["stats"]["overall"]["nodes_identified"]["count"] += 1
                if strings and nodes[node_name]["string_name"] is not None:
                    state["stats"][nodes[node_name]["string_name"]]["nodes_identified"][
                        "count"
                    ] += 1
            else:
                state["nodes"][node_name]["state_identified"] = "offline"

            if node_name in cache.keys() and len(cache[node_name]):
                # Node is online - populate state struct
                if state["nodes"][node_name]["state_online"] == "offline":
                    logging("info", f"Node {node_name} came online")
                else:
                    logging("debug", f"Node {node_name} is online")

                state["stats"]["overall"]["nodes_online"]["count"] += 1
                if strings and nodes[node_name]["string_name"] is not None:
                    state["stats"][nodes[node_name]["string_name"]]["nodes_online"][
                        "count"
                    ] += 1

                last = max(cache[node_name].keys())

                # Update sensors
                for sensor in sensors.keys():
                    value = None
                    type = (
                        list(sensors[sensor]["type_node"])[0]
                        if sensors[sensor]["type_node"]
                        else None
                    )
                    if type == "node":
                        value = nodes[node_name][sensors[sensor]["type_node"]["node"]]
                        state["nodes"][node_name][sensor] = value
                    elif type in ["daily", "weekly", "monthly", "yearly"]:
                        prev_tmstp = state["nodes"][node_name]["tmstp"]
                        value = 0
                        for tmstp in cache[node_name].keys():
                            if prev_tmstp + int(config["TAPTAP"]["UPDATE"]) + 1 > tmstp:
                                value += cache[node_name][tmstp][
                                    sensors[sensor]["type_node"][type]
                                ] * (tmstp - prev_tmstp)
                            prev_tmstp = tmstp
                        if "scale" in sensors[sensor]:
                            value *= sensors[sensor]["scale"]
                        state["nodes"][node_name][sensor] += value
                    elif type == "value":
                        if sensors[sensor]["unit"]:
                            # Calculate average for data smoothing
                            value = 0
                            for tmstp in cache[node_name].keys():
                                value += cache[node_name][tmstp][
                                    sensors[sensor]["type_node"][type]
                                ]
                            value /= len(cache[node_name])
                            if "scale" in sensors[sensor]:
                                value *= sensors[sensor]["scale"]
                        else:
                            # Take latest value
                            value = cache[node_name][last][
                                sensors[sensor]["type_node"][type]
                            ]
                        state["nodes"][node_name][sensor] = value
                    else:
                        continue

                    # Update stat sensor
                    if strings and nodes[node_name]["string_name"] is not None:
                        for type in sensors[sensor]["type_string"]:
                            update_stat_sensor(
                                sensor,
                                type,
                                state["stats"][nodes[node_name]["string_name"]],
                                value,
                            )

                        for type in sensors[sensor]["type_stat"]:
                            update_stat_sensor(
                                sensor, type, state["stats"]["overall"], value
                            )
                    else:
                        for type in sensors[sensor]["type_string"]:
                            update_stat_sensor(
                                sensor, type, state["stats"]["overall"], value
                            )

                state["nodes"][node_name].update(
                    {
                        "state_online": "online",
                        "state_init": "online",
                        "tmstp": cache[node_name][last]["tmstp"],
                        "timestamp": cache[node_name][last]["timestamp"],
                    }
                )

                # Reset cache
                cache[node_name] = {}

            elif (
                state["nodes"][node_name]["tmstp"] + int(config["TAPTAP"]["TIMEOUT"])
                < now
                and state["nodes"][node_name]["state_online"] == "online"
            ):
                # Node went recently offline - reset values
                logging("info", f"Node {node_name} went offline")
                state["nodes"][node_name].update(
                    {
                        "node_name": nodes[node_name]["node_name"],
                        "node_serial": nodes[node_name]["node_serial"],
                        "gateway_address": nodes[node_name]["gateway_address"],
                        "state_online": "offline",
                    }
                )
                for sensor in sensors.keys():
                    type = (
                        list(sensors[sensor]["type_node"])[0]
                        if sensors[sensor]["type_node"]
                        else None
                    )
                    if sensors[sensor]["avail_online_key"] == "state_init":
                        continue
                    if type == "value":
                        state["nodes"][node_name][sensor] = None
            else:
                # update node id, name and serial
                state["nodes"][node_name].update(
                    {
                        "node_name": nodes[node_name]["node_name"],
                        "node_serial": nodes[node_name]["node_serial"],
                        "gateway_address": nodes[node_name]["gateway_address"],
                    }
                )

        for string_name in ["overall"] + list(strings.keys()):
            # Set identified state
            if state["stats"][string_name]["nodes_identified"]["count"] == 0:
                logging("debug", f"No nodes were find identified during last cycle")
                state["stats"][string_name]["state_identified"] = "offline"
            elif (
                state["stats"][string_name]["nodes_identified"]["count"]
                < state["stats"][string_name]["nodes_total"]["count"]
            ):
                logging(
                    "info",
                    f"Only '{state['stats'][string_name]['nodes_identified']['count']}' nodes were find identified during last cycle",
                )
                state["stats"][string_name]["state_identified"] = "offline"
            else:
                logging(
                    "debug",
                    f"All '{state['stats'][string_name]['nodes_identified']['count']}' nodes were find identified during last cycle",
                )
                state["stats"][string_name]["state_identified"] = "online"

            # Set device state
            if state["stats"][string_name]["nodes_online"]["count"] == 0:
                logging("debug", f"No nodes reported online during last cycle")
                state["stats"][string_name]["state_online"] = "offline"
            elif (
                state["stats"][string_name]["nodes_online"]["count"]
                < state["stats"][string_name]["nodes_total"]["count"]
            ):
                logging(
                    "info",
                    f"Only '{state['stats'][string_name]['nodes_online']['count']}' nodes reported online during last cycle",
                )
                state["stats"][string_name]["state_online"] = "online"
            else:
                logging(
                    "debug",
                    f"All '{state['stats'][string_name]['nodes_online']['count']}' nodes reported online during last cycle",
                )
                state["stats"][string_name]["state_online"] = "online"

        else:
            logging("debug", f"No nodes reported online during last cycle")

        time_up = uptime.uptime()
        result = "%01d" % int(time_up / 86400)
        time_up = time_up % 86400
        result = result + "T" + "%02d" % (int(time_up / 3600))
        time_up = time_up % 3600
        state["uptime"] = (
            result + ":" + "%02d" % (int(time_up / 60)) + ":" + "%02d" % (time_up % 60)
        )
        state["time"] = datetime.fromtimestamp(now, tz.tzlocal()).isoformat()

        if client and client.is_connected():
            # Sent LWT update
            logging("debug", f"Publish MQTT lwt topic {lwt_topic}")
            client.publish(
                lwt_topic, payload="online", qos=int(config["MQTT"]["QOS"]), retain=True
            )
            # Sent State update
            logging("debug", f"Updating MQTT state topic {state_topic}")
            logging("debug", json.dumps(state))
            client.publish(
                state_topic, payload=json.dumps(state), qos=int(config["MQTT"]["QOS"])
            )
            last_tele = now
        else:
            logging("error", "MQTT not connected!")
            raise MqttError("MQTT not connected!")


def reset_stat_sensor(sensor: str, type: str, dt: datetime, state_data: dict) -> None:
    logging("debug", "Into reset_stat_sensor")

    if sensor not in state_data:
        state_data[sensor] = {}

    if type in ["daily", "weekly", "monthly", "yearly"]:
        if type not in state_data[sensor] or reset_sensor_integral(type, dt):
            state_data[sensor][type] = 0
    elif type in ["count"]:
        state_data[sensor][type] = 0
    else:
        state_data[sensor][type] = None


def update_stat_sensor(sensor: str, type: str, state_data: dict, value) -> None:
    logging("debug", "Into update_stat_sensor")

    if type == "max":
        if state_data[sensor][type] is None or value > state_data[sensor][type]:
            state_data[sensor][type] = value
    elif type == "min":
        if state_data[sensor][type] is None or value < state_data[sensor][type]:
            state_data[sensor][type] = value
    elif type == "sum":
        if state_data[sensor][type] is None:
            state_data[sensor][type] = value
        else:
            state_data[sensor][type] += value
    elif type == "avg":
        if state_data[sensor][type] is None:
            state_data[sensor][type] = value
        else:
            state_data[sensor][type] += (value - state_data[sensor][type]) / (
                state_data["nodes_online"]["count"]
            )
    elif type in ["daily", "weekly", "monthly", "yearly"]:
        state_data[sensor][type] += value


def reset_node_sensor(sensor: str, type: str, dt: datetime, state_data: dict) -> None:
    logging("debug", "Into reset_node_sensor")

    if sensors[sensor]["avail_online_key"] == "state_init":
        if sensor not in state_data:
            state_data[sensor] = None
    elif sensor not in state_data:
        if type in ["daily", "weekly", "monthly", "yearly"]:
            state_data[sensor] = 0
        else:
            state_data[sensor] = None
    elif type in ["daily", "weekly", "monthly", "yearly"]:
        if reset_sensor_integral(type, dt):
            state_data[sensor] = 0
    else:
        state_data[sensor] = None


def reset_sensor_integral(type: str, dt: datetime) -> bool:
    logging("debug", "Into reset_sensor_integral")

    if (
        (dt["last"].year != dt["now"].year and type in ["daily", "monthly", "yearly"])
        or (dt["last"].month != dt["now"].month and type in ["daily", "monthly"])
        or (dt["last"].day != dt["now"].day and type == "daily")
        or (
            dt["last"].isocalendar()[1] != dt["now"].isocalendar()[1]
            and type == "weekly"
        )
    ):
        # reset integral
        return True
    else:
        return False


def taptap_power_event(data: dict, now: float) -> bool:
    logging("debug", "Into taptap_power_event")

    for name in [
        "gateway",
        "node",
        "voltage_in",
        "voltage_out",
        "current",
        "dc_dc_duty_cycle",
        "temperature",
        "rssi",
        "timestamp",
    ]:
        if name not in data.keys():
            logging("warning", f"Missing required key: '{name}'")
            logging("debug", data)
            return False
        elif name in ["gateway", "node"]:
            if not isinstance(data[name], int):
                logging("warning", f"Invalid key: '{name}' value: '{data[name]}'")
                logging("debug", data)
                return False
            data[name + "_id"] = str(data[name])
            del data[name]
        elif name in [
            "voltage_in",
            "voltage_out",
            "current",
            "dc_dc_duty_cycle",
            "temperature",
        ]:
            if not isinstance(data[name], (float, int)):
                logging("warning", f"Invalid key: '{name}' value: '{data[name]}'")
                logging("debug", data)
                return False
            if name == "dc_dc_duty_cycle":
                data["duty_cycle"] = data["dc_dc_duty_cycle"] * 100
        elif name in ["rssi"]:
            if not isinstance(data[name], int):
                logging("warning", f"Invalid key: '{name}' value: '{data[name]}'")
                logging("debug", data)
                return False
        elif name == "timestamp":
            if not (isinstance(data[name], str)) and data[name]:
                logging("warning", f"Invalid key: '{name}' value: '{data[name]}'")
                logging("debug", data)
                return False
            try:
                if re.match(
                    r"^\d{4}\-\d{2}\-\d{2}T\d{2}\:\d{2}\:\d{2}\.\d{9}[+-]\d{2}\:\d{2}$",
                    data[name],
                ):
                    tmstp = datetime.strptime(
                        data[name][0:26] + data[name][29:],
                        "%Y-%m-%dT%H:%M:%S.%f%z",
                    )
                elif re.match(
                    r"^\d{4}\-\d{2}\-\d{2}T\d{2}\:\d{2}\:\d{2}\.\d{6}[+-]\d{2}\:\d{2}$",
                    data[name],
                ):
                    tmstp = datetime.strptime(
                        data[name],
                        "%Y-%m-%dT%H:%M:%S.%f%z",
                    )
                elif re.match(
                    r"^\d{4}\-\d{2}\-\d{2}T\d{2}\:\d{2}\:\d{2}\.\d{9}Z$", data[name]
                ):
                    tmstp = datetime.strptime(
                        data[name][0:26] + "Z",
                        "%Y-%m-%dT%H:%M:%S.%fZ",
                    )
                elif re.match(
                    r"^\d{4}\-\d{2}\-\d{2}T\d{2}\:\d{2}\:\d{2}\.\d{6}Z$", data[name]
                ):
                    tmstp = datetime.strptime(
                        data[name],
                        "%Y-%m-%dT%H:%M:%S.%fZ",
                    )
                else:
                    logging(
                        "warning", f"Invalid key 'timestamp' format: '{data[name]}'"
                    )
                    logging("debug", data)
                    return False
                data["timestamp"] = tmstp.isoformat()
                data["tmstp"] = tmstp.timestamp()
            except:
                logging("warning", f"Invalid key: '{name}' value: '{data[name]}'")
                logging("debug", data)
                return False
            # Copy validated data into cache struct
            if data["tmstp"] + int(config["TAPTAP"]["UPDATE"]) < now:
                diff = round(now - data["tmstp"], 1)
                logging(
                    "warning",
                    f"Old data detected: '{data[name]}', time difference: '{diff}'s",
                )
                logging("debug", data)
                return False
            else:
                # Calculate power and current_out
                data["current_out"] = data.pop("current")
                data["power"] = data["voltage_out"] * data["current_out"]
                data["current_in"] = (
                    data["power"] / data["voltage_in"] if data["voltage_in"] else 0.0
                )
                if not taptap_enumerate_node(data["gateway_id"], data["node_id"]):
                    # get node name and serial and enumerate if necessary
                    logging(
                        "warning",
                        f"Unable to enumerate node id: '{data['node_id']}'",
                    )
                    logging("debug", data)
                    return False
                else:
                    return True
    return False


def taptap_infrastructure_event(data: dict) -> bool:
    logging("debug", "Into taptap_infrastructure_event")
    global nodes
    global gateways
    global nodes_ids
    global nodes_configured

    enumerated = False
    pattern_id = re.compile(r"^\d+$")

    if not "gateways" in data.keys() and isinstance(data["nodes"], dict):
        logging("warning", f"Invalid 'gateways' key in infrastructure event")
        logging("debug", data)
    else:
        for gateway_id in data["gateways"].keys():
            if not pattern_id.match(gateway_id):
                logging(
                    "warning",
                    f"Invalid gateway id in gateways key in the the infrastructure event: '{gateway_id}'",
                )
                logging("debug", data)
                continue
            elif not isinstance(data["gateways"][gateway_id], dict):
                logging(
                    "warning", f"Invalid gateways structure in the infrastructure event"
                )
                logging("debug", data)
                continue
            elif "address" in data["gateways"][gateway_id]:
                if not gateway_id in gateways.keys():
                    gateways[gateway_id] = {"address": "", "version": ""}
                if re.match(
                    r"^([0-9A-Fa-f]{2}[:-]){7}([0-9A-Fa-f]{2})$",
                    data["gateways"][gateway_id]["address"],
                ):
                    logging(
                        "debug",
                        f"Found valid address: '{data['gateways'][gateway_id]['address']}' for getaway id: '{gateway_id}'",
                    )
                    gateways[gateway_id]["address"] = data["gateways"][gateway_id][
                        "address"
                    ]
            elif "version" in data["gateways"][gateway_id]:
                if not gateway_id in gateways.keys():
                    gateways[gateway_id] = {"address": "", "version": ""}
                if data["gateways"][gateway_id]["version"] != "":
                    logging(
                        "debug",
                        f"Found valid version: '{data['gateways'][gateway_id]['version']}' for getaway id: '{gateway_id}'",
                    )
                    gateways[gateway_id]["version"] = data["gateways"][gateway_id][
                        "version"
                    ]
            else:
                if not gateway_id in gateways.keys():
                    gateways[gateway_id] = {"address": "", "version": ""}
                logging(
                    "warning",
                    f"Missing address or version keys in the gateways structure in the infrastructure event",
                )
                logging("debug", data)
                continue

        logging("debug", f"Processes gateways data in the infrastructure event")
        logging("debug", gateways)

    if not "nodes" in data.keys() and isinstance(data["nodes"], dict):
        logging("warning", f"Invalid 'nodes' key in infrastructure event")
        logging("debug", data)
        return enumerated

    for gateway_id in data["nodes"].keys():
        if not pattern_id.match(gateway_id):
            logging(
                "warning",
                f"Invalid gateway id in nodes key in in the infrastructure event: '{gateway_id}'",
            )
            logging("debug", data)
            continue
        elif not isinstance(data["nodes"][gateway_id], dict):
            logging("warning", f"Invalid nodes structure in the infrastructure event")
            logging("debug", data)
            continue
        for node_id in data["nodes"][gateway_id].keys():
            if not pattern_id.match(node_id):
                logging(
                    "warning",
                    f"Invalid nodes id in the infrastructure event: '{node_id}'",
                )
                logging("debug", data)
            elif "barcode" not in data["nodes"][gateway_id][node_id].keys():
                logging(
                    "warning",
                    f"Missing barcode in the infrastructure event for node id: '{node_id}'",
                )
                logging("debug", data)
            elif not re.match(
                r"^[0-9A-Z]\-[0-9A-Z]{7}$",
                data["nodes"][gateway_id][node_id]["barcode"],
            ):
                logging(
                    "warning",
                    f"Invalid barcode format in the infrastructure event for node id: '{node_id}'",
                )
            else:
                # If we reach this point, the serial is valid
                node_serial = data["nodes"][gateway_id][node_id]["barcode"]
                gateway_address = (
                    gateways[gateway_id]["address"]
                    if gateway_id in gateways.keys()
                    else None
                )
                logging(
                    "debug",
                    f"Discovered valid node serial: {node_serial}",
                )
                nodes_ids.pop(node_id, None)
                for node_name in sorted(nodes.keys()):
                    if nodes[node_name]["node_serial"] == node_serial:
                        if nodes[node_name]["node_id"] != node_id:
                            # discovered new permanent mapping
                            logging(
                                "info",
                                f"Permanently enumerated node id: {node_id} to node name: {node_name} and serial: {node_serial}",
                            )
                            enumerated = True
                        nodes[node_name].update(
                            {
                                "node_id": node_id,
                                "gateway_id": gateway_id,
                                "gateway_address": gateway_address,
                            }
                        )
                        nodes_ids[node_id] = node_name
                    elif nodes[node_name]["node_id"] == node_id:
                        # delete temporary mapping
                        logging(
                            "info",
                            f"Delete invalid serial {node_serial} and node name: {node_name} entries for node id: {node_id}",
                        )
                        enumerated = True
                        nodes[node_name].update(
                            {
                                "node_id": None,
                                "gateway_id": None,
                                "gateway_address": None,
                            }
                        )
                if node_id not in nodes_ids:
                    for node_name in sorted(nodes.keys()):
                        if nodes[node_name]["node_serial"] is None:
                            # create permanent mapping for unknown serial
                            logging(
                                "warning",
                                f"Discovered unconfigured node serial {node_serial} on node id: {node_id} assigning it to the first available node name: {node_name}",
                            )
                            logging(
                                "warning",
                                f"Consider to permanently assign discovered node serial: {node_serial} to the correct node name in the configuration!",
                            )
                            nodes_configured = False
                            enumerated = True
                            nodes[node_name].update(
                                {
                                    "node_id": node_id,
                                    "node_serial": node_serial,
                                    "gateway_id": gateway_id,
                                    "gateway_address": gateway_address,
                                }
                            )
                            nodes_ids[node_id] = node_name
                            taptap_nodes_conf("warning")
                            break
                    else:
                        logging(
                            "error",
                            f"Discovered unconfigured node serial {node_serial} on node id: {node_id} but there is not any free node_name to assign!",
                        )
                        logging(
                            "error",
                            f"You shall define all node names and corresponding node serials in the configuration!",
                        )

    if not enumerated:
        logging(
            "debug",
            f"Finished processing node data, no enumeration was required",
        )
    else:
        logging("debug", f"Finished processing node data, nodes were enumerated")

    logging("debug", nodes)

    return enumerated


def taptap_nodes_conf(level: str) -> None:
    logging("debug", "Into taptap_nodes_conf")
    if nodes_configured:
        # all nodes are properly configured
        return

    nodes_conf = []
    for node_name in sorted(nodes.keys()):
        if nodes[node_name]["node_serial"] is not None:
            if nodes[node_name]["string_name"] is not None:
                node_name
                nodes_conf.append(
                    nodes[node_name]["string_name"]
                    + ":"
                    + nodes[node_name]["node_name_short"]
                    + ":"
                    + nodes[node_name]["node_serial"]
                )
            else:
                nodes_conf.append(
                    ":" + node_name + ":" + nodes[node_name]["node_serial"]
                )
        elif nodes[node_name]["string_name"] is not None:
            nodes_conf.append(nodes[node_name]["string_name"] + ":" + node_name + ":")
        else:
            nodes_conf.append(":" + node_name + ":")
    logging(
        level,
        f"To simplify nodes configuration you will find all currently discovered nodes printed bellow in the proper format. Adjust string and modules names to your needs.",
    )
    logging(
        level,
        ", ".join(nodes_conf),
    )


def taptap_enumerate_node(gateway_id: str, node_id: str) -> bool:
    logging("debug", "Into taptap_enumerate_node")
    global nodes
    global nodes_ids

    if node_id in nodes_ids.keys():
        # node was already discovered
        node_name = nodes_ids[node_id]
        logging(
            "debug",
            f"Node id: {node_id} already enumerated to node name: '{node_name}' and serial: '{nodes[node_name]['node_serial']}'",
        )
        if (
            gateway_id in gateways.keys()
            and gateways[gateway_id]["address"] != nodes[node_name]["gateway_address"]
        ):
            nodes[node_name]["gateway_address"] = gateways[gateway_id]["address"]
            logging(
                "info",
                f"Updated gateway address for node id: {node_id} to '{gateways[gateway_id]['address']}'",
            )
        return True
    else:
        # need to find unused node name and assign it to node_id temporarily
        for node_name in nodes.keys():
            if nodes[node_name]["node_id"] is None:
                nodes[node_name]["node_id"] = node_id
                nodes_ids[node_id] = node_name
                logging(
                    "info",
                    f"Temporary enumerated node id: {node_id} to node name: {node_name}",
                )
                if (
                    gateway_id in gateways.keys()
                    and gateways[gateway_id]["address"]
                    != nodes[node_name]["gateway_address"]
                ):
                    nodes[node_name]["gateway_address"] = gateways[gateway_id][
                        "address"
                    ]
                    logging(
                        "info",
                        f"Updated gateway address for node id: {node_id} to '{gateways[gateway_id]['address']}'",
                    )
                return True

    logging(
        "warning",
        f"Unable to enumerate node id: {node_id} - no more node names available!",
    )
    logging("debug", nodes)
    return False


def taptap_discovery(mode: int) -> None:
    logging("debug", "Into taptap_discovery")

    if not config["HA"]["DISCOVERY_PREFIX"]:
        return
    if str_to_bool(config["HA"]["DISCOVERY_LEGACY"]):
        taptap_discovery_legacy(mode)
    else:
        taptap_discovery_device(mode)


def taptap_discovery_device(mode: int) -> None:
    logging("debug", "Into taptap_discovery_device")
    global discovery

    object_id = str(
        uuid.uuid5(uuid.NAMESPACE_URL, "taptap_" + config["TAPTAP"]["TOPIC_NAME"])
    )

    if mode:
        discovery = {}
        discovery["device"] = {
            "identifiers": object_id,
            "name": config["TAPTAP"]["TOPIC_NAME"].title(),
            "manufacturer": "Tigo",
            "model": "Tigo CCA",
        }

        # Origin
        discovery["origin"] = {
            "name": "TapTap MQTT Bridge",
            "sw_version": "0.1",
            "support_url": "https://github.com/litinoveweedle/taptap2mqtt",
        }

        # Statistic sensors components
        discovery["components"] = {}
        for sensor in sensors.keys():
            if strings:
                for string_name in strings.keys():
                    for type in sensors[sensor]["type_string"]:
                        name = "_".join(["string", string_name, sensor, type])
                        taptap_discovery_device_sensor(
                            name,
                            sensor,
                            "strings",
                            ".".join(["stats", string_name, sensor, type]),
                            ".".join(["stats", string_name]),
                        )

                for type in sensors[sensor]["type_stat"]:
                    name = "_".join(["overall", sensor, type])
                    taptap_discovery_device_sensor(
                        name,
                        sensor,
                        "stats",
                        ".".join(["stats", "overall", sensor, type]),
                        ".".join(["stats", "overall"]),
                    )
            else:
                for type in sensors[sensor]["type_string"]:
                    name = "_".join(["overall", sensor, type])
                    taptap_discovery_device_sensor(
                        name,
                        sensor,
                        "stats",
                        ".".join(["stats", "overall", sensor, type]),
                        ".".join(["stats", "overall"]),
                    )

        # Node sensors components
        for node_name in nodes.keys():
            for sensor in sensors.keys():
                if not sensors[sensor]["type_node"]:
                    continue
                name = "_".join([node_name, sensor])
                taptap_discovery_device_sensor(
                    name,
                    sensor,
                    "nodes",
                    ".".join(["nodes", node_name, sensor]),
                    ".".join(["nodes", node_name]),
                )

        discovery["state_topic"] = state_topic
        discovery["qos"] = config["MQTT"]["QOS"]

    if len(discovery):
        if client and client.is_connected():
            # Sent discovery
            discovery_topic = (
                config["HA"]["DISCOVERY_PREFIX"] + "/device/" + object_id + "/config"
            )
            logging("debug", f"Publish MQTT discovery topic {discovery_topic}")
            logging("debug", discovery)
            client.publish(
                discovery_topic,
                payload=json.dumps(discovery),
                qos=int(config["MQTT"]["QOS"]),
            )
        else:
            print("MQTT not connected!")
            raise MqttError("MQTT not connected!")


def taptap_discovery_device_sensor(
    name: str,
    sensor: str,
    mode: str,
    state_json_path: str,
    avail_json_path: str,
) -> None:
    logging("debug", "Into taptap_discovery_device_sensor")
    global discovery

    sensor_id = config["TAPTAP"]["TOPIC_NAME"] + "_" + name
    sensor_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, sensor_id))
    discovery["components"][sensor_id] = {
        "platform": "sensor",
        "name": name.replace("_", " ").title(),
        "unique_id": sensor_uuid,
        "default_entity_id": "sensor." + sensor_id,
        "device_class": sensors[sensor]["device_class"],
        "unit_of_measurement": sensors[sensor]["unit"],
        "value_template": "{{ value_json." + state_json_path + " }}",
        "availability_mode": "all",
        "availability": [{"topic": lwt_topic}],
    }

    if sensors[sensor]["precision"] is not None:
        discovery["components"][sensor_id]["suggested_display_precision"] = sensors[
            sensor
        ]["precision"]

    if sensors[sensor]["state_class"] and sensor in config["HA"][
        mode.upper() + "_SENSORS_RECORDER"
    ].split(","):
        discovery["components"][sensor_id]["state_class"] = sensors[sensor][
            "state_class"
        ]

    if (
        str_to_bool(config["HA"][mode.upper() + "_AVAILABILITY_ONLINE"])
        and sensors[sensor]["avail_online_key"]
    ):
        discovery["components"][sensor_id]["availability"].append(
            {
                "topic": state_topic,
                "value_template": "{{ value_json."
                + avail_json_path
                + "."
                + sensors[sensor]["avail_online_key"]
                + " }}",
            },
        )

    if (
        str_to_bool(config["HA"][mode.upper() + "_AVAILABILITY_IDENTIFIED"])
        and sensors[sensor]["avail_ident_key"]
    ):
        discovery["components"][sensor_id]["availability"].append(
            {
                "topic": state_topic,
                "value_template": "{{ value_json."
                + avail_json_path
                + "."
                + sensors[sensor]["avail_ident_key"]
                + " }}",
            },
        )


def taptap_discovery_legacy(mode: int) -> None:
    logging("debug", "Into taptap_discovery_legacy")
    global discovery

    object_id = str(
        uuid.uuid5(uuid.NAMESPACE_URL, "taptap_" + config["TAPTAP"]["TOPIC_NAME"])
    )

    if mode:
        discovery = {}
        device = {
            "identifiers": object_id,
            "name": config["TAPTAP"]["TOPIC_NAME"].title(),
            "manufacturer": "Tigo",
            "model": "Tigo CCA",
        }

        # Origin
        origin = {
            "name": "TapTap MQTT Bridge",
            "sw_version": "0.1",
            "support_url": "https://github.com/litinoveweedle/taptap2mqtt",
        }

        # Statistic sensors components
        for sensor in sensors.keys():
            if strings:
                for string_name in strings.keys():
                    for type in sensors[sensor]["type_string"]:
                        name = "_".join(["string", string_name, sensor, type])
                        taptap_discovery_legacy_sensor(
                            name,
                            sensor,
                            "strings",
                            ".".join(["stats", string_name, sensor, type]),
                            ".".join(["stats", string_name]),
                            object_id,
                            origin,
                            device,
                        )

                for type in sensors[sensor]["type_stat"]:
                    name = "_".join(["overall", sensor, type])
                    taptap_discovery_legacy_sensor(
                        name,
                        sensor,
                        "stats",
                        ".".join(["stats", "overall", sensor, type]),
                        ".".join(["stats", "overall"]),
                        object_id,
                        origin,
                        device,
                    )
            else:
                for type in sensors[sensor]["type_string"]:
                    name = "_".join(["overall", sensor, type])
                    taptap_discovery_legacy_sensor(
                        name,
                        sensor,
                        "stats",
                        ".".join(["stats", "overall", sensor, type]),
                        ".".join(["stats", "overall"]),
                        object_id,
                        origin,
                        device,
                    )

        # Node sensors components
        for node_name in nodes.keys():
            for sensor in sensors.keys():
                if not sensors[sensor]["type_node"]:
                    continue
                name = "_".join([node_name, sensor])
                taptap_discovery_legacy_sensor(
                    name,
                    sensor,
                    "nodes",
                    ".".join(["nodes", node_name, sensor]),
                    ".".join(["nodes", node_name]),
                    object_id,
                    origin,
                    device,
                )

    if len(discovery):
        for component in discovery.keys():
            if client and client.is_connected():
                discovery_topic = (
                    config["HA"]["DISCOVERY_PREFIX"] + "/" + component + "/config"
                )
                # Sent discovery
                logging("debug", f"Publish MQTT discovery topic {discovery_topic}")
                logging("debug", discovery[component])
                client.publish(
                    discovery_topic,
                    payload=json.dumps(discovery[component]),
                    qos=int(config["MQTT"]["QOS"]),
                )
            else:
                print("MQTT not connected!")
                raise MqttError("MQTT not connected!")


def taptap_discovery_legacy_sensor(
    name: str,
    sensor: str,
    mode: str,
    state_json_path: str,
    avail_json_path: str,
    object_id: str,
    origin: str,
    device: str,
) -> None:
    logging("debug", "Into taptap_discovery_device_sensor")
    global discovery

    sensor_id = config["TAPTAP"]["TOPIC_NAME"] + "_" + name
    sensor_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, sensor_id))
    key = "sensor/" + object_id + "/" + sensor_id
    discovery[key] = {
        "device": device,
        "origin": origin,
        "name": name.replace("_", " ").title(),
        "unique_id": sensor_uuid,
        "default_entity_id": "sensor." + sensor_id,
        "device_class": sensors[sensor]["device_class"],
        "unit_of_measurement": sensors[sensor]["unit"],
        "state_topic": state_topic,
        "value_template": "{{ value_json." + state_json_path + " }}",
        "availability_mode": "all",
        "availability": [{"topic": lwt_topic}],
        "qos": config["MQTT"]["QOS"],
    }

    if sensors[sensor]["precision"] is not None:
        discovery[key][sensor_id]["suggested_display_precision"] = sensors[sensor][
            "precision"
        ]

    if sensors[sensor]["state_class"] and sensor in config["HA"][
        mode.upper() + "_SENSORS_RECORDER"
    ].split(","):
        discovery[key][sensor_id]["state_class"] = sensors[sensor]["state_class"]

    if (
        str_to_bool(config["HA"][mode.upper() + "_AVAILABILITY_ONLINE"])
        and sensors[sensor]["avail_online_key"]
    ):
        discovery[key][sensor_id]["availability"].append(
            {
                "topic": state_topic,
                "value_template": "{{ value_json."
                + avail_json_path
                + "."
                + sensors[sensor]["avail_online_key"]
                + " }}",
            },
        )

    if (
        str_to_bool(config["HA"][mode.upper() + "_AVAILABILITY_IDENTIFIED"])
        and sensors[sensor]["avail_ident_key"]
    ):
        discovery[key][sensor_id]["availability"].append(
            {
                "topic": state_topic,
                "value_template": "{{ value_json."
                + avail_json_path
                + "."
                + sensors[sensor]["avail_ident_key"]
                + " }}",
            },
        )


def taptap_init() -> None:
    logging("debug", "Into taptap_init")
    global taptap

    with open(config["TAPTAP"]["BINARY"], "rb") as fh:
        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        logging("debug", "Using TapTap binary with MD5 checksum: " + m.hexdigest())

    # Initialize taptap process
    if config["TAPTAP"]["SERIAL"]:
        logging(
            "debug",
            "Starting TapTap process: "
            + config["TAPTAP"]["BINARY"]
            + " observe --serial "
            + config["TAPTAP"]["SERIAL"]
            + " --state-file "
            + config["TAPTAP"]["STATE_FILE"],
        )
        taptap = subprocess.Popen(
            [
                config["TAPTAP"]["BINARY"],
                "observe",
                "--serial",
                config["TAPTAP"]["SERIAL"],
                "--state-file",
                config["TAPTAP"]["STATE_FILE"],
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pipesize=1024 * 1024,
        )
    elif config["TAPTAP"]["ADDRESS"]:
        logging(
            "debug",
            "Starting TapTap process: "
            + config["TAPTAP"]["BINARY"]
            + " observe --tcp "
            + config["TAPTAP"]["ADDRESS"]
            + " --port "
            + config["TAPTAP"]["PORT"]
            + " --state-file "
            + config["TAPTAP"]["STATE_FILE"],
        )
        taptap = subprocess.Popen(
            [
                config["TAPTAP"]["BINARY"],
                "observe",
                "--tcp",
                config["TAPTAP"]["ADDRESS"],
                "--port",
                config["TAPTAP"]["PORT"],
                "--state-file",
                config["TAPTAP"]["STATE_FILE"],
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pipesize=1024 * 1024,
        )
    else:
        logging("error", "Either TAPTAP SERIAL or ADDRESS and PORT shall be set!")
        exit(1)

    if taptap and taptap.stdout:
        # Set stdout as non blocking
        logging("info", "TapTap process started")
        os.set_blocking(taptap.stdout.fileno(), False)
    else:
        logging("error", "TapTap process can't be started!")
        raise AppError("TapTap process can't be started!")


def taptap_cleanup() -> None:
    logging("debug", "Into taptap_cleanup")
    global taptap

    if taptap:
        if taptap.poll() is None:
            logging("info", "Terminating TapTap process.")
            taptap.terminate()
            time.sleep(5)
            if taptap.poll() is None:
                logging("warning", "TapTap process is still running, sending kill!")
                taptap.kill()
                time.sleep(5)
                if taptap.poll() is None:
                    logging(
                        "error", "TapTap process is still running, terminating anyway!"
                    )
        else:
            code = taptap.returncode
            logging(
                "error", f"Process TapTap exited unexpectedly with error code: {code}"
            )
        taptap = None


def mqtt_init() -> None:
    logging("debug", "Into mqtt_init")
    global client

    # Create mqtt client
    client = mqtt.Client()
    # Register LWT message
    client.will_set(lwt_topic, payload="offline", qos=0, retain=True)
    # Register connect callback
    client.on_connect = mqtt_on_connect
    # Register disconnect callback
    client.on_disconnect = mqtt_on_disconnect
    # Register publish message callback
    client.on_message = mqtt_on_message
    # Set access token
    client.username_pw_set(config["MQTT"]["USER"], config["MQTT"]["PASS"])
    # Run receive thread
    client.loop_start()
    # Connect to broker
    client.connect(
        config["MQTT"]["SERVER"],
        int(config["MQTT"]["PORT"]),
        int(config["MQTT"]["TIMEOUT"]),
    )

    timeout = 0
    reconnect = 0
    time.sleep(1)
    while not client.is_connected():
        time.sleep(1)
        timeout += 1
        if timeout > 15:
            print("MQTT waiting to connect")
            if reconnect > 10:
                print("MQTT not connected!")
                raise MqttError("MQTT not connected!")
            client.reconnect()
            reconnect += 1
            timeout = 0

    # Subscribe for Home Assistant birth messages
    if config["HA"]["BIRTH_TOPIC"]:
        client.subscribe(config["HA"]["BIRTH_TOPIC"])


def mqtt_cleanup() -> None:
    logging("debug", "Into mqtt_cleanup")
    global client

    if client:
        client.loop_stop()
        if client.is_connected():
            if config["HA"]["BIRTH_TOPIC"]:
                client.unsubscribe(config["HA"]["BIRTH_TOPIC"])
            client.disconnect()
        client = None


# The callback for when the client receives a CONNACK response from the server.
def mqtt_on_connect(client, userdata, flags, rc) -> None:
    logging("debug", "Into mqtt_on_connect")
    if rc != 0:
        logging("warning", "MQTT unexpected connect return code " + str(rc))
    else:
        logging("info", "MQTT client connected")


# The callback for when the client receives a DISCONNECT from the server.
def mqtt_on_disconnect(client, userdata, rc) -> None:
    logging("debug", "Into mqtt_on_disconnect")
    if rc != 0:
        logging("warning", "MQTT unexpected disconnect return code " + str(rc))
    logging("info", "MQTT client disconnected")


# The callback for when a PUBLISH message is received from the server.
def mqtt_on_message(client, userdata, msg) -> None:
    logging("debug", "Into mqtt_on_message")
    topic = str(msg.topic)
    payload = str(msg.payload.decode("utf-8"))
    logging("debug", f"MQTT received topic: {topic}, payload: {payload}")
    match_birth = re.match(r"^" + config["HA"]["BIRTH_TOPIC"] + "$", topic)
    if config["HA"]["BIRTH_TOPIC"] and match_birth:
        # discovery
        taptap_discovery(0)
    else:
        logging("warning", "Unknown topic: " + topic + ", message: " + payload)


# Touch state file on successful run
def run_file(mode: int) -> None:
    logging("debug", "Into run_file")
    if mode:
        if config["RUNTIME"]["RUN_FILE"]:
            path = os.path.split(config["RUNTIME"]["RUN_FILE"])
            try:
                # Create stat file directory if not exists
                if not os.path.isdir(path[0]):
                    os.makedirs(path[0], exist_ok=True)
                # Write stats file
                with open(config["RUNTIME"]["RUN_FILE"], "a"):
                    os.utime(config["RUNTIME"]["RUN_FILE"], None)
                logging("debug", "stats file updated")
            except IOError as error:
                logging(
                    "error",
                    f"Unable to write to file: {config['RUNTIME']['RUN_FILE']} error: {error}",
                )
                exit(1)
    elif os.path.isfile(config["RUNTIME"]["RUN_FILE"]):
        os.remove(config["RUNTIME"]["RUN_FILE"])


def str_to_bool(string: str) -> bool:
    # Converts `s` to boolean. Assumes string is case-insensitive
    return string.lower() in ["true", "1", "t", "y", "yes"]


client = None
taptap = None
restart = 0
while True:
    try:
        # Init counters
        last_tele = 0
        # Init modules conf
        taptap_conf()
        # Create mqtt client
        if not client:
            # Init mqtt
            mqtt_init()
        if not taptap:
            # Init taptap
            taptap_init()
        # Sent discovery
        taptap_discovery(1)
        # Run update loop
        while True:
            taptap_tele()
            run_file(1)
            restart = 0
            time.sleep(1)
    except BaseException as error:
        logging("error", f"An exception occurred: {type(error).__name__} – {error}")
        if type(error) in [MqttError, AppError] and (
            int(config["RUNTIME"]["MAX_ERROR"]) == 0
            or restart <= int(config["RUNTIME"]["MAX_ERROR"])
        ):
            if type(error) == MqttError:
                mqtt_cleanup()
            elif type(error) == AppError:
                taptap_cleanup()
            restart += 1
            # Try to reconnect later
            time.sleep(10)
        elif type(error) in [KeyboardInterrupt, SystemExit]:
            logging("error", "Gracefully terminating application")
            mqtt_cleanup()
            taptap_cleanup()
            run_file(0)
            # Print any unknown nodes
            taptap_nodes_conf("error")
            # Graceful shutdown
            sys.exit(0)
        else:
            logging("error", f"Unknown exception, aborting application")
            logging("debug", f"Exception details: {traceback.format_exc()}")
            # Exit with error
            sys.exit(1)
