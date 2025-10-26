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


def logging(level, message):
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

state = {"time": 0, "uptime": 0, "state": "offline", "nodes": {}, "stats": {}}
stats_ops = ["min", "max", "avg"]
stats_sensors = [
    "voltage_in",
    "voltage_out",
    "current",
    "power",
    "duty_cycle",
    "temperature",
    "rssi",
]
sensors = {
    "voltage_in": {
        "class": "voltage",
        "unit": "V",
        "round": 2,
        "avail_key": "state",
    },
    "voltage_out": {
        "class": "voltage",
        "unit": "V",
        "round": 2,
        "avail_key": "state",
    },
    "current": {
        "class": "current",
        "unit": "A",
        "round": 2,
        "avail_key": "state",
    },
    "power": {
        "class": "power",
        "unit": "W",
        "round": 0,
        "avail_key": "state",
    },
    "temperature": {
        "class": "temperature",
        "unit": "°C",
        "round": 1,
        "avail_key": "state",
    },
    "duty_cycle": {
        "class": "power_factor",
        "unit": "%",
        "round": 0,
        "avail_key": "state",
    },
    "rssi": {
        "class": "signal_strength",
        "unit": "dB",
        "round": 0,
        "avail_key": "state",
    },
    "timestamp": {
        "class": "timestamp",
        "unit": None,
        "round": None,
        "avail_key": "init_state",
    },
    "node_serial": {
        "class": None,
        "unit": None,
        "round": None,
        "avail_key": "",
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
        "MODULES_SERIALS": r"^\s*\w+\s*\:\s*[0-9A-Z]\-[0-9A-Z]{7}\s*(\,\s*\w+\s*\:\s*[0-9A-Z]\-[0-9A-Z]{7}\s*)*$",
        "TOPIC_PREFIX": r"^(\w+)(\/\w+)*",
        "TOPIC_NAME": r"^(\w+)$",
        "TIMEOUT": r"^\d+$",
        "UPDATE": r"^\d+$",
        "PERSISTENT_FILE": r"^(\.{0,2}\/)*(\w+\/)*taptap.json$",
    },
    "HA": {
        "DISCOVERY_PREFIX": r"^(\w+)(\/\w+)*",
        "DISCOVERY_LEGACY": r"^(true|false)$",
        "BIRTH_TOPIC": r"^(\w+)(\/\w+)*",
        "ENTITY_AVAILABILITY": r"^(true|false)$",
    },
    "RUNTIME": {
        "MAX_ERROR": r"^\d+$",
        "STATE_FILE?": r"^\/\w+(\/[\.\w]+)*$",
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
    logging("error", "TATTAP BINARY doesn't exists!")
    exit(1)

if (
    (not config["TAPTAP"]["SERIAL"] and not config["TAPTAP"]["ADDRESS"])
    or (config["TAPTAP"]["SERIAL"] and config["TAPTAP"]["ADDRESS"])
    or (config["TAPTAP"]["ADDRESS"] and not config["TAPTAP"]["PORT"])
):
    logging("error", "Either TAPTAP SERIAL or ADDRESS and PORT shall be set!")
    exit(1)


nodes_names = []
nodes_serials = []
for entry in list(map(str.strip, config["TAPTAP"]["MODULEs_SERIALS"].split(","))):
    (node_name, node_serial) = list(map(str.strip, entry.split(":")))
    nodes_names.append(node_name.lower())
    nodes_serials.append(node_serial.upper())
if not len(nodes_names) or not len(nodes_serials):
    logging("error", "MODULES_SERIALS need to have at least one module defined")
    exit(1)


# Init nodes dictionary
# node serials -> node names mapping
nodes_serials_names = dict(zip(nodes_serials, nodes_names))
# node names -> node ids mapping
nodes_names_ids = {}
# node ids -> node names + serials mapping
nodes = {}
gateways = {}

# Init cache struct
cache = dict.fromkeys(nodes_names, {})

# Init discovery struct
discovery = None

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

logging("debug", f"Configured nodes: {nodes}")


def taptap_tele(mode):
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
                cache = dict.fromkeys(nodes_names, {})
        elif data["event_type"] == "power_report":
            logging("debug", "Received power_report event")
            logging("debug", data)
            if taptap_power_event(data, now):
                # Power Report processed
                cache[data["node_name"]][data["tmstp"]] = data
                logging("debug", "Successfully processed power event")
                logging("debug", data)
        else:
            logging("warning", "Unknown taptap event type")
            logging("debug", data)
            continue

    if mode or last_tele + int(config["TAPTAP"]["UPDATE"]) < now:
        online_nodes = 0
        # Init statistic values
        for sensor in stats_sensors:
            state["stats"][sensor] = {}
            for op in stats_ops:
                state["stats"][sensor][op] = None

        for node_id in nodes.keys():
            node_name = nodes[node_id]["node_name"]
            if node_name in cache.keys() and len(cache[node_name]):
                # Node is online - populate state struct
                if (
                    not node_name in state["nodes"]
                    or state["nodes"][node_name]["state"] == "offline"
                ):
                    logging("info", f"Node {node_name} came online")
                else:
                    logging("debug", f"Node {node_name} is online")
                online_nodes += 1
                last = max(cache[node_name].keys())
                state["nodes"][node_name]["state"] = "online"
                state["nodes"][node_name]["init_state"] = "online"
                state["nodes"][node_name]["tmstp"] = cache[node_name][last]["tmstp"]
                state["nodes"][node_name]["timestamp"] = cache[node_name][last][
                    "timestamp"
                ]

                # Update state data
                for sensor in sensors.keys():
                    if sensors[sensor]["unit"]:
                        # Calculate average for data smoothing
                        sum = 0
                        for tmstp in cache[node_name].keys():
                            sum += cache[node_name][tmstp][sensor]
                        state["nodes"][node_name][sensor] = sum / len(cache[node_name])
                    else:
                        # Take latest value
                        state["nodes"][node_name][sensor] = cache[node_name][last][
                            sensor
                        ]
                    if sensors[sensor]["round"] is not None:
                        state["nodes"][node_name][sensor] = round(
                            state["nodes"][node_name][sensor],
                            sensors[sensor]["round"],
                        )

                # Reset cache
                cache[node_name] = {}

                # Calculate max, min and sum for average sensor
                for sensor in stats_sensors:
                    for op in stats_ops:
                        if state["stats"][sensor][op] is None:
                            state["stats"][sensor][op] = state["nodes"][node_name][
                                sensor
                            ]
                        elif op == "max":
                            if (
                                online_nodes == 0
                                or state["nodes"][node_name][sensor]
                                > state["stats"][sensor][op]
                            ):
                                state["stats"][sensor][op] = state["nodes"][node_name][
                                    sensor
                                ]
                        elif op == "min":
                            if (
                                online_nodes == 0
                                or state["nodes"][node_name][sensor]
                                < state["stats"][sensor][op]
                            ):
                                state["stats"][sensor][op] = state["nodes"][node_name][
                                    sensor
                                ]
                        elif op == "avg":
                            state["stats"][sensor][op] += state["nodes"][node_name][
                                sensor
                            ]

            elif not node_name in state["nodes"]:
                # Node state unknown - init default values
                logging("debug", f"Node {node_name} init as offline")
                state["nodes"][node_name] = {
                    "node_id": node_id,
                    "node_name": nodes[node_id]["node_name"],
                    "node_serial": nodes[node_id]["node_serial"],
                    "gateway_id": 0,
                    "state": "offline",
                    "init_state": "offline",
                    "timestamp": datetime.fromtimestamp(0, tz.tzlocal()).isoformat(),
                    "tmstp": 0,
                    "voltage_in": 0,
                    "voltage_out": 0,
                    "current": 0,
                    "duty_cycle": 0,
                    "temperature": 0,
                    "rssi": 0,
                    "power": 0,
                }

            elif (
                state["nodes"][node_name]["tmstp"] + int(config["TAPTAP"]["TIMEOUT"])
                < now
                and state["nodes"][node_name]["state"] == "online"
            ):
                # Node went recently offline - reset values
                logging("info", f"Node {node_name} went offline")
                state["nodes"][node_name].update(
                    {
                        "node_id": node_id,
                        "node_name": nodes[node_id]["node_name"],
                        "node_serial": nodes[node_id]["node_serial"],
                        "state": "offline",
                        "voltage_in": 0,
                        "voltage_out": 0,
                        "current": 0,
                        "duty_cycle": 0,
                        "temperature": 0,
                        "rssi": 0,
                        "power": 0,
                    }
                )
            elif (
                state["nodes"][node_name]["node_id"] != node_id
                or state["nodes"][node_name]["node_name"] != nodes[node_id]["node_name"]
                or state["nodes"][node_name]["node_serial"]
                != nodes[node_id]["node_serial"]
            ):
                # Node node was enumerated - update values
                logging("info", f"Node {node_name} went offline")
                state["nodes"][node_name].update(
                    {
                        "node_id": node_id,
                        "node_name": nodes[node_id]["node_name"],
                        "node_serial": nodes[node_id]["node_serial"],
                    }
                )

        # Calculate averages and set device state
        if online_nodes > 0:
            if online_nodes < len(nodes_names):
                logging("info", f"Only {online_nodes} nodes reported online")
            else:
                logging("debug", f"{online_nodes} nodes reported online")
            state["state"] = "online"
            for sensor in stats_sensors:
                state["stats"][sensor]["avg"] /= online_nodes
                if sensors[sensor]["round"] is not None:
                    state["stats"][sensor]["avg"] = round(
                        state["stats"][sensor]["avg"], sensors[sensor]["round"]
                    )
        else:
            logging("debug", f"No nodes reported online")
            for sensor in stats_sensors:
                for op in stats_ops:
                    state["stats"][sensor][op] = 0

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
            client.publish(
                state_topic, payload=json.dumps(state), qos=int(config["MQTT"]["QOS"])
            )
            last_tele = now
        else:
            logging("error", "MQTT not connected!")
            raise MqttError("MQTT not connected!")


def taptap_power_event(data, now):
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
                data["duty_cycle"] = round(data.pop("dc_dc_duty_cycle") * 100, 2)
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
                data["power"] = data["voltage_out"] * data["current"]
                if not taptap_enumerate_node(data):
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


def taptap_infrastructure_event(data):
    logging("debug", "Into taptap_infrastructure_event")
    global nodes
    global gateways
    global nodes_names_ids

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
            elif (
                data["nodes"][gateway_id][node_id]["barcode"]
                not in nodes_serials_names.keys()
            ):
                logging(
                    "warning",
                    f"Unknown serial detected in the infrastructure event: '{data['nodes'][gateway_id][node_id]['barcode']}'",
                )
                logging("debug", data)
            else:
                # If we reach this point, the serial is valid
                node_serial = data["nodes"][gateway_id][node_id]["barcode"]
                node_name = nodes_serials_names[node_serial]
                logging(
                    "debug",
                    f"Discovered valid serial: {node_serial} and node name: {node_name} for node id: {node_id}",
                )
                for key in nodes.keys():
                    # Update mapping table
                    if key != node_id:
                        if (
                            nodes[key]["node_serial"] == node_serial
                            or nodes[key]["node_name"] == node_name
                        ):
                            # Some other Node is using this node serial or name, delete those records
                            logging(
                                "info",
                                f"Delete invalid serial {node_serial} and node name: {node_name} entries for node id: {key}",
                            )
                            nodes.pop(key)
                            nodes_names_ids.pop(node_name)
                            enumerated = True

                if node_id not in nodes.keys():
                    # discovered new permanent mapping
                    logging(
                        "info",
                        f"Permanently enumerated node id: {node_id} to node name: {node_name} and serial: {node_serial}",
                    )
                    nodes[node_id] = {
                        "node_serial": node_serial,
                        "node_name": node_name,
                    }
                    nodes_names_ids[node_name] = node_id
                    enumerated = True
                elif (
                    nodes[node_id]["node_serial"] != node_serial
                    or nodes[node_id]["node_name"] != node_name
                ):
                    # there is different serial or name for this node id - update it
                    logging(
                        "info",
                        f"Updating node name {node_name} and serial: {node_serial} for node id: {node_id}",
                    )
                    nodes[node_id] = {
                        "node_serial": node_serial,
                        "node_name": node_name,
                    }
                    nodes_names_ids[node_name] = node_id
                    enumerated = True

    if not enumerated:
        logging(
            "debug",
            f"Finished processing node data, no enumeration was required",
        )
    else:
        logging("debug", f"Finished processing node data, nodes were enumerated")

    logging("debug", nodes)

    return enumerated


def taptap_enumerate_node(data):
    logging("debug", "Into taptap_enumerate_node")
    global nodes
    global nodes_names_ids

    if data["node_id"] in nodes.keys():
        # node was already discovered
        logging(
            "debug",
            f"Node id: {data['node_id']} already enumerated to node name: '{nodes[data['node_id']]['node_name']}' and serial: '{nodes[data['node_id']]['node_serial']}'",
        )
        data["node_name"] = nodes[data["node_id"]]["node_name"]
        data["node_serial"] = nodes[data["node_id"]]["node_serial"]
        return True
    else:
        # need to find unused node name and assign it to node_id temporarily
        for node_name in nodes_names:
            if node_name not in nodes_names_ids.keys():
                nodes[data["node_id"]] = {"node_serial": "", "node_name": node_name}
                nodes_names_ids[node_name] = data["node_id"]
                data["node_name"] = node_name
                data["node_serial"] = ""
                logging(
                    "info",
                    f"Temporary enumerated node id: '{data['node_id']}' to node name: {node_name}",
                )
                return True

    logging(
        "warning",
        f"Unable to enumerate node id: '{data['node_id']}' - no more node names available!",
    )
    logging("debug", nodes_names_ids)
    return False


def taptap_discovery():
    logging("debug", "Into taptap_discovery")
    if not config["HA"]["DISCOVERY_PREFIX"]:
        return
    if str_to_bool(config["HA"]["DISCOVERY_LEGACY"]):
        taptap_discovery_legacy()
    else:
        taptap_discovery_device()


def taptap_discovery_device():
    logging("debug", "Into taptap_discovery_device")
    global discovery

    if discovery is None:
        discovery = {}
        discovery["device"] = {
            "ids": str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL, "taptap_" + config["TAPTAP"]["TOPIC_NAME"]
                )
            ),
            "name": config["TAPTAP"]["TOPIC_NAME"].title(),
            "mf": "Tigo",
            "mdl": "Tigo CCA",
        }

        # Origin
        discovery["origin"] = {
            "name": "TapTap MQTT Bridge",
            "sw": "0.1",
            "url": "https://github.com/litinoveweedle/taptap2mqtt",
        }

        # Statistic sensors components
        discovery["components"] = {}
        for sensor in stats_sensors:
            for op in stats_ops:
                sensor_id = config["TAPTAP"]["TOPIC_NAME"] + "_" + sensor + "_" + op
                sensor_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, sensor_id))
                discovery["components"][sensor_id] = {
                    "p": "sensor",
                    "name": (sensor + " " + op).replace("_", " ").title(),
                    "unique_id": sensor_uuid,
                    "default_entity_id": sensor_id,
                    "device_class": sensors[sensor]["class"],
                    "unit_of_measurement": sensors[sensor]["unit"],
                    "state_topic": state_topic,
                    "value_template": "{{ value_json.stats."
                    + sensor
                    + "."
                    + op
                    + " }}",
                }
                if (
                    str_to_bool(config["HA"]["ENTITY_AVAILABILITY"])
                    and sensors[sensor]["avail_key"]
                ):
                    discovery["components"][sensor_id].update(
                        {
                            "availability_mode": "all",
                            "availability": [
                                {"topic": lwt_topic},
                                {
                                    "topic": state_topic,
                                    "value_template": "{{ value_json."
                                    + sensors[sensor]["avail_key"]
                                    + " }}",
                                },
                            ],
                        }
                    )
                else:
                    discovery["components"][sensor_id].update(
                        {"availability_topic": lwt_topic}
                    )

        # Node sensors components
        for node_name in nodes_names:
            node_id = config["TAPTAP"]["TOPIC_NAME"] + "_" + node_name
            for sensor in sensors.keys():
                sensor_id = node_id + "_" + sensor
                sensor_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, sensor_id))
                discovery["components"][sensor_id] = {
                    "p": "sensor",
                    "name": (node_name + " " + sensor).replace("_", " ").title(),
                    "unique_id": sensor_uuid,
                    "default_entity_id": sensor_id,
                    "device_class": sensors[sensor]["class"],
                    "unit_of_measurement": sensors[sensor]["unit"],
                    "state_topic": state_topic,
                    "value_template": "{{ value_json.nodes."
                    + node_name
                    + "."
                    + sensor
                    + " }}",
                    "json_attributes_topic": "{{}}",
                }

                if (
                    str_to_bool(config["HA"]["ENTITY_AVAILABILITY"])
                    and sensors[sensor]["avail_key"]
                ):
                    discovery["components"][sensor_id].update(
                        {
                            "availability_mode": "all",
                            "availability": [
                                {"topic": lwt_topic},
                                {
                                    "topic": state_topic,
                                    "value_template": "{{ value_json.nodes."
                                    + node_name
                                    + "."
                                    + sensors[sensor]["avail_key"]
                                    + " }}",
                                },
                            ],
                        }
                    )
                else:
                    discovery["components"][sensor_id].update(
                        {"availability_topic": lwt_topic}
                    )

        discovery["state_topic"] = state_topic
        discovery["qos"] = config["MQTT"]["QOS"]

    if len(discovery):
        if client and client.is_connected():
            # Sent discovery
            discovery_topic = (
                config["HA"]["DISCOVERY_PREFIX"]
                + "/device/"
                + config["TAPTAP"]["TOPIC_NAME"]
                + "/config"
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


def taptap_discovery_legacy():
    logging("debug", "Into taptap_discovery_legacy")
    global discovery

    if discovery is None:
        discovery = {}
        device = {
            "ids": str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL, "taptap_" + config["TAPTAP"]["TOPIC_NAME"]
                )
            ),
            "name": config["TAPTAP"]["TOPIC_NAME"].title(),
            "mf": "Tigo",
            "mdl": "Tigo CCA",
        }

        # Origin
        origin = {
            "name": "TapTap MQTT Bridge",
            "sw": "0.1",
            "url": "https://github.com/litinoveweedle/taptap2mqtt",
        }

        # Statistic sensors components
        for sensor in stats_sensors:
            for op in stats_ops:
                sensor_id = config["TAPTAP"]["TOPIC_NAME"] + "_" + sensor + "_" + op
                sensor_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, sensor_id))
                discovery["sensor/" + sensor_id] = {
                    "device": device,
                    "origin": origin,
                    "name": (sensor + " " + op).replace("_", " ").title(),
                    "unique_id": sensor_uuid,
                    "object_id": sensor_id,
                    "device_class": sensors[sensor]["class"],
                    "unit_of_measurement": sensors[sensor]["unit"],
                    "state_topic": state_topic,
                    "value_template": "{{ value_json.stats."
                    + sensor
                    + "."
                    + op
                    + " }}",
                    "qos": config["MQTT"]["QOS"],
                }
                if (
                    str_to_bool(config["HA"]["ENTITY_AVAILABILITY"])
                    and sensors[sensor]["avail_key"]
                ):
                    discovery["sensor/" + sensor_id].update(
                        {
                            "availability_mode": "all",
                            "availability": [
                                {"topic": lwt_topic},
                                {
                                    "topic": state_topic,
                                    "value_template": "{{ value_json."
                                    + sensors[sensor]["avail_key"]
                                    + " }}",
                                },
                            ],
                        }
                    )
                else:
                    discovery["sensor/" + sensor_id].update(
                        {"availability_topic": lwt_topic}
                    )

        # Node sensors components
        for node_name in nodes_names:
            node_id = config["TAPTAP"]["TOPIC_NAME"] + "_" + node_name
            for sensor in sensors.keys():
                sensor_id = node_id + "_" + sensor
                sensor_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, sensor_id))
                discovery["sensor/" + sensor_id] = {
                    "device": device,
                    "origin": origin,
                    "name": (node_name + " " + sensor).replace("_", " ").title(),
                    "unique_id": sensor_uuid,
                    "object_id": sensor_id,
                    "device_class": sensors[sensor]["class"],
                    "unit_of_measurement": sensors[sensor]["unit"],
                    "state_topic": state_topic,
                    "value_template": "{{ value_json.nodes."
                    + node_name
                    + "."
                    + sensor
                    + " }}",
                    "qos": config["MQTT"]["QOS"],
                }

                if (
                    str_to_bool(config["HA"]["ENTITY_AVAILABILITY"])
                    and sensors[sensor]["avail_key"]
                ):
                    discovery["sensor/" + sensor_id].update(
                        {
                            "availability_mode": "all",
                            "availability": [
                                {"topic": lwt_topic},
                                {
                                    "topic": state_topic,
                                    "value_template": "{{ value_json.nodes."
                                    + node_name
                                    + "."
                                    + sensors[sensor]["avail_key"]
                                    + " }}",
                                },
                            ],
                        }
                    )
                else:
                    discovery["sensor/" + sensor_id].update(
                        {"availability_topic": lwt_topic}
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


def taptap_init():
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
            + " --persistent-file "
            + config["TAPTAP"]["PERSISTENT_FILE"],
        )
        taptap = subprocess.Popen(
            [
                config["TAPTAP"]["BINARY"],
                "observe",
                "--serial",
                config["TAPTAP"]["SERIAL"],
                "--persistent-file",
                config["TAPTAP"]["PERSISTENT_FILE"],
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
            + " --persistent-file "
            + config["TAPTAP"]["PERSISTENT_FILE"],
        )
        taptap = subprocess.Popen(
            [
                config["TAPTAP"]["BINARY"],
                "observe",
                "--tcp",
                config["TAPTAP"]["ADDRESS"],
                "--port",
                config["TAPTAP"]["PORT"],
                "--persistent-file",
                config["TAPTAP"]["PERSISTENT_FILE"],
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


def taptap_cleanup():
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


def mqtt_init():
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

    # Subscribe for homeassistant birth messages
    if config["HA"]["BIRTH_TOPIC"]:
        client.subscribe(config["HA"]["BIRTH_TOPIC"])


def mqtt_cleanup():
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
def mqtt_on_connect(client, userdata, flags, rc):
    logging("debug", "Into mqtt_on_connect")
    if rc != 0:
        logging("warning", "MQTT unexpected connect return code " + str(rc))
    else:
        logging("info", "MQTT client connected")


# The callback for when the client receives a DISCONNECT from the server.
def mqtt_on_disconnect(client, userdata, rc):
    logging("debug", "Into mqtt_on_disconnect")
    if rc != 0:
        logging("warning", "MQTT unexpected disconnect return code " + str(rc))
    logging("info", "MQTT client disconnected")


# The callback for when a PUBLISH message is received from the server.
def mqtt_on_message(client, userdata, msg):
    logging("debug", "Into mqtt_on_message")
    topic = str(msg.topic)
    payload = str(msg.payload.decode("utf-8"))
    logging("debug", f"MQTT received topic: {topic}, payload: {payload}")
    match_birth = re.match(r"^" + config["HA"]["BIRTH_TOPIC"] + "$", topic)
    if config["HA"]["BIRTH_TOPIC"] and match_birth:
        # discovery
        taptap_discovery()
    else:
        logging("warning", "Unknown topic: " + topic + ", message: " + payload)


# Touch state file on successful run
def state_file(mode):
    logging("debug", "Into state_file")
    if mode:
        if config["RUNTIME"]["STATE_FILE"]:
            path = os.path.split(config["RUNTIME"]["STATE_FILE"])
            try:
                # Create stat file directory if not exists
                if not os.path.isdir(path[0]):
                    os.makedirs(path[0], exist_ok=True)
                # Write stats file
                with open(config["RUNTIME"]["STATE_FILE"], "a"):
                    os.utime(config["RUNTIME"]["STATE_FILE"], None)
                logging("debug", "stats file updated")
            except IOError as error:
                logging(
                    "error",
                    f"Unable to write to file: {config['RUNTIME']['STATE_FILE']} error: {error}",
                )
                exit(1)
    elif os.path.isfile(config["RUNTIME"]["STATE_FILE"]):
        os.remove(config["RUNTIME"]["STATE_FILE"])


def str_to_bool(string):
    # Converts `s` to boolean. Assumes string is case-insensitive
    return string.lower() in ["true", "1", "t", "y", "yes"]


client = None
taptap = None
restart = 0
while True:
    try:
        # Init counters
        last_tele = 0
        # Create mqtt client
        if not client:
            # Init mqtt
            mqtt_init()
        if not taptap:
            # Init taptap
            taptap_init()
        # Sent discovery
        taptap_discovery()
        # Run update loop
        while True:
            taptap_tele(0)
            state_file(1)
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
            state_file(0)
            # Graceful shutdown
            sys.exit(0)
        else:
            logging("error", f"Unknown exception, aborting application")
            logging("debug", f"Exception details: {traceback.format_exc()}")
            # Exit with error
            sys.exit(1)
