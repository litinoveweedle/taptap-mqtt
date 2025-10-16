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
    "voltage_in": {"class": "voltage", "unit": "V", "round": 2},
    "voltage_out": {"class": "voltage", "unit": "V", "round": 2},
    "current": {"class": "current", "unit": "A", "round": 2},
    "power": {"class": "power", "unit": "W", "round": 0},
    "temperature": {"class": "temperature", "unit": "°C", "round": 1},
    "duty_cycle": {"class": "power_factor", "unit": "%", "round": 0},
    "rssi": {"class": "signal_strength", "unit": "dB", "round": 0},
    "timestamp": {"class": "timestamp", "unit": None, "round": None},
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
        "MODULE_IDS": r"^\s*\d+\s*(\,\s*\d+\s*)*$",
        "MODULE_NAMES": r"^\s*\w+\s*(\,\s*\w+\s*)*$",
        "TOPIC_PREFIX": r"^(\w+)(\/\w+)*",
        "TOPIC_NAME": r"^(\w+)$",
        "TIMEOUT": r"^\d+$",
        "UPDATE": r"^\d+$",
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


node_names = list(map(str.strip, config["TAPTAP"]["MODULE_NAMES"].lower().split(",")))
if not len(node_names) or not (all([re.match(r"^\w+$", val) for val in node_names])):
    logging(
        "error",
        f"MODULE_NAMES shall be comma separated list of modules names: {node_names}",
    )
    exit(1)

node_ids = list(map(str.strip, config["TAPTAP"]["MODULE_IDS"].split(",")))
if not len(node_ids) or not (all([re.match(r"^\d+$", val) for val in node_ids])):
    logging(
        "error", f"MODULE_IDS shall be comma separated list of modules IDs: {node_ids}"
    )
    exit(1)

if len(node_ids) != len(node_names):
    logging("error", "MODULE_IDS and MODULE_NAMES shall have same number of modules")
    exit(1)

# Init nodes dictionary
nodes = dict(zip(node_ids, node_names))

# Init cache struct
cache = dict.fromkeys(node_names, {})

# Init discovery struct
discovery = None

# Init MQTT topics
lwt_topic = (
    config["TAPTAP"]["TOPIC_PREFIX"] + "/" + config["TAPTAP"]["TOPIC_NAME"] + "/lwt"
)
state_topic = (
    config["TAPTAP"]["TOPIC_PREFIX"] + "/" + config["TAPTAP"]["TOPIC_NAME"] + "/state"
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
            logging("warning", line)
            continue

        logging("debug", "Received taptap data")
        logging("debug", line)
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
                break
            elif name in ["gateway", "node"]:
                if not (
                    isinstance(data[name], dict)
                    and "id" in data[name].keys()
                    and isinstance(data[name]["id"], int)
                ):
                    logging("warning", f"Invalid key: '{name}' value: '{data[name]}'")
                    logging("debug", data)
                    break
                if name == "node" and str(data[name]["id"]) not in nodes.keys():
                    logging("warning", f"Unknown node id: '{data[name]['id']}'")
                    logging("debug", data)
                    break
                data[name + "_id"] = data[name]["id"]
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
                    break
                if name == "dc_dc_duty_cycle":
                    data["duty_cycle"] = round(data.pop("dc_dc_duty_cycle") * 100, 2)
            elif name in ["rssi"]:
                if not isinstance(data[name], int):
                    logging("warning", f"Invalid key: '{name}' value: '{data[name]}'")
                    logging("debug", data)
                    break
            elif name == "timestamp":
                if not (isinstance(data[name], str)) and data[name]:
                    logging("warning", f"Invalid key: '{name}' value: '{data[name]}'")
                    logging("debug", data)
                    break
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
                        break
                    data["timestamp"] = tmstp.isoformat()
                    data["tmstp"] = tmstp.timestamp()
                except:
                    logging("warning", f"Invalid key: '{name}' value: '{data[name]}'")
                    logging("debug", data)
                    break
                # Copy validated data into cache struct
                if data["tmstp"] + int(config["TAPTAP"]["UPDATE"]) < now:
                    diff = round(now - data["tmstp"], 1)
                    logging(
                        "warning",
                        f"Old data detected: '{data[name]}', time difference: '{diff}'s",
                    )
                    logging("debug", data)
                    break
                else:
                    data["power"] = data["voltage_out"] * data["current"]
                    cache[nodes[str(data["node_id"])]][data["tmstp"]] = data
                    logging("debug", "Successfully processed data line")
                    logging("debug", data)

    if mode or last_tele + int(config["TAPTAP"]["UPDATE"]) < now:
        online_nodes = 0
        # Init statistic values
        for sensor in stats_sensors:
            state["stats"][sensor] = {}
            for op in stats_ops:
                state["stats"][sensor][op] = None

        for node_id in nodes.keys():
            node_name = nodes[node_id]
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
                    "gateway_id": 0,
                    "state": "offline",
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

        # Calculate averages and set device state
        if online_nodes > 0:
            if online_nodes < len(node_ids):
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
                if str_to_bool(config["HA"]["ENTITY_AVAILABILITY"]):
                    discovery["components"][sensor_id].update(
                        {
                            "availability_mode": "all",
                            "availability": [
                                {"topic": lwt_topic},
                                {
                                    "topic": state_topic,
                                    "value_template": "{{ value_json.state }}",
                                },
                            ],
                        }
                    )
                else:
                    discovery["components"][sensor_id].update(
                        {"availability_topic": lwt_topic}
                    )

        # Node sensors components
        for node_name in nodes.values():
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
                }

                if str_to_bool(config["HA"]["ENTITY_AVAILABILITY"]):
                    discovery["components"][sensor_id].update(
                        {
                            "availability_mode": "all",
                            "availability": [
                                {"topic": lwt_topic},
                                {
                                    "topic": state_topic,
                                    "value_template": "{{ value_json.nodes."
                                    + node_name
                                    + ".state }}",
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
                if str_to_bool(config["HA"]["ENTITY_AVAILABILITY"]):
                    discovery["sensor/" + sensor_id].update(
                        {
                            "availability_mode": "all",
                            "availability": [
                                {"topic": lwt_topic},
                                {
                                    "topic": state_topic,
                                    "value_template": "{{ value_json.state }}",
                                },
                            ],
                        }
                    )
                else:
                    discovery["sensor/" + sensor_id].update(
                        {"availability_topic": lwt_topic}
                    )

        # Node sensors components
        for node_name in nodes.values():
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

                if str_to_bool(config["HA"]["ENTITY_AVAILABILITY"]):
                    discovery["sensor/" + sensor_id].update(
                        {
                            "availability_mode": "all",
                            "availability": [
                                {"topic": lwt_topic},
                                {
                                    "topic": state_topic,
                                    "value_template": "{{ value_json.nodes."
                                    + node_name
                                    + ".state }}",
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
            + config["TAPTAP"]["SERIAL"],
        )
        taptap = subprocess.Popen(
            [
                config["TAPTAP"]["BINARY"],
                "observe",
                "--serial",
                config["TAPTAP"]["SERIAL"],
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
            + config["TAPTAP"]["PORT"],
        )
        taptap = subprocess.Popen(
            [
                config["TAPTAP"]["BINARY"],
                "observe",
                "--tcp",
                config["TAPTAP"]["ADDRESS"],
                "--port",
                config["TAPTAP"]["PORT"],
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
        if taptap.poll() is not None:
            logging("info", "Terminating TapTap process.")
            taptap.terminate()
            time.sleep(1)
            if taptap.poll() is not None:
                logging("warning", "TapTap process is still running, sending kill!")
                taptap.kill()
                time.sleep(3)
                if taptap.poll() is not None:
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
            # Exit with error
            sys.exit(1)
