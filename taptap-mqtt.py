#! /usr/bin/python3

import paho.mqtt.client as mqtt
import configparser
import json
import time
import uptime
import os
import sys
import uuid
import re
import subprocess
from dateutil import tz
from datetime import datetime, timezone
from pathlib import Path


# Define user-defined exception
class AppError(Exception):
    "Raised on application error"

    pass


class MqttError(Exception):
    "Raised on MQTT connection failure"

    pass


# Global variables
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
        "BIRTH_TOPIC": r"^(\w+)(\/\w+)*",
        "ENTITY_AVAILABILITY": r"^(true|false)$",
    },
    "RUNTIME": {
        "MAX_ERROR": r"^\d+$",
        "STATE_FILE?": r"^\/\w+(\/[\.\w]+)*$",
    },
}


# Read config
config = configparser.ConfigParser()
if len(sys.argv) > 1 and sys.argv[1] and Path(sys.argv[1]).is_file():
    print("Reading config file: " + sys.argv[1])
    config.read(sys.argv[1])
elif Path("config.ini").is_file():
    print("Reading default config file: ./config.ini")
    config.read("config.ini")
else:
    print("No valid configuration file found/specified")
    exit(1)

for section in config_validation:
    if not section in config.sections():
        print("Missing config section: " + section)
        exit(1)
    for param1 in config_validation[section]:
        optional = False
        param2 = param1
        if param1[-1:] == "?":
            param2 = param1[:-1]
            optional = True

        if not param2 in config[section] or config[section][param2] is None:
            print("Missing config parameter: " + param2)
            exit(1)
        elif config_validation[section][param1] and not re.match(
            config_validation[section][param1], config[section][param2]
        ):
            if not (optional and not config[section][param2]):
                print("Invalid config entry: " + section + "/" + param2)
                exit(1)


if not Path(config["TAPTAP"]["BINARY"]).is_file():
    print("TATTAP BINARY doesn't exists!")
    exit(1)

if (
    (not config["TAPTAP"]["SERIAL"] and not config["TAPTAP"]["ADDRESS"])
    or (config["TAPTAP"]["SERIAL"] and config["TAPTAP"]["ADDRESS"])
    or (config["TAPTAP"]["ADDRESS"] and not config["TAPTAP"]["PORT"])
):
    print("Either TAPTAP SERIAL or ADDRESS and PORT shall be set!")
    exit(1)


node_names = list(map(str.strip, config["TAPTAP"]["MODULE_NAMES"].lower().split(",")))
if not len(node_names) or not (all([re.match(r"^\w+$", val) for val in node_names])):
    print(f"MODULE_NAMES shall be comma separated list of modules names: {node_names}")
    exit(1)

node_ids = list(map(str.strip, config["TAPTAP"]["MODULE_IDS"].split(",")))
if not len(node_ids) or not (all([re.match(r"^\d+$", val) for val in node_ids])):
    print(f"MODULE_IDS shall be comma separated list of modules IDs: {node_ids}")
    exit(1)

if len(node_ids) != len(node_names):
    print("MODULE_IDS and MODULE_NAMES shall have same number of modules")
    exit(1)

# Init nodes dictionary
nodes = dict(zip(node_ids, node_names))

# Init cache records
cache = dict.fromkeys(node_names, {})

# Init MQTT topics
lwt_topic = (
    config["TAPTAP"]["TOPIC_PREFIX"] + "/" + config["TAPTAP"]["TOPIC_NAME"] + "/lwt"
)
state_topic = (
    config["TAPTAP"]["TOPIC_PREFIX"] + "/" + config["TAPTAP"]["TOPIC_NAME"] + "/state"
)
discovery_topic = (
    config["HA"]["DISCOVERY_PREFIX"]
    + "/device/"
    + config["TAPTAP"]["TOPIC_NAME"]
    + "/config"
)


def taptap_tele(mode):
    global last_tele
    global taptap
    global state
    global cache
    now = time.time()

    # Check taptap process is alive
    if not taptap or not taptap.stdout or taptap.poll() is not None:
        print("TapTap process is not running!")
        raise AppError("TapTap process is not running!")

    for line in taptap.stdout:
        try:
            data = json.loads(line)
        except json.JSONDecodeError as error:
            print(f"Can't parse json: {error}")
            continue

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
                print(f"Missing required key: '{name}'")
                print(data)
                break
            elif name in ["gateway", "node"]:
                if not (
                    isinstance(data[name], dict)
                    and "id" in data[name].keys()
                    and isinstance(data[name]["id"], int)
                ):
                    print(f"Invalid key: '{name}' value: '{data[name]}'")
                    break
                if name == "node" and str(data[name]["id"]) not in nodes.keys():
                    print(f"Unknown node id: '{data[name]['id']}'")
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
                    print(f"Invalid key: '{name}' value: '{data[name]}'")
                    break
                if name == "dc_dc_duty_cycle":
                    data["duty_cycle"] = round(data.pop("dc_dc_duty_cycle") * 100, 2)
            elif name in ["rssi"]:
                if not isinstance(data[name], int):
                    print(f"Invalid key: '{name}' value: '{data[name]}'")
                    break
            elif name == "timestamp":
                if not (isinstance(data[name], str)) and re.match(
                    r"^\d{4}\-\d{2}\-\d{2}T\d{2}\:\d{2}\:\d{2}\.\d{6,9}\+\d{2}\:\d{2}$",
                    data[name],
                ):
                    print(f"Invalid key: '{name}' value: '{data[name]}'")
                    break
                try:
                    if len(data[name]) == 35:
                        tmstp = datetime.strptime(
                            data[name][0:26] + data[name][29:],
                            "%Y-%m-%dT%H:%M:%S.%f%z",
                        )
                    elif len(data[name]) == 32:
                        tmstp = datetime.strptime(
                            data[name],
                            "%Y-%m-%dT%H:%M:%S.%f%z",
                        )
                    else:
                        print(f"Invalid key 'timestamp' format: '{data[name]}'")
                        break
                    data["timestamp"] = tmstp.isoformat()
                    data["tmstp"] = tmstp.timestamp()
                except:
                    print(f"Invalid key: '{name}' value: '{data[name]}'")
                    break
                # Copy validated data into cache struct
                if data["tmstp"] + int(config["TAPTAP"]["UPDATE"]) < now:
                    diff = round(now - data["tmstp"], 1)
                    print(f"Old data detected: '{data[name]}', time difference: '{diff}'s")
                    break
                else:
                    data["power"] = data["voltage_out"] * data["current"]
                    cache[nodes[str(data["node_id"])]][data["tmstp"]] = data

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
                    state["stats"][sensor]["avg"] = 0
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
                # Node not online - init default values
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
            ):
                # Node went recently offline - reset values
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
            state["state"] = "online"
            for sensor in stats_sensors:
                state["stats"][sensor]["avg"] /= online_nodes
                if sensors[sensor]["round"] is not None:
                    state["stats"][sensor]["avg"] = round(
                        state["stats"][sensor]["avg"], sensors[sensor]["round"]
                    )
        else:
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

        if client and client.connected_flag:
            client.publish(state_topic, json.dumps(state), int(config["MQTT"]["QOS"]))
            last_tele = now
        else:
            print("MQTT not connected!")
            raise MqttError("MQTT not connected!")


def taptap_discovery():
    if not config["HA"]["DISCOVERY_PREFIX"]:
        return

    discovery = {}
    discovery["device"] = {
        "ids": str(
            uuid.uuid5(uuid.NAMESPACE_URL, "taptap_" + config["TAPTAP"]["TOPIC_NAME"])
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
                "object_id": sensor_id,
                "device_class": sensors[sensor]["class"],
                "unit_of_measurement": sensors[sensor]["unit"],
                "state_topic": state_topic,
                "value_template": "{{ value_json.stats." + sensor + "." + op + " }}",
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
                "object_id": sensor_id,
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

    if client and client.connected_flag:
        # Sent LWT update
        client.publish(lwt_topic, payload="online", qos=0, retain=True)
        # Sent discovery
        client.publish(
            discovery_topic, json.dumps(discovery), int(config["MQTT"]["QOS"])
        )
    else:
        print("MQTT not connected!")
        raise MqttError("MQTT not connected!")


def taptap_init():
    global taptap

    # Initialize taptap process
    if config["TAPTAP"]["SERIAL"]:
        taptap = subprocess.Popen(
            [
                config["TAPTAP"]["BINARY"],
                "observe",
                "--serial",
                config["TAPTAP"]["SERIAL"],
            ],
            stdout=subprocess.PIPE,
        )
    elif config["TAPTAP"]["ADDRESS"]:
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
        )
    else:
        print("Either TAPTAP SERIAL or ADDRESS and PORT shall be set!")
        exit(1)

    if taptap and taptap.stdout:
        # Set stdout as non blocking
        os.set_blocking(taptap.stdout.fileno(), False)
    else:
        print("TapTap process is not running!")
        raise AppError("TapTap process is not running!")


def taptap_cleanup():
    global taptap

    if taptap:
        taptap.terminate()
        time.sleep(1)
        if taptap.poll() is not None:
            taptap.kill()
        del taptap


def mqtt_init():
    global client

    # Create mqtt client
    client = mqtt.Client()
    client.connected_flag = 0
    client.reconnect_count = 0
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

    time.sleep(1)
    while not client.connected_flag:
        print("MQTT waiting to connect")
        client.reconnect_count += 1
        if client.reconnect_count > 10:
            print("MQTT not connected!")
            raise MqttError("MQTT not connected!")
        time.sleep(3)

    # Subscribe for homeassistant birth messages
    if config["HA"]["BIRTH_TOPIC"]:
        client.subscribe(config["HA"]["BIRTH_TOPIC"])


def mqtt_cleanup():
    global client

    if client:
        client.loop_stop()
        if client.connected_flag:
            if config["HA"]["BIRTH_TOPIC"]:
                client.unsubscribe(config["HA"]["BIRTH_TOPIC"])
            client.disconnect()
        del client


# The callback for when the client receives a CONNACK response from the server.
def mqtt_on_connect(client, userdata, flags, rc):
    if rc != 0:
        print("MQTT unexpected connect return code " + str(rc))
    else:
        print("MQTT client connected")
        client.connected_flag = 1


# The callback for when the client receives a DISCONNECT from the server.
def mqtt_on_disconnect(client, userdata, rc):
    client.connected_flag = 0
    if rc != 0:
        print("MQTT unexpected disconnect return code " + str(rc))
    print("MQTT client disconnected")


# The callback for when a PUBLISH message is received from the server.
def mqtt_on_message(client, userdata, msg):
    topic = str(msg.topic)
    payload = str(msg.payload.decode("utf-8"))
    match_birth = re.match(r"^" + config["HA"]["BIRTH_TOPIC"] + "$", topic)
    if config["HA"]["BIRTH_TOPIC"] and match_birth:
        # discovery
        taptap_discovery()
    else:
        print("Unknown topic: " + topic + ", message: " + payload)


# Touch state file on successful run
def state_file(mode):
    if mode:
        if int(config["RUNTIME"]["MAX_ERROR"]) > 0 and config["RUNTIME"]["STATE_FILE"]:
            path = os.path.split(config["RUNTIME"]["STATE_FILE"])
            try:
                # Create stat file directory if not exists
                if not os.path.isdir(path[0]):
                    os.makedirs(path[0], exist_ok=True)
                # Write stats file
                with open(config["RUNTIME"]["STATE_FILE"], "a"):
                    os.utime(config["RUNTIME"]["STATE_FILE"], None)
            except IOError as error:
                print(
                    f"Unable to write to file: {config['RUNTIME']['STATE_FILE']} error: {error}"
                )
                exit(1)
    elif os.path.isfile(config["RUNTIME"]["STATE_FILE"]):
        os.remove(config["RUNTIME"]["STATE_FILE"])


def str_to_bool(string):
    """Converts `s` to boolean. Assumes `s` is case-insensitive."""
    return string.lower() in ["true", "1", "t", "y", "yes"]


# Add connection flags
mqtt.Client.connected_flag = 0
mqtt.Client.reconnect_count = 0

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
        # Run sending thread
        while True:
            taptap_tele(0)
            state_file(1)
            restart = 0
            time.sleep(1)
    except BaseException as error:
        print("An exception occurred:", type(error).__name__, "–", error)
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
            mqtt_cleanup()
            taptap_cleanup()
            state_file(0)
            # Graceful shutdown
            sys.exit(0)
        else:
            # Exit with error
            sys.exit(1)
