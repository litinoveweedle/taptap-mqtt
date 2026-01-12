# TapTap‑MQTT Docker README

This is a Docker implementation of the **TapTap → MQTT bridge** for reading data from **Tigo TS4 optimizers** via the CCA/TAP and publishing it into **Home Assistant** using MQTT.

This container bundles:

- the TapTap binary (downloaded per‑architecture)
- the TapTap‑MQTT Python bridge
- automatic config initialization
- persistent config + state
- multi‑architecture support (amd64, arm64, armv7)

This is for users running:

- Home Assistant Core in Docker  
- Standalone Docker setups  
- Unraid, Proxmox, Raspberry Pi, etc.

If you are running **Home Assistant OS** or **Home Assistant Supervised**, use the official add‑on instead:

https://github.com/litinoveweedle/hassio-addons/tree/main/taptap

---

# Installation Prerequisites

Before running this container, you need:

### 1. MQTT Broker  
Any MQTT broker works (Mosquitto, EMQX, HiveMQ, etc.).

### 2. Home Assistant MQTT Integration  
Required for automatic discovery.

### 3. RS485 → Serial/Ethernet Converter  
Example: Waveshare RS485‑to‑Ethernet.

### 4. Correct Wiring  
Wire the converter **in parallel** with the TAP wiring on the Tigo CCA:

- A → A  
- B → B  
- Ground → Ground  

### 5. Converter Configuration  
Typical settings:

- Baud: 38400  
- Data bits: 8  
- Stop bits: 1  
- Flow control: None  
- Mode: Modbus TCP Server  
- Protocol: None  

### 6. Network Setup  
- Assign a stable IP  
- Note the TCP port (usually 502)

---

# Configuration

The container supports **two ways** to set up your configuration.

---

## Option A — Let the container create the initial config

1. Start the container for the first time.  
2. The container will: 
   - create a new `config.ini`  
   - set the correct internal paths for:
     ```
     BINARY = /app/taptap/taptap
     STATE_FILE = /app/data/taptap.json
     ```
   - then **exit immediately**
3. Edit your config file:

```
~/taptap-mqtt/config/config.ini
```

Or on Unraid:

```
/mnt/user/appdata/taptap-mqtt/config/config.ini
```

4. Restart the container.  
   It will now run normally and never modify your config again.

---

## Option B — Create the config yourself before first run

If you prefer to prepare everything manually in advance:

1. Create the folders:
   ```
   mkdir -p ~/taptap-mqtt/config
   mkdir -p ~/taptap-mqtt/data
   ```
2. Copy the example config and rename it:
   ```
   config.ini.example → config.ini
   ```
3. You **must** set these two values correctly in the config file:

```
BINARY = /app/taptap/taptap
STATE_FILE = /app/data/taptap.json
```

If these values are missing or incorrect, the container will warn you on startup but will not modify your file.

Fill out the rest of the variables in the config file and save it.

4. Start the container.  
   Since your config already exists, it will run immediately.

---

## Log level recommendation

For first‑time setup:

```
LOG_LEVEL = debug
```

After everything is working, change to:

```
LOG_LEVEL = info
```

or

```
LOG_LEVEL = warning
```

---

# Quick Start (Docker Run)

Create persistent folders:

```sh
mkdir -p ~/taptap-mqtt/config
mkdir -p ~/taptap-mqtt/data
```

Run:

```sh
docker run -d --name taptap-mqtt \
  --cap-add=SYS_RESOURCE \
  -v ~/taptap-mqtt/config:/app/config \
  -v ~/taptap-mqtt/data:/app/data \
  --restart unless-stopped \
  ghcr.io/godel00/taptap-mqtt:latest
```

---

# Using docker‑compose

A `docker-compose.yml` is included. 
You can dowload it with wget:
```
wget https://raw.githubusercontent.com/godel00/taptap-mqtt/add-docker/docker/docker-compose.yml
```
or
```
curl -o docker-compose.yml \
  https://raw.githubusercontent.com/godel00/taptap-mqtt/add-docker/docker/docker-compose.yml
```
Start:

```sh
docker compose up -d
```

Update:

```sh
docker compose pull
docker compose up -d
```

---

# Running on Unraid (GUI)

Create folders (either SSH into Unraid or use the shell from GUI) - This is the usual path:

```sh
mkdir -p /mnt/user/appdata/taptap-mqtt/config
mkdir -p /mnt/user/appdata/taptap-mqtt/data
```

Then in Docker → Add Container:

- Switch from *Basic View* to *Advanced View*
- Name: `taptap-mqtt`
- Repository: `ghcr.io/godel00/taptap-mqtt:latest`
- Path: `/app/config` → `/mnt/user/appdata/taptap-mqtt/config`
- Path: `/app/data` → `/mnt/user/appdata/taptap-mqtt/data`
- Capability: `SYS_RESOURCE`
- Restart policy: `Unless stopped`

---

# Running on Unraid (Template XML Method)

Save the provided XML as:

```
/boot/config/plugins/dockerMan/templates-user/my-taptap-mqtt.xml
```

Then in Unraid:

**Docker → Add Container → Template dropdown → my-taptap-mqtt**

Click **Apply**.

---

# Folder Structure

### Host (persistent)

```
~/taptap-mqtt/
├── config/
│   ├── config.ini
│   └── config.ini.example
└── data/
    └── taptap.json
```

### Inside the container

```
/app
├── config/
│   ├── config.ini
│   └── config.ini.example
├── data/
│   └── taptap.json
├── taptap/
│   └── taptap
└── taptap-mqtt/
    └── taptap-mqtt.py
```

---

# Home Assistant Integration

Once running with valid MQTT settings, Home Assistant will automatically discover:

- Optimizer sensors  
- Voltage, current, temperature  
- Module power  
- TAP/CCA status  
- Availability sensors  

They appear under:

Home Assistant → Settings → Devices & Services → MQTT → Devices

If nothing appears:

- verify MQTT credentials  
- check Modbus converter IP/port  
- ensure protocol = None  
- temporarily set `LOG_LEVEL = debug`


---


# **Docker Cheat Sheet**

A quick reference for common Docker commands used when building, running, and managing the TapTap‑MQTT container.

---

## **Images**

### **List all images**
```bash
docker images
```

### **Build an image**
```bash
docker build -t taptap-mqtt:latest .
```

### **Remove an image**
```bash
docker rmi taptap-mqtt:latest
```

---

## **Containers**

### **List running containers**
```bash
docker ps
```

### **List all containers (including stopped)**
```bash
docker ps -a
```

### **Start a container**
```bash
docker start taptap-mqtt
```

### **Stop a container**
```bash
docker stop taptap-mqtt
```

### **Restart a container**
```bash
docker restart taptap-mqtt
```

### **Remove a container**
```bash
docker rm taptap-mqtt
```

If it’s running, stop it first:
```bash
docker stop taptap-mqtt
docker rm taptap-mqtt
```

---

## **Logs & Debugging**

### **View container logs**
```bash
docker logs taptap-mqtt
```

### **Follow logs in real time**
```bash
docker logs -f taptap-mqtt
```

### **Inspect container details**
```bash
docker inspect taptap-mqtt
```

### **Enter a shell inside the container**
```bash
docker exec -it taptap-mqtt /bin/sh
```

---

## **Volumes & Bind Mounts**

### **List Docker volumes**
```bash
docker volume ls
```

### **Inspect a volume**
```bash
docker volume inspect <volume-name>
```

*(TapTap‑MQTT uses bind mounts, not named volumes, but these commands are still useful.)*

---

## **Docker Compose**

### **Start services**
```bash
docker compose up -d
```

### **Stop services**
```bash
docker compose down
```

### **View compose logs**
```bash
docker compose logs -f
```