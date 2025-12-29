# Create a Docker Container for taptap‑mqtt

This repository provides a Dockerized version of the TapTap‑MQTT bridge. It includes a Dockerfile, a docker‑compose example, and Unraid setup instructions.

---

## Build a Docker Image for the taptap‑mqtt Container


If you don’t already have Docker installed, follow the official installation guide:

https://docs.docker.com/engine/install/

---

### Create a Docker Build Folder

This folder will contain the `Dockerfile` and all files required to build the Docker image. It will also store your persistent `config.ini`.

To create a folder in your home directory (adjust as needed):

```bash
mkdir -p ~/taptap-mqtt
cd ~/taptap-mqtt
```

If you are planning to run this on Unraid, a typical appdata path is:

```bash
mkdir -p /mnt/user/appdata/taptap-mqtt
cd /mnt/user/appdata/taptap-mqtt
```

Adjust the path if your appdata share is located elsewhere.

---

### Files Required in the Build Folder

```
taptap-mqtt/
├── Dockerfile            (builds the container image)
├── taptap-mqtt.py        (main Python program, from the main repository)
├── config.ini            (configuration file for taptap-mqtt.py)
├── taptap                (TapTap binary, from the upstream TapTap repository)
├── requirements.txt      (Python dependencies, from the main repository)
├── docker-compose.yml    (optional, if using docker-compose)
```

### Persistent Data Files
TapTap maintains a small JSON file (`taptap.json`) that stores previously detected module serial numbers. This allows TapTap to initialize the pv panel topology much faster on restart. This file needs to be mounted outside of the docker container for persistent storage so that it remains intact when you recreate docker containers. 

For the file to be persistent, update `config.ini` with this line: 

```STATE_FILE = /app/taptap.json```

The `config.ini` file will also be mounted outside of the docker so it is persistent as well. 

---

### Build the Image

From the folder containing the Dockerfile, run:

```bash
docker build -t taptap-mqtt:latest .
```
Depending on your user's privilages, you may have to run the docker commands with `sudo` if you don't have root privilages. 

This builds a Docker image named `taptap-mqtt` with the tag `latest`, using the files in the current directory.

---

## Run the Docker Container

### Run the Container Using `docker run`

The following command will run the container (for Unraid, see the next section):

- Runs in **detached mode**  
- Names the container **taptap-mqtt**  
- Restarts automatically unless manually stopped  
- Adds the minimal capability required by the Python script  
- Mounts your `config.ini` into the container  
- Uses bridge networking  
- Runs the image you built earlier  

```bash
docker run -d --name taptap-mqtt \
  --restart unless-stopped \
  --cap-add=SYS_RESOURCE \
  -v ~/taptap-mqtt/config.ini:/app/config.ini:ro \
  -v ~/taptap-mqtt/taptap.json:/app/taptap.json \
  --network bridge \
  taptap-mqtt:latest
```

To view logs:

```bash
docker logs -f taptap-mqtt
```

---

## Running with Docker Compose

Create a file named `docker-compose.yml` with:

```yaml
services:
  taptap-mqtt:
    image: taptap-mqtt:latest
    container_name: taptap-mqtt
    restart: unless-stopped
    cap_add:
      - SYS_RESOURCE
    volumes:
      - ./config.ini:/app/config.ini:ro
      - ./taptap.json:/app/taptap.json
```

Or create it automatically:

```bash
cat << 'EOF' > docker-compose.yml
services:
  taptap-mqtt:
    image: taptap-mqtt:latest
    container_name: taptap-mqtt
    restart: unless-stopped
    cap_add:
      - SYS_RESOURCE
    volumes:
      - ./config.ini:/app/config.ini:ro
      - ./taptap.json:/app/taptap.json
EOF
```

Start the container:

```bash
docker compose up -d
```
To view logs:

```bash
docker logs -f taptap-mqtt
```
---

## Running TapTap‑MQTT on Unraid

This section explains how to deploy TapTap‑MQTT using the Unraid Docker GUI.

1. Open the Docker tab:  
   **Unraid Web UI → Docker → Add Container**

2. Switch to Advanced View:  
   **Top‑right corner → Advanced View**

3. Name the container:  
   `taptap-mqtt`

4. Set the Repository:  
   `taptap-mqtt:latest`

5. Add required volume mappings:

   - Host: `/mnt/user/appdata/taptap-mqtt/config.ini`  
     Container: `/app/config.ini`  
     Mode: `Read Only`

   - Host: `/mnt/user/appdata/taptap-mqtt/taptap.json`  
     Container: `/app/taptap.json`  
     Mode: `Read/Write` 

6. Add Extra Parameters:  
   `--cap-add=SYS_RESOURCE`

7. Enable Autostart:  
   `Autostart: Yes`

8. Apply and Start:  
   Click **Apply**

9. View Logs:  
   Click the **Log** icon next to the container.  
   You should see TapTap‑MQTT initializing and publishing MQTT messages.

---


## Updating the Container

If you update **taptap-mqtt.py** or **taptap** with a new version, rebuild the image and restart the container:

```bash
# Rebuild the image
docker build -t taptap-mqtt:latest .

# Restart the container to load the new image
docker restart taptap-mqtt
```

If you only update **config.ini**, simply restart the container:

```bash
docker restart taptap-mqtt
```

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

---