FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies required by requirements.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy TapTap binary and MQTT bridge
COPY taptap .
COPY taptap-mqtt.py .

# Make TapTap binary executable
RUN chmod +x /app/taptap

#start taptap-mqtt python program
CMD ["python3", "taptap-mqtt.py"]