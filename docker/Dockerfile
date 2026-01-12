# ============================
# Stage 1 — Builder
# ============================
FROM python:3.14-alpine AS builder

LABEL org.opencontainers.image.title="TapTap-MQTT"
LABEL org.opencontainers.image.description="Docker implementation of Tigo CCA Tap to MQTT bridge."
LABEL org.opencontainers.image.source="https://github.com/litinoveweedle/taptap-mqtt"
LABEL org.opencontainers.image.licenses="MIT"

ARG TAPTAP_VERSION=""
ARG TAPTAP_MQTT_VERSION=""
ARG TARGETARCH

RUN apk add --no-cache curl tar git

WORKDIR /build

###############################################################################
# Install TapTap binary (from separate repo)
###############################################################################
RUN set -eux; \
    \
    if [ -z "$TAPTAP_VERSION" ]; then \
        TAPTAP_VERSION=$( \
            curl -sSL https://api.github.com/repos/litinoveweedle/taptap/releases/latest \
            | grep -oE '"tag_name":\s*"v?([0-9]+\.[0-9]+\.[0-9]+)"' \
            | sed -E 's/.*"v?([0-9]+\.[0-9]+\.[0-9]+)".*/\1/' \
            || true \
        ); \
    fi; \
    \
    if [ -z "$TAPTAP_VERSION" ]; then TAPTAP_VERSION="0.2.6"; fi; \
    \
    case "$TARGETARCH" in \
        amd64) TAPTAP_ARCH="musl-x86_64" ;; \
        arm64) TAPTAP_ARCH="musl-arm64" ;; \
        arm)   TAPTAP_ARCH="musleabihf-armv7" ;; \
        *) echo "Unsupported architecture: $TARGETARCH"; exit 1 ;; \
    esac; \
    \
    TAPTAP_URL="https://github.com/litinoveweedle/taptap/releases/download/v${TAPTAP_VERSION}/taptap-Linux-${TAPTAP_ARCH}.tar.gz"; \
    curl -sSLf -o taptap.tgz "$TAPTAP_URL"; \
    mkdir -p /tmp/taptap-extract; \
    tar -xzf taptap.tgz -C /tmp/taptap-extract; \
    install -m 755 /tmp/taptap-extract/taptap /build/taptap

###############################################################################
# Install TapTap-MQTT
# - If TAPTAP_MQTT_VERSION is passed → download release tarball
# - If not passed → copy from repo working tree
###############################################################################
# Local copies from repo root (Dockerfile lives in docker/)
COPY ../taptap-mqtt.py /build/local-taptap-mqtt.py
COPY ../requirements.txt /build/local-requirements.txt
COPY ../config.ini.example /build/local-config.ini.example

RUN set -eux; \
    if [ -n "$TAPTAP_MQTT_VERSION" ]; then \
        echo "Using release version v$TAPTAP_MQTT_VERSION"; \
        URL="https://github.com/litinoveweedle/taptap-mqtt/archive/refs/tags/v${TAPTAP_MQTT_VERSION}.tar.gz"; \
        echo "Downloading: $URL"; \
        curl -sSLf -o taptap-mqtt.tgz "$URL"; \
        mkdir -p /tmp/taptap-mqtt-extract; \
        tar -xzf taptap-mqtt.tgz -C /tmp/taptap-mqtt-extract; \
        install -m 755 /tmp/taptap-mqtt-extract/*/taptap-mqtt.py /build/taptap-mqtt.py; \
        cp /tmp/taptap-mqtt-extract/*/config.ini.example /build/config.ini.example; \
        cp /tmp/taptap-mqtt-extract/*/requirements.txt /build/requirements.txt; \
    else \
        echo "No TAPTAP_MQTT_VERSION provided — using local repo copy"; \
        install -m 755 /build/local-taptap-mqtt.py /build/taptap-mqtt.py; \
        cp /build/local-config.ini.example /build/config.ini.example; \
        cp /build/local-requirements.txt /build/requirements.txt; \
    fi; \
    \
    python -m venv /build/venv; \
    /build/venv/bin/pip install --no-cache-dir -r /build/requirements.txt

# ============================
# Stage 2 — Runtime
# ============================
FROM python:3.14-alpine

RUN apk add --no-cache bash

WORKDIR /app

RUN mkdir -p /app/taptap /app/taptap-mqtt

# TapTap binary
COPY --from=builder /build/taptap /app/taptap/taptap

# TapTap-MQTT script
COPY --from=builder /build/taptap-mqtt.py /app/taptap-mqtt/taptap-mqtt.py

# Example config
COPY --from=builder /build/config.ini.example /app/config.ini.example

# Python venv
COPY --from=builder /build/venv /app/venv

# Entrypoint
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENV PATH="/app/venv/bin:${PATH}"

ENTRYPOINT ["/entrypoint.sh"]