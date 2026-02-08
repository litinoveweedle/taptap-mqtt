#!/bin/sh
set -e

###############################################################################
# Helper functions
###############################################################################
info()  { printf "%s\n" "$1"; }
ok()    { printf "OK: %s\n" "$1"; }
warn()  { printf "WARN: %s\n" "$1"; }
error() { printf "ERROR: %s\n" "$1"; }

###############################################################################
# Paths
###############################################################################
CONFIG_DIR="/app/config"
DATA_DIR="/app/data"
CONFIG_FILE="${CONFIG_DIR}/config.ini"
CONFIG_EXAMPLE="${CONFIG_DIR}/config.ini.example"
INIT_FLAG="${CONFIG_DIR}/.docker_initialized"

TAPTAP_BIN="/app/taptap/taptap"
EXPECTED_BINARY="$TAPTAP_BIN"

STATE_FILE="${DATA_DIR}/taptap.json"
EXPECTED_STATE="$STATE_FILE"

MQTT_SCRIPT="/app/taptap-mqtt/taptap-mqtt.py"

###############################################################################
# Banner
###############################################################################
info "========================================"
info "TapTap MQTT Docker Initialization"
info "========================================"

###############################################################################
# Validate required binaries
###############################################################################
command -v python3 >/dev/null 2>&1 || {
    error "python3 not found — container build is broken"
    exit 1
}

[ -x "$TAPTAP_BIN" ] || {
    error "TapTap binary missing: $TAPTAP_BIN"
    exit 1
}

[ -f "$MQTT_SCRIPT" ] || {
    error "TapTap-MQTT script missing: $MQTT_SCRIPT"
    exit 1
}

###############################################################################
# First-run logic (robust)
###############################################################################
# We treat "first run" as:
#   - INIT_FLAG missing OR
#   - config.ini missing
###############################################################################
if [ ! -f "$INIT_FLAG" ] || [ ! -f "$CONFIG_FILE" ]; then
    warn "Initialization required — preparing persistent directories"

    mkdir -p "$CONFIG_DIR" "$DATA_DIR"
    chmod 755 "$CONFIG_DIR" "$DATA_DIR"

    if [ -f "$CONFIG_FILE" ]; then
        #######################################################################
        # CASE B — User pre-created config.ini
        #######################################################################
        ok "Detected user-provided config.ini — not modifying it"

        # Validate BINARY
        USER_BINARY=$(grep -E "^BINARY *=.*" "$CONFIG_FILE" | sed 's/^BINARY *= *//')
        if [ -n "$USER_BINARY" ] && [ "$USER_BINARY" != "$EXPECTED_BINARY" ]; then
            warn "Your config.ini contains BINARY=$USER_BINARY"
            warn "Expected BINARY=$EXPECTED_BINARY"
        fi

        # Validate STATE_FILE
        USER_STATE=$(grep -E "^STATE_FILE *=.*" "$CONFIG_FILE" | sed 's/^STATE_FILE *= *//')
        if [ -n "$USER_STATE" ] && [ "$USER_STATE" != "$EXPECTED_STATE" ]; then
            warn "Your config.ini contains STATE_FILE=$USER_STATE"
            warn "Expected STATE_FILE=$EXPECTED_STATE"
        fi

        touch "$INIT_FLAG"
        ok "Initialization complete — starting TapTap-MQTT"

    else
        #######################################################################
        # CASE A — No config.ini provided by user
        #######################################################################
        warn "No config.ini found — creating default configuration"

        # Copy example config into persistent directory
        if [ -f "/app/config.ini.example" ]; then
            cp "/app/config.ini.example" "$CONFIG_EXAMPLE"
            chmod 644 "$CONFIG_EXAMPLE"
            ok "Placed config.ini.example into $CONFIG_EXAMPLE"
        else
            error "Missing /app/config.ini.example in image"
            exit 1
        fi

        # Create config.ini from example
        cp "$CONFIG_EXAMPLE" "$CONFIG_FILE"
        chmod 644 "$CONFIG_FILE"
        ok "Created new config.ini at $CONFIG_FILE"

        # Rewrite BINARY and STATE_FILE
        sed -i "s|^BINARY *=.*|BINARY = ${EXPECTED_BINARY}|g" "$CONFIG_FILE"
        sed -i "s|^STATE_FILE *=.*|STATE_FILE = ${EXPECTED_STATE}|g" "$CONFIG_FILE"
        ok "Configured BINARY and STATE_FILE paths"

        touch "$INIT_FLAG"

        warn "Please edit your configuration file before starting:"
        info "  $CONFIG_FILE"
        info "Container will now exit. Restart after editing."
        exit 0
    fi
else
    ###########################################################################
    # CASE C — Normal startup
    ###########################################################################
    ok "Initialization previously completed — starting normally"
fi

###############################################################################
# Symlink config.ini for TapTap-MQTT auto-detection
###############################################################################
ln -sf "$CONFIG_FILE" /app/config.ini
ok "Linked config.ini into /app/config.ini"

###############################################################################
# Startup summary
###############################################################################
info ""
info "========================================"
info "Starting TapTap MQTT Bridge"
info "========================================"
info "Config file: $CONFIG_FILE"
info "State file:  $STATE_FILE"
info "Binary:      $TAPTAP_BIN"
info ""

###############################################################################
# Graceful shutdown handler
###############################################################################
trap "info 'Stopping TapTap MQTT...'; exit 0" SIGTERM SIGINT

###############################################################################
# Start application
###############################################################################
exec python3 "$MQTT_SCRIPT"