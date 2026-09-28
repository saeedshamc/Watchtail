#!/bin/sh
# Container entrypoint: persist state under WATCHTAIL_DATA_DIR, make
# sure an admin password exists, then serve via gunicorn+eventlet.
set -e

DATA_DIR="${WATCHTAIL_DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"

# Keep the SQLite database and the session key on the persistent volume.
export WATCHTAIL_DATABASE_URL="${WATCHTAIL_DATABASE_URL:-sqlite:///$DATA_DIR/watchtail.db}"

CONFIG_FILE="${WATCHTAIL_CONFIG:-/srv/watchtail/watchtail.yml}"
if [ ! -f "$CONFIG_FILE" ]; then
    # First boot: drop a starter config into the data dir so operators
    # can edit (or mount) it without rebuilding the image.
    CONFIG_FILE="$DATA_DIR/watchtail.yml"
    export WATCHTAIL_CONFIG="$CONFIG_FILE"
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "watchtail: writing starter config to $CONFIG_FILE" >&2
        {
            echo "server:"
            echo "  host: 0.0.0.0"
            echo "  port: ${WATCHTAIL_PORT:-5555}"
            echo "database:"
            echo "  url: sqlite:///$DATA_DIR/watchtail.db"
            echo "sources: []"
        } > "$CONFIG_FILE"
    fi
fi
export WATCHTAIL_CONFIG

# Fail fast with a clear message instead of booting with an unknown
# credential the operator cannot log in with.
if [ -z "$WATCHTAIL_ADMIN_PASSWORD" ]; then
    echo "watchtail: WATCHTAIL_ADMIN_PASSWORD is required in Docker." >&2
    echo "  e.g. docker run -e WATCHTAIL_ADMIN_PASSWORD='choose-one' ..." >&2
    exit 1
fi

HOST="${WATCHTAIL_HOST:-0.0.0.0}"
PORT="${WATCHTAIL_PORT:-5555}"
WORKERS="${WATCHTAIL_WORKERS:-1}"

# One worker only: Socket.IO broadcasts live updates in-process and
# the tailer threads live in the same process by design.
exec gunicorn \
    --worker-class eventlet \
    --workers "$WORKERS" \
    --bind "$HOST:$PORT" \
    --access-logfile - \
    --error-logfile - \
    wsgi:application
