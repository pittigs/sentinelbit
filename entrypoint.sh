#!/bin/sh
set -e

# Ensure data directory exists and is owned by unprivileged sentinelbit user
mkdir -p "${SENTINELBIT_DATA_DIR:-/data}"
chown -R sentinelbit:sentinelbit "${SENTINELBIT_DATA_DIR:-/data}" 2>/dev/null || true

# Drop root privileges and execute process as sentinelbit (UID 10001)
exec su-exec sentinelbit "$@"
