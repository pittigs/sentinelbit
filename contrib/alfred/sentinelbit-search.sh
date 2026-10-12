#!/bin/bash
# SentinelBit Alfred Workflow Script Filter
# Searches items and outputs Alfred JSON format

QUERY="{query}"
SENTINELBIT_BIN="${SENTINELBIT_CLI:-sentinelbit-cli}"

if ! command -v "$SENTINELBIT_BIN" &> /dev/null; then
    if [ -f "./bin/sentinelbit-cli" ]; then
        SENTINELBIT_BIN="./bin/sentinelbit-cli"
    elif [ -f "$HOME/.local/bin/sentinelbit-cli" ]; then
        SENTINELBIT_BIN="$HOME/.local/bin/sentinelbit-cli"
    fi
fi

cat <<EOF
{
  "items": [
    {
      "uid": "sentinelbit-status",
      "title": "SentinelBit Status",
      "subtitle": "Server & Vault Status prüfen",
      "arg": "status",
      "icon": { "path": "icon.png" }
    },
    {
      "uid": "sentinelbit-audit",
      "title": "SentinelBit DB Audit",
      "subtitle": "Integritätscheck durchführen",
      "arg": "audit",
      "icon": { "path": "icon.png" }
    }
  ]
}
EOF
