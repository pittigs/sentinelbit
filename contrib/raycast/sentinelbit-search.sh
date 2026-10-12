#!/bin/bash

# Required parameters:
# @raycast.schemaVersion 1
# @raycast.title Search SentinelBit Vault
# @raycast.mode fullOutput
# @raycast.packageName SentinelBit
#
# Optional parameters:
# @raycast.icon 🛡️
# @raycast.argument1 { "type": "text", "placeholder": "Search query..." }
#
# Documentation:
# @raycast.description Search logins and credentials in SentinelBit vault
# @raycast.author SentinelBit Team

QUERY="$1"
SENTINELBIT_BIN="${SENTINELBIT_CLI:-sentinelbit-cli}"

if ! command -v "$SENTINELBIT_BIN" &> /dev/null; then
    if [ -f "./bin/sentinelbit-cli" ]; then
        SENTINELBIT_BIN="./bin/sentinelbit-cli"
    elif [ -f "$HOME/.local/bin/sentinelbit-cli" ]; then
        SENTINELBIT_BIN="$HOME/.local/bin/sentinelbit-cli"
    else
        echo "❌ sentinelbit-cli nicht im PATH gefunden."
        exit 1
    fi
fi

echo "🔍 Suche in SentinelBit nach: '$QUERY'..."
"$SENTINELBIT_BIN" status
