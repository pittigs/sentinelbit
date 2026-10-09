#!/usr/bin/env bash
set -e

echo -e "\033[36m========================================================\033[0m"
echo -e "\033[32m  sentinelbit - Zero-Knowledge Password & Passkey Manager\033[0m"
echo -e "\033[36m========================================================\033[0m"
echo ""

if [ -f "./sentinelbit" ]; then
    echo -e "\033[33mStarte sentinelbit Go Binary...\033[0m"
    ./sentinelbit
elif [ -f "./bin/sentinelbit" ]; then
    echo -e "\033[33mStarte sentinelbit Go Binary aus bin/...\033[0m"
    ./bin/sentinelbit
else
    echo -e "\033[33mKein vorkompiliertes Binary gefunden. Starte mit 'go run ./cmd/server' auf http://127.0.0.1:8000 ...\033[0m"
    echo -e "\033[90mDruecke Strg+C zum Beenden.\033[0m"
    echo ""
    go run ./cmd/server
fi
