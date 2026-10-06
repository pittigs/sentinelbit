@echo off
title sentinelbit Password Manager
echo ========================================================
echo   sentinelbit - Zero-Knowledge Password & Passkey Manager
echo ========================================================
echo.

if exist sentinelbit.exe (
    echo Starte sentinelbit Go Binary...
    sentinelbit.exe
) else if exist bin\sentinelbit.exe (
    echo Starte sentinelbit Go Binary aus bin\...
    bin\sentinelbit.exe
) else if exist sentinelbit (
    echo Starte sentinelbit Go Binary...
    sentinelbit
) else (
    echo Kein kompiliertes Go-Binary gefunden.
    echo Starte direkt mit 'go run ./cmd/server' ...
    echo Druecke Strg+C zum Beenden.
    echo.
    go run ./cmd/server
)
pause
