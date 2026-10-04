@echo off
title sentinelbit Password Manager
echo ========================================================
echo   sentinelbit - Zero-Knowledge Password & Passkey Manager
echo ========================================================
echo.
echo Starte Web-Server auf http://127.0.0.1:8000 ...
echo Druecke Strg+C zum Beenden.
echo.

python -m uvicorn server:app --host 127.0.0.1 --port 8000 --reload
pause

