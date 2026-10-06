Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  sentinelbit - Zero-Knowledge Password & Passkey Manager" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

if (Test-Path ".\sentinelbit.exe") {
    Write-Host "Starte sentinelbit Go Binary (Windows)..." -ForegroundColor Yellow
    .\sentinelbit.exe
} elseif (Test-Path ".\bin\sentinelbit.exe") {
    Write-Host "Starte sentinelbit Go Binary aus bin\... " -ForegroundColor Yellow
    .\bin\sentinelbit.exe
} elseif (Test-Path ".\sentinelbit") {
    Write-Host "Starte sentinelbit Go Binary..." -ForegroundColor Yellow
    .\sentinelbit
} else {
    Write-Host "Kein vorkompiliertes Binary gefunden. Starte mit 'go run ./cmd/server' auf http://127.0.0.1:8000 ..." -ForegroundColor Yellow
    Write-Host "Druecke Strg+C zum Beenden." -ForegroundColor Gray
    Write-Host ""
    go run ./cmd/server
}
