Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  sentinelbit - Zero-Knowledge Password & Passkey Manager" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Starte Web-Server auf http://127.0.0.1:8000 ..." -ForegroundColor Yellow
Write-Host "Druecke Strg+C zum Beenden." -ForegroundColor Gray
Write-Host ""

python -m uvicorn server:app --host 127.0.0.1 --port 8000 --reload

