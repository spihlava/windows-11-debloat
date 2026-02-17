# Re-enable driver updates via Windows Update
Write-Host "Enabling driver updates via Windows Update..." -ForegroundColor Cyan

$wuPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

if (Test-Path $wuPolicyPath) {
    Remove-ItemProperty -Path $wuPolicyPath -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
    Write-Host "[OK] Driver updates re-enabled" -ForegroundColor Green
} else {
    Write-Host "[OK] Driver updates were not disabled" -ForegroundColor Green
}

Write-Host ""
Write-Host "Driver updates are now enabled via Windows Update" -ForegroundColor Green
Write-Host "You can check for driver updates in Settings > Windows Update" -ForegroundColor White
