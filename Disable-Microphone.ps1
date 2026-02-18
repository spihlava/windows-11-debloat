# Disable-Microphone.ps1
# Disables or re-enables the microphone system-wide via registry.
# Run as Administrator.
#
# Usage:
#   .\Disable-Microphone.ps1          - Disables microphone
#   .\Disable-Microphone.ps1 -Enable  - Re-enables microphone

param(
    [switch]$Enable
)

# Check for admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

$micPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"

if ($Enable) {
    Write-Host "`nRe-enabling microphone..." -ForegroundColor Yellow

    if (-not (Test-Path $micPath)) { New-Item -Path $micPath -Force | Out-Null }
    Set-ItemProperty -Path $micPath -Name "Value" -Value "Allow" -Type String -Force
    Write-Host "  [+] Microphone access set to Allow" -ForegroundColor Green

    Write-Host "`nMicrophone is now ENABLED." -ForegroundColor Green
} else {
    Write-Host "`nDisabling microphone..." -ForegroundColor Yellow

    if (-not (Test-Path $micPath)) { New-Item -Path $micPath -Force | Out-Null }
    Set-ItemProperty -Path $micPath -Name "Value" -Value "Deny" -Type String -Force
    Write-Host "  [+] Microphone access set to Deny" -ForegroundColor Green

    Write-Host "`nMicrophone is now DISABLED." -ForegroundColor Green
    Write-Host "To re-enable, run: .\Disable-Microphone.ps1 -Enable" -ForegroundColor Cyan
}
