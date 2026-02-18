# Disable-Camera.ps1
# Disables or re-enables the camera system-wide via registry and the Camera Frame Server service.
# Run as Administrator.
#
# Usage:
#   .\Disable-Camera.ps1          - Disables camera
#   .\Disable-Camera.ps1 -Enable  - Re-enables camera

param(
    [switch]$Enable
)

# Check for admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

$cameraPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"

if ($Enable) {
    Write-Host "`nRe-enabling camera..." -ForegroundColor Yellow

    # Allow global camera access
    if (-not (Test-Path $cameraPath)) { New-Item -Path $cameraPath -Force | Out-Null }
    Set-ItemProperty -Path $cameraPath -Name "Value" -Value "Allow" -Type String -Force
    Write-Host "  [+] Camera access set to Allow" -ForegroundColor Green

    # Re-enable Camera Frame Server service
    try {
        Set-Service -Name "FrameServer" -StartupType Manual -ErrorAction Stop
        Start-Service -Name "FrameServer" -ErrorAction Stop
        Write-Host "  [+] Camera Frame Server service enabled and started" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Could not start FrameServer service: $_" -ForegroundColor Yellow
    }

    Write-Host "`nCamera is now ENABLED." -ForegroundColor Green
} else {
    Write-Host "`nDisabling camera..." -ForegroundColor Yellow

    # Deny global camera access
    if (-not (Test-Path $cameraPath)) { New-Item -Path $cameraPath -Force | Out-Null }
    Set-ItemProperty -Path $cameraPath -Name "Value" -Value "Deny" -Type String -Force
    Write-Host "  [+] Camera access set to Deny" -ForegroundColor Green

    # Disable Camera Frame Server service
    try {
        Stop-Service -Name "FrameServer" -Force -ErrorAction Stop
        Set-Service -Name "FrameServer" -StartupType Disabled -ErrorAction Stop
        Write-Host "  [+] Camera Frame Server service stopped and disabled" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Could not stop FrameServer service: $_" -ForegroundColor Yellow
    }

    Write-Host "`nCamera is now DISABLED." -ForegroundColor Green
    Write-Host "To re-enable, run: .\Disable-Camera.ps1 -Enable" -ForegroundColor Cyan
}
