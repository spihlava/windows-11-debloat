# ============================================
# OneDrive Restore Script
# ============================================
# Restores OneDrive functionality after running Enhanced-Privacy-Settings.ps1
# Run as Administrator for full functionality

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  OneDrive Restore Script" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will restore OneDrive Personal functionality:" -ForegroundColor Yellow
Write-Host "  - Re-enable OneDrive Personal file sync" -ForegroundColor White
Write-Host "  - Restore OneDrive Personal in File Explorer sidebar" -ForegroundColor White
Write-Host "  - Add OneDrive Personal to startup" -ForegroundColor White
Write-Host "  - Launch OneDrive application" -ForegroundColor White
Write-Host ""
Write-Host "Note: OneDrive for Business will NOT be affected" -ForegroundColor Gray
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator!" -ForegroundColor Red
    Write-Host "Some settings require admin rights to restore." -ForegroundColor Yellow
    Write-Host "Press Enter to continue anyway, or Ctrl+C to exit and restart as Admin..." -ForegroundColor Yellow
    Read-Host
}

Write-Host "`nPress Enter to restore OneDrive, or Ctrl+C to cancel..." -ForegroundColor Yellow
Read-Host

# ============================================
# STEP 1: Re-enable OneDrive Personal File Sync
# ============================================
Write-Host "`n[1/5] Re-enabling OneDrive Personal File Sync..." -ForegroundColor Yellow

try {
    if ($isAdmin) {
        $onedrivePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"

        # Remove the disable policies for Personal OneDrive
        if (Test-Path $onedrivePath) {
            Remove-ItemProperty -Path $onedrivePath -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $onedrivePath -Name "DisableFileSync" -ErrorAction SilentlyContinue
            Write-Host "  [+] Removed OneDrive Personal sync restrictions" -ForegroundColor Green
        } else {
            Write-Host "  [+] OneDrive Personal sync was not disabled" -ForegroundColor Green
        }
    } else {
        Write-Host "  [!] Skipped (requires Administrator)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [-] Error re-enabling Personal file sync: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================
# STEP 2: Restore OneDrive Personal in File Explorer
# ============================================
Write-Host "`n[2/5] Restoring OneDrive Personal in File Explorer..." -ForegroundColor Yellow

try {
    # Check if HKCR: drive exists, if not create it
    if (-not (Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null
    }

    # Restore OneDrive Personal only
    $explorerPathPersonal = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    if (Test-Path $explorerPathPersonal) {
        Set-ItemProperty -Path $explorerPathPersonal -Name "System.IsPinnedToNameSpaceTree" -Value 1 -Type DWord -Force
        Write-Host "  [+] OneDrive Personal restored to File Explorer" -ForegroundColor Green
    } else {
        Write-Host "  [!] OneDrive Personal registry key not found (may need reinstall)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [-] Error restoring File Explorer integration: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================
# STEP 3: Add OneDrive to Startup
# ============================================
Write-Host "`n[3/5] Adding OneDrive to Startup..." -ForegroundColor Yellow

try {
    $oneDrivePath = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"

    if (Test-Path $oneDrivePath) {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -Value "`"$oneDrivePath`" /background" -Type String -Force
        Write-Host "  [+] OneDrive added to startup" -ForegroundColor Green
    } else {
        Write-Host "  [!] OneDrive.exe not found at: $oneDrivePath" -ForegroundColor Yellow
        Write-Host "      You may need to reinstall OneDrive" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [-] Error adding to startup: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================
# STEP 4: Restart Explorer (to refresh sidebar)
# ============================================
Write-Host "`n[4/5] Refreshing File Explorer..." -ForegroundColor Yellow

try {
    # Restart explorer to refresh the sidebar
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "  [+] File Explorer refreshed" -ForegroundColor Green
} catch {
    Write-Host "  [!] Could not refresh Explorer automatically" -ForegroundColor Yellow
}

# ============================================
# STEP 5: Launch OneDrive
# ============================================
Write-Host "`n[5/5] Launching OneDrive..." -ForegroundColor Yellow

try {
    $oneDrivePath = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"

    if (Test-Path $oneDrivePath) {
        # Kill any existing OneDrive processes
        Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1

        # Start OneDrive
        Start-Process $oneDrivePath
        Write-Host "  [+] OneDrive launched successfully" -ForegroundColor Green
        Write-Host "      Look for the OneDrive cloud icon in your system tray" -ForegroundColor Gray
    } else {
        Write-Host "  [!] OneDrive.exe not found" -ForegroundColor Yellow
        Write-Host "      OneDrive may not be installed on this system" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [-] Error launching OneDrive: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================
# Summary
# ============================================
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "  ONEDRIVE RESTORE COMPLETE!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host 'Actions Completed:' -ForegroundColor White
Write-Host '  [1] OneDrive Personal file sync re-enabled' -ForegroundColor White
Write-Host '  [2] OneDrive Personal restored to File Explorer' -ForegroundColor White
Write-Host '  [3] OneDrive Personal added to startup' -ForegroundColor White
Write-Host '  [4] File Explorer refreshed' -ForegroundColor White
Write-Host '  [5] OneDrive Personal launched' -ForegroundColor White
Write-Host ''
Write-Host 'Note: OneDrive for Business was NOT modified' -ForegroundColor Gray
Write-Host ''
Write-Host 'Next Steps:' -ForegroundColor Yellow
Write-Host '  1. Check your system tray for the OneDrive cloud icon' -ForegroundColor White
Write-Host '  2. Sign in with your Microsoft account if prompted' -ForegroundColor White
Write-Host '  3. Configure your OneDrive sync settings' -ForegroundColor White
Write-Host '  4. Check File Explorer - OneDrive should appear in the sidebar' -ForegroundColor White
Write-Host ''
Write-Host 'If OneDrive does not appear:' -ForegroundColor Yellow
Write-Host '  - You may need to reinstall OneDrive' -ForegroundColor White
Write-Host '  - Download from: https://www.microsoft.com/en-us/microsoft-365/onedrive/download' -ForegroundColor White
Write-Host ''
Write-Host 'Press Enter to exit...' -ForegroundColor Cyan
Read-Host
