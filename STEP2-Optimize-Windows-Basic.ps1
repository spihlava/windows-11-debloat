# ============================================
# Windows Debloat & Optimization Script
# ============================================
# Run this script as Administrator for full functionality
# Right-click PowerShell and select "Run as Administrator"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Windows Debloat & Optimization Script" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator!" -ForegroundColor Red
    Write-Host "Some features (services, system apps) will not work without admin rights." -ForegroundColor Yellow
    Write-Host "Press Enter to continue anyway, or Ctrl+C to exit and restart as Admin..." -ForegroundColor Yellow
    Read-Host
}

# ============================================
# CREATE SYSTEM RESTORE POINT
# ============================================
Write-Host "`nCreating System Restore Point..." -ForegroundColor Cyan

if ($isAdmin) {
    try {
        # Enable System Restore if not already enabled
        Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue

        # Create restore point
        $restorePointName = "Before Windows Optimization - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        Checkpoint-Computer -Description $restorePointName -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Host "[✓] Restore point created: $restorePointName" -ForegroundColor Green
        Write-Host "    You can revert changes later via System Restore" -ForegroundColor Gray
    } catch {
        Write-Host "[!] Could not create restore point: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "    Continuing anyway..." -ForegroundColor Gray
    }
} else {
    Write-Host "[!] Restore point requires Administrator privileges - Skipping" -ForegroundColor Yellow
}

Write-Host "`nPress Enter to begin optimization, or Ctrl+C to cancel..." -ForegroundColor Yellow
Read-Host

# ============================================
# STEP 1: Remove Bloatware Apps
# ============================================
Write-Host "`n[1/5] Removing Bloatware Apps..." -ForegroundColor Yellow

$appsToRemove = @(
    '*BingWeather*',
    '*BingSearch*',
    '*Solitaire*',
    '*XboxApp*',
    '*Xbox.TCUI*',
    '*XboxGameOverlay*',
    '*XboxGamingOverlay*',
    '*XboxIdentityProvider*',
    '*XboxSpeechToTextOverlay*',
    '*GamingApp*',
    '*MixedReality*',
    '*3DViewer*',
    '*SkypeApp*',
    '*YourPhone*',
    '*People*',
    '*OfficeHub*',
    '*Todos*',
    '*StickyNotes*',
    '*GetHelp*',
    '*Feedback*',
    '*WindowsMaps*',
    '*WindowsCamera*',
    '*SoundRecorder*',
    '*QuickAssist*',
    '*OneNote*',
    '*OutlookForWindows*',
    '*WindowsAlarms*',
    '*BingNews*',
    '*MicrosoftOfficeHub*'
)

$removedCount = 0
foreach ($app in $appsToRemove) {
    $packages = Get-AppxPackage -Name $app -ErrorAction SilentlyContinue
    foreach ($package in $packages) {
        try {
            Remove-AppxPackage -Package $package.PackageFullName -ErrorAction Stop
            Write-Host "  [+] Removed: $($package.Name)" -ForegroundColor Green
            $removedCount++
        } catch {
            Write-Host "  [-] Failed: $($package.Name)" -ForegroundColor Red
        }
    }
}

Write-Host "  >> Removed $removedCount apps" -ForegroundColor Cyan

# ============================================
# STEP 2: Disable Startup Programs
# ============================================
Write-Host "`n[2/5] Disabling Non-Essential Startup Programs..." -ForegroundColor Yellow

$startupItems = @(
    'Adobe Acrobat Synchronizer',
    'Slack',
    'com.squirrel.Teams.Teams',
    'MicrosoftTeams',
    'Teams',
    'Logitech Download Assistant',
    'Logi Tune',
    'Spotify',
    'Discord'
)

$disabledCount = 0
foreach ($item in $startupItems) {
    try {
        $exists = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $item -ErrorAction SilentlyContinue
        if ($exists) {
            Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $item -ErrorAction Stop
            Write-Host "  [+] Disabled: $item" -ForegroundColor Green
            $disabledCount++
        }
    } catch {
        # Item might not exist or couldn't be removed
    }
}

Write-Host "  >> Disabled $disabledCount startup items" -ForegroundColor Cyan

# ============================================
# STEP 3: Optimize Visual Effects
# ============================================
Write-Host "`n[3/5] Optimizing Visual Effects for Performance..." -ForegroundColor Yellow

try {
    # Set visual effects to best performance
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -Value 2 -Type DWord -Force

    # Disable animations
    $desktopPath = 'HKCU:\Control Panel\Desktop'
    Set-ItemProperty -Path $desktopPath -Name 'UserPreferencesMask' -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -Force
    Set-ItemProperty -Path $desktopPath -Name 'MenuShowDelay' -Value 0 -Type String -Force

    # Disable DWM effects
    $dwmPath = 'HKCU:\Software\Microsoft\Windows\DWM'
    if (-not (Test-Path $dwmPath)) { New-Item -Path $dwmPath -Force | Out-Null }
    Set-ItemProperty -Path $dwmPath -Name 'EnableAeroPeek' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $dwmPath -Name 'AlwaysHibernateThumbnails' -Value 0 -Type DWord -Force

    # Disable taskbar animations
    $advancedPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    Set-ItemProperty -Path $advancedPath -Name 'TaskbarAnimations' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $advancedPath -Name 'ListviewAlphaSelect' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $advancedPath -Name 'ListviewShadow' -Value 0 -Type DWord -Force

    Write-Host "  [+] Visual effects optimized" -ForegroundColor Green
} catch {
    Write-Host "  [-] Error optimizing visual effects" -ForegroundColor Red
}

# ============================================
# STEP 4: Clean Temporary Files
# ============================================
Write-Host "`n[4/5] Cleaning Temporary Files..." -ForegroundColor Yellow

# Clean user temp
try {
    $tempPath = $env:TEMP
    $tempFiles = (Get-ChildItem -Path $tempPath -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
    Remove-Item -Path "$tempPath\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] Cleaned user temp folder ($tempFiles items)" -ForegroundColor Green
} catch {
    Write-Host "  [-] Error cleaning user temp" -ForegroundColor Red
}

# Clean Windows temp
try {
    $winTempPath = "C:\Windows\Temp"
    $winTempFiles = (Get-ChildItem -Path $winTempPath -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
    Remove-Item -Path "$winTempPath\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] Cleaned Windows temp folder ($winTempFiles items)" -ForegroundColor Green
} catch {
    Write-Host "  [-] Error cleaning Windows temp" -ForegroundColor Red
}

# Clear Windows Update cache
try {
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    Write-Host "  [+] Cleared Windows Update cache" -ForegroundColor Green
} catch {
    Write-Host "  [-] Error clearing Windows Update cache" -ForegroundColor Red
}

# Empty Recycle Bin
try {
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] Emptied Recycle Bin" -ForegroundColor Green
} catch {
    Write-Host "  [-] Error emptying Recycle Bin" -ForegroundColor Red
}

# ============================================
# STEP 5: Disable Unnecessary Services
# ============================================
Write-Host "`n[5/5] Disabling Unnecessary Windows Services..." -ForegroundColor Yellow

if ($isAdmin) {
    $servicesToDisable = @(
        'XblAuthManager',           # Xbox Live Auth Manager
        'XblGameSave',              # Xbox Live Game Save
        'XboxGipSvc',               # Xbox Accessory Management
        'XboxNetApiSvc',            # Xbox Live Networking
        'SysMain',                  # Superfetch (can slow down SSDs)
        'DiagTrack',                # Diagnostics Tracking (telemetry)
        'dmwappushservice',         # WAP Push Message Routing
        'RetailDemo',               # Retail Demo Service
        'RemoteRegistry',           # Remote Registry
        'WerSvc',                   # Windows Error Reporting
        'Fax',                      # Fax service
        'TabletInputService',       # Touch Keyboard (if not using touch)
        'WMPNetworkSvc'             # Windows Media Player Network Sharing
    )

    $disabledServices = 0
    foreach ($service in $servicesToDisable) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $service -Force -ErrorAction Stop
                Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
                Write-Host "  [+] Disabled: $service" -ForegroundColor Green
                $disabledServices++
            }
        } catch {
            Write-Host "  [-] Failed to disable: $service" -ForegroundColor Red
        }
    }

    Write-Host "  >> Disabled $disabledServices services" -ForegroundColor Cyan
} else {
    Write-Host "  [!] Skipped (requires Administrator privileges)" -ForegroundColor Yellow
}

# ============================================
# BONUS: Additional Optimizations
# ============================================
Write-Host "`n[BONUS] Additional Optimizations..." -ForegroundColor Yellow

# Disable Windows Search indexing (optional - makes search slower but improves performance)
try {
    Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WSearch" -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "  [+] Disabled Windows Search indexing" -ForegroundColor Green
} catch {
    Write-Host "  [-] Could not disable Windows Search (may require admin)" -ForegroundColor Yellow
}

# Disable hibernation to free up disk space
if ($isAdmin) {
    try {
        powercfg.exe /hibernate off
        Write-Host "  [+] Disabled hibernation (frees up disk space)" -ForegroundColor Green
    } catch {
        Write-Host "  [-] Could not disable hibernation" -ForegroundColor Red
    }
}

# Disable GameDVR
try {
    $gameDVRPath = "HKCU:\System\GameConfigStore"
    if (-not (Test-Path $gameDVRPath)) { New-Item -Path $gameDVRPath -Force | Out-Null }
    Set-ItemProperty -Path $gameDVRPath -Name "GameDVR_Enabled" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled Xbox Game DVR" -ForegroundColor Green
} catch {
    Write-Host "  [-] Could not disable Game DVR" -ForegroundColor Red
}

# Disable telemetry
try {
    $telemetryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if ($isAdmin) {
        if (-not (Test-Path $telemetryPath)) { New-Item -Path $telemetryPath -Force | Out-Null }
        Set-ItemProperty -Path $telemetryPath -Name "AllowTelemetry" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled telemetry" -ForegroundColor Green
    } else {
        Write-Host "  [!] Cannot disable telemetry (requires admin)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [-] Could not disable telemetry" -ForegroundColor Red
}

# ============================================
# Summary
# ============================================
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "  OPTIMIZATION COMPLETE!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor White
Write-Host "  - Removed bloatware apps" -ForegroundColor White
Write-Host "  - Disabled unnecessary startup programs" -ForegroundColor White
Write-Host "  - Optimized visual effects for performance" -ForegroundColor White
Write-Host "  - Cleaned temporary files and caches" -ForegroundColor White
Write-Host "  - Disabled unnecessary Windows services" -ForegroundColor White
Write-Host ""
Write-Host "[!] IMPORTANT: Please restart your computer for all changes to take effect!" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Enter to exit..." -ForegroundColor Cyan
Read-Host
