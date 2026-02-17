# ============================================
# Windows 11 Ultimate Optimization Script
# ============================================
# Comprehensive optimization including bloatware removal, privacy, performance, and UI tweaks
# Run as Administrator for full functionality

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Windows 11 Ultimate Optimizer" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator!" -ForegroundColor Red
    Write-Host "Many optimizations require admin rights." -ForegroundColor Yellow
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
Write-Host "`n[1/12] Removing Bloatware Apps..." -ForegroundColor Yellow

$appsToRemove = @(
    '*BingWeather*',
    '*BingSearch*',
    '*BingNews*',
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
    '*WindowsAlarms*',
    '*SoundRecorder*',
    '*QuickAssist*',
    '*OneNote*',
    '*OutlookForWindows*',
    '*MicrosoftOfficeHub*',
    '*PowerAutomateDesktop*'
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
Write-Host "`n[2/12] Disabling Non-Essential Startup Programs..." -ForegroundColor Yellow

$startupItems = @(
    'Adobe Acrobat Synchronizer',
    'Slack',
    'com.squirrel.Teams.Teams',
    'MicrosoftTeams',
    'Teams',
    'Logitech Download Assistant',
    'Logi Tune',
    'Spotify',
    'Discord',
    'OneDrive'
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
    } catch {}
}

Write-Host "  >> Disabled $disabledCount startup items" -ForegroundColor Cyan

# ============================================
# STEP 3: Privacy & Telemetry Settings
# ============================================
Write-Host "`n[3/12] Configuring Privacy & Telemetry Settings..." -ForegroundColor Yellow

# Disable Telemetry
try {
    $telemetryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if ($isAdmin) {
        if (-not (Test-Path $telemetryPath)) { New-Item -Path $telemetryPath -Force | Out-Null }
        Set-ItemProperty -Path $telemetryPath -Name "AllowTelemetry" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled telemetry" -ForegroundColor Green
    } else {
        Write-Host "  [!] Telemetry requires admin" -ForegroundColor Yellow
    }
} catch {}

# Disable Advertising ID
try {
    $adPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    if (-not (Test-Path $adPath)) { New-Item -Path $adPath -Force | Out-Null }
    Set-ItemProperty -Path $adPath -Name "Enabled" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled Advertising ID" -ForegroundColor Green
} catch {}

# Disable Location Tracking
try {
    if ($isAdmin) {
        $locationPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
        if (-not (Test-Path $locationPath)) { New-Item -Path $locationPath -Force | Out-Null }
        Set-ItemProperty -Path $locationPath -Name "Value" -Value "Deny" -Type String -Force
        Write-Host "  [+] Disabled Location Tracking" -ForegroundColor Green
    } else {
        Write-Host "  [!] Location tracking requires admin" -ForegroundColor Yellow
    }
} catch {}

# Disable Activity History
try {
    $activityPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    if ($isAdmin) {
        if (-not (Test-Path $activityPath)) { New-Item -Path $activityPath -Force | Out-Null }
        Set-ItemProperty -Path $activityPath -Name "EnableActivityFeed" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $activityPath -Name "PublishUserActivities" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $activityPath -Name "UploadUserActivities" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled Activity History" -ForegroundColor Green
    }
} catch {}

# ============================================
# STEP 4: Notification Settings
# ============================================
Write-Host "`n[4/12] Configuring Notification Settings..." -ForegroundColor Yellow

# Disable notification sounds
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] Disabled notification sounds" -ForegroundColor Green
} catch {}

# Disable tips and suggestions
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled tips and suggestions" -ForegroundColor Green
} catch {}

# Disable app suggestions in Start
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled app suggestions in Start" -ForegroundColor Green
} catch {}

# ============================================
# STEP 5: Taskbar Customization
# ============================================
Write-Host "`n[5/12] Customizing Taskbar..." -ForegroundColor Yellow

$advancedPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

# Hide Search Box
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Type DWord -Force
    Write-Host "  [+] Hidden taskbar search box" -ForegroundColor Green
} catch {}

# Hide Task View Button
try {
    Set-ItemProperty -Path $advancedPath -Name "ShowTaskViewButton" -Value 0 -Type DWord -Force
    Write-Host "  [+] Hidden Task View button" -ForegroundColor Green
} catch {}

# Hide Widgets Button
try {
    Set-ItemProperty -Path $advancedPath -Name "TaskbarDa" -Value 0 -Type DWord -Force
    Write-Host "  [+] Hidden Widgets button" -ForegroundColor Green
} catch {}

# Hide Chat/Meet Now
try {
    Set-ItemProperty -Path $advancedPath -Name "TaskbarMn" -Value 0 -Type DWord -Force
    Write-Host "  [+] Hidden Chat button" -ForegroundColor Green
} catch {}

# Disable Copilot
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] Hidden Copilot button" -ForegroundColor Green
} catch {}

# ============================================
# STEP 6: File Explorer Settings
# ============================================
Write-Host "`n[6/12] Configuring File Explorer..." -ForegroundColor Yellow

# Show file extensions
try {
    Set-ItemProperty -Path $advancedPath -Name "HideFileExt" -Value 0 -Type DWord -Force
    Write-Host "  [+] Enabled file extensions" -ForegroundColor Green
} catch {}

# Show hidden files
try {
    Set-ItemProperty -Path $advancedPath -Name "Hidden" -Value 1 -Type DWord -Force
    Write-Host "  [+] Enabled showing hidden files" -ForegroundColor Green
} catch {}

# Disable ads in File Explorer
try {
    Set-ItemProperty -Path $advancedPath -Name "ShowSyncProviderNotifications" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled File Explorer ads" -ForegroundColor Green
} catch {}

# Show full path in title bar
try {
    Set-ItemProperty -Path $advancedPath -Name "FullPathAddress" -Value 1 -Type DWord -Force
    Write-Host "  [+] Enabled full path in title bar" -ForegroundColor Green
} catch {}

# ============================================
# STEP 7: Disable Cortana & Search
# ============================================
Write-Host "`n[7/12] Disabling Cortana & Bing Search..." -ForegroundColor Yellow

# Disable Cortana
try {
    if ($isAdmin) {
        $cortanaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        if (-not (Test-Path $cortanaPath)) { New-Item -Path $cortanaPath -Force | Out-Null }
        Set-ItemProperty -Path $cortanaPath -Name "AllowCortana" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled Cortana" -ForegroundColor Green
    }
} catch {}

# Disable Bing in Windows Search
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled Bing in Windows Search" -ForegroundColor Green
} catch {}

# ============================================
# STEP 8: Visual Effects & Performance
# ============================================
Write-Host "`n[8/12] Optimizing Visual Effects for Performance..." -ForegroundColor Yellow

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
    Set-ItemProperty -Path $advancedPath -Name 'TaskbarAnimations' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $advancedPath -Name 'ListviewAlphaSelect' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $advancedPath -Name 'ListviewShadow' -Value 0 -Type DWord -Force

    Write-Host "  [+] Visual effects optimized" -ForegroundColor Green
} catch {}

# ============================================
# STEP 9: Gaming Optimizations
# ============================================
Write-Host "`n[9/12] Optimizing Gaming Settings..." -ForegroundColor Yellow

# Disable Game DVR
try {
    $gameDVRPath = "HKCU:\System\GameConfigStore"
    if (-not (Test-Path $gameDVRPath)) { New-Item -Path $gameDVRPath -Force | Out-Null }
    Set-ItemProperty -Path $gameDVRPath -Name "GameDVR_Enabled" -Value 0 -Type DWord -Force

    $gameBarPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"
    if (-not (Test-Path $gameBarPath)) { New-Item -Path $gameBarPath -Force | Out-Null }
    Set-ItemProperty -Path $gameBarPath -Name "AppCaptureEnabled" -Value 0 -Type DWord -Force

    Write-Host "  [+] Disabled Game DVR" -ForegroundColor Green
} catch {}

# Disable Game Bar
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled Game Bar" -ForegroundColor Green
} catch {}

# ============================================
# STEP 10: Disable Unnecessary Services
# ============================================
Write-Host "`n[10/12] Disabling Unnecessary Services..." -ForegroundColor Yellow

if ($isAdmin) {
    $servicesToDisable = @(
        'XblAuthManager',           # Xbox Live Auth Manager
        'XblGameSave',              # Xbox Live Game Save
        'XboxGipSvc',               # Xbox Accessory Management
        'XboxNetApiSvc',            # Xbox Live Networking
        'SysMain',                  # Superfetch
        'DiagTrack',                # Diagnostics Tracking
        'dmwappushservice',         # WAP Push Message Routing
        'RetailDemo',               # Retail Demo Service
        'RemoteRegistry',           # Remote Registry
        'WerSvc',                   # Windows Error Reporting
        'Fax',                      # Fax
        'TabletInputService',       # Touch Keyboard
        'WMPNetworkSvc',            # Windows Media Player Network
        'WSearch'                   # Windows Search
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
        } catch {}
    }

    Write-Host "  >> Disabled $disabledServices services" -ForegroundColor Cyan
} else {
    Write-Host "  [!] Skipped (requires Administrator)" -ForegroundColor Yellow
}

# ============================================
# STEP 11: Clean Temporary Files
# ============================================
Write-Host "`n[11/12] Cleaning Temporary Files..." -ForegroundColor Yellow

# Clean user temp
try {
    $tempPath = $env:TEMP
    $tempFiles = (Get-ChildItem -Path $tempPath -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
    Remove-Item -Path "$tempPath\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] Cleaned user temp folder ($tempFiles items)" -ForegroundColor Green
} catch {}

# Clean Windows temp
try {
    $winTempPath = "C:\Windows\Temp"
    $winTempFiles = (Get-ChildItem -Path $winTempPath -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
    Remove-Item -Path "$winTempPath\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] Cleaned Windows temp folder ($winTempFiles items)" -ForegroundColor Green
} catch {}

# Clear Windows Update cache
try {
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    Write-Host "  [+] Cleared Windows Update cache" -ForegroundColor Green
} catch {}

# Empty Recycle Bin
try {
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] Emptied Recycle Bin" -ForegroundColor Green
} catch {}

# ============================================
# STEP 12: Power & System Optimizations
# ============================================
Write-Host "`n[12/12] System Optimizations..." -ForegroundColor Yellow

# Disable hibernation
if ($isAdmin) {
    try {
        powercfg.exe /hibernate off
        Write-Host "  [+] Disabled hibernation (frees disk space)" -ForegroundColor Green
    } catch {}

    # Set High Performance power plan
    try {
        powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        Write-Host "  [+] Set High Performance power plan" -ForegroundColor Green
    } catch {}
}

# Disable Background Apps
try {
    if ($isAdmin) {
        $bgAppsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
        if (-not (Test-Path $bgAppsPath)) { New-Item -Path $bgAppsPath -Force | Out-Null }
        Set-ItemProperty -Path $bgAppsPath -Name "LetAppsRunInBackground" -Value 2 -Type DWord -Force
        Write-Host "  [+] Disabled background apps" -ForegroundColor Green
    }
} catch {}

# Disable Windows Error Reporting
try {
    if ($isAdmin) {
        $werPath = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"
        Set-ItemProperty -Path $werPath -Name "Disabled" -Value 1 -Type DWord -Force
        Write-Host "  [+] Disabled Windows Error Reporting" -ForegroundColor Green
    }
} catch {}

# Disable Delivery Optimization (P2P Windows Updates)
try {
    $doPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    if ($isAdmin) {
        if (-not (Test-Path $doPath)) { New-Item -Path $doPath -Force | Out-Null }
        Set-ItemProperty -Path $doPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled Delivery Optimization (P2P updates)" -ForegroundColor Green
    }
} catch {}

# ============================================
# Summary
# ============================================
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "  ULTIMATE OPTIMIZATION COMPLETE!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Optimizations Applied:" -ForegroundColor White
Write-Host "  [1] Removed bloatware apps" -ForegroundColor White
Write-Host "  [2] Disabled startup programs" -ForegroundColor White
Write-Host "  [3] Enhanced privacy (telemetry, tracking, activity history)" -ForegroundColor White
Write-Host "  [4] Configured notifications (disabled sounds & suggestions)" -ForegroundColor White
Write-Host "  [5] Customized taskbar (hidden search, widgets, chat, copilot)" -ForegroundColor White
Write-Host "  [6] Optimized File Explorer (extensions, hidden files, no ads)" -ForegroundColor White
Write-Host "  [7] Disabled Cortana & Bing Search" -ForegroundColor White
Write-Host "  [8] Optimized visual effects for performance" -ForegroundColor White
Write-Host "  [9] Disabled gaming features (Game DVR, Game Bar)" -ForegroundColor White
Write-Host "  [10] Disabled unnecessary services" -ForegroundColor White
Write-Host "  [11] Cleaned temporary files and caches" -ForegroundColor White
Write-Host "  [12] System optimizations (hibernation, power plan, background apps)" -ForegroundColor White
Write-Host ""
Write-Host "[!] IMPORTANT: Restart your computer for all changes to take effect!" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Enter to exit..." -ForegroundColor Cyan
Read-Host
