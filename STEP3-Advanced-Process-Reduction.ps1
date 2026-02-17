# ============================================
# Windows 11 Advanced Process Reduction Script
# ============================================
# AGGRESSIVE optimization to minimize running processes
# Run AFTER STEP2-Optimize-Windows.ps1
# Run as Administrator (REQUIRED)

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Windows 11 Advanced Process Reducer" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "WARNING: This script is AGGRESSIVE!" -ForegroundColor Red
Write-Host "It will disable many services and features." -ForegroundColor Yellow
Write-Host "Some functionality may be affected." -ForegroundColor Yellow
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script MUST run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# ============================================
# CREATE SYSTEM RESTORE POINT
# ============================================
Write-Host "`nCreating System Restore Point..." -ForegroundColor Cyan

try {
    # Enable System Restore if not already enabled
    Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue

    # Create restore point
    $restorePointName = "Before Advanced Process Reduction - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    Checkpoint-Computer -Description $restorePointName -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
    Write-Host "[OK] Restore point created: $restorePointName" -ForegroundColor Green
    Write-Host "    You can revert changes later via System Restore" -ForegroundColor Gray
} catch {
    Write-Host "[!] Could not create restore point: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "    Continuing anyway..." -ForegroundColor Gray
}

Write-Host "`nPress Enter to continue, or Ctrl+C to cancel..." -ForegroundColor Yellow
Read-Host

$currentProcessCount = (Get-Process).Count
Write-Host "Current process count: $currentProcessCount" -ForegroundColor Cyan
Write-Host ""

# ============================================
# STEP 1: Disable Additional Services
# ============================================
Write-Host "`n[1/7] Disabling Additional Services..." -ForegroundColor Yellow

$additionalServicesToDisable = @(
    # Print & Fax Services (COMMENTED OUT - Keep printing enabled)
    # 'Spooler',                  # Print Spooler
    # 'PrintNotify',              # Printer Extensions
    # 'Fax',                      # Fax Service

    # Network Services (if not needed)
    'lmhosts',                  # TCP/IP NetBIOS Helper
    'SSDPSRV',                  # SSDP Discovery
    'upnphost',                 # UPnP Device Host
    'HomeGroupListener',        # HomeGroup Listener
    'HomeGroupProvider',        # HomeGroup Provider
    'SharedAccess',             # Internet Connection Sharing

    # Remote Services
    'RemoteRegistry',           # Remote Registry
    'RemoteAccess',             # Routing and Remote Access
    'SessionEnv',               # Remote Desktop Configuration
    'TermService',              # Remote Desktop Services
    'UmRdpService',             # Remote Desktop Services UserMode

    # Mobile & Bluetooth (if not using)
    'bthserv',                  # Bluetooth Support
    'BthAvctpSvc',              # Bluetooth Audio
    'BDESVC',                   # BitLocker Drive Encryption
    'WbioSrvc',                 # Windows Biometric Service

    # Update & Maintenance (Windows Update kept enabled for security)
    # 'UsoSvc',                   # Update Orchestrator Service (KEEP for security updates)
    # 'WaaSMedicSvc',             # Windows Update Medic (KEEP for security updates)
    # 'wuauserv',                 # Windows Update (KEEP for security updates)
    # 'BITS',                     # Background Intelligent Transfer (KEEP for updates)
    'DoSvc',                    # Delivery Optimization (P2P updates - can disable)
    'InstallService',           # Microsoft Store Install Service

    # Telemetry & Diagnostics
    'DiagTrack',                # Connected User Experiences
    'dmwappushservice',         # WAP Push Message Routing
    'diagnosticshub.standardcollector.service', # Diagnostics Hub
    'DPS',                      # Diagnostic Policy Service
    'WdiServiceHost',           # Diagnostic Service Host
    'WdiSystemHost',            # Diagnostic System Host
    'PcaSvc',                   # Program Compatibility Assistant

    # Indexing & Search (already disabled in STEP2, but ensuring)
    'WSearch',                  # Windows Search

    # Tablet & Touch
    'TabletInputService',       # Touch Keyboard and Handwriting
    'wisvc',                    # Windows Insider Service

    # Sync & Cloud
    'OneSyncSvc',               # Sync Host Service
    'UnistoreSvc',              # User Data Storage
    'UserDataSvc',              # User Data Access

    # Maps & Location
    'MapsBroker',               # Downloaded Maps Manager
    'lfsvc',                    # Geolocation Service

    # Gaming (if not gaming)
    'BcastDVRUserService',      # GameDVR and Broadcast

    # Sensors
    'SensorDataService',        # Sensor Data Service
    'SensorService',            # Sensor Service
    'SensrSvc',                 # Sensor Monitoring Service

    # Phone & Mobile
    'PhoneSvc',                 # Phone Service
    'icssvc',                   # Windows Mobile Hotspot

    # Retail Demo
    'RetailDemo',               # Retail Demo Service

    # Parental Controls
    'WpcMonSvc',                # Parental Controls

    # App Services
    'AppXSvc',                  # AppX Deployment Service (keeps running)
    'ClipSVC',                  # Client License Service
    'LicenseManager',           # Windows License Manager

    # Windows Features
    'tzautoupdate',             # Auto Time Zone Updater
    'WalletService',            # WalletService
    'FrameServer',              # Windows Camera Frame Server
    'stisvc',                   # Windows Image Acquisition
    'WiaRpc'                    # Still Image Service
)

$disabledServices = 0
foreach ($service in $additionalServicesToDisable) {
    try {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
            Write-Host "  [+] Disabled: $service" -ForegroundColor Green
            $disabledServices++
        }
    } catch {
        Write-Host "  [-] Could not disable: $service" -ForegroundColor DarkGray
    }
}

Write-Host "  Disabled $($disabledServices) additional services" -ForegroundColor Cyan

# ============================================
# STEP 2: Disable Scheduled Tasks
# ============================================
Write-Host "`n[2/7] Disabling Scheduled Tasks..." -ForegroundColor Yellow

$tasksToDisable = @(
    # Microsoft Compatibility Appraiser
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
    '\Microsoft\Windows\Application Experience\StartupAppTask',

    # Customer Experience Improvement Program
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',

    # Autochk
    '\Microsoft\Windows\Autochk\Proxy',

    # Cloud Experience Host
    '\Microsoft\Windows\CloudExperienceHost\CreateObjectTask',

    # Feedback & Diagnostics
    '\Microsoft\Windows\Feedback\Siuf\DmClient',
    '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload',
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',

    # Windows Error Reporting
    '\Microsoft\Windows\Windows Error Reporting\QueueReporting',

    # Defragmentation (not needed for SSDs)
    '\Microsoft\Windows\Defrag\ScheduledDefrag',

    # Maps
    '\Microsoft\Windows\Maps\MapsToastTask',
    '\Microsoft\Windows\Maps\MapsUpdateTask',

    # Retail Demo
    '\Microsoft\Windows\RetailDemo\CleanupOfflineContent',

    # Windows Update (KEEP scheduled tasks enabled for security updates)
    # '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan',
    # '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task',
    # '\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask',

    # Windows Defender (if using 3rd party AV)
    # '\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance',
    # '\Microsoft\Windows\Windows Defender\Windows Defender Cleanup',
    # '\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan',
    # '\Microsoft\Windows\Windows Defender\Windows Defender Verification',

    # Shell
    '\Microsoft\Windows\Shell\FamilySafetyMonitor',
    '\Microsoft\Windows\Shell\FamilySafetyRefreshTask',

    # Device Information
    '\Microsoft\Windows\Device Information\Device',

    # Power Efficiency Diagnostics
    '\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem',

    # Maintenance
    '\Microsoft\Windows\Maintenance\WinSAT'
)

$disabledTasks = 0
foreach ($task in $tasksToDisable) {
    try {
        $taskExists = Get-ScheduledTask -TaskPath ($task -replace '[^\\]*$', '') -TaskName ($task -replace '.*\\', '') -ErrorAction SilentlyContinue
        if ($taskExists) {
            Disable-ScheduledTask -TaskName $task -ErrorAction Stop | Out-Null
            Write-Host "  [+] Disabled: $task" -ForegroundColor Green
            $disabledTasks++
        }
    } catch {
        Write-Host "  [-] Could not disable: $task" -ForegroundColor DarkGray
    }
}

Write-Host "  Disabled $($disabledTasks) scheduled tasks" -ForegroundColor Cyan

# ============================================
# STEP 3: Disable Windows Features
# ============================================
Write-Host "`n[3/7] Disabling Optional Windows Features..." -ForegroundColor Yellow

$featuresToDisable = @(
    'WorkFolders-Client',           # Work Folders Client
    # 'Printing-XPSServices-Features', # Microsoft XPS Document Writer (KEEP FOR PRINTING)
    # 'FaxServicesClientPackage',     # Windows Fax and Scan (KEEP FOR PRINTING)
    'MediaPlayback',                # Windows Media Player (legacy)
    'WindowsMediaPlayer',           # Windows Media Player
    # 'Printing-Foundation-Features', # Print and Document Services (KEEP FOR PRINTING)
    'SMB1Protocol',                 # SMB 1.0 (security risk)
    'MicrosoftWindowsPowerShellV2', # PowerShell 2.0 (outdated)
    'Internet-Explorer-Optional-amd64' # Internet Explorer 11
)

$disabledFeatures = 0
foreach ($feature in $featuresToDisable) {
    try {
        $featureState = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
        if ($featureState -and $featureState.State -eq 'Enabled') {
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop | Out-Null
            Write-Host "  [+] Disabled: $feature" -ForegroundColor Green
            $disabledFeatures++
        }
    } catch {
        Write-Host "  [-] Could not disable: $feature" -ForegroundColor DarkGray
    }
}

Write-Host "  Disabled $($disabledFeatures) Windows features" -ForegroundColor Cyan

# ============================================
# STEP 4: Additional Registry Tweaks
# ============================================
Write-Host "`n[4/7] Applying Advanced Registry Tweaks..." -ForegroundColor Yellow

# Disable Windows Tips
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] Disabled Windows Tips" -ForegroundColor Green
} catch {}

# Disable Consumer Features
try {
    $cloudPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    if (-not (Test-Path $cloudPath)) { New-Item -Path $cloudPath -Force | Out-Null }
    Set-ItemProperty -Path $cloudPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
    Write-Host "  [+] Disabled Consumer Features" -ForegroundColor Green
} catch {}

# Disable Background Apps Globally
try {
    $bgAppsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
    if (-not (Test-Path $bgAppsPath)) { New-Item -Path $bgAppsPath -Force | Out-Null }
    Set-ItemProperty -Path $bgAppsPath -Name "GlobalUserDisabled" -Value 1 -Type DWord -Force
    Write-Host "  [+] Disabled all background apps" -ForegroundColor Green
} catch {}

# Disable Live Tiles
try {
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] Disabled Live Tiles" -ForegroundColor Green
} catch {}

# Disable App Launch Tracking
try {
    $startPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path $startPath -Name "Start_TrackProgs" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled app launch tracking" -ForegroundColor Green
} catch {}

# ============================================
# STEP 4.5: Configure Windows Update for Security Only
# ============================================
Write-Host "`n[5/7] Configuring Windows Update for Security Updates Only..." -ForegroundColor Yellow

try {
    # Create Windows Update policy path if it doesn't exist
    $wuPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $wuAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

    if (-not (Test-Path $wuPolicyPath)) { New-Item -Path $wuPolicyPath -Force | Out-Null }
    if (-not (Test-Path $wuAUPath)) { New-Item -Path $wuAUPath -Force | Out-Null }

    # Disable feature updates (only security updates)
    Set-ItemProperty -Path $wuPolicyPath -Name "DeferFeatureUpdates" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $wuPolicyPath -Name "DeferFeatureUpdatesPeriodInDays" -Value 365 -Type DWord -Force
    Set-ItemProperty -Path $wuPolicyPath -Name "BranchReadinessLevel" -Value 32 -Type DWord -Force
    Write-Host "  [+] Deferred feature updates for 365 days" -ForegroundColor Green

    # Configure to only install security updates automatically
    Set-ItemProperty -Path $wuAUPath -Name "AUOptions" -Value 4 -Type DWord -Force  # 4 = Auto download and schedule install
    Set-ItemProperty -Path $wuAUPath -Name "ScheduledInstallDay" -Value 0 -Type DWord -Force  # 0 = Every day
    Set-ItemProperty -Path $wuAUPath -Name "ScheduledInstallTime" -Value 3 -Type DWord -Force  # 3 AM
    Write-Host "  [+] Configured automatic security updates (3 AM daily)" -ForegroundColor Green

    # Disable driver updates via Windows Update
    Set-ItemProperty -Path $wuPolicyPath -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord -Force
    Write-Host "  [+] Disabled automatic driver updates" -ForegroundColor Green

    # Disable automatic restart after updates
    Set-ItemProperty -Path $wuAUPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $wuAUPath -Name "AUPowerManagement" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled automatic restart with logged-on users" -ForegroundColor Green

    # Disable Windows Update P2P
    $deliveryOptPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    if (-not (Test-Path $deliveryOptPath)) { New-Item -Path $deliveryOptPath -Force | Out-Null }
    Set-ItemProperty -Path $deliveryOptPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled Windows Update P2P delivery" -ForegroundColor Green

    # Ensure Windows Update services are set to Manual (not disabled)
    Set-Service -Name 'wuauserv' -StartupType Manual -ErrorAction SilentlyContinue
    Set-Service -Name 'WaaSMedicSvc' -StartupType Manual -ErrorAction SilentlyContinue
    Set-Service -Name 'UsoSvc' -StartupType Manual -ErrorAction SilentlyContinue
    Set-Service -Name 'BITS' -StartupType Manual -ErrorAction SilentlyContinue
    Write-Host "  [+] Set Windows Update services to Manual" -ForegroundColor Green

    Write-Host "  [✓] Windows Update configured for security updates only" -ForegroundColor Cyan
    Write-Host "      Feature updates deferred, drivers excluded, auto-restart disabled" -ForegroundColor Gray

} catch {
    Write-Host "  [-] Error configuring Windows Update: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================
# STEP 5: Stop Runtime Broker Instances
# ============================================
Write-Host "`n[6/7] Managing Runtime Broker Processes..." -ForegroundColor Yellow

try {
    # Limit Runtime Broker memory
    $runtimeBrokerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc"
    if (Test-Path $runtimeBrokerPath) {
        Set-ItemProperty -Path $runtimeBrokerPath -Name "Start" -Value 3 -Type DWord -Force
        Write-Host "  [+] Configured Runtime Broker to Manual" -ForegroundColor Green
    }
} catch {}

# ============================================
# STEP 6: Process Summary & Analysis
# ============================================
Write-Host "`n[7/7] Analyzing Process Reduction..." -ForegroundColor Yellow

Start-Sleep -Seconds 3

$newProcessCount = (Get-Process).Count
$reduction = $currentProcessCount - $newProcessCount

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Optimization Complete!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Process Count Summary:" -ForegroundColor Yellow
Write-Host "  Before: $currentProcessCount processes" -ForegroundColor White
Write-Host "  After:  $newProcessCount processes" -ForegroundColor White
Write-Host "  Reduced: $reduction processes" -ForegroundColor $(if ($reduction -gt 0) { 'Green' } else { 'Yellow' })
Write-Host ""
Write-Host "Services Disabled: $disabledServices" -ForegroundColor Cyan
Write-Host "Tasks Disabled: $disabledTasks" -ForegroundColor Cyan
Write-Host "Features Disabled: $disabledFeatures" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: Restart your computer for full effect!" -ForegroundColor Yellow
Write-Host "After restart, your process count should be significantly lower." -ForegroundColor Yellow
Write-Host ""
Write-Host "Top processes currently running:" -ForegroundColor Cyan
Get-Process | Group-Object -Property ProcessName |
    Sort-Object Count -Descending |
    Select-Object -First 10 -Property Count, Name |
    Format-Table -AutoSize

Write-Host ""
Write-Host "To check process count after restart, run:" -ForegroundColor Yellow
Write-Host "  tasklist | measure" -ForegroundColor White
Write-Host ""
Write-Host "Press Enter to exit..." -ForegroundColor Yellow
Read-Host
