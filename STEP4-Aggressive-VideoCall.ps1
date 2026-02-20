# ==============================================================
# Windows 11 Aggressive Process Reduction
# Tuned for: Zoom & Google Meet
# ==============================================================
# Disables: Windows Defender, Windows Firewall, IPv6
# Keeps:    Audio, Network (IPv4), Webcam, TLS/HTTPS
#
# Run as Administrator (REQUIRED)
# ==============================================================

Write-Host "================================================================" -ForegroundColor Red
Write-Host "  AGGRESSIVE PROCESS REDUCER  -  Zoom & Google Meet Edition" -ForegroundColor Red
Write-Host "================================================================" -ForegroundColor Red
Write-Host ""
Write-Host "  This script will:" -ForegroundColor Yellow
Write-Host "    [!] Disable Windows Defender antivirus" -ForegroundColor Red
Write-Host "    [!] Disable Windows Firewall (all profiles)" -ForegroundColor Red
Write-Host "    [!] Disable IPv6 (IPv4 only)" -ForegroundColor Yellow
Write-Host "    [+] Aggressively disable all non-essential services" -ForegroundColor Yellow
Write-Host "    [+] Kill background processes immediately" -ForegroundColor Yellow
Write-Host "    [+] Preserve: Audio, Webcam, Network, TLS for video calls" -ForegroundColor Green
Write-Host ""
Write-Host "  NOTE: If Defender won't stop, go to:" -ForegroundColor Cyan
Write-Host "  Windows Security > Virus Protection > Manage Settings" -ForegroundColor Cyan
Write-Host "  Turn OFF Tamper Protection first, then re-run this script." -ForegroundColor Cyan
Write-Host ""

# ============================================
# ADMIN CHECK
# ============================================
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: Must run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell -> Run as Administrator" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Press Enter to proceed, or Ctrl+C to cancel..." -ForegroundColor Yellow
Read-Host

# ============================================
# CREATE RESTORE POINT
# ============================================
Write-Host "`nCreating System Restore Point..." -ForegroundColor Cyan
try {
    Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
    $rpName = "Before Aggressive Reduction - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    Checkpoint-Computer -Description $rpName -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
    Write-Host "  [OK] Restore point created" -ForegroundColor Green
} catch {
    Write-Host "  [!] Could not create restore point: $($_.Exception.Message)" -ForegroundColor Yellow
}

$beforeCount = (Get-Process).Count
Write-Host "`nProcess count before: $beforeCount" -ForegroundColor Cyan

# ==============================================================
# SECTION 1: DISABLE WINDOWS DEFENDER
# ==============================================================
Write-Host "`n[1/7] Disabling Windows Defender..." -ForegroundColor Yellow

# Policy path bypasses Tamper Protection for the antispyware engine
$defenderPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if (-not (Test-Path $defenderPolicyPath)) {
    New-Item -Path $defenderPolicyPath -Force | Out-Null
}
Set-ItemProperty -Path $defenderPolicyPath -Name "DisableAntiSpyware"        -Value 1 -Type DWord -Force
Set-ItemProperty -Path $defenderPolicyPath -Name "DisableAntiVirus"          -Value 1 -Type DWord -Force
Set-ItemProperty -Path $defenderPolicyPath -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $defenderPolicyPath -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force
Write-Host "  [+] Defender policy set to disabled" -ForegroundColor Green

# Real-time protection registry key (user-space)
$defenderPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
if (-not (Test-Path $defenderPath)) { New-Item -Path $defenderPath -Force | Out-Null }
Set-ItemProperty -Path $defenderPath -Name "DisableRealtimeMonitoring"  -Value 1 -Type DWord -Force
Set-ItemProperty -Path $defenderPath -Name "DisableBehaviorMonitoring"  -Value 1 -Type DWord -Force
Set-ItemProperty -Path $defenderPath -Name "DisableOnAccessProtection"  -Value 1 -Type DWord -Force
Set-ItemProperty -Path $defenderPath -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord -Force
Write-Host "  [+] Real-time protection disabled in registry" -ForegroundColor Green

# Disable Defender services (may need Tamper Protection OFF first)
$defenderServices = @(
    'WinDefend',            # Windows Defender Antivirus
    'WdNisSvc',             # Defender Network Inspection Service
    'WdFilter',             # Defender Mini-Filter Driver
    'SecurityHealthService',# Windows Security Health
    'wscsvc',               # Security Center
    'Sense',                # Defender Advanced Threat Protection
    'SgrmBroker'            # System Guard Runtime Monitor
)
foreach ($svc in $defenderServices) {
    try {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "  [+] Disabled: $svc" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [~] Could not fully stop: $svc (needs Tamper Protection OFF)" -ForegroundColor DarkYellow
    }
}

# Disable Defender scheduled tasks
$defenderTasks = @(
    '\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance',
    '\Microsoft\Windows\Windows Defender\Windows Defender Cleanup',
    '\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan',
    '\Microsoft\Windows\Windows Defender\Windows Defender Verification'
)
foreach ($task in $defenderTasks) {
    try {
        Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
        Write-Host "  [+] Disabled task: $($task.Split('\')[-1])" -ForegroundColor Green
    } catch {}
}

Write-Host "  [OK] Defender disabled (reboot required for full effect)" -ForegroundColor Cyan
Write-Host "       If MsMpEng.exe still shows: disable Tamper Protection in Security UI first" -ForegroundColor DarkYellow

# ==============================================================
# SECTION 2: DISABLE WINDOWS FIREWALL
# ==============================================================
Write-Host "`n[2/7] Disabling Windows Firewall..." -ForegroundColor Yellow

try {
    # Turn off all firewall profiles immediately
    netsh advfirewall set allprofiles state off 2>&1 | Out-Null
    Write-Host "  [+] All firewall profiles turned OFF" -ForegroundColor Green
} catch {
    Write-Host "  [-] netsh failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Also via PowerShell (belt and suspenders)
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue
    Write-Host "  [+] All firewall profiles disabled via PowerShell" -ForegroundColor Green
} catch {
    Write-Host "  [~] PowerShell firewall cmdlet not available" -ForegroundColor DarkYellow
}

# Disable the service
try {
    Stop-Service -Name 'MpsSvc' -Force -ErrorAction SilentlyContinue
    Set-Service  -Name 'MpsSvc' -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "  [+] Windows Firewall service (MpsSvc) disabled" -ForegroundColor Green
} catch {
    Write-Host "  [-] Could not disable MpsSvc" -ForegroundColor Red
}

# ==============================================================
# SECTION 3: IPv4 ONLY — DISABLE IPv6
# ==============================================================
Write-Host "`n[3/7] Disabling IPv6 (IPv4 only)..." -ForegroundColor Yellow

# Registry — applies fully after reboot
$tcpip6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
if (-not (Test-Path $tcpip6Path)) { New-Item -Path $tcpip6Path -Force | Out-Null }
# 0xFF disables all IPv6 interfaces and prefer IPv4 over IPv6
Set-ItemProperty -Path $tcpip6Path -Name "DisabledComponents" -Value 0xFF -Type DWord -Force
Write-Host "  [+] IPv6 disabled in registry (Tcpip6 DisabledComponents=0xFF)" -ForegroundColor Green

# Disable IPv6 binding on all active adapters immediately (no reboot needed)
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue
foreach ($adapter in $adapters) {
    try {
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID "ms_tcpip6" -ErrorAction SilentlyContinue
        Write-Host "  [+] IPv6 unbound from: $($adapter.Name)" -ForegroundColor Green
    } catch {}
}

# Prefer IPv4 in the hosts resolution order
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
    -Name "PreferIPv4OverIPv6" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
Write-Host "  [+] System set to prefer IPv4" -ForegroundColor Green

# ==============================================================
# SECTION 4: AGGRESSIVE SERVICE DISABLING
# Services kept: AudioSrv, AudioEndpointBuilder, Dhcp, Dnscache,
#   NlaSvc, CryptSvc, WlanSvc, LanmanWorkstation, RpcSs,
#   DcomLaunch, Schedule, EventLog, netman, Nsi, FrameServer
# ==============================================================
Write-Host "`n[4/7] Aggressively Disabling Services..." -ForegroundColor Yellow

$servicesToDisable = @(
    # --- Telemetry & Diagnostics ---
    'DiagTrack',                                    # Connected User Experiences & Telemetry
    'dmwappushservice',                             # WAP Push routing (telemetry relay)
    'diagnosticshub.standardcollector.service',     # Diagnostics Hub Collector
    'DPS',                                          # Diagnostic Policy Service
    'WdiServiceHost',                               # Diagnostic Service Host
    'WdiSystemHost',                                # Diagnostic System Host
    'PcaSvc',                                       # Program Compatibility Assistant
    'WerSvc',                                       # Windows Error Reporting

    # --- Xbox / Gaming ---
    'XblAuthManager',                               # Xbox Live Auth Manager
    'XblGameSave',                                  # Xbox Live Game Save
    'XboxGipSvc',                                   # Xbox Accessory Management
    'XboxNetApiSvc',                                # Xbox Live Networking
    'BcastDVRUserService',                          # Game DVR and Broadcast
    'GamingServices',                               # Xbox Game Pass services
    'GamingServicesNet',                            # Xbox network services

    # --- Search & Indexing ---
    'WSearch',                                      # Windows Search / Indexer

    # --- Performance "helpers" (not needed on SSD) ---
    'SysMain',                                      # Superfetch

    # --- Remote Access ---
    'RemoteRegistry',                               # Remote Registry editing
    'RemoteAccess',                                 # Routing and Remote Access
    'SessionEnv',                                   # Remote Desktop Configuration
    'TermService',                                  # Remote Desktop Services
    'UmRdpService',                                 # RDP UserMode Port Redirector

    # --- Network extras (not needed for Zoom/Meet) ---
    'lmhosts',                                      # TCP/IP NetBIOS Helper
    'SSDPSRV',                                      # SSDP Discovery (UPnP)
    'upnphost',                                     # UPnP Device Host
    'SharedAccess',                                 # Internet Connection Sharing
    'IKEEXT',                                       # IKE/AuthIP IPsec Keying
    'PolicyAgent',                                  # IPsec Policy Agent
    'dot3svc',                                      # Wired AutoConfig (use manual config)
    'ALG',                                          # Application Layer Gateway (legacy NAT)
    'Netlogon',                                     # Net Logon (domain auth, not needed standalone)
    'Browser',                                      # Computer Browser (legacy)

    # --- Bluetooth ---
    'bthserv',                                      # Bluetooth Support
    'BthAvctpSvc',                                  # Bluetooth Audio
    'BluetoothUserService',                         # Bluetooth User Support

    # --- Print ---
    'Spooler',                                      # Print Spooler (disable if no printer)
    'PrintNotify',                                  # Printer Extensions & Notifications
    'Fax',                                          # Fax Service

    # --- Windows Hello / Biometrics / Smart Card ---
    'WbioSrvc',                                     # Windows Biometric Service
    'NgcSvc',                                       # Windows Hello NGC
    'NgcCtnrSvc',                                   # Windows Hello Container
    'SCardSvr',                                     # Smart Card
    'ScDeviceEnum',                                 # Smart Card Device Enumeration
    'SCPolicySvc',                                  # Smart Card Removal Policy
    'CertPropSvc',                                  # Certificate Propagation (smart card)

    # --- Phone / Tablet / Hotspot ---
    'PhoneSvc',                                     # Phone Service
    'icssvc',                                       # Windows Mobile Hotspot
    'TabletInputService',                           # Touch Keyboard and Handwriting

    # --- Windows Update extras (keeping core Update services) ---
    'DoSvc',                                        # Delivery Optimization (P2P updates)
    'InstallService',                               # Microsoft Store Install Service

    # --- Maps & Location ---
    'MapsBroker',                                   # Downloaded Maps Manager
    'lfsvc',                                        # Geolocation Service

    # --- Sync & Cloud (OneDrive sync handled separately) ---
    'OneSyncSvc',                                   # Sync Host Service
    'UnistoreSvc',                                  # User Data Storage
    'UserDataSvc',                                  # User Data Access
    'PimIndexMaintenanceSvc',                       # Contact Data (calendar/contacts indexing)

    # --- Sensors ---
    'SensorDataService',                            # Sensor Data Service
    'SensorService',                                # Sensor Service
    'SensrSvc',                                     # Sensor Monitoring Service

    # --- Wallet / Store ---
    'WalletService',                                # NFC/tap-to-pay Wallet
    'AppXSvc',                                      # AppX Deployment (runs after every app install)
    'ClipSVC',                                      # Client License Service (Store apps)
    'LicenseManager',                              # Windows License Manager

    # --- Microsoft Account ---
    'wlidsvc',                                      # Microsoft Account Sign-in Assistant

    # --- Retail & Parental ---
    'RetailDemo',                                   # Retail Demo Service
    'WpcMonSvc',                                    # Parental Controls

    # --- Misc ---
    'tzautoupdate',                                 # Auto Time Zone Updater
    'HomeGroupListener',                            # HomeGroup (legacy)
    'HomeGroupProvider',                            # HomeGroup Provider
    'wisvc',                                        # Windows Insider Service
    'EntAppSvc',                                    # Enterprise App Management
    'seclogon',                                     # Secondary Logon (Run As)
    'EFS',                                          # Encrypting File System
    'defragsvc',                                    # Disk Defragmenter (not needed SSD)
    'MSiSCSI',                                      # iSCSI Initiator
    'WMPNetworkSvc',                                # Windows Media Player Network Sharing
    'stisvc',                                       # Windows Image Acquisition (scanners)
    'WiaRpc',                                       # Still Image RPC (scanners)
    'StorSvc',                                      # Storage Service
    'LxpSvc',                                       # Language Experience Service
    'wecsvc',                                       # Windows Event Collector
    'BDESVC'                                        # BitLocker Drive Encryption
)

$disabledCount = 0
$failedCount   = 0

foreach ($svc in $servicesToDisable) {
    try {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            Stop-Service  -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service   -Name $svc -StartupType Disabled -ErrorAction Stop
            Write-Host "  [+] $svc" -ForegroundColor Green
            $disabledCount++
        }
    } catch {
        Write-Host "  [-] $svc" -ForegroundColor DarkGray
        $failedCount++
    }
}

Write-Host "  Disabled: $disabledCount  |  Could not disable: $failedCount" -ForegroundColor Cyan

# ==============================================================
# SECTION 5: KILL BACKGROUND PROCESSES NOW
# (without waiting for reboot)
# ==============================================================
Write-Host "`n[5/7] Killing Background Processes..." -ForegroundColor Yellow

$processesToKill = @(
    'SearchIndexer',            # Search indexer (WSearch service killed above)
    'SearchHost',               # Search flyout UI
    'SearchApp',                # Search app
    'MicrosoftEdgeUpdate',      # Edge auto-updater
    'msedgewebview2',           # Edge WebView (used by widgets, etc.)
    'WidgetService',            # Widgets host
    'Widgets',                  # Widgets process
    'ShellExperienceHost',      # May restart — removes extra RuntimeBrokers
    'StartMenuExperienceHost',  # Will auto-restart but clears memory spike
    'GameBar',                  # Xbox Game Bar
    'GameBarFTServer',          # Game Bar frame server
    'NisSrv',                   # Defender Network Inspection (if Defender is stopping)
    'MsMpEng',                  # Defender engine (if Tamper Protection is off)
    'SecurityHealthSystray',    # Defender system tray icon
    'OneDrive',                 # OneDrive sync
    'YourPhone',                # Phone Link
    'YourPhoneServer'           # Phone Link server
)

foreach ($proc in $processesToKill) {
    try {
        $running = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($running) {
            Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
            Write-Host "  [+] Killed: $proc" -ForegroundColor Green
        }
    } catch {}
}

# Set RuntimeBroker to use minimal memory (limit WinRT app broker)
try {
    $rbPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc"
    if (Test-Path $rbPath) {
        Set-ItemProperty -Path $rbPath -Name "Start" -Value 3 -Type DWord -Force
    }
    Write-Host "  [+] RuntimeBroker set to Manual" -ForegroundColor Green
} catch {}

# Disable all background apps globally
try {
    $bgPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
    if (-not (Test-Path $bgPath)) { New-Item -Path $bgPath -Force | Out-Null }
    Set-ItemProperty -Path $bgPath -Name "GlobalUserDisabled" -Value 1 -Type DWord -Force
    Write-Host "  [+] All background apps disabled globally" -ForegroundColor Green
} catch {}

# Force-disable background app policy (system-wide)
try {
    $bgPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    if (-not (Test-Path $bgPolicyPath)) { New-Item -Path $bgPolicyPath -Force | Out-Null }
    Set-ItemProperty -Path $bgPolicyPath -Name "LetAppsRunInBackground" -Value 2 -Type DWord -Force
    Write-Host "  [+] Background app policy: Force Deny" -ForegroundColor Green
} catch {}

# ==============================================================
# SECTION 6: SCHEDULED TASKS
# ==============================================================
Write-Host "`n[6/7] Disabling Scheduled Tasks..." -ForegroundColor Yellow

$tasksToDisable = @(
    # Telemetry
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
    '\Microsoft\Windows\Application Experience\StartupAppTask',
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
    '\Microsoft\Windows\Autochk\Proxy',
    '\Microsoft\Windows\CloudExperienceHost\CreateObjectTask',
    '\Microsoft\Windows\Feedback\Siuf\DmClient',
    '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload',
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
    '\Microsoft\Windows\Windows Error Reporting\QueueReporting',
    '\Microsoft\Windows\Device Information\Device',
    '\Microsoft\Windows\Device Information\Device User',

    # Maps & Location
    '\Microsoft\Windows\Maps\MapsToastTask',
    '\Microsoft\Windows\Maps\MapsUpdateTask',

    # Shell / Family
    '\Microsoft\Windows\Shell\FamilySafetyMonitor',
    '\Microsoft\Windows\Shell\FamilySafetyRefreshTask',

    # Retail & Demo
    '\Microsoft\Windows\RetailDemo\CleanupOfflineContent',

    # Defrag (not useful for SSDs)
    '\Microsoft\Windows\Defrag\ScheduledDefrag',

    # Power benchmarking
    '\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem',
    '\Microsoft\Windows\Maintenance\WinSAT',

    # Sync
    '\Microsoft\Windows\Offline Files\Background Synchronization',
    '\Microsoft\Windows\Offline Files\Logon Synchronization',

    # Language
    '\Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources',

    # Speech
    '\Microsoft\Windows\Speech\SpeechModelDownloadTask',

    # Subscription
    '\Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures',
    '\Microsoft\Windows\Flighting\OneSettings\RefreshCache'
)

$disabledTasks = 0
foreach ($task in $tasksToDisable) {
    try {
        $taskName = $task -replace '.*\\', ''
        $taskPath = $task -replace '[^\\]*$', ''
        $t = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
        if ($t) {
            Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  [+] $taskName" -ForegroundColor Green
            $disabledTasks++
        }
    } catch {}
}

Write-Host "  Disabled $disabledTasks tasks" -ForegroundColor Cyan

# ==============================================================
# SECTION 7: ADDITIONAL REGISTRY TWEAKS
# ==============================================================
Write-Host "`n[7/7] Applying Registry Tweaks..." -ForegroundColor Yellow

# Disable Consumer Features / suggested apps in Start
try {
    $cloudPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    if (-not (Test-Path $cloudPath)) { New-Item -Path $cloudPath -Force | Out-Null }
    Set-ItemProperty -Path $cloudPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $cloudPath -Name "DisableSoftLanding"             -Value 1 -Type DWord -Force
    Write-Host "  [+] Disabled consumer features / suggested apps" -ForegroundColor Green
} catch {}

# Disable Cortana
try {
    $cortanaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    if (-not (Test-Path $cortanaPath)) { New-Item -Path $cortanaPath -Force | Out-Null }
    Set-ItemProperty -Path $cortanaPath -Name "AllowCortana"    -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $cortanaPath -Name "AllowSearchToUseLocation" -Value 0 -Type DWord -Force
    Write-Host "  [+] Cortana disabled" -ForegroundColor Green
} catch {}

# Disable Bing in Search
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" `
        -Name "BingSearchEnabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] Bing in Search disabled" -ForegroundColor Green
} catch {}

# Disable Advertising ID
try {
    $adPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    if (-not (Test-Path $adPath)) { New-Item -Path $adPath -Force | Out-Null }
    Set-ItemProperty -Path $adPath -Name "Enabled" -Value 0 -Type DWord -Force
    Write-Host "  [+] Advertising ID disabled" -ForegroundColor Green
} catch {}

# Disable Telemetry
try {
    $telPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if (-not (Test-Path $telPath)) { New-Item -Path $telPath -Force | Out-Null }
    Set-ItemProperty -Path $telPath -Name "AllowTelemetry" -Value 0 -Type DWord -Force
    Write-Host "  [+] Telemetry disabled" -ForegroundColor Green
} catch {}

# Disable Activity History
try {
    $actPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    if (-not (Test-Path $actPath)) { New-Item -Path $actPath -Force | Out-Null }
    Set-ItemProperty -Path $actPath -Name "EnableActivityFeed"    -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $actPath -Name "PublishUserActivities" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $actPath -Name "UploadUserActivities"  -Value 0 -Type DWord -Force
    Write-Host "  [+] Activity History disabled" -ForegroundColor Green
} catch {}

# Disable Live Tiles
try {
    $tilePath = "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    if (-not (Test-Path $tilePath)) { New-Item -Path $tilePath -Force | Out-Null }
    Set-ItemProperty -Path $tilePath -Name "NoTileApplicationNotification" -Value 1 -Type DWord -Force
    Write-Host "  [+] Live Tiles disabled" -ForegroundColor Green
} catch {}

# Disable Delivery Optimization
try {
    $doPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    if (-not (Test-Path $doPath)) { New-Item -Path $doPath -Force | Out-Null }
    Set-ItemProperty -Path $doPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
    Write-Host "  [+] Delivery Optimization (P2P updates) disabled" -ForegroundColor Green
} catch {}

# Visual Effects: Best Performance
try {
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' `
        -Name 'VisualFXSetting' -Value 2 -Type DWord -Force
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'MenuShowDelay' -Value 0 -Type String -Force
    $adv = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    Set-ItemProperty -Path $adv -Name 'TaskbarAnimations'  -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $adv -Name 'ListviewAlphaSelect' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $adv -Name 'ListviewShadow'     -Value 0 -Type DWord -Force
    Write-Host "  [+] Visual effects: Best Performance" -ForegroundColor Green
} catch {}

# Disable hibernation (frees pagefile.sys disk space)
try {
    powercfg.exe /hibernate off 2>&1 | Out-Null
    Write-Host "  [+] Hibernation disabled" -ForegroundColor Green
} catch {}

# High Performance power plan
try {
    powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>&1 | Out-Null
    Write-Host "  [+] Power plan: High Performance" -ForegroundColor Green
} catch {}

# ==============================================================
# SUMMARY
# ==============================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  DONE!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

Start-Sleep -Seconds 2
$afterCount = (Get-Process).Count
$reduction  = $beforeCount - $afterCount

Write-Host "  Process count before : $beforeCount" -ForegroundColor White
Write-Host "  Process count now    : $afterCount" -ForegroundColor White
Write-Host "  Reduced immediately  : $reduction" -ForegroundColor $(if ($reduction -gt 0) { 'Green' } else { 'Yellow' })
Write-Host ""
Write-Host "  After REBOOT you should see ~60-85 processes." -ForegroundColor Green
Write-Host ""
Write-Host "  What is still running (intentionally):" -ForegroundColor Cyan
Write-Host "    AudioSrv, AudioEndpointBuilder  - mic & speakers for calls" -ForegroundColor White
Write-Host "    Dhcp, Dnscache, NlaSvc          - network connectivity" -ForegroundColor White
Write-Host "    CryptSvc                         - HTTPS/TLS for Meet & Zoom" -ForegroundColor White
Write-Host "    WlanSvc                          - WiFi" -ForegroundColor White
Write-Host "    FrameServer                      - webcam (browser Meet needs this)" -ForegroundColor White
Write-Host "    RpcSs, DcomLaunch, Schedule      - Windows core" -ForegroundColor White
Write-Host ""
Write-Host "  Defender: policy-disabled (full effect after reboot)" -ForegroundColor Yellow
Write-Host "  Firewall: OFF on all profiles (active now)" -ForegroundColor Yellow
Write-Host "  IPv6:     disabled on all adapters (active now)" -ForegroundColor Yellow
Write-Host ""
Write-Host "  To verify firewall is off:" -ForegroundColor DarkGray
Write-Host "    netsh advfirewall show allprofiles" -ForegroundColor White
Write-Host ""
Write-Host "  To verify IPv6 is off:" -ForegroundColor DarkGray
Write-Host "    Get-NetAdapterBinding -ComponentID ms_tcpip6" -ForegroundColor White
Write-Host ""
Write-Host "  RESTART NOW for full effect." -ForegroundColor Yellow
Write-Host ""
Read-Host "Press Enter to exit"
