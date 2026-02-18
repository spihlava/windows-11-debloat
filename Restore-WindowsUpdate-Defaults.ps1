# ============================================
# Windows Update - Restore Default Settings
# ============================================
# Removes all custom Windows Update policy settings and restores
# services/tasks to their original Windows 11 defaults.
# Run as Administrator (REQUIRED)

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Windows Update - Restore Defaults" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script MUST run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "This script will restore Windows Update to factory defaults:" -ForegroundColor Yellow
Write-Host "  1. Remove Windows Update policy registry keys" -ForegroundColor White
Write-Host "  2. Remove Delivery Optimization policy (restore P2P to default)" -ForegroundColor White
Write-Host "  3. Restore Windows Update service startup types to defaults" -ForegroundColor White
Write-Host "  4. Re-enable Windows Update scheduled tasks" -ForegroundColor White
Write-Host "  5. Restart Windows Update services" -ForegroundColor White
Write-Host ""
Write-Host "Press Enter to continue, or Ctrl+C to cancel..." -ForegroundColor Yellow
Read-Host

# ============================================
# STEP 1: Remove Windows Update Policy Registry Keys
# ============================================
Write-Host "`n[1/5] Removing Windows Update policy registry keys..." -ForegroundColor Yellow

$wuPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$wuAUPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

# Remove individual values set by the configure script
$wuValues = @(
    'DeferFeatureUpdates',
    'DeferFeatureUpdatesPeriodInDays',
    'BranchReadinessLevel',
    'ExcludeWUDriversInQualityUpdate'
)

if (Test-Path $wuPolicyPath) {
    foreach ($val in $wuValues) {
        try {
            Remove-ItemProperty -Path $wuPolicyPath -Name $val -ErrorAction SilentlyContinue
            Write-Host "  [+] Removed: WindowsUpdate\$val" -ForegroundColor Green
        } catch {
            Write-Host "  [-] Could not remove $val : $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }
} else {
    Write-Host "  [OK] WindowsUpdate policy key not present - nothing to remove" -ForegroundColor Cyan
}

$auValues = @(
    'AUOptions',
    'ScheduledInstallDay',
    'ScheduledInstallTime',
    'NoAutoRebootWithLoggedOnUsers',
    'AUPowerManagement'
)

if (Test-Path $wuAUPath) {
    foreach ($val in $auValues) {
        try {
            Remove-ItemProperty -Path $wuAUPath -Name $val -ErrorAction SilentlyContinue
            Write-Host "  [+] Removed: WindowsUpdate\AU\$val" -ForegroundColor Green
        } catch {
            Write-Host "  [-] Could not remove $val : $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }

    # Remove the AU key itself if it is now empty
    $remaining = Get-Item -Path $wuAUPath -ErrorAction SilentlyContinue |
                 Get-ItemProperty -ErrorAction SilentlyContinue |
                 Select-Object -Property * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider
    if ($remaining.PSObject.Properties.Count -eq 0) {
        Remove-Item -Path $wuAUPath -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] Removed empty AU policy key" -ForegroundColor Green
    }
} else {
    Write-Host "  [OK] WindowsUpdate\AU policy key not present - nothing to remove" -ForegroundColor Cyan
}

# Remove the WindowsUpdate policy key itself if it is now empty
if (Test-Path $wuPolicyPath) {
    $children = Get-ChildItem -Path $wuPolicyPath -ErrorAction SilentlyContinue
    $props     = Get-ItemProperty -Path $wuPolicyPath -ErrorAction SilentlyContinue |
                 Select-Object -Property * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider
    if ((-not $children) -and ($props.PSObject.Properties.Count -eq 0)) {
        Remove-Item -Path $wuPolicyPath -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] Removed empty WindowsUpdate policy key" -ForegroundColor Green
    }
}

# ============================================
# STEP 2: Remove Delivery Optimization Policy
# ============================================
Write-Host "`n[2/5] Restoring Delivery Optimization to default..." -ForegroundColor Yellow

$deliveryOptPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"

if (Test-Path $deliveryOptPath) {
    try {
        Remove-ItemProperty -Path $deliveryOptPath -Name "DODownloadMode" -ErrorAction SilentlyContinue
        Write-Host "  [+] Removed DODownloadMode policy (P2P restored to Windows default)" -ForegroundColor Green

        # Remove the key if empty
        $doProps = Get-ItemProperty -Path $deliveryOptPath -ErrorAction SilentlyContinue |
                   Select-Object -Property * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider
        if ($doProps.PSObject.Properties.Count -eq 0) {
            Remove-Item -Path $deliveryOptPath -Force -ErrorAction SilentlyContinue
            Write-Host "  [+] Removed empty DeliveryOptimization policy key" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "  [OK] DeliveryOptimization policy key not present - nothing to remove" -ForegroundColor Cyan
}

# ============================================
# STEP 3: Restore Service Startup Types to Windows Defaults
# ============================================
Write-Host "`n[3/5] Restoring Windows Update service startup types..." -ForegroundColor Yellow

# Windows 11 default startup types:
#   wuauserv    - Manual  (trigger-started automatically when needed)
#   WaaSMedicSvc - Manual (protected; change may be blocked by the OS)
#   UsoSvc      - Automatic (Delayed Start)
#   BITS        - Manual  (trigger-started)
$serviceDefaults = @{
    'wuauserv'    = 'Manual'
    'WaaSMedicSvc'= 'Manual'
    'UsoSvc'      = 'Automatic'
    'BITS'        = 'Manual'
}

foreach ($entry in $serviceDefaults.GetEnumerator()) {
    $svcName     = $entry.Key
    $startupType = $entry.Value
    try {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            Set-Service -Name $svcName -StartupType $startupType -ErrorAction Stop
            Write-Host "  [+] $svcName -> $startupType" -ForegroundColor Green
        } else {
            Write-Host "  [-] Service not found: $svcName" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  [-] Could not set $svcName : $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "      (WaaSMedicSvc is a protected service and may resist changes)" -ForegroundColor DarkGray
    }
}

# ============================================
# STEP 4: Re-enable Windows Update Scheduled Tasks
# ============================================
Write-Host "`n[4/5] Re-enabling Windows Update scheduled tasks..." -ForegroundColor Yellow

$updateTasks = @(
    '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan',
    '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task',
    '\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask'
)

foreach ($taskPath in $updateTasks) {
    try {
        $taskName   = $taskPath -replace '.*\\', ''
        $taskFolder = $taskPath -replace '[^\\]*$', ''
        $task = Get-ScheduledTask -TaskPath $taskFolder -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            if ($task.State -eq 'Disabled') {
                Enable-ScheduledTask -TaskName $taskPath -ErrorAction Stop | Out-Null
                Write-Host "  [+] Re-enabled: $taskPath" -ForegroundColor Green
            } else {
                Write-Host "  [OK] Already enabled: $taskPath" -ForegroundColor Cyan
            }
        } else {
            Write-Host "  [-] Task not found: $taskPath" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  [-] Could not enable: $taskPath - $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

# ============================================
# STEP 5: Restart Windows Update Services
# ============================================
Write-Host "`n[5/5] Restarting Windows Update services..." -ForegroundColor Yellow

$startOrder = @('BITS', 'wuauserv', 'UsoSvc')

foreach ($svcName in $startOrder) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -eq 'Running') {
                Restart-Service -Name $svcName -Force -ErrorAction Stop
                Write-Host "  [+] Restarted: $svcName" -ForegroundColor Green
            } else {
                Start-Service -Name $svcName -ErrorAction Stop
                Write-Host "  [+] Started: $svcName" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "  [-] Could not start $svcName : $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "      (Service will start automatically when needed)" -ForegroundColor DarkGray
    }
}

# ============================================
# Summary
# ============================================
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Restore Complete!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Windows Update has been restored to defaults:" -ForegroundColor Yellow
Write-Host "  * Custom policy registry keys: Removed" -ForegroundColor Green
Write-Host "  * Feature update deferral: Removed (updates install normally)" -ForegroundColor Green
Write-Host "  * Driver updates via Windows Update: Default (enabled)" -ForegroundColor Green
Write-Host "  * P2P delivery: Default (local network)" -ForegroundColor Green
Write-Host "  * Auto-restart: Default Windows behavior" -ForegroundColor Green
Write-Host "  * Services: Restored to Windows defaults" -ForegroundColor Green
Write-Host "  * Scheduled tasks: Enabled" -ForegroundColor Green
Write-Host ""
Write-Host "Windows Update will now behave as it did out of the box." -ForegroundColor Cyan
Write-Host "You can verify in Settings > Windows Update > Advanced options." -ForegroundColor White
Write-Host ""
Write-Host "Press Enter to exit..." -ForegroundColor Yellow
Read-Host
