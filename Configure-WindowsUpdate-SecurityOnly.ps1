# ============================================
# Windows Update - Security Only Configuration
# ============================================
# Re-enables Windows Update and configures it for security updates only
# Defers feature updates, disables driver updates, and prevents auto-restart
# Run as Administrator (REQUIRED)

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Windows Update Security-Only Configurator" -ForegroundColor Cyan
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

Write-Host "This script will:" -ForegroundColor Yellow
Write-Host "  1. Re-enable Windows Update services (if disabled)" -ForegroundColor White
Write-Host "  2. Configure automatic security updates only" -ForegroundColor White
Write-Host "  3. Defer feature updates for 365 days" -ForegroundColor White
Write-Host "  4. Disable driver updates via Windows Update" -ForegroundColor White
Write-Host "  5. Disable automatic restart with logged-on users" -ForegroundColor White
Write-Host "  6. Disable P2P update delivery" -ForegroundColor White
Write-Host "  7. Start Windows Update services" -ForegroundColor White
Write-Host ""
Write-Host "Press Enter to continue, or Ctrl+C to cancel..." -ForegroundColor Yellow
Read-Host

# ============================================
# STEP 1: Re-enable Windows Update Services
# ============================================
Write-Host "`n[1/4] Re-enabling Windows Update Services..." -ForegroundColor Yellow

$updateServices = @(
    'wuauserv',      # Windows Update
    'WaaSMedicSvc',  # Windows Update Medic
    'UsoSvc',        # Update Orchestrator Service
    'BITS'           # Background Intelligent Transfer Service
)

$enabledServices = 0
foreach ($serviceName in $updateServices) {
    try {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            $currentStartup = (Get-Service -Name $serviceName).StartType

            # Re-enable if disabled
            if ($currentStartup -eq 'Disabled') {
                Set-Service -Name $serviceName -StartupType Manual -ErrorAction Stop
                Write-Host "  [+] Re-enabled: $serviceName (was Disabled, now Manual)" -ForegroundColor Green
                $enabledServices++
            } else {
                Set-Service -Name $serviceName -StartupType Manual -ErrorAction Stop
                Write-Host "  [✓] Configured: $serviceName (Manual)" -ForegroundColor Cyan
            }
        } else {
            Write-Host "  [-] Service not found: $serviceName" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  [-] Error configuring $serviceName : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "  Re-enabled $enabledServices services" -ForegroundColor Cyan

# ============================================
# STEP 2: Configure Windows Update Registry Settings
# ============================================
Write-Host "`n[2/4] Configuring Windows Update Registry Settings..." -ForegroundColor Yellow

try {
    # Create Windows Update policy paths if they don't exist
    $wuPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $wuAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

    if (-not (Test-Path $wuPolicyPath)) {
        New-Item -Path $wuPolicyPath -Force | Out-Null
        Write-Host "  [+] Created Windows Update policy registry path" -ForegroundColor Green
    }
    if (-not (Test-Path $wuAUPath)) {
        New-Item -Path $wuAUPath -Force | Out-Null
        Write-Host "  [+] Created Auto Update policy registry path" -ForegroundColor Green
    }

    # Defer feature updates (only security updates will install)
    Set-ItemProperty -Path $wuPolicyPath -Name "DeferFeatureUpdates" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $wuPolicyPath -Name "DeferFeatureUpdatesPeriodInDays" -Value 365 -Type DWord -Force
    Set-ItemProperty -Path $wuPolicyPath -Name "BranchReadinessLevel" -Value 32 -Type DWord -Force
    Write-Host "  [+] Deferred feature updates for 365 days" -ForegroundColor Green

    # Configure automatic security updates
    # AUOptions: 4 = Auto download and schedule install
    Set-ItemProperty -Path $wuAUPath -Name "AUOptions" -Value 4 -Type DWord -Force
    Set-ItemProperty -Path $wuAUPath -Name "ScheduledInstallDay" -Value 0 -Type DWord -Force  # Every day
    Set-ItemProperty -Path $wuAUPath -Name "ScheduledInstallTime" -Value 3 -Type DWord -Force  # 3 AM
    Write-Host "  [+] Configured automatic security updates (daily at 3 AM)" -ForegroundColor Green

    # Exclude driver updates
    Set-ItemProperty -Path $wuPolicyPath -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord -Force
    Write-Host "  [+] Disabled automatic driver updates" -ForegroundColor Green

    # Disable automatic restart with logged-on users
    Set-ItemProperty -Path $wuAUPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $wuAUPath -Name "AUPowerManagement" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled automatic restart with logged-on users" -ForegroundColor Green

    # Disable Windows Update P2P delivery
    $deliveryOptPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    if (-not (Test-Path $deliveryOptPath)) {
        New-Item -Path $deliveryOptPath -Force | Out-Null
    }
    Set-ItemProperty -Path $deliveryOptPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled P2P update delivery (saves bandwidth)" -ForegroundColor Green

    Write-Host "  [✓] Registry settings configured successfully" -ForegroundColor Cyan

} catch {
    Write-Host "  [-] Error configuring registry: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================
# STEP 3: Re-enable Windows Update Scheduled Tasks
# ============================================
Write-Host "`n[3/4] Re-enabling Windows Update Scheduled Tasks..." -ForegroundColor Yellow

$updateTasks = @(
    '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan',
    '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task',
    '\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask'
)

$enabledTasks = 0
foreach ($taskPath in $updateTasks) {
    try {
        $task = Get-ScheduledTask -TaskPath ($taskPath -replace '[^\\]*$', '') -TaskName ($taskPath -replace '.*\\', '') -ErrorAction SilentlyContinue
        if ($task) {
            if ($task.State -eq 'Disabled') {
                Enable-ScheduledTask -TaskName $taskPath -ErrorAction Stop | Out-Null
                Write-Host "  [+] Re-enabled: $taskPath" -ForegroundColor Green
                $enabledTasks++
            } else {
                Write-Host "  [✓] Already enabled: $taskPath" -ForegroundColor Cyan
            }
        }
    } catch {
        Write-Host "  [-] Could not enable: $taskPath" -ForegroundColor DarkGray
    }
}

Write-Host "  Re-enabled $enabledTasks scheduled tasks" -ForegroundColor Cyan

# ============================================
# STEP 4: Start Windows Update Services
# ============================================
Write-Host "`n[4/4] Starting Windows Update Services..." -ForegroundColor Yellow

$startedServices = 0
foreach ($serviceName in $updateServices) {
    try {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -ne 'Running') {
                Start-Service -Name $serviceName -ErrorAction Stop
                Write-Host "  [+] Started: $serviceName" -ForegroundColor Green
                $startedServices++
            } else {
                Write-Host "  [✓] Already running: $serviceName" -ForegroundColor Cyan
            }
        }
    } catch {
        Write-Host "  [-] Could not start $serviceName : $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "      (Service may start automatically when needed)" -ForegroundColor DarkGray
    }
}

Write-Host "  Started $startedServices services" -ForegroundColor Cyan

# ============================================
# Summary
# ============================================
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Configuration Complete!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Windows Update Status:" -ForegroundColor Yellow
Write-Host "  ✓ Services: Re-enabled and set to Manual" -ForegroundColor Green
Write-Host "  ✓ Security Updates: Enabled (auto-install)" -ForegroundColor Green
Write-Host "  ✓ Feature Updates: Deferred for 365 days" -ForegroundColor Green
Write-Host "  ✓ Driver Updates: Disabled" -ForegroundColor Green
Write-Host "  ✓ Auto-Restart: Disabled with logged-on users" -ForegroundColor Green
Write-Host "  ✓ P2P Delivery: Disabled" -ForegroundColor Green
Write-Host ""
Write-Host "What happens now:" -ForegroundColor Cyan
Write-Host "  • Security updates will download and install automatically" -ForegroundColor White
Write-Host "  • Scheduled to install daily at 3:00 AM" -ForegroundColor White
Write-Host "  • Feature updates won't install for 1 year" -ForegroundColor White
Write-Host "  • Your PC won't restart automatically while you're logged in" -ForegroundColor White
Write-Host "  • You can manually check for updates anytime in Settings" -ForegroundColor White
Write-Host ""
Write-Host "To check for updates now:" -ForegroundColor Yellow
Write-Host "  Settings > Windows Update > Check for updates" -ForegroundColor White
Write-Host ""
Write-Host "Press Enter to exit..." -ForegroundColor Yellow
Read-Host
