# ============================================
# Windows Update Configuration Verification
# ============================================
# Shows current Windows Update configuration
# No changes made - read-only verification

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Windows Update Configuration Checker" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# ============================================
# Check Windows Update Services
# ============================================
Write-Host "[1] Windows Update Services Status:" -ForegroundColor Yellow
Write-Host ""

$services = @{
    'wuauserv' = 'Windows Update'
    'WaaSMedicSvc' = 'Windows Update Medic'
    'UsoSvc' = 'Update Orchestrator'
    'BITS' = 'Background Intelligent Transfer'
}

foreach ($svc in $services.GetEnumerator()) {
    $service = Get-Service -Name $svc.Key -ErrorAction SilentlyContinue
    if ($service) {
        $status = $service.Status
        $startup = $service.StartType
        $color = if ($startup -eq 'Disabled') { 'Red' } else { 'Green' }
        Write-Host "  $($svc.Value):" -ForegroundColor White
        Write-Host "    Status: $status | Startup: $startup" -ForegroundColor $color
    }
}

# ============================================
# Check Registry Settings
# ============================================
Write-Host ""
Write-Host "[2] Windows Update Policy Settings:" -ForegroundColor Yellow
Write-Host ""

$wuPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$wuAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

# Check Feature Update Deferral
if (Test-Path $wuPolicyPath) {
    $deferFeature = Get-ItemProperty -Path $wuPolicyPath -Name "DeferFeatureUpdates" -ErrorAction SilentlyContinue
    $deferDays = Get-ItemProperty -Path $wuPolicyPath -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
    $branchLevel = Get-ItemProperty -Path $wuPolicyPath -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue

    Write-Host "  Feature Updates:" -ForegroundColor White
    if ($deferFeature.DeferFeatureUpdates -eq 1) {
        Write-Host "    Status: DEFERRED for $($deferDays.DeferFeatureUpdatesPeriodInDays) days" -ForegroundColor Green
        Write-Host "    This means: Only security updates will install" -ForegroundColor Cyan
    } else {
        Write-Host "    Status: NOT DEFERRED (feature updates will install)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Feature Updates: NOT CONFIGURED (default Windows behavior)" -ForegroundColor Yellow
}

Write-Host ""

# Check Automatic Update Configuration
if (Test-Path $wuAUPath) {
    $auOptions = Get-ItemProperty -Path $wuAUPath -Name "AUOptions" -ErrorAction SilentlyContinue
    $schedDay = Get-ItemProperty -Path $wuAUPath -Name "ScheduledInstallDay" -ErrorAction SilentlyContinue
    $schedTime = Get-ItemProperty -Path $wuAUPath -Name "ScheduledInstallTime" -ErrorAction SilentlyContinue

    Write-Host "  Automatic Updates:" -ForegroundColor White
    if ($auOptions) {
        switch ($auOptions.AUOptions) {
            2 { Write-Host "    Notify before download" -ForegroundColor Cyan }
            3 { Write-Host "    Auto download, notify before install" -ForegroundColor Cyan }
            4 {
                Write-Host "    Auto download and schedule install" -ForegroundColor Green
                $dayText = if ($schedDay.ScheduledInstallDay -eq 0) { "Every day" } else { "Day $($schedDay.ScheduledInstallDay)" }
                Write-Host "    Schedule: $dayText at $($schedTime.ScheduledInstallTime):00" -ForegroundColor Green
            }
            5 { Write-Host "    Allow local admin to choose" -ForegroundColor Cyan }
            default { Write-Host "    Custom configuration" -ForegroundColor Cyan }
        }
    }

    $noReboot = Get-ItemProperty -Path $wuAUPath -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
    if ($noReboot.NoAutoRebootWithLoggedOnUsers -eq 1) {
        Write-Host "    Auto-restart: DISABLED with logged-on users" -ForegroundColor Green
    }
}

Write-Host ""

# Check Driver Updates
$excludeDrivers = Get-ItemProperty -Path $wuPolicyPath -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
Write-Host "  Driver Updates:" -ForegroundColor White
if ($excludeDrivers.ExcludeWUDriversInQualityUpdate -eq 1) {
    Write-Host "    Status: DISABLED (drivers won't update)" -ForegroundColor Yellow
} else {
    Write-Host "    Status: ENABLED (drivers will update)" -ForegroundColor Green
}

Write-Host ""

# Check P2P Delivery
$deliveryOptPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
$doMode = Get-ItemProperty -Path $deliveryOptPath -Name "DODownloadMode" -ErrorAction SilentlyContinue
Write-Host "  P2P Update Delivery:" -ForegroundColor White
if ($doMode.DODownloadMode -eq 0) {
    Write-Host "    Status: DISABLED (saves bandwidth)" -ForegroundColor Green
} else {
    Write-Host "    Status: ENABLED" -ForegroundColor Yellow
}

# ============================================
# Summary
# ============================================
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

if ($deferFeature.DeferFeatureUpdates -eq 1) {
    Write-Host "[OK] Security Updates ONLY mode is ACTIVE" -ForegroundColor Green
    Write-Host "     - Security patches will install automatically" -ForegroundColor White
    Write-Host "     - Feature updates deferred for $($deferDays.DeferFeatureUpdatesPeriodInDays) days" -ForegroundColor White
} else {
    Write-Host "[!] Security Updates ONLY mode is NOT configured" -ForegroundColor Yellow
    Write-Host "    Both security and feature updates will install" -ForegroundColor White
}

Write-Host ""
Write-Host "To verify in Windows Settings:" -ForegroundColor Cyan
Write-Host "  1. Open Settings > Windows Update > Advanced options" -ForegroundColor White
Write-Host "  2. Look for 'Feature update' section - should show deferral" -ForegroundColor White
Write-Host "  3. Check 'Optional updates' for driver updates" -ForegroundColor White
Write-Host ""
Write-Host "Press Enter to exit..." -ForegroundColor Yellow
Read-Host
