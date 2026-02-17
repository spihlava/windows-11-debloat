# ============================================
# Windows Settings Review & Audit Script
# ============================================
# This script reviews your current Windows settings and generates a report

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Windows Settings Review & Audit" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

$report = @()
$issues = 0
$optimized = 0

# Function to add to report
function Add-ReportItem {
    param($Category, $Setting, $Current, $Status, $Recommendation)
    $script:report += [PSCustomObject]@{
        Category = $Category
        Setting = $Setting
        Current = $Current
        Status = $Status
        Recommendation = $Recommendation
    }
    if ($Status -eq "NEEDS ATTENTION") { $script:issues++ }
    if ($Status -eq "OPTIMIZED") { $script:optimized++ }
}

Write-Host "[1/10] Checking Privacy Settings..." -ForegroundColor Yellow

# Telemetry
$telemetry = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
if ($telemetry.AllowTelemetry -eq 0) {
    Add-ReportItem "Privacy" "Telemetry" "Disabled" "OPTIMIZED" "Keep disabled"
} else {
    Add-ReportItem "Privacy" "Telemetry" "Enabled" "NEEDS ATTENTION" "Disable for privacy"
}

# Advertising ID
$adId = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -ErrorAction SilentlyContinue
if ($adId.Enabled -eq 0 -or $null -eq $adId) {
    Add-ReportItem "Privacy" "Advertising ID" "Disabled" "OPTIMIZED" "Keep disabled"
} else {
    Add-ReportItem "Privacy" "Advertising ID" "Enabled" "NEEDS ATTENTION" "Disable for privacy"
}

# Location tracking
$location = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -ErrorAction SilentlyContinue
if ($location.Value -eq "Deny") {
    Add-ReportItem "Privacy" "Location Tracking" "Disabled" "OPTIMIZED" "Keep disabled"
} else {
    Add-ReportItem "Privacy" "Location Tracking" "Enabled" "NEEDS ATTENTION" "Disable unless needed"
}

Write-Host "[2/10] Checking Services..." -ForegroundColor Yellow

# Check key services
$servicesToCheck = @{
    'DiagTrack' = 'Diagnostics Tracking'
    'SysMain' = 'Superfetch'
    'WSearch' = 'Windows Search'
    'XblAuthManager' = 'Xbox Live Auth'
    'XboxGipSvc' = 'Xbox Accessory'
}

foreach ($svc in $servicesToCheck.GetEnumerator()) {
    $service = Get-Service -Name $svc.Key -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.StartType -eq 'Disabled') {
            Add-ReportItem "Services" $svc.Value "Disabled" "OPTIMIZED" "Keep disabled"
        } else {
            Add-ReportItem "Services" $svc.Value "$($service.StartType)" "NEEDS ATTENTION" "Consider disabling"
        }
    }
}

Write-Host "[3/10] Checking Startup Programs..." -ForegroundColor Yellow

$startupCount = (Get-CimInstance Win32_StartupCommand | Measure-Object).Count
if ($startupCount -le 5) {
    Add-ReportItem "Performance" "Startup Programs" "$startupCount items" "OPTIMIZED" "Good, keep minimal"
} elseif ($startupCount -le 10) {
    Add-ReportItem "Performance" "Startup Programs" "$startupCount items" "OK" "Consider reducing"
} else {
    Add-ReportItem "Performance" "Startup Programs" "$startupCount items" "NEEDS ATTENTION" "Too many, reduce to speed up boot"
}

Write-Host "[4/10] Checking Visual Effects..." -ForegroundColor Yellow

$visualFX = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -ErrorAction SilentlyContinue
if ($visualFX.VisualFXSetting -eq 2) {
    Add-ReportItem "Performance" "Visual Effects" "Best Performance" "OPTIMIZED" "Keep for best performance"
} else {
    Add-ReportItem "Performance" "Visual Effects" "Default/Custom" "NEEDS ATTENTION" "Set to 'Best Performance'"
}

Write-Host "[5/10] Checking Taskbar Settings..." -ForegroundColor Yellow

# Search box
$searchBox = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -ErrorAction SilentlyContinue
if ($searchBox.SearchboxTaskbarMode -eq 0) {
    Add-ReportItem "UI" "Taskbar Search Box" "Hidden" "OPTIMIZED" "Keep hidden"
} else {
    Add-ReportItem "UI" "Taskbar Search Box" "Visible" "INFO" "Hide to save space"
}

# Widgets
$widgets = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -ErrorAction SilentlyContinue
if ($widgets.TaskbarDa -eq 0) {
    Add-ReportItem "UI" "Taskbar Widgets" "Hidden" "OPTIMIZED" "Keep hidden"
} else {
    Add-ReportItem "UI" "Taskbar Widgets" "Visible" "INFO" "Hide if not used"
}

# Task View
$taskView = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue
if ($taskView.ShowTaskViewButton -eq 0) {
    Add-ReportItem "UI" "Task View Button" "Hidden" "OPTIMIZED" "Keep hidden"
} else {
    Add-ReportItem "UI" "Task View Button" "Visible" "INFO" "Hide if not used"
}

Write-Host "[6/10] Checking File Explorer Settings..." -ForegroundColor Yellow

# File extensions
$fileExt = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -ErrorAction SilentlyContinue
if ($fileExt.HideFileExt -eq 0) {
    Add-ReportItem "File Explorer" "Show File Extensions" "Enabled" "OPTIMIZED" "Keep enabled for security"
} else {
    Add-ReportItem "File Explorer" "Show File Extensions" "Disabled" "NEEDS ATTENTION" "Enable for security"
}

# Hidden files
$hiddenFiles = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -ErrorAction SilentlyContinue
if ($hiddenFiles.Hidden -eq 1) {
    Add-ReportItem "File Explorer" "Show Hidden Files" "Enabled" "OPTIMIZED" "Good for power users"
} else {
    Add-ReportItem "File Explorer" "Show Hidden Files" "Disabled" "INFO" "Enable if you're a power user"
}

Write-Host "[7/10] Checking Windows Update Settings..." -ForegroundColor Yellow

$wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
if ($wuService.StartType -eq 'Manual') {
    Add-ReportItem "Updates" "Windows Update Service" "Manual" "OPTIMIZED" "Manual control"
} elseif ($wuService.StartType -eq 'Disabled') {
    Add-ReportItem "Updates" "Windows Update Service" "Disabled" "WARNING" "Don't disable completely - security risk!"
} else {
    Add-ReportItem "Updates" "Windows Update Service" "Automatic" "INFO" "Consider manual for control"
}

Write-Host "[8/10] Checking Gaming Settings..." -ForegroundColor Yellow

# Game DVR
$gameDVR = Get-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -ErrorAction SilentlyContinue
if ($gameDVR.GameDVR_Enabled -eq 0) {
    Add-ReportItem "Gaming" "Game DVR" "Disabled" "OPTIMIZED" "Keep disabled for performance"
} else {
    Add-ReportItem "Gaming" "Game DVR" "Enabled" "NEEDS ATTENTION" "Disable for better performance"
}

# Game Mode
$gameMode = Get-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -ErrorAction SilentlyContinue
if ($null -ne $gameMode) {
    if ($gameMode.AutoGameModeEnabled -eq 0) {
        Add-ReportItem "Gaming" "Game Mode" "Disabled" "INFO" "Enable if you game regularly"
    } else {
        Add-ReportItem "Gaming" "Game Mode" "Enabled" "INFO" "Disable if you don't game"
    }
}

Write-Host "[9/10] Checking Power Settings..." -ForegroundColor Yellow

$powerPlan = powercfg /getactivescheme
if ($powerPlan -match "High performance" -or $powerPlan -match "Ultimate") {
    Add-ReportItem "Power" "Power Plan" "High Performance" "OPTIMIZED" "Good for performance"
} elseif ($powerPlan -match "Balanced") {
    Add-ReportItem "Power" "Power Plan" "Balanced" "INFO" "Switch to High Performance for desktops"
} else {
    Add-ReportItem "Power" "Power Plan" "Power Saver" "NEEDS ATTENTION" "Switch to High Performance"
}

# Hibernation
$hibStatus = powercfg /a | Select-String "Hibernate"
if ($hibStatus -match "not available") {
    Add-ReportItem "Power" "Hibernation" "Disabled" "OPTIMIZED" "Saves disk space"
} else {
    Add-ReportItem "Power" "Hibernation" "Enabled" "INFO" "Disable to free up disk space"
}

Write-Host "[10/10] Checking System Information..." -ForegroundColor Yellow

# Installed bloatware apps
$bloatware = @('*Xbox*', '*Bing*', '*Solitaire*', '*Candy*', '*MixedReality*', '*SkypeApp*', '*YourPhone*', '*People*', '*OfficeHub*', '*Todos*', '*GetHelp*', '*Feedback*')
$bloatCount = 0
$bloatList = @()
foreach ($app in $bloatware) {
    $found = Get-AppxPackage -Name $app -ErrorAction SilentlyContinue
    if ($found) {
        $bloatCount += ($found | Measure-Object).Count
        $bloatList += $found.Name
    }
}

if ($bloatCount -eq 0) {
    Add-ReportItem "Apps" "Bloatware Apps" "None found" "OPTIMIZED" "Clean system"
} elseif ($bloatCount -le 5) {
    Add-ReportItem "Apps" "Bloatware Apps" "$bloatCount found ($($bloatList -join ', '))" "INFO" "Some bloatware present"
} else {
    Add-ReportItem "Apps" "Bloatware Apps" "$bloatCount found" "NEEDS ATTENTION" "Run debloat script"
}

# Temp files size
$tempSize = 0
try {
    $tempSize = [math]::Round((Get-ChildItem -Path $env:TEMP -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
} catch {}

if ($tempSize -lt 100) {
    Add-ReportItem "Storage" "Temp Files" "$tempSize MB" "OPTIMIZED" "Clean"
} elseif ($tempSize -lt 500) {
    Add-ReportItem "Storage" "Temp Files" "$tempSize MB" "INFO" "Consider cleaning"
} else {
    Add-ReportItem "Storage" "Temp Files" "$tempSize MB" "NEEDS ATTENTION" "Run cleanup script"
}

# Display Report
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "  REVIEW COMPLETE" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Summary:" -ForegroundColor White
Write-Host "  Optimized: $optimized settings" -ForegroundColor Green
Write-Host "  Needs Attention: $issues settings" -ForegroundColor Yellow
Write-Host ""

# Group by category and display
$categories = $report | Group-Object -Property Category
foreach ($category in $categories) {
    Write-Host "`n[$($category.Name)]" -ForegroundColor Cyan
    foreach ($item in $category.Group) {
        $color = switch ($item.Status) {
            "OPTIMIZED" { "Green" }
            "NEEDS ATTENTION" { "Yellow" }
            "WARNING" { "Red" }
            "INFO" { "White" }
            default { "Gray" }
        }
        Write-Host "  $($item.Setting): " -NoNewline -ForegroundColor White
        Write-Host "$($item.Current) " -NoNewline -ForegroundColor $color
        Write-Host "[$($item.Status)]" -ForegroundColor $color
        Write-Host "    -> $($item.Recommendation)" -ForegroundColor DarkGray
    }
}

# Save report to file
$reportPath = "$env:USERPROFILE\Desktop\Windows-Settings-Report.txt"
$report | Format-Table -AutoSize | Out-String | Out-File -FilePath $reportPath
Write-Host "`nFull report saved to: $reportPath" -ForegroundColor Green

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "Press Enter to exit..." -ForegroundColor Cyan
Read-Host
