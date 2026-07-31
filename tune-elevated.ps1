# tune-elevated.ps1 - Windows-side dev-latency tuning. Run ELEVATED.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\bin\tune-elevated.ps1"
#
# Does: restore point -> registry export -> Defender exclusions for the WSL2 and Docker
# VHDX directories -> remove selected startup entries -> disable selected scheduled tasks.
#
# Does NOT touch: Defender itself, VBS, memory integrity, the page file, or any service.
# Aborts before any change if a restore point cannot be created.

$ErrorActionPreference = 'Stop'

# --- Per-machine config. Edit these; everything else is derived. ---------------
# Directories holding WSL2 / Docker Desktop virtual disks. Excluded from real-time
# scanning because the VM rewrites them constantly and Defender cannot see inside anyway.
$ExcludePaths = @(
    "$env:LOCALAPPDATA\wsl"       # WSL2 distro ext4.vhdx
    "$env:LOCALAPPDATA\Docker"    # Docker Desktop docker_data.vhdx
)
$ExcludeProcesses = @('vmmemWSL', 'vmmem', 'wslservice.exe')

# HKCU\...\Run value names to remove. Wildcards allowed (Edge appends a per-install hash).
$RemoveStartup = @(
    'MicrosoftEdgeAutoLaunch_*'
    'Adobe Acrobat Synchronizer'
)

# Scheduled task names to disable. Wildcards allowed. Allow-list only - anything not
# matched here is left alone, so task names you depend on cannot be caught by accident.
$DisableTasks = @(
    'SoftLanding*'                # Windows Spotlight / "creative management" upsells
    'Adobe Acrobat Update Task'
    'NVIDIA App SelfUpdate*'      # updates the NVIDIA App shell, not the driver
    'ZoomUpdateTaskUser*'
)
# ------------------------------------------------------------------------------

$backup = Join-Path $env:USERPROFILE 'bin\backups'
New-Item -ItemType Directory -Force -Path $backup | Out-Null

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Not elevated. Re-run as Administrator.'
}

# --- Restore point. Hard gate: no change happens without one. ------------------
Write-Host '=== [0] System restore point ===' -ForegroundColor Cyan
$before = (Get-ComputerRestorePoint | Select-Object -Last 1).SequenceNumber
try { Checkpoint-Computer -Description 'Pre dev-latency tuning' -RestorePointType MODIFY_SETTINGS }
catch { Write-Warning "Checkpoint-Computer failed: $($_.Exception.Message)" }
$after = (Get-ComputerRestorePoint | Select-Object -Last 1).SequenceNumber

if ($after -eq $before) {
    Write-Warning 'No new restore point was created.'
    Write-Warning 'Either System Protection is off for C:, or the 24h throttle blocked it.'
    Write-Warning 'Fix:  Enable-ComputerRestore -Drive "C:\"   then re-run this script.'
    Write-Warning 'Aborting per guardrail - nothing has been changed.'
    exit 1
}
Write-Host "Restore point created (seq $after)." -ForegroundColor Green

# --- Export every key before modifying it -------------------------------------
Write-Host '=== Registry export ===' -ForegroundColor Cyan
reg export 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' "$backup\HKCU-Run.reg" /y | Out-Null
reg export 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' "$backup\HKLM-Run.reg" /y | Out-Null
reg export 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved' `
    "$backup\HKCU-StartupApproved.reg" /y | Out-Null
Write-Host "Exported to $backup" -ForegroundColor Green

# Record exclusions as they were, so the reversal is exact rather than guessed.
$mp = Get-MpPreference
@{ ExclusionPath      = @($mp.ExclusionPath)
   ExclusionProcess   = @($mp.ExclusionProcess)
   ExclusionExtension = @($mp.ExclusionExtension)
} | ConvertTo-Json | Set-Content "$backup\defender-exclusions-before.json"
Write-Host '--- Defender exclusions BEFORE ---' -ForegroundColor Yellow
'Paths     : ' + (@($mp.ExclusionPath)      -join ', ')
'Processes : ' + (@($mp.ExclusionProcess)   -join ', ')
'Extensions: ' + (@($mp.ExclusionExtension) -join ', ')

# --- Defender exclusions ------------------------------------------------------
Write-Host '=== [1] Defender exclusions ===' -ForegroundColor Cyan
foreach ($p in $ExcludePaths) {
    if (-not (Test-Path $p)) { Write-Host "  path not present yet, adding anyway: $p" -ForegroundColor DarkGray }
    Add-MpPreference -ExclusionPath $p
    Write-Host "  path:    $p" -ForegroundColor Green
}
foreach ($p in $ExcludeProcesses) {
    Add-MpPreference -ExclusionProcess $p
    Write-Host "  process: $p" -ForegroundColor Green
}

# --- Startup entries ----------------------------------------------------------
Write-Host '=== [6] Startup entries ===' -ForegroundColor Cyan
$runKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$present = (Get-Item $runKey).Property
foreach ($pattern in $RemoveStartup) {
    $hits = $present | Where-Object { $_ -like $pattern }
    if (-not $hits) { Write-Host "  no match (skipped): $pattern" -ForegroundColor DarkGray; continue }
    foreach ($name in $hits) {
        Remove-ItemProperty -Path $runKey -Name $name
        Write-Host "  removed: $name" -ForegroundColor Green
    }
}

# --- Scheduled tasks ----------------------------------------------------------
Write-Host '=== [7] Scheduled tasks ===' -ForegroundColor Cyan
$all = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
foreach ($pattern in $DisableTasks) {
    $hits = $all | Where-Object { $_.TaskName -like $pattern }
    if (-not $hits) { Write-Host "  no match (skipped): $pattern" -ForegroundColor DarkGray; continue }
    foreach ($t in $hits) {
        Disable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName | Out-Null
        Write-Host "  disabled: $($t.TaskPath)$($t.TaskName)" -ForegroundColor Green
    }
}

Write-Host ''
Write-Host "Done. Backups in $backup" -ForegroundColor Cyan
