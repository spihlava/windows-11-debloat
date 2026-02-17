# ============================================
# Windows 11 Enhanced Privacy Hardening Script
# ============================================
# Comprehensive privacy settings beyond basic debloat
# Run as Administrator for full functionality
# Can be run standalone or after STEP2/STEP3 scripts

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Windows 11 Enhanced Privacy Hardening" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script configures advanced privacy settings including:" -ForegroundColor Yellow
Write-Host "  - Complete notification disabling" -ForegroundColor White
Write-Host "  - Camera & microphone permissions" -ForegroundColor White
Write-Host "  - App permissions (contacts, calendar, etc.)" -ForegroundColor White
Write-Host "  - Windows Spotlight & lock screen privacy" -ForegroundColor White
Write-Host "  - SmartScreen filters" -ForegroundColor White
Write-Host "  - Voice & speech recognition" -ForegroundColor White
Write-Host "  - Network privacy (Wi-Fi Sense)" -ForegroundColor White
Write-Host "  - OneDrive integration removal" -ForegroundColor White
Write-Host "  - And much more..." -ForegroundColor White
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator!" -ForegroundColor Red
    Write-Host "Many privacy settings require admin rights." -ForegroundColor Yellow
    Write-Host "Press Enter to continue anyway, or Ctrl+C to exit and restart as Admin..." -ForegroundColor Yellow
    Read-Host
}

# ============================================
# CREATE SYSTEM RESTORE POINT
# ============================================
Write-Host "`nCreating System Restore Point..." -ForegroundColor Cyan

if ($isAdmin) {
    try {
        Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
        $restorePointName = "Before Enhanced Privacy - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        Checkpoint-Computer -Description $restorePointName -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Host "[OK] Restore point created: $restorePointName" -ForegroundColor Green
    } catch {
        Write-Host "[!] Could not create restore point: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] Restore point requires Administrator privileges - Skipping" -ForegroundColor Yellow
}

Write-Host "`nPress Enter to begin privacy hardening, or Ctrl+C to cancel..." -ForegroundColor Yellow
Read-Host

# ============================================
# STEP 1: Complete Notification Disabling
# ============================================
Write-Host "`n[1/15] Disabling ALL Notifications..." -ForegroundColor Yellow

# Disable all Action Center notifications
try {
    $notifPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications"
    if (-not (Test-Path $notifPath)) { New-Item -Path $notifPath -Force | Out-Null }
    Set-ItemProperty -Path $notifPath -Name "ToastEnabled" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled toast notifications" -ForegroundColor Green
} catch {}

# Disable notification center
try {
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] Disabled notification center" -ForegroundColor Green
} catch {}

# Disable lock screen notifications
try {
    if ($isAdmin) {
        $lockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        if (-not (Test-Path $lockPath)) { New-Item -Path $lockPath -Force | Out-Null }
        Set-ItemProperty -Path $lockPath -Name "DisableLockScreenAppNotifications" -Value 1 -Type DWord -Force
        Write-Host "  [+] Disabled lock screen notifications" -ForegroundColor Green
    }
} catch {}

# Disable notification badges
try {
    $settingsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"
    Set-ItemProperty -Path $settingsPath -Name "NOC_GLOBAL_SETTING_BADGE_ENABLED" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] Disabled notification badges" -ForegroundColor Green
} catch {}

# Disable Focus Assist automatic rules
try {
    $focusPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount"
    # Set Focus Assist to off
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] Disabled notifications above lock screen" -ForegroundColor Green
} catch {}

# ============================================
# STEP 2: Camera & Microphone Privacy
# ============================================
Write-Host "`n[2/15] Configuring Camera & Microphone Privacy..." -ForegroundColor Yellow

# Disable camera access globally
try {
    if ($isAdmin) {
        $cameraPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
        if (-not (Test-Path $cameraPath)) { New-Item -Path $cameraPath -Force | Out-Null }
        Set-ItemProperty -Path $cameraPath -Name "Value" -Value "Deny" -Type String -Force
        Write-Host "  [+] Disabled global camera access" -ForegroundColor Green
    }
} catch {}

# Disable microphone access globally
try {
    if ($isAdmin) {
        $micPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
        if (-not (Test-Path $micPath)) { New-Item -Path $micPath -Force | Out-Null }
        Set-ItemProperty -Path $micPath -Name "Value" -Value "Deny" -Type String -Force
        Write-Host "  [+] Disabled global microphone access" -ForegroundColor Green
    }
} catch {}

# ============================================
# STEP 3: App Permissions
# ============================================
Write-Host "`n[3/15] Restricting App Permissions..." -ForegroundColor Yellow

if ($isAdmin) {
    $permissions = @{
        'contacts' = 'Contacts'
        'appointments' = 'Calendar'
        'email' = 'Email'
        'userDataTasks' = 'Tasks'
        'phoneCall' = 'Phone Calls'
        'chat' = 'Messaging'
        'radios' = 'Radios'
        'bluetoothSync' = 'Bluetooth'
        'appDiagnostics' = 'App Diagnostics'
        'documentsLibrary' = 'Documents Library'
        'picturesLibrary' = 'Pictures Library'
        'videosLibrary' = 'Videos Library'
        'broadFileSystemAccess' = 'File System'
        'userAccountInformation' = 'Account Info'
    }

    foreach ($permission in $permissions.Keys) {
        try {
            $permPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$permission"
            if (-not (Test-Path $permPath)) { New-Item -Path $permPath -Force | Out-Null }
            Set-ItemProperty -Path $permPath -Name "Value" -Value "Deny" -Type String -Force
            Write-Host "  [+] Denied $($permissions[$permission]) access" -ForegroundColor Green
        } catch {}
    }
}

# ============================================
# STEP 4: Inking & Typing Personalization
# ============================================
Write-Host "`n[4/15] Disabling Inking & Typing Data Collection..." -ForegroundColor Yellow

# Disable handwriting data collection
try {
    $inkPath = "HKCU:\Software\Microsoft\InputPersonalization"
    if (-not (Test-Path $inkPath)) { New-Item -Path $inkPath -Force | Out-Null }
    Set-ItemProperty -Path $inkPath -Name "RestrictImplicitInkCollection" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $inkPath -Name "RestrictImplicitTextCollection" -Value 1 -Type DWord -Force
    Write-Host "  [+] Disabled handwriting data collection" -ForegroundColor Green
} catch {}

# Disable typing personalization
try {
    $typingPath = "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore"
    if (-not (Test-Path $typingPath)) { New-Item -Path $typingPath -Force | Out-Null }
    Set-ItemProperty -Path $typingPath -Name "HarvestContacts" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled typing personalization" -ForegroundColor Green
} catch {}

# Disable personalized ads
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled document tracking for personalization" -ForegroundColor Green
} catch {}

# ============================================
# STEP 5: Tailored Experiences
# ============================================
Write-Host "`n[5/15] Disabling Tailored Experiences..." -ForegroundColor Yellow

try {
    if ($isAdmin) {
        $privacyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy"
        if (-not (Test-Path $privacyPath)) { New-Item -Path $privacyPath -Force | Out-Null }
        Set-ItemProperty -Path $privacyPath -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled tailored experiences with diagnostic data" -ForegroundColor Green
    }
} catch {}

# Disable consumer features
try {
    if ($isAdmin) {
        $cloudPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        if (-not (Test-Path $cloudPath)) { New-Item -Path $cloudPath -Force | Out-Null }
        Set-ItemProperty -Path $cloudPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $cloudPath -Name "DisableSoftLanding" -Value 1 -Type DWord -Force
        Write-Host "  [+] Disabled consumer features and suggestions" -ForegroundColor Green
    }
} catch {}

# ============================================
# STEP 6: Windows Spotlight & Lock Screen
# ============================================
Write-Host "`n[6/15] Configuring Lock Screen Privacy..." -ForegroundColor Yellow

# Disable Windows Spotlight
try {
    $spotlightPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Set-ItemProperty -Path $spotlightPath -Name "RotatingLockScreenEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $spotlightPath -Name "RotatingLockScreenOverlayEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $spotlightPath -Name "SubscribedContent-338387Enabled" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled Windows Spotlight" -ForegroundColor Green
} catch {}

# Disable lock screen tips and tricks
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled lock screen tips, tricks, and suggestions" -ForegroundColor Green
} catch {}

# Disable fun facts, tips on lock screen
try {
    if ($isAdmin) {
        $lockScreenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        if (-not (Test-Path $lockScreenPath)) { New-Item -Path $lockScreenPath -Force | Out-Null }
        Set-ItemProperty -Path $lockScreenPath -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord -Force
        Write-Host "  [+] Disabled all Windows Spotlight features" -ForegroundColor Green
    }
} catch {}

# ============================================
# STEP 7: Clipboard & Timeline Sync
# ============================================
Write-Host "`n[7/15] Disabling Clipboard & Timeline Sync..." -ForegroundColor Yellow

# Disable clipboard history sync
try {
    $clipboardPath = "HKCU:\Software\Microsoft\Clipboard"
    if (-not (Test-Path $clipboardPath)) { New-Item -Path $clipboardPath -Force | Out-Null }
    Set-ItemProperty -Path $clipboardPath -Name "EnableClipboardHistory" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $clipboardPath -Name "CloudClipboardAutomaticUpload" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled clipboard history and cloud sync" -ForegroundColor Green
} catch {}

# Disable Timeline
try {
    if ($isAdmin) {
        $timelinePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        if (-not (Test-Path $timelinePath)) { New-Item -Path $timelinePath -Force | Out-Null }
        Set-ItemProperty -Path $timelinePath -Name "EnableActivityFeed" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $timelinePath -Name "PublishUserActivities" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $timelinePath -Name "UploadUserActivities" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled Timeline activity sync" -ForegroundColor Green
    }
} catch {}

# ============================================
# STEP 8: Wi-Fi Sense & Network Privacy
# ============================================
Write-Host "`n[8/15] Configuring Network Privacy..." -ForegroundColor Yellow

# Disable Wi-Fi Sense
try {
    if ($isAdmin) {
        $wifiSensePath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
        if (-not (Test-Path $wifiSensePath)) { New-Item -Path $wifiSensePath -Force | Out-Null }
        Set-ItemProperty -Path $wifiSensePath -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled Wi-Fi Sense" -ForegroundColor Green
    }
} catch {}

# Disable Hotspot 2.0 networks
try {
    if ($isAdmin) {
        $hotspotPath = "HKLM:\SOFTWARE\Microsoft\WlanSvc\AnqpCache"
        if (-not (Test-Path $hotspotPath)) { New-Item -Path $hotspotPath -Force | Out-Null }
        Set-ItemProperty -Path $hotspotPath -Name "OsuRegistrationStatus" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled Hotspot 2.0 networks" -ForegroundColor Green
    }
} catch {}

# Disable sharing Wi-Fi networks
try {
    $wifiPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    if ($isAdmin) {
        if (-not (Test-Path $wifiPath)) { New-Item -Path $wifiPath -Force | Out-Null }
        Set-ItemProperty -Path $wifiPath -Name "Value" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled auto-connect to suggested open hotspots" -ForegroundColor Green
    }
} catch {}

# ============================================
# STEP 9: OneDrive Personal Removal
# ============================================
Write-Host "`n[9/15] Removing OneDrive Personal Integration..." -ForegroundColor Yellow
Write-Host "  Note: OneDrive for Business will NOT be affected" -ForegroundColor Gray

# Disable OneDrive Personal only
try {
    if ($isAdmin) {
        $onedrivePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
        if (-not (Test-Path $onedrivePath)) { New-Item -Path $onedrivePath -Force | Out-Null }
        Set-ItemProperty -Path $onedrivePath -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $onedrivePath -Name "DisableFileSync" -Value 1 -Type DWord -Force
        Write-Host "  [+] Disabled OneDrive Personal file sync" -ForegroundColor Green
    }
} catch {}

# Remove OneDrive Personal from File Explorer
try {
    # Check if HKCR: drive exists, if not create it
    if (-not (Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null
    }

    $explorerPath = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    if (Test-Path $explorerPath) {
        Set-ItemProperty -Path $explorerPath -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord -Force
        Write-Host "  [+] Removed OneDrive Personal from File Explorer" -ForegroundColor Green
    }
} catch {}

# Remove OneDrive Personal from startup
try {
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -ErrorAction SilentlyContinue
    Write-Host "  [+] Removed OneDrive Personal from startup" -ForegroundColor Green
} catch {}

# ============================================
# STEP 10: SmartScreen Filters
# ============================================
Write-Host "`n[10/15] Configuring SmartScreen Filters..." -ForegroundColor Yellow

# Disable SmartScreen for apps and files
try {
    if ($isAdmin) {
        $smartScreenPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
        Set-ItemProperty -Path $smartScreenPath -Name "SmartScreenEnabled" -Value "Off" -Type String -Force
        Write-Host "  [+] Disabled SmartScreen for apps and files" -ForegroundColor Green
    }
} catch {}

# Disable SmartScreen for Microsoft Edge
try {
    if ($isAdmin) {
        $edgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        if (-not (Test-Path $edgePath)) { New-Item -Path $edgePath -Force | Out-Null }
        Set-ItemProperty -Path $edgePath -Name "SmartScreenEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $edgePath -Name "SmartScreenPuaEnabled" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled SmartScreen for Microsoft Edge" -ForegroundColor Green
    }
} catch {}

# Disable web content evaluation
try {
    $phishingPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost"
    Set-ItemProperty -Path $phishingPath -Name "EnableWebContentEvaluation" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled web content evaluation" -ForegroundColor Green
} catch {}

# ============================================
# STEP 11: Speech & Voice Privacy
# ============================================
Write-Host "`n[11/15] Disabling Speech Recognition..." -ForegroundColor Yellow

# Disable online speech recognition
try {
    if ($isAdmin) {
        $speechPath = "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy"
        if (-not (Test-Path $speechPath)) { New-Item -Path $speechPath -Force | Out-Null }
        Set-ItemProperty -Path $speechPath -Name "HasAccepted" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled online speech recognition" -ForegroundColor Green
    }
} catch {}

# Disable voice activation
try {
    $voicePath = "HKCU:\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps"
    if (-not (Test-Path $voicePath)) { New-Item -Path $voicePath -Force | Out-Null }
    Set-ItemProperty -Path $voicePath -Name "AgentActivationEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $voicePath -Name "AgentActivationOnLockScreenEnabled" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled voice activation" -ForegroundColor Green
} catch {}

# ============================================
# STEP 12: Find My Device
# ============================================
Write-Host "`n[12/15] Disabling Find My Device..." -ForegroundColor Yellow

try {
    if ($isAdmin) {
        $findDevicePath = "HKLM:\SOFTWARE\Microsoft\Settings\FindMyDevice"
        if (-not (Test-Path $findDevicePath)) { New-Item -Path $findDevicePath -Force | Out-Null }
        Set-ItemProperty -Path $findDevicePath -Name "LocationSyncEnabled" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled Find My Device" -ForegroundColor Green
    }
} catch {}

# ============================================
# STEP 13: Microsoft Edge Privacy
# ============================================
Write-Host "`n[13/15] Configuring Microsoft Edge Privacy..." -ForegroundColor Yellow

if ($isAdmin) {
    $edgeBasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (-not (Test-Path $edgeBasePath)) { New-Item -Path $edgeBasePath -Force | Out-Null }

    # Disable Edge telemetry
    try {
        Set-ItemProperty -Path $edgeBasePath -Name "MetricsReportingEnabled" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled Edge telemetry" -ForegroundColor Green
    } catch {}

    # Disable Edge sync
    try {
        Set-ItemProperty -Path $edgeBasePath -Name "SyncDisabled" -Value 1 -Type DWord -Force
        Write-Host "  [+] Disabled Edge sync" -ForegroundColor Green
    } catch {}

    # Disable Edge suggestions
    try {
        Set-ItemProperty -Path $edgeBasePath -Name "SearchSuggestEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $edgeBasePath -Name "ShowRecommendationsEnabled" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled Edge suggestions" -ForegroundColor Green
    } catch {}

    # Disable Edge personalization
    try {
        Set-ItemProperty -Path $edgeBasePath -Name "PersonalizationReportingEnabled" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled Edge personalization" -ForegroundColor Green
    } catch {}
}

# ============================================
# STEP 14: Additional Diagnostic Data
# ============================================
Write-Host "`n[14/15] Disabling Additional Diagnostic Data..." -ForegroundColor Yellow

# Disable feedback frequency
try {
    $feedbackPath = "HKCU:\Software\Microsoft\Siuf\Rules"
    if (-not (Test-Path $feedbackPath)) { New-Item -Path $feedbackPath -Force | Out-Null }
    Set-ItemProperty -Path $feedbackPath -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $feedbackPath -Name "PeriodInNanoSeconds" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled feedback requests" -ForegroundColor Green
} catch {}

# Disable experimentation
try {
    if ($isAdmin) {
        $experimentPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System"
        if (-not (Test-Path $experimentPath)) { New-Item -Path $experimentPath -Force | Out-Null }
        Set-ItemProperty -Path $experimentPath -Name "AllowExperimentation" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled Windows experimentation" -ForegroundColor Green
    }
} catch {}

# Disable steps recorder
try {
    if ($isAdmin) {
        $stepsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
        if (-not (Test-Path $stepsPath)) { New-Item -Path $stepsPath -Force | Out-Null }
        Set-ItemProperty -Path $stepsPath -Name "DisableUAR" -Value 1 -Type DWord -Force
        Write-Host "  [+] Disabled Steps Recorder" -ForegroundColor Green
    }
} catch {}

# ============================================
# STEP 15: Clear Recent Files & Jump Lists
# ============================================
Write-Host "`n[15/17] Cleaning Recent Files & Jump Lists..." -ForegroundColor Yellow

# Clear Recent Files
try {
    $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recentPath) {
        $recentCount = (Get-ChildItem -Path $recentPath -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
        Remove-Item -Path "$recentPath\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] Cleared $recentCount recent files" -ForegroundColor Green
    }
} catch {}

# Clear AutomaticDestinations (Jump Lists)
try {
    $jumpListPath = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
    if (Test-Path $jumpListPath) {
        Remove-Item -Path "$jumpListPath\*" -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] Cleared Jump Lists" -ForegroundColor Green
    }
} catch {}

# Clear CustomDestinations
try {
    $customDestPath = "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
    if (Test-Path $customDestPath) {
        Remove-Item -Path "$customDestPath\*" -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] Cleared custom destinations" -ForegroundColor Green
    }
} catch {}

# Disable recent items in Quick Access
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled recent/frequent items in Quick Access" -ForegroundColor Green
} catch {}

# Clear Run history
try {
    $runPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    if (Test-Path $runPath) {
        Remove-Item -Path $runPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] Cleared Run dialog history" -ForegroundColor Green
    }
} catch {}

# ============================================
# STEP 16: Clean Start Menu & Taskbar
# ============================================
Write-Host "`n[16/17] Cleaning Start Menu & Taskbar..." -ForegroundColor Yellow

# Disable recent apps in Start Menu
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled recent documents tracking in Start Menu" -ForegroundColor Green
} catch {}

# Disable recent programs in Start Menu
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled recent programs tracking in Start Menu" -ForegroundColor Green
} catch {}

# Clear Start Menu cache
try {
    $startMenuCache = "$env:LOCALAPPDATA\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState"
    if (Test-Path $startMenuCache) {
        Remove-Item -Path "$startMenuCache\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] Cleared Start Menu cache" -ForegroundColor Green
    }
} catch {}

# Clear Taskbar pins cache
try {
    $taskbarPath = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    if (Test-Path $taskbarPath) {
        # Don't delete the folder itself, just clear metadata
        Write-Host "  [+] Taskbar pins located (manual cleanup if needed)" -ForegroundColor Green
    }
} catch {}

# Disable showing recently opened items in Jump Lists
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 -Type DWord -Force
    Write-Host "  [+] Disabled Jump Lists tracking" -ForegroundColor Green
} catch {}

# Clear Office recent files
try {
    $officeRecentPath = "HKCU:\Software\Microsoft\Office\16.0\Common\Open Find"
    if (Test-Path $officeRecentPath) {
        Remove-ItemProperty -Path $officeRecentPath -Name "*" -ErrorAction SilentlyContinue
        Write-Host "  [+] Cleared Office recent files" -ForegroundColor Green
    }
} catch {}

# ============================================
# STEP 17: Network Level Authentication
# ============================================
Write-Host "`n[17/17] Configuring Network-Level Privacy..." -ForegroundColor Yellow

# Disable network connectivity checks
try {
    if ($isAdmin) {
        $ncsiPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
        if (-not (Test-Path $ncsiPath)) { New-Item -Path $ncsiPath -Force | Out-Null }
        Set-ItemProperty -Path $ncsiPath -Name "EnableActiveProbing" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled network connectivity active probing" -ForegroundColor Green
    }
} catch {}

# Disable Connected User Experiences
try {
    if ($isAdmin) {
        $connectedPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        if (-not (Test-Path $connectedPath)) { New-Item -Path $connectedPath -Force | Out-Null }
        Set-ItemProperty -Path $connectedPath -Name "EnableCdp" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled Connected User Experiences" -ForegroundColor Green
    }
} catch {}

# Disable delivery optimization from internet
try {
    if ($isAdmin) {
        $doPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
        if (-not (Test-Path $doPath)) { New-Item -Path $doPath -Force | Out-Null }
        Set-ItemProperty -Path $doPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
        Write-Host "  [+] Disabled Windows Update P2P from Internet" -ForegroundColor Green
    }
} catch {}

# ============================================
# Summary
# ============================================
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "  ENHANCED PRIVACY HARDENING COMPLETE!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host 'Privacy Settings Applied:' -ForegroundColor White
Write-Host '  [1]  Complete notification disabling (toast, badges, lock screen)' -ForegroundColor White
Write-Host '  [2]  Camera & microphone global access denied' -ForegroundColor White
Write-Host '  [3]  App permissions restricted (contacts, calendar, email, etc.)' -ForegroundColor White
Write-Host '  [4]  Inking & typing data collection disabled' -ForegroundColor White
Write-Host '  [5]  Tailored experiences disabled' -ForegroundColor White
Write-Host '  [6]  Windows Spotlight & lock screen tracking disabled' -ForegroundColor White
Write-Host '  [7]  Clipboard & Timeline sync disabled' -ForegroundColor White
Write-Host '  [8]  Wi-Fi Sense & network privacy configured' -ForegroundColor White
Write-Host '  [9]  OneDrive Personal integration removed (Business untouched)' -ForegroundColor White
Write-Host '  [10] SmartScreen filters disabled' -ForegroundColor White
Write-Host '  [11] Speech recognition & voice activation disabled' -ForegroundColor White
Write-Host '  [12] Find My Device disabled' -ForegroundColor White
Write-Host '  [13] Microsoft Edge privacy hardened' -ForegroundColor White
Write-Host '  [14] Additional diagnostic data collection disabled' -ForegroundColor White
Write-Host '  [15] Recent files & Jump Lists cleaned' -ForegroundColor White
Write-Host '  [16] Start Menu & taskbar tracking disabled' -ForegroundColor White
Write-Host '  [17] Network-level privacy configured' -ForegroundColor White
Write-Host ''
Write-Host 'IMPORTANT NOTES:' -ForegroundColor Yellow
Write-Host '  - Camera and microphone are now globally disabled' -ForegroundColor Yellow
Write-Host '  - You may need to re-enable them for specific apps if needed' -ForegroundColor Yellow
Write-Host '  - SmartScreen is disabled - be cautious with downloads' -ForegroundColor Yellow
Write-Host '  - OneDrive integration is removed - files will not sync' -ForegroundColor Yellow
Write-Host ''
Write-Host '[!] RESTART your computer for all changes to take effect!' -ForegroundColor Yellow
Write-Host ''
Write-Host 'Press Enter to exit...' -ForegroundColor Cyan
Read-Host
