# Windows 11 Optimization Suite

Comprehensive PowerShell scripts to remove bloatware and optimize Windows 11 for maximum performance.

## 🚀 Quick Start

**New here? Read [START-HERE.txt](START-HERE.txt) first!**

### Simple 2-3 Step Process:

1. **Run:** `STEP1-Audit-Windows.ps1` (Review your current settings)
2. **Run:** `STEP2-Optimize-Windows.ps1` (Full optimization - Recommended)
3. **Optional:** `STEP3-Advanced-Process-Reduction.ps1` (AGGRESSIVE - Minimum processes)

Then **restart your computer**. That's it!

---

## 📦 What's Included

### 📋 **STEP1-Audit-Windows.ps1**
**Run this FIRST** to review your current Windows settings.
- ✅ No changes made - just a review
- ✅ Shows what's already optimized
- ✅ Identifies what needs attention
- ✅ Generates a detailed report
- ✅ Checks 10+ categories (privacy, services, startup, etc.)

### ⚡ **STEP2-Optimize-Windows.ps1** (Recommended)
**Full optimization** - Everything you need!
- ✅ 12 optimization categories
- ✅ 30+ bloatware apps removed
- ✅ Privacy & telemetry controls
- ✅ Taskbar & UI customization
- ✅ File Explorer optimization
- ✅ Gaming optimizations
- ✅ Power & performance tweaks
- ✅ And much more!

### 🔧 **STEP2-Optimize-Windows-Basic.ps1** (Alternative)
**Basic optimization** - Just the essentials.
- ✅ Removes bloatware apps
- ✅ Disables startup programs
- ✅ Optimizes visual effects
- ✅ Cleans temporary files
- ✅ Disables some services

**Note:** Only run ONE of the STEP2 scripts (Full or Basic).

### ⚡ **STEP3-Advanced-Process-Reduction.ps1** (Optional - AGGRESSIVE)
**Maximum process reduction** - For advanced users who want absolute minimum processes.
- ⚠️ **VERY AGGRESSIVE** - Disables many services and features
- ✅ Disables 50+ additional services (bluetooth, remote access, updates, sync, etc.)
- ✅ **Keeps printing enabled** - Print Spooler and print services remain active
- ✅ Disables 25+ scheduled tasks (telemetry, diagnostics, maintenance)
- ✅ Disables Windows features (Media Player, SMB1, IE11)
- ✅ Advanced registry tweaks for background apps
- ✅ Targets reducing process count to minimum
- ⚠️ May affect some functionality - only use if you know what you need

**Run this AFTER STEP2 and ONLY if you want extreme optimization.**
**Target: Reduce from 270+ processes to 150-180 processes.**

## 🎯 Which Script Should I Use?

| Feature | Basic | **Ultimate** | **Advanced** | Audit |
|---------|-------|------------|------------|-------|
| Remove bloatware | ✅ | ✅ | - | - |
| Disable startup programs | ✅ | ✅ | - | - |
| Visual effects | ✅ | ✅ | - | - |
| Clean temp files | ✅ | ✅ | - | - |
| Disable services (14) | ✅ | ✅ | - | - |
| Privacy & telemetry | Partial | ✅ Full | ✅ | - |
| Notifications | ❌ | ✅ | ✅ | - |
| Taskbar customization | ❌ | ✅ | - | - |
| File Explorer tweaks | ❌ | ✅ | - | - |
| Cortana/Bing disable | ❌ | ✅ | - | - |
| Gaming optimizations | Partial | ✅ Full | ✅ | - |
| Power plan optimization | ❌ | ✅ | - | - |
| Background apps | ❌ | ✅ | ✅ Full | - |
| Additional services (50+) | ❌ | ❌ | ✅ | - |
| Scheduled tasks (25+) | ❌ | ❌ | ✅ | - |
| Windows features | ❌ | ❌ | ✅ | - |
| Process reduction | ❌ | ❌ | ✅ Max | - |
| Settings audit | - | - | - | ✅ |

**Recommendations:**
- **Most users:** STEP2 Ultimate Optimizer
- **Maximum performance:** STEP2 + STEP3 Advanced (warning: very aggressive!)

## 🚀 Features (Ultimate Optimizer)

### Core Features:
- ✅ **Remove Bloatware** - Removes 30+ unnecessary apps (Xbox, Bing, Games, Office Hub, etc.)
- ✅ **Disable Startup Programs** - Speeds up boot time
- ✅ **Clean Temporary Files** - Frees up disk space
- ✅ **Disable Unnecessary Services** - 14+ services including Xbox, telemetry, Superfetch

### Privacy & Security:
- ✅ **Disable Telemetry** - Stops data collection
- ✅ **Disable Location Tracking** - Enhanced privacy
- ✅ **Disable Activity History** - No timeline tracking
- ✅ **Disable Advertising ID** - No personalized ads
- ✅ **Show File Extensions** - Security best practice

### Performance:
- ✅ **Optimize Visual Effects** - Best performance mode
- ✅ **High Performance Power Plan** - Maximum speed
- ✅ **Disable Hibernation** - Frees 8-16 GB disk space
- ✅ **Disable Background Apps** - Less RAM usage
- ✅ **Disable Superfetch** - Better for SSDs

### UI Customization:
- ✅ **Clean Taskbar** - Hide search, widgets, task view, chat, Copilot
- ✅ **Disable Notifications** - No sounds or suggestions
- ✅ **Optimize File Explorer** - Show hidden files, extensions, no ads
- ✅ **Disable Cortana** - No voice assistant
- ✅ **Disable Bing Search** - Faster local search

### Gaming:
- ✅ **Disable Game DVR** - Better FPS
- ✅ **Disable Game Bar** - No overlays
- ✅ **Disable Xbox Services** - Free up resources

### Network & Updates:
- ✅ **Disable P2P Updates** - Save bandwidth
- ✅ **Manual Windows Update** - Full control

## 📋 What Gets Removed

### Apps Removed:
- Bing Weather & Bing Search
- Microsoft Solitaire Collection
- All Xbox gaming apps (Xbox, Game Bar, Game DVR)
- Mixed Reality Portal
- 3D Viewer
- Skype
- Your Phone / Phone Link
- People app
- Microsoft To Do
- Sticky Notes
- Maps, Camera, Sound Recorder
- Windows Feedback Hub
- Office Hub, OneNote (UWP), Outlook (new version)

### Apps Kept (Essential):
- Microsoft Edge
- Microsoft Store
- Windows Terminal
- Notepad, Calculator, Paint, Photos
- File Explorer, Settings
- All core system components

### Startup Programs Disabled:
- Adobe Acrobat Synchronizer
- Slack auto-start
- Microsoft Teams auto-start
- Logitech utilities
- Spotify auto-start
- Discord auto-start

### Services Disabled:
- Xbox Live services (4 services)
- Superfetch (SysMain) - can slow down SSDs
- Diagnostics Tracking (telemetry)
- Windows Error Reporting
- Windows Search indexing
- Remote Registry & Remote Access
- And more...

## 🔧 How to Use

### 📍 Step 1: Audit Your System
```powershell
.\STEP1-Audit-Windows.ps1
```
- Reviews your current settings (no changes made)
- Generates a report on your Desktop
- Shows what needs optimization

### ⚡ Step 2: Optimize Windows
Choose ONE:

**Full Optimization (Recommended):**
```powershell
.\STEP2-Optimize-Windows.ps1
```

**Basic Optimization:**
```powershell
.\STEP2-Optimize-Windows-Basic.ps1
```

### 🚀 Step 3: Advanced Process Reduction (Optional)
**Only for advanced users wanting minimum processes:**
```powershell
.\STEP3-Advanced-Process-Reduction.ps1
```
- Run AFTER Step 2
- Very aggressive optimization
- Targets 150-180 process count
- **Printing remains enabled**
- May disable other features (bluetooth, remote access, updates, etc.)

### 🔐 Running as Administrator (Recommended)

For full functionality:

1. Right-click the **Start button**
2. Select **"Terminal (Admin)"** or **"PowerShell (Admin)"**
3. Navigate to the folder:
   ```powershell
   cd C:\Users\Sakari\Projects\bloatware
   ```
4. Run the scripts:
   ```powershell
   .\STEP1-Audit-Windows.ps1
   .\STEP2-Optimize-Windows.ps1
   ```
5. **Restart your computer**

### If You Get Execution Policy Error:

**This is common on new Windows installations.** PowerShell blocks script execution by default.

**From PowerShell (Admin):**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**From bash/Git Bash:**
```bash
powershell.exe -Command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser"
```

**Execution Policy Options:**
- `RemoteSigned` (Recommended) - Allows local scripts, requires signature for downloaded scripts
- `Bypass` - No restrictions (use if RemoteSigned doesn't work)
- `Unrestricted` - Prompts before running unsigned downloaded scripts

**Note:** `-Scope CurrentUser` means no admin privileges required and only affects your user account.

## ⚡ Performance Improvements

After running this script, you can expect:
- **Faster boot time** - Fewer startup programs
- **Snappier UI** - Visual effects reduced
- **More free disk space** - Temp files cleaned, hibernation disabled
- **Fewer background processes** - Unnecessary services disabled
- **Better SSD performance** - Superfetch disabled
- **Reduced telemetry** - Less data sent to Microsoft

## ⚠️ Important Notes

- **Administrator privileges required** for full functionality (especially service optimization)
- **Automatic System Restore Point** - Each script creates a restore point before making changes
- **Restart required** after running for all changes to take effect
- **Safe to use** - Only removes bloatware and optimizes settings
- **Reversible** - You can use System Restore or manually reinstall apps/re-enable services
- **Windows Search will be disabled** - File search will be slower, but system performance improves

## 🔄 Reversing Changes

If you need to undo any changes:

### Option 1: System Restore (Recommended)
1. Press `Win + R`
2. Type `rstrui.exe` and press Enter
3. Select the restore point created before optimization
4. Follow the wizard to restore your system

### Option 2: Manual Reversal

### Reinstall Apps:
- Open Microsoft Store
- Search for the app you want
- Click "Install"

### Re-enable Services:
1. Press `Win + R`
2. Type `services.msc` and press Enter
3. Find the service, right-click, select Properties
4. Change Startup type to "Automatic" or "Manual"
5. Click "Start" to start the service

### Reset Visual Effects:
1. Press `Win + R`
2. Type `sysdm.cpl` and press Enter
3. Go to "Advanced" tab
4. Click "Settings" under Performance
5. Select "Let Windows choose what's best for my computer"

## 📊 Tested On

- ✅ Windows 11 Pro (Build 26100)
- ✅ Windows 11 Home
- ✅ Clean installs and upgraded systems
- ✅ Windows PowerShell 5.x and PowerShell 7+

## 🛡️ Safety

This script:
- ✅ **Automatically creates System Restore Point** before making any changes
- ✅ Only removes bloatware, not system components
- ✅ Uses safe PowerShell commands
- ✅ Includes error handling
- ✅ Can be run multiple times safely
- ✅ Does not require external dependencies
- ✅ Does not download or install anything

## 📝 What the Script Does (Technical)

1. **Removes AppX packages** matching bloatware patterns
2. **Modifies registry keys** to disable startup programs and visual effects
3. **Stops and disables services** that aren't needed for most users
4. **Deletes temporary files** from user and system temp folders
5. **Clears Windows Update cache** to free up space
6. **Disables hibernation** using `powercfg.exe`
7. **Modifies registry** to disable Game DVR and telemetry

## 🤝 Contributing

Feel free to open issues or submit pull requests if you have suggestions for improvements!

## ⚖️ License

This script is provided as-is for personal use. Use at your own risk.

## 🙏 Credits

Created to help users reclaim performance and disk space on Windows 11.

---

**⚠️ Remember to restart your computer after running the script!**

**Last Updated:** February 2026
