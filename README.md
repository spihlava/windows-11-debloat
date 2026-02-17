# Windows 11 Debloat & Optimization Script

A comprehensive PowerShell script to remove bloatware and optimize Windows 11 for better performance.

## 🚀 Features

- ✅ **Remove Bloatware** - Removes unnecessary pre-installed apps (Xbox, Bing, Games, etc.)
- ✅ **Disable Startup Programs** - Speeds up boot time by disabling non-essential startup items
- ✅ **Optimize Visual Effects** - Improves performance by reducing animations and visual effects
- ✅ **Clean Temporary Files** - Frees up disk space by removing temp files and caches
- ✅ **Disable Unnecessary Services** - Reduces background processes for better performance
- ✅ **Bonus Optimizations** - Disables telemetry, hibernation, Game DVR, and Windows Search indexing

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

### Method 1: Simple Run (Right-click)
1. Download `Windows-Debloat-Optimize.ps1`
2. Right-click the file
3. Select **"Run with PowerShell"**

### Method 2: Run as Administrator (Recommended)
For full functionality including service optimization:

1. Right-click the Windows Start button
2. Select **"Terminal (Admin)"** or **"PowerShell (Admin)"**
3. Navigate to the script location:
   ```powershell
   cd ~\Desktop
   ```
4. Run the script:
   ```powershell
   .\Windows-Debloat-Optimize.ps1
   ```

### If You Get Execution Policy Error:
Run this command first in PowerShell (Admin):
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
```

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
- **Restart required** after running for all changes to take effect
- **Safe to use** - Only removes bloatware and optimizes settings
- **Reversible** - You can reinstall apps from Microsoft Store or re-enable services
- **Windows Search will be disabled** - File search will be slower, but system performance improves

## 🔄 Reversing Changes

If you need to undo any changes:

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

## 🛡️ Safety

This script:
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
