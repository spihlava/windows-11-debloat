# windows-11-debloat

Windows 11 tuning for a WSL2 + Docker development workstation. Two scripts and an audit
method. No registry blasting, no service purges, no "disable Defender for FPS" nonsense.

The premise: on a dev box, almost all OS-induced latency comes from a small number of
real sources — antivirus real-time scanning of the WSL virtual disk, the content indexer
crawling build output, a memory cap that throttles the VM, and package caches sitting on
the slowest available volume. Everything else marketed as a "debloat tweak" is noise.

**Audit before you change anything.** On the machine this was built for, three of the five
changes originally planned turned out to be no-ops — see [Findings that changed the plan](#findings-that-changed-the-plan).

## Contents

| File | What it is |
|---|---|
| [`tune-elevated.ps1`](tune-elevated.ps1) | Windows side. Restore point, registry export, Defender exclusions for WSL/Docker VHDX dirs, selected startup + scheduled task removals. Needs elevation. |
| [`post-reboot-wsl-tune.sh`](post-reboot-wsl-tune.sh) | WSL side. Moves npm/pip/uv caches off the distro VHDX onto a faster volume. |
| `.gitignore` | Keeps machine-specific audit output (`LOCAL-NOTES.md`) and registry backups out of git. |

Both scripts are idempotent and skip cleanly when a target is absent.

## The prompt

This repo was produced by running the following against a Claude Code session with
Windows interop available from WSL. It is reusable as-is — replace the context line.

```text
Context: Windows 11 25H2 workstation, used for software development.
WSL2 runs on a dedicated ext4 NVMe volume. I have a CS/software engineering
background — skip explanations of basics, but tell me what you're doing and why
before you do it.

Goal: reduce OS noise and eliminate the real sources of dev-workload latency.
Not interested in placebo tweaks.

Phase 1 — audit only, change nothing:
- Detect whether I have a ReFS Dev Drive or just a standard NTFS/ext4 volume setup,
  and report the layout (volumes, filesystems, free space).
- List current Defender exclusions (paths, processes, extensions).
- List Windows Search indexed locations.
- Dump current .wslconfig if present.
- List startup apps and enabled non-Microsoft scheduled tasks.
- Report package manager cache locations (npm, pip, cargo, uv, go).

Then show me a proposed change set and wait for my approval before applying anything.

Phase 2 — apply after I approve:
- Defender exclusions: the WSL2 ext4/VHDX volume, vmmem/vmmemWSL processes,
  and my Windows-side repo directories.
- Windows Search: exclude repo, build, node_modules, venv, and target directories.
  Keep Search itself enabled.
- .wslconfig: set sensible memory and processor caps for this hardware,
  enable sparseVhd, enable autoMemoryReclaim.
- Redirect npm/pip/cargo caches onto the fast volume.
- Recommend which startup entries to disable; let me pick.

Guardrails — do not violate these:
- Take a system restore point before the first change.
- Export any registry key before modifying it.
- Do not disable Windows Defender, VBS, or memory integrity.
- Do not disable the page file.
- Do not mass-disable services. Anything beyond the list above, propose first.
- Do not run remote scripts piped to iex.

Finish with a written summary of every change made and how to reverse each one.
```

The guardrail block is the important part. Without it you get a script that turns off
real-time protection and calls it a performance win.

## Audit commands

All read-only. Run from WSL (`powershell.exe -NoProfile -Command '…'`) or directly in
PowerShell. Items marked ⚠ need elevation.

```powershell
# Volume layout + Dev Drive detection
Get-Volume | Format-Table DriveLetter,FileSystemLabel,FileSystemType,Size,SizeRemaining
Get-Volume | Where-Object DriveLetter | ForEach-Object { fsutil devdrv query "$($_.DriveLetter):" }

# ⚠ Defender exclusions
Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension

# Search indexed locations
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows Search\CrawlScopeManager\Windows\SystemIndex\WorkingSetRules' |
  ForEach-Object { $p = Get-ItemProperty $_.PSPath
    '{0} {1}' -f $(if ($p.Include -eq 1) {'INCLUDE'} else {'EXCLUDE'}), $p.URL }

# WSL: version, distros, VHDX location and real size
wsl --version; wsl -l -v
Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss' |
  ForEach-Object { (Get-ItemProperty $_.PSPath) | Select-Object DistributionName,BasePath }
fsutil sparse queryflag  "<path>\ext4.vhdx"
fsutil file queryvaliddata "<path>\ext4.vhdx"

# Startup entries and their enabled/disabled state
Get-Item 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

# Enabled tasks outside the \Microsoft\ tree
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' }

# VBS / memory integrity — report only, never disable
Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus,SecurityServicesRunning
```

WSL side:

```bash
df -hT | grep -Ev 'tmpfs|overlay'
lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT
du -sh ~/.npm ~/.cache/pip ~/.cache/uv ~/.cargo 2>/dev/null
```

## The changes that actually matter

### 1. Defender exclusions for the virtual disks

The WSL2 distro disk and Docker Desktop's data disk are large files the VM rewrites
constantly. Real-time scanning of that write stream is the single largest Defender cost on
a dev box, and it buys nothing: Defender cannot inspect the ext4 contents anyway.

```powershell
Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\wsl"      # distro ext4.vhdx
Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Docker"   # docker_data.vhdx
Add-MpPreference -ExclusionProcess vmmemWSL, vmmem, wslservice.exe
```

A bare-metal ext4 volume attached with `wsl --mount` needs **no** exclusion — Windows has
no filesystem driver for it and Defender never reads it. Excluding it is theatre.

Defender itself, VBS, and memory integrity stay on.

### 2. `.wslconfig` memory, CPU, sparse disk, memory reclaim

`%USERPROFILE%\.wslconfig`:

```ini
[wsl2]
memory=24GB               # default is 50% of host RAM; raise it if WSL is where you work
processors=20             # hold a few cores back so Windows stays responsive under load

[experimental]
autoMemoryReclaim=gradual # return freed guest pages instead of holding the high-water mark
sparseVhd=true            # auto-shrink virtual disks as data is freed
```

**The section matters.** `autoMemoryReclaim` and `sparseVhd` are still `[experimental]`
— they never graduated to `[wsl2]` the way `networkingMode`, `dnsTunneling`, `firewall`,
and `autoProxy` did. Put them under `[wsl2]` and WSL prints `Unknown key 'wsl2.sparseVhd'`
and silently ignores them, which is easy to miss because the keys it *does* recognise in
the same file still apply. Verify after `wsl --shutdown`:

```
wsl echo ok        # any "Unknown key" warning names the exact line number
```

Two more things people get wrong here:

- **These limits are VM-wide, not per-distro.** Docker Desktop's WSL2 backend shares one
  VM with your distros. Containers spend the same `memory=` budget.
- **`sparseVhd` only applies to newly created disks.** An existing VHDX needs a one-off
  conversion, with the distro stopped:

  ```powershell
  wsl --terminate <distro>
  wsl --manage <distro> --set-sparse true
  ```

  Corollary: set `sparseVhd=true` *before* installing Docker Desktop and its data disk is
  created sparse from the start.

Changes to `.wslconfig` require `wsl --shutdown` (or a reboot) to take effect.

### 3. Package caches off the distro VHDX

Caches at `~/.cache/uv`, `~/.npm`, `~/.cache/pip` are usually the reason a distro VHDX
grows to tens of GB. Move them to a faster or roomier volume and point the tools at the
new location — `post-reboot-wsl-tune.sh` does this, then leaves symlinks behind so
hardcoded paths keep working.

Use `cp -a`, not `mv`. uv's cache is hardlink-dense and a cross-filesystem `mv` inflates
it several times over.

Do this while no toolchain is running. A cache yanked out from under a live `npm exec` or
`uv run` breaks it.

### 4. WSL's 10-second boot deadline vs. the `/tmp` wipe

If a WSL session logs in with `Failed to start the systemd user session`, check boot time
before assuming anything is broken:

```bash
systemd-analyze              # userspace total
systemd-analyze blame | head # what ate it
systemctl --failed           # usually empty - it's slow, not broken
```

WSL gives `/sbin/init` **10 seconds**, then gives up on creating the user session:

```
/sbin/init failed to start within 10000ms
CreateLoginSession: Timed out waiting for user session for uid=1000
```

systemd itself comes up fine seconds later, which is why the box looks healthy while
`systemctl --user` still reports `Failed to connect to bus`.

A common cause on a dev box is the shipped tmpfiles rule `D /tmp 1777 root root 30d`. The
capital `D` means *delete everything in `/tmp` at every boot*. Build temp dirs, test
fixtures, and agent scratchpads accumulate there across long uptimes, and the unlink pass
runs synchronously during boot. Tens of GB of small files takes tens of seconds and blows
the deadline. It presents as intermittent, because it scales with how long the previous
session ran.

Fix — override the boot wipe, keep the age-based cleanup:

```bash
# lowercase d = create if missing, do NOT wipe contents at boot
echo 'd /tmp 1777 root root 7d' | sudo tee /etc/tmpfiles.d/tmp.conf
```

`systemd-tmpfiles-clean.timer` still removes files untouched for 7 days, asynchronously,
off the boot path. Confirm it's running with `systemctl is-active systemd-tmpfiles-clean.timer`.

Check the shipped file first — if `/usr/lib/tmpfiles.d/tmp.conf` holds more than the one
`/tmp` line, copy it and edit that line rather than replacing the file, since a
same-named file in `/etc/tmpfiles.d/` shadows the whole thing.

### 5. Startup entries and scheduled tasks

Worth removing on most dev boxes:

- `MicrosoftEdgeAutoLaunch_*` — preloads a hidden Edge window at logon
- `Adobe Acrobat Synchronizer` — polls for shared-review comments
- `SoftLanding*` tasks — Windows Spotlight upsell prompts
- vendor self-updaters that re-check on launch anyway (Zoom, NVIDIA App shell)

`tune-elevated.ps1` uses an **allow-list of name patterns**, so a task you depend on
cannot be caught by accident. Export the key first; the script does.

## Findings that changed the plan

From the run that produced this repo — a useful illustration of why the audit phase is not
optional:

- **"Exclude the WSL ext4 volume from Defender"** — impossible and unnecessary. It was a
  bare-metal `wsl --mount` passthrough, invisible to Windows. Only the VHDX mattered.
- **"Exclude repo/build/node_modules dirs from Windows Search"** — nothing to do. Search
  indexed only `C:\Users`, `AppData` was already excluded, and there were zero
  Windows-side repos: all development happened inside WSL.
- **"Redirect npm/pip/cargo caches"** — no toolchain existed on the Windows side at all.
  The version that paid off was entirely WSL-side.

Three of five planned changes were placebo on that specific machine. They would have been
applied anyway by any script that skips straight to Phase 2.

## Reversing everything

| Change | Reverse |
|---|---|
| Defender path exclusion | `Remove-MpPreference -ExclusionPath '<path>'` |
| Defender process exclusion | `Remove-MpPreference -ExclusionProcess '<name>'` |
| Startup entries | `reg import %USERPROFILE%\bin\backups\HKCU-Run.reg` |
| Scheduled tasks | `Enable-ScheduledTask -TaskName '<name>'` |
| `.wslconfig` | restore `.wslconfig.bak`, then `wsl --shutdown` |
| Sparse VHDX | `wsl --manage <distro> --set-sparse false` |
| Cache relocation | delete the symlinks, `cp -a` the trees back, drop the `.bashrc` block |
| Everything at once | the restore point `tune-elevated.ps1` takes before its first change |

`tune-elevated.ps1` writes the pre-change Defender exclusion list to
`bin\backups\defender-exclusions-before.json` so the reversal is exact rather than guessed.

## What this does not do

No Dev Drive creation — that means reformatting a volume as ReFS, which is a deliberate
decision with real tradeoffs (no compression, weaker tooling compatibility), not something
a tuning script should do to you.

No page file changes. No service disabling. No telemetry-registry cargo cult. No
`irm … | iex`.

## License

MIT.
