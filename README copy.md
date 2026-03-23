# Digital Forensics PowerShell Script

## What this script does

This is a **Windows DFIR triage collector** written in PowerShell.

Its job is to gather a broad set of live-response and forensic artifacts from a Windows workstation or server, write them into a timestamped case folder, export many of them to CSV for SIEM or spreadsheet use, and optionally compress the results into a ZIP archive.

In practice, it is designed for **incident response on a potentially compromised Windows host**. It tries to answer questions like:

- What is running right now?
- What users are active?
- What persistence mechanisms exist?
- What network activity is visible?
- What forensic artifacts indicate execution, browsing, remote access, USB usage, or malware defense tampering?
- What logs and raw artifacts should be preserved for later offline analysis?

---

## High-level behavior

When the script starts, it:

1. Reads its parameters:
   - `sw`: lookback window in days, default `2`
   - `OutputPath`: where to create the evidence folder, default is current directory
   - `NoCompress`: skip ZIP creation if set

2. Collects host context:
   - computer name
   - Windows product name
   - Windows build
   - current username
   - current user SID
   - whether the current session is elevated as Administrator

3. Creates an output structure:
   - `DFIR-<COMPUTERNAME>-<timestamp>`
   - `CSV Results (SIEM Import Data)` inside that folder

4. Tries to load the optional `PowerForensics` module:
   - if present, it intends to use it for Prefetch, Amcache, and UserAssist parsing
   - if absent, it falls back to copying raw artifacts instead

5. Runs a large number of collection functions:
   - always runs the non-admin-safe set
   - runs the admin-only set when elevated

6. Compresses the output folder into a ZIP unless `-NoCompress` is supplied

---

## Parameters

### `-sw`
An integer lookback window in days.

Used mainly for:
- Security event count
- Security event collection

Default: `2`

### `-OutputPath`
Base directory where the result folder is created.

Default: current working directory (`$pwd`)

### `-NoCompress`
If present, the script does not ZIP the results.

---

## Output structure

The script creates a case folder named like:

```text
DFIR-WORKSTATION01-2026-03-16_14-30-55
```

Inside it, it creates category folders such as:

- `Connections`
- `Persistence`
- `UserInformation`
- `ProcessInformation`
- `SecurityEvents`
- `Applications`
- `Services`
- `ScheduledTask`
- `ConnectedDevices`
- `Browsers\Chromium`
- `Browsers\Firefox`
- `MPLogs`
- `DefenderExclusions`
- `ShimCache`
- `Shellbags`
- `RecycleBin`
- `JumpLists`
- `SRUM`
- `WMI`
- `SystemRestore`
- `Clipboard`
- `MFT`
- `Memory`

It also creates:

- `CSV Results (SIEM Import Data)`

That CSV folder is a secondary export location for many artifacts so they can be imported into a SIEM or processed with other tooling.

---

## Safety and resilience design

Two helper functions drive the script’s resilience:

### `Invoke-SafeRun`
Wraps each collection step in `try/catch`, so a single failing artifact does not stop the entire triage run.

### `Export-ToCsv`
Writes structured objects to UTF-8 CSV when data exists.

This means the script is designed to be **best effort**. If one area fails because of permissions, missing registry keys, absent modules, or platform differences, the rest of the collection still continues.

---

## What each collection function gathers

## System and host information

### `Get-IPInfo`
Collects:
- `Get-NetIPAddress`
- `ipconfig /all`

Purpose:
- determine local IP addressing
- identify adapters, DNS servers, gateways, DHCP details, IPv4/IPv6 configuration

Outputs:
- `ipinfo.txt`
- `ipconfig.txt`
- `IPConfiguration.csv`

### `Get-ShadowCopies`
Collects Volume Shadow Copy metadata through `Win32_ShadowCopy`.

Purpose:
- find restore-like point-in-time snapshots that may preserve deleted or altered data

Outputs:
- `ShadowCopies.txt`
- `ShadowCopy.csv`

### `Get-InstalledUpdates`
Collects installed hotfixes via `Get-HotFix`.

Purpose:
- understand patch state
- correlate install timing with compromise timing

Outputs:
- `InstalledUpdates.txt`
- `InstalledUpdates.csv`

### `Get-SystemRestorePoints`
Collects restore point metadata via `Get-ComputerRestorePoint`.

Purpose:
- timeline system changes
- identify rollback points

Outputs:
- `RestorePoints.csv`

---

## Network and remote access artifacts

### `Get-OpenConnections`
Collects currently established TCP sessions.

Purpose:
- identify active outbound or inbound connections
- catch suspicious C2, lateral movement, remote administration, or data exfiltration channels

Outputs:
- `Connections\OpenConnections.txt`
- `OpenTCPConnections.csv`

### `Get-OfficeConnections`
Reads the Office Server Cache registry area.

Purpose:
- identify network/server connections initiated by Office applications
- useful in phishing or malicious document cases

Outputs:
- `Connections\ConnectionsMadeByOffice.txt`
- `OfficeConnections.csv`

### `Get-NetworkShares`
Reads `MountPoints2` for the current user or supplied SID.

Purpose:
- reveal mounted network shares, remote volumes, or historically accessed shares

Outputs:
- `Connections\NetworkShares.txt`
- `NetworkShares.csv`

### `Get-SMBShares`
Lists local SMB shares using `Get-SmbShare`.

Purpose:
- show file shares exposed by the host
- useful for lateral movement and data access scoping

Outputs:
- `Connections\SMBShares.txt`
- `SMBShares.csv`

### `Get-RDPSessions`
Uses `qwinsta` to list terminal / RDP sessions.

Purpose:
- identify active or recent remote desktop sessions

Outputs:
- `Connections\RDPSessions.txt`
- `RDPSessions.csv`

### `Get-RemotelyOpenedFiles`
Uses `openfiles`.

Purpose:
- show files opened remotely via SMB or similar mechanisms
- useful for file server cases

Outputs:
- `Connections\RemotelyOpenedFiles.txt`
- `RemotelyOpenedFiles.csv`

### `Get-DNSCache`
Reads the DNS client cache.

Purpose:
- recover recently resolved domains
- often valuable when browser history is missing or malware used domain-based infrastructure

Outputs:
- `Connections\DNSCache.txt`
- `DNSCache.csv`

---

## User and account artifacts

### `Get-ActiveUsers`
Uses `query user`.

Purpose:
- identify logged-in or active sessions on the host

Outputs:
- `UserInformation\ActiveUsers.txt`
- `ActiveUsers.csv`

### `Get-LocalUsers`
Uses `Get-LocalUser`.

Purpose:
- enumerate local accounts
- inspect enabled/disabled local users that may have been abused or created by an attacker

Outputs:
- `UserInformation\LocalUsers.txt`
- `LocalUsers.csv`

### `Get-PowershellHistoryCurrentUser`
Collects the current PowerShell session history (`Get-History`).

Purpose:
- recover commands executed in the current interactive session

Outputs:
- `PowerShellHistory\PowershellHistoryCurrentUser.txt`
- `PowerShellHistory.csv`

### `Get-PowershellConsoleHistory-AllUsers`
Copies `ConsoleHost_history.txt` from all user profiles.

Purpose:
- recover persistent PSReadLine command history from multiple users
- often reveals attacker hands-on-keyboard commands

Outputs:
- copies raw history files into per-user folders under `PowerShellHistory`

---

## Process, execution, and persistence artifacts

### `Get-ActiveProcesses`
Enumerates running processes via `Win32_Process`, then hashes executable images with SHA-256.

Purpose:
- identify suspicious running binaries
- link process names to paths and command lines
- support hash-based enrichment in threat intel platforms

Outputs:
- `ProcessInformation\UniqueProcessHash.csv`
- `ProcessInformation\ProcessList.csv`
- `Processes.csv`

Captured fields:
- executable path
- SHA-256 hash
- process name
- command line
- parent process ID
- process ID

### `Get-AutoRunInfo`
Collects startup commands via `Win32_StartupCommand` and selected WOW6432Node Run / RunOnce registry keys.

Purpose:
- discover common autorun persistence locations

Outputs:
- `Persistence\AutoRunInfo.txt`
- `AutoRun.csv`
- `Persistence\Win32RegRunKey.txt`
- `Win32RegRunKey.csv`

### `Get-InstalledDrivers`
Uses `driverquery`.

Purpose:
- list installed drivers, which can expose malicious kernel drivers or unusual software

Outputs:
- `Persistence\InstalledDrivers.txt`
- `Drivers.csv`

### `Get-RunningServices`
Lists services whose status is `Running`.

Purpose:
- identify suspicious services and service-based persistence

Outputs:
- `Services\RunningServices.txt`
- `RunningServices.csv`

### `Get-ScheduledTasks`
Collects enabled or recently run tasks.

Filter logic:
- not disabled
- either never run, or last run within the last 7 days

Purpose:
- scheduled-task persistence and execution tracking

Outputs:
- `ScheduledTask\ScheduledTasksList.txt`
- `ScheduledTasks.csv`

### `Get-ScheduledTasksRunInfo`
Collects `Get-ScheduledTaskInfo` for enabled tasks.

Purpose:
- capture last run time, next run time, last result, and other execution metadata

Outputs:
- `ScheduledTask\ScheduledTasksListRunInfo.txt`
- `ScheduledTasksRunInfo.csv`

### `Get-WMIPersistence`
Enumerates WMI event consumers and filters from `root\subscription`.

Purpose:
- identify WMI-based persistence, a common stealth mechanism

Outputs:
- `WMI\WMIConsumers.csv`
- `WMI\WMIFilters.csv`

### `Get-WindowsFirewallRules`
Exports firewall rules.

Purpose:
- spot attacker-added allow rules, disabled controls, or unusual inbound/outbound policy changes

Outputs:
- `Firewall\FirewallRules.csv`
- `FirewallRules.csv`

---

## Event logs and logging artifacts

### `Get-SecurityEventCount`
Reads Security log entries from the last `sw` days and groups them by `EventID`.

Purpose:
- quickly show what types of security events are most common in the time window

Outputs:
- `SecurityEvents\EventCount.txt`

### `Get-SecurityEvents`
Exports full Security event log entries from the last `sw` days.

Purpose:
- preserve detailed event content for authentication, privilege use, process creation, audit activity, and other investigations

Outputs:
- `SecurityEvents\SecurityEvents.txt`
- `SecurityEvents.csv`

### `Get-EventViewerFiles`
Copies selected `.evtx` files directly from `C:\Windows\System32\winevt\Logs`.

Channels targeted:
- Application
- Security
- System
- Sysmon Operational
- TaskScheduler Operational
- PowerShell Operational

Purpose:
- preserve raw native event log files for offline parsing and integrity

Outputs:
- copied `.evtx` files under `Event Viewer`

### `Get-RecentlyInstalledSoftwareEventLogs`
Reads `msiinstaller` provider events where event ID = 1033.

Purpose:
- identify MSI-based software installations and when they occurred

Outputs:
- `Applications\RecentlyInstalledSoftwareEventLogs.txt`
- `InstalledSoftware.csv`

### `Get-MPLogs`
Copies Windows Defender support logs from:

```text
C:\ProgramData\Microsoft\Windows Defender\Support\
```

Purpose:
- preserve Defender operational traces that may show scans, detections, remediation, or errors

Outputs:
- copied `.log` files under `MPLogs`

### `Get-DefenderExclusions`
Collects Defender exclusions from `Get-MpPreference`.

Purpose:
- detect paths, extensions, IPs, or processes excluded from scanning
- extremely valuable in malware investigations because exclusions are often abused

Outputs:
- text files for each exclusion class
- `DefenderExclusions.csv`

---

## Browser and user activity artifacts

### `Get-ChromiumFiles`
Searches under the user’s local app data for Chromium-based browser profile folders containing a valid SQLite `History` file.

Copies:
- `Preferences`
- `History`
- `IndexedDB`

Purpose:
- preserve raw browsing and application web-storage artifacts from Chromium-family browsers

Outputs:
- copied profile data under `Browsers\Chromium`

### `Get-FirefoxFiles`
Searches Firefox profiles and copies selected files when `places.sqlite` is present and appears to be SQLite.

Copies:
- `places.sqlite`
- `permissions.sqlite`
- `content-prefs.sqlite`
- `extensions`

Purpose:
- preserve Firefox history and selected profile artifacts

Outputs:
- copied profile data under `Browsers\Firefox`

### `Get-RecentFiles`
Collects `%APPDATA%\Microsoft\Windows\Recent`.

Purpose:
- show recently accessed items
- preserve `.lnk` shortcut artifacts that can reveal file execution and access

Outputs:
- `RecentFiles\RecentFiles.csv`
- copies raw `.lnk` files into `RecentFiles`

### `Get-LnkArtifacts`
Collects `.lnk` files from:
- Recent items
- Desktop

Then attempts to resolve:
- target path
- arguments
- working directory

Purpose:
- shortcut artifacts are highly valuable for reconstructing execution and document access

Outputs:
- copied `.lnk` files under `LNK`
- `LNK\LnkDetails.csv`
- `LnkDetails.csv`

### `Get-JumpLists`
Collects `AutomaticDestinations` Jump List files.

Purpose:
- show application-specific recently accessed files and destinations

Outputs:
- `JumpLists\JumpLists.csv`

### `Get-ClipboardContents`
Captures current clipboard text.

Purpose:
- may reveal copied commands, secrets, URLs, or attacker staging data

Outputs:
- `Clipboard\Clipboard.txt`

---

## Application execution and forensic execution traces

### `Get-Prefetch`
Intended behavior:
- if PowerForensics is available, parse Prefetch
- otherwise copy raw `.pf` files from `C:\Windows\Prefetch`

Purpose:
- Prefetch helps determine executable run history and file usage

Outputs:
- `Prefetch\Prefetch.txt` and `Prefetch.csv` if parsed
- or copied `.pf` files and `PrefetchFiles.csv`

### `Get-Amcache`
Intended behavior:
- if PowerForensics is available, parse Amcache
- otherwise copy `C:\Windows\AppCompat\Programs\Amcache.hve`

Purpose:
- Amcache is a key execution and program inventory artifact

Outputs:
- parsed text/CSV if available
- or raw `Amcache.hve`

### `Get-UserAssist`
Intended behavior:
- if PowerForensics is available, parse UserAssist
- otherwise export the raw UserAssist registry branch

Purpose:
- UserAssist records GUI-launched program usage in the user context

Outputs:
- `UserAssist.txt` / `UserAssist.csv` if parsed
- or raw `UserAssist.reg`

### `Get-ShimCache`
Reads AppCompatCache registry data and saves:
- raw data in base64
- a CSV export of registry values

Purpose:
- ShimCache can show evidence that executables were seen by the system

Outputs:
- `ShimCache\AppCompatCache_Base64.txt`
- `ShimCache\AppCompatCache.csv`

### `Get-Shellbags`
Exports BagMRU / Bags registry trees and attempts raw registry exports.

Purpose:
- Shellbags provide evidence of folder browsing and shell interaction, including removable or network locations

Outputs:
- CSV exports into the SIEM folder
- `.reg` exports under `Shellbags`

### `Get-SRUM`
Copies `SRUDB.dat`.

Purpose:
- SRUM contains valuable historical application and network usage data

Outputs:
- raw `SRUDB.dat` under `SRUM`

### `Get-RecycleBin`
Enumerates contents of `C:\$Recycle.Bin`.

Purpose:
- identify deleted files and their timestamps/size

Outputs:
- `RecycleBin\RecycleBin.csv`

---

## Device artifacts

### `Get-ConnectedDevices`
Exports all Plug and Play devices.

Purpose:
- broad hardware inventory
- useful for USB, removable media, virtual devices, and suspicious drivers

Outputs:
- `ConnectedDevices\ConnectedDevices.csv`
- `ConnectedDevices.csv`

### `Get-USBDevices`
Filters PnP devices to classes matching `USB|DiskDrive`.

Purpose:
- identify attached USB storage and related devices

Outputs:
- `USB\USBDevices.csv`
- `USBDevices.csv`

---

## Raw evidence, advanced artifacts, and external-tool integrations

### `Invoke-DFIRTools`
Looks for:
- `kape.exe`
- `registry-extractor.exe`

Search locations:
- PATH
- same folder as the script

If found, it runs them.

Purpose:
- extend the triage set with external specialist DFIR tooling

Outputs:
- KAPE output under `KAPE`
- registry-extractor output under `RegistryExtractor`

### `Get-MFT`
Looks for `MFTECmd.exe` in PATH or beside the script.

If found, runs it against `C:\$MFT`.

Purpose:
- preserve and parse NTFS Master File Table data

Outputs:
- CSV under `MFT`

### `Get-MemoryDump`
Looks for `DumpIt.exe` in PATH or beside the script.

If found, acquires memory.

Purpose:
- capture volatile memory for advanced malware, credential, and injected-code analysis

Outputs:
- `Memory\memory.dmp`

---

## Admin vs non-admin execution model

## Always runs
The script always runs `Start-WithoutAdminPrivilege`.

That includes:
- IP info
- open connections
- autoruns
- users
- processes
- Office / network shares
- SMB shares
- RDP sessions
- PowerShell history
- DNS cache
- drivers
- MSI install events
- services
- tasks
- devices
- recent files
- Prefetch / Amcache / UserAssist
- updates
- firewall rules
- installed programs
- USB devices
- LNK files
- Recycle Bin
- Jump Lists
- clipboard
- Chromium / Firefox file collection if username is known

## Only runs when elevated
If `$IsAdmin` is true, it also runs:
- security event count
- security events
- remotely opened files
- shadow copies
- selected EVTX file copy
- Defender MP logs
- Defender exclusions
- all-user PowerShell console history
- ShimCache
- Shellbags
- external DFIR tools
- SRUM
- WMI persistence
- system restore points
- MFT collection
- memory dump

This split matters because many artifacts require elevation, file-system access, registry access, or security log access that a normal user does not have.

---

## Compression

At the end, `Compress-Results`:

- skips compression if `-NoCompress` is set
- otherwise creates `<FolderCreation>.zip`

Purpose:
- package all evidence for transport, upload, or secure storage

---

## What this script is good at

This script is strong as a **broad first-response triage collector**.

It is especially useful for:
- ransomware response
- suspicious PowerShell activity
- malware triage
- unauthorized remote access
- suspicious persistence checks
- user activity reconstruction
- quick live-response evidence preservation

It gathers both:
- **human-readable summaries**
- **raw artifacts for later offline analysis**

That combination is exactly what you want in early-stage incident response.

---

## Important implementation problems and caveats

This script is useful, but it is **not fully clean or production-safe as written**. There are a few important issues.

### 1. `Get-Prefetch`, `Get-Amcache`, and `Get-UserAssist` have a naming collision bug
These functions have the same names as the PowerForensics commands they are trying to call.

Inside each function, the code does things like:

```powershell
$out = Get-Prefetch
```

But because the current script already defines a function called `Get-Prefetch`, that call resolves to the script function itself, not the module command. That can cause recursion instead of calling PowerForensics.

So the intended behavior is clear, but the PowerForensics branch is flawed unless those commands are called with explicit module qualification or different function names are used.

### 2. `Get-FirefoxFiles` calls `Ensure-Folder`, which is not defined
The script defines:
- `New-Folder`
- `New-FolderIfMissing`

But `Get-FirefoxFiles` calls:

```powershell
Ensure-Folder $destpath
```

That function does not exist in the script.

Result:
- Firefox collection will error when it reaches that line, unless another loaded module happens to define `Ensure-Folder`

Because the function call is wrapped by `Invoke-SafeRun`, the overall script continues, but Firefox collection likely fails.

### 3. Some CSV outputs are not true structured CSV
A few functions convert fixed-width console output into comma-separated text with regex replacements, for example:
- `driverquery`
- `query user`
- `qwinsta`
- `openfiles`

This is useful for quick export, but those files may not parse cleanly as proper CSV in all cases.

### 4. `Get-History` only captures the current session
That is not the same as the PSReadLine history file.
So `Get-PowershellHistoryCurrentUser` is limited to the current PowerShell session.

### 5. Several artifacts are copied raw, not parsed
That is not wrong. In DFIR, raw collection is often preferable.
But it means downstream analysis still requires specialist tools for:
- Prefetch
- Amcache
- SRUM
- MFT
- Jump Lists
- Shellbags
- memory dumps

### 6. Some commands depend on Windows edition, role, or feature state
Examples:
- `Get-SmbShare`
- `openfiles`
- `Get-ComputerRestorePoint`
- `Get-MpPreference`
- `Get-PnpDevice`
- `Get-ScheduledTask`
- `DumpIt.exe`, `MFTECmd.exe`, `kape.exe`, `registry-extractor.exe`

On some systems those may fail or return little data. The script is built to tolerate that.

### 7. It performs live collection, not dead-box acquisition
That means:
- some artifacts may change while being collected
- running commands on a compromised host can alter system state
- malware may react to collection

That is normal for live response, but important to understand.

---