<#
.DESCRIPTION
    The DFIR Script is a tool to perform digital forensics via PowerShell on compromised devices
    with a Windows Operating System (Workstation & Server).
#>

param(
    [Parameter(Mandatory=$false)][int]$sw = 2, # Defines custom search window in days
    [Parameter(Mandatory=$false)][string]$OutputPath = $pwd,
    [Parameter(Mandatory=$false)][switch]$NoCompress
)

function New-FolderIfMissing {
    param(
        [Parameter(Mandatory=$true)][string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

# ---------------------------
# Global / Banner / Context
# ---------------------------
Write-Host "===========================================" -ForegroundColor Cyan

$HostName = $env:COMPUTERNAME
$OSProductName = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'ProductName').ProductName
$OSBuild = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuild').CurrentBuild
Write-Host "Host Information (HostName: $HostName | OS: $OSProductName | OS Build: $OSBuild)" -ForegroundColor Cyan

$currentUsername = $env:USERNAME
$currentUserSid = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' |
    Where-Object { $_.PSChildName -match 'S-1-5-21-\d+-\d+-\d+-\d+$' -and $_.ProfileImagePath -match "\\$currentUsername$" } |
    ForEach-Object { $_.PSChildName } | Select-Object -First 1

Write-Host "Current user: $currentUsername $currentUserSid" -ForegroundColor Cyan

$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($IsAdmin) {
    Write-Host "DFIR Session starting as Administrator..." -ForegroundColor Green
}
else {
    Write-Host "No Administrator session detected. For best performance run as Administrator. Not all artifacts can be collected..." -ForegroundColor Red
    Write-Host "DFIR Session starting..." -ForegroundColor Yellow
}

Write-Host "Creating output directory..."

$ExecutionTime = (Get-Date -Format yyyy-MM-dd_HH-mm-ss)
$FolderCreation = Join-Path -Path $OutputPath -ChildPath "DFIR-$env:COMPUTERNAME-$ExecutionTime"
New-Item -Path $FolderCreation -ItemType Directory -Force | Out-Null

Write-Host "Output directory created: $FolderCreation"

$CSVOutputFolder = Join-Path -Path $FolderCreation -ChildPath "CSV Results (SIEM Import Data)"
New-Item -Path $CSVOutputFolder -ItemType Directory -Force | Out-Null
Write-Host "SIEM Export Output directory created: $CSVOutputFolder"

Write-Host "Collecting data from last $sw days" -ForegroundColor Cyan

# ---------------------------
# Optional Dependencies
# ---------------------------
$PowerForensicsAvailable = $false
try {
    Import-Module PowerForensics -ErrorAction Stop
    $PowerForensicsAvailable = $true
    Write-Host "Loaded module: PowerForensics (Prefetch/Amcache/UserAssist available)" -ForegroundColor Green
} catch {
    Write-Host "PowerForensics not available. Will use fallback collection for Prefetch/Amcache/UserAssist." -ForegroundColor Yellow
}

# ---------------------------
# Helpers
# ---------------------------
function Invoke-SafeRun {
    param(
        [Parameter(Mandatory=$true)][ScriptBlock]$Script,
        [Parameter(Mandatory=$false)][string]$Context = "Task"
    )
    try {
        & $Script
    } catch {
        Write-Host "ERROR collecting $Context : $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Export-ToCsv {
    param(
        [Parameter(Mandatory=$false)]$Object,
        [Parameter(Mandatory=$true)][string]$FileName
    )
    try {
        if ($null -ne $Object -and @($Object).Count -gt 0) {
            $out = Join-Path -Path $CSVOutputFolder -ChildPath $FileName
            $Object | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $out -Encoding UTF8
        }
    } catch {
        Write-Host "ERROR exporting CSV $FileName : $($_.Exception.Message)" -ForegroundColor Red
    }
}

function New-Folder {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -ItemType Directory -Force | Out-Null }
}

# ---------------------------
# Core Collection Functions (from your script)
# ---------------------------
function Get-IPInfo {
    Write-Host "Collecting local IP info..."
    $Ipinfoutput = Join-Path $FolderCreation "ipinfo.txt"
    Get-NetIPAddress | Out-File -Force -FilePath $Ipinfoutput
    $Ipconfigoutput = Join-Path $FolderCreation "ipconfig.txt"
    ipconfig /all | Out-File -Force -FilePath $Ipconfigoutput
    Export-ToCsv -Object (Get-NetIPAddress) -FileName "IPConfiguration.csv"
}

function Get-ShadowCopies {
    Write-Host "Collecting Shadow Copies..."
    $ShadowCopy = Join-Path $FolderCreation "ShadowCopies.txt"
    Get-CimInstance Win32_ShadowCopy | Out-File -Force -FilePath $ShadowCopy
    Export-ToCsv -Object (Get-CimInstance Win32_ShadowCopy) -FileName "ShadowCopy.csv"
}

function Get-OpenConnections {
    Write-Host "Collecting Open Connections..."
    $ConnectionFolder = Join-Path $FolderCreation "Connections"
    New-Folder $ConnectionFolder
    $OpenConnections = Join-Path $ConnectionFolder "OpenConnections.txt"
    Get-NetTCPConnection -State Established | Out-File -Force -FilePath $OpenConnections
    Export-ToCsv -Object (Get-NetTCPConnection -State Established) -FileName "OpenTCPConnections.csv"
}

function Get-AutoRunInfo {
    Write-Host "Collecting AutoRun info..."
    $AutoRunFolder = Join-Path $FolderCreation "Persistence"
    New-Folder $AutoRunFolder
    $RegKeyOutput = Join-Path $AutoRunFolder "AutoRunInfo.txt"
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-List | Out-File -Force -FilePath $RegKeyOutput
    Export-ToCsv -Object (Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User) -FileName "AutoRun.csv"

    $RegKeyOutputWin32 = Join-Path $AutoRunFolder "Win32RegRunKey.txt"
    Get-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce -ErrorAction SilentlyContinue | Format-List | Out-File -Force -FilePath $RegKeyOutputWin32
    Get-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue | Format-List | Out-File -Append -Force -FilePath $RegKeyOutputWin32

    $results = @()
    $keys = @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($key in $keys) {
        $results += Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    }
    Export-ToCsv -Object $results -FileName "Win32RegRunKey.csv"
}

function Get-InstalledDrivers {
    Write-Host "Collecting Installed Drivers..."
    $AutoRunFolder = Join-Path $FolderCreation "Persistence"
    New-FolderIfMissing $AutoRunFolder
    $RegKeyOutput = Join-Path $AutoRunFolder "InstalledDrivers.txt"
    driverquery | Out-File -Force -FilePath $RegKeyOutput

    # crude CSV conversion
    $drivers = driverquery | Out-String
    $drivers -split "`n" | ForEach-Object { $_ -replace '\s\s+', ',' } |
        Out-File -Force (Join-Path -Path $CSVOutputFolder -ChildPath "Drivers.csv") -Encoding UTF8
}

function Get-ActiveUsers {
    Write-Host "Collecting Active users..."
    $UserFolder = Join-Path $FolderCreation "UserInformation"
    New-Folder $UserFolder
    $ActiveUserOutput = Join-Path $UserFolder "ActiveUsers.txt"
    query user /server:localhost | Out-File -Force -FilePath $ActiveUserOutput
    (query user /server:localhost) -split "`n" -replace '\s\s+', ',' |
        Out-File -FilePath (Join-Path $CSVOutputFolder "ActiveUsers.csv") -Encoding UTF8
}

function Get-LocalUsers {
    Write-Host "Collecting Local users..."
    $UserFolder = Join-Path $FolderCreation "UserInformation"
    New-FolderIfMissing $UserFolder
    $LocalUserOutput = Join-Path $UserFolder "LocalUsers.txt"
    Get-LocalUser | Format-Table | Out-File -Force -FilePath $LocalUserOutput
    Export-ToCsv -Object (Get-LocalUser) -FileName "LocalUsers.csv"
}

function Get-ActiveProcesses {
    Write-Host "Collecting Active Processes..."
    $ProcessFolder = Join-Path $FolderCreation "ProcessInformation"
    New-Folder $ProcessFolder
    $UniqueProcessHashOutput = Join-Path $ProcessFolder "UniqueProcessHash.csv"
    $ProcessListOutput = Join-Path $ProcessFolder "ProcessList.csv"

    $processes_list = @()
    foreach ($process in Get-CimInstance Win32_Process | Select-Object Name, ExecutablePath, CommandLine, ParentProcessId, ProcessId) {
        if ($null -ne $process.ExecutablePath -and (Test-Path $process.ExecutablePath)) {
            $hash = (Get-FileHash -Algorithm SHA256 -Path $process.ExecutablePath -ErrorAction SilentlyContinue).Hash
            $processes_list += [PSCustomObject]@{
                Proc_Hash            = $hash
                Proc_Name            = $process.Name
                Proc_Path            = $process.ExecutablePath
                Proc_CommandLine     = $process.CommandLine
                Proc_ParentProcessId = $process.ParentProcessId
                Proc_ProcessId       = $process.ProcessId
            }
        }
    }

    $processes_list | Select-Object Proc_Path, Proc_Hash -Unique | Export-Csv -NoTypeInformation -Path $UniqueProcessHashOutput
    Export-ToCsv -Object ($processes_list | Select-Object Proc_Path, Proc_Hash -Unique) -FileName "Processes.csv"
    $processes_list | Export-Csv -NoTypeInformation -Path $ProcessListOutput
}

function Get-SecurityEventCount {
    param([Parameter(Mandatory=$true)][int]$sw)
    Write-Host "Collecting stats Security Events last $sw days..."
    $SecurityEventsFolder = Join-Path $FolderCreation "SecurityEvents"
    New-Folder $SecurityEventsFolder
    $ProcessOutput = Join-Path $SecurityEventsFolder "EventCount.txt"
    $SecurityEvents = Get-EventLog -LogName security -After (Get-Date).AddDays(-$sw) -ErrorAction SilentlyContinue
    $SecurityEvents | Group-Object -Property EventID -NoElement | Sort-Object -Property Count -Descending |
        Out-File -Force -FilePath $ProcessOutput
}

function Get-SecurityEvents {
    param([Parameter(Mandatory=$true)][int]$sw)
    Write-Host "Collecting Security Events last $sw days..."
    $SecurityEventsFolder = Join-Path $FolderCreation "SecurityEvents"
    New-Item -Path $SecurityEventsFolder -ItemType Directory -Force | Out-Null
    $ProcessOutput = Join-Path $SecurityEventsFolder "SecurityEvents.txt"
    Get-EventLog security -After (Get-Date).AddDays(-$sw) -ErrorAction SilentlyContinue |
        Format-List * | Out-File -Force -FilePath $ProcessOutput
    Export-ToCsv -Object (Get-EventLog security -After (Get-Date).AddDays(-$sw) -ErrorAction SilentlyContinue) -FileName "SecurityEvents.csv"
}

function Get-EventViewerFiles {
    Write-Host "Collecting Important Event Viewer Files..."
    $EventViewer = Join-Path $FolderCreation "Event Viewer"
    New-Folder $EventViewer
    $evtxPath = "C:\Windows\System32\winevt\Logs"
    $channels = @(
        "Application",
        "Security",
        "System",
        "Microsoft-Windows-Sysmon%4Operational",
        "Microsoft-Windows-TaskScheduler%4Operational",
        "Microsoft-Windows-PowerShell%4Operational"
    )

    Get-ChildItem "$evtxPath\*.evtx" -ErrorAction SilentlyContinue |
        Where-Object { $_.BaseName -in $channels } |
        ForEach-Object { Copy-Item -Path $_.FullName -Destination (Join-Path $EventViewer $_.Name) -Force -ErrorAction SilentlyContinue }
}

function Get-OfficeConnections {
    param([Parameter(Mandatory=$false)][string]$UserSid)
    Write-Host "Collecting connections made from office applications..."
    $ConnectionFolder = Join-Path $FolderCreation "Connections"
    New-FolderIfMissing $ConnectionFolder
    $OfficeConnection = Join-Path $ConnectionFolder "ConnectionsMadeByOffice.txt"

    if ($UserSid) {
        Get-ChildItem -Path "registry::HKEY_USERS\$UserSid\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache" -ErrorAction SilentlyContinue |
            Out-File -Force -FilePath $OfficeConnection
        Export-ToCsv -Object (Get-ChildItem -Path "registry::HKEY_USERS\$UserSid\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache" -ErrorAction SilentlyContinue) -FileName "OfficeConnections.csv"
    } else {
        try {
            Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache -ErrorAction Stop |
                Out-File -Force -FilePath $OfficeConnection
            Export-ToCsv -Object (Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache -ErrorAction Stop) -FileName "OfficeConnections.csv"
        } catch {
            Write-Host "Office Server Cache registry not found: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Get-NetworkShares {
    param([Parameter(Mandatory=$false)][string]$UserSid)
    Write-Host "Collecting Active Network Shares..."
    $ConnectionFolder = Join-Path $FolderCreation "Connections"
    New-FolderIfMissing $ConnectionFolder
    $ProcessOutput = Join-Path $ConnectionFolder "NetworkShares.txt"

    if ($UserSid) {
        Get-ItemProperty -Path "registry::HKEY_USERS\$UserSid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\" -ErrorAction SilentlyContinue |
            Format-Table | Out-File -Force -FilePath $ProcessOutput
        Export-ToCsv -Object (Get-ItemProperty -Path "registry::HKEY_USERS\$UserSid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\" -ErrorAction SilentlyContinue) -FileName "NetworkShares.csv"
    } else {
        Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\ -ErrorAction SilentlyContinue |
            Format-Table | Out-File -Force -FilePath $ProcessOutput
        Export-ToCsv -Object (Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\ -ErrorAction SilentlyContinue) -FileName "NetworkShares.csv"
    }
}

function Get-SMBShares {
    Write-Host "Collecting SMB Shares..."
    $ConnectionFolder = Join-Path $FolderCreation "Connections"
    New-FolderIfMissing $ConnectionFolder
    $ProcessOutput = Join-Path $ConnectionFolder "SMBShares.txt"
    Get-SmbShare -ErrorAction SilentlyContinue | Out-File -Force -FilePath $ProcessOutput
    Export-ToCsv -Object (Get-SmbShare -ErrorAction SilentlyContinue) -FileName "SMBShares.csv"
}

function Get-RDPSessions {
    Write-Host "Collecting RDS Sessions..."
    $ConnectionFolder = Join-Path $FolderCreation "Connections"
    New-FolderIfMissing $ConnectionFolder
    $ProcessOutput = Join-Path $ConnectionFolder "RDPSessions.txt"
    qwinsta /server:localhost | Out-File -Force -FilePath $ProcessOutput
    (qwinsta /server:localhost) -split "`n" -replace '\s\s+', ',' |
        Out-File -FilePath (Join-Path $CSVOutputFolder "RDPSessions.csv") -Encoding UTF8
}

function Get-RemotelyOpenedFiles {
    Write-Host "Collecting Remotely Opened Files..."
    $ConnectionFolder = Join-Path $FolderCreation "Connections"
    New-FolderIfMissing $ConnectionFolder
    $ProcessOutput = Join-Path $ConnectionFolder "RemotelyOpenedFiles.txt"
    openfiles | Out-File -Force -FilePath $ProcessOutput
    (openfiles) -split "`n" -replace '\s\s+', ',' |
        Out-File -FilePath (Join-Path $CSVOutputFolder "RemotelyOpenedFiles.csv") -Encoding UTF8
}

function Get-DNSCache {
    Write-Host "Collecting DNS Cache..."
    $ConnectionFolder = Join-Path $FolderCreation "Connections"
    New-FolderIfMissing $ConnectionFolder
    $ProcessOutput = Join-Path $ConnectionFolder "DNSCache.txt"
    Get-DnsClientCache -ErrorAction SilentlyContinue | Format-List | Out-File -Force -FilePath $ProcessOutput
    Export-ToCsv -Object (Get-DnsClientCache -ErrorAction SilentlyContinue) -FileName "DNSCache.csv"
}

function Get-PowershellHistoryCurrentUser {
    Write-Host "Collecting PowerShell History..."
    $PowershellConsoleHistory = Join-Path $FolderCreation "PowerShellHistory"
    New-FolderIfMissing $PowershellConsoleHistory
    $PowershellHistoryOutput = Join-Path $PowershellConsoleHistory "PowershellHistoryCurrentUser.txt"
    Get-History | Out-File -Force -FilePath $PowershellHistoryOutput
    Export-ToCsv -Object (Get-History) -FileName "PowerShellHistory.csv"
}

function Get-PowershellConsoleHistory-AllUsers {
    Write-Host "Collecting PowerShell Console History for All Users..."
    $PowershellConsoleHistory = Join-Path $FolderCreation "PowerShellHistory"
    New-FolderIfMissing $PowershellConsoleHistory
    $usersDirectory = "C:\Users"
    Get-ChildItem -Path $usersDirectory -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $historyFilePath = Join-Path -Path $_.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path -Path $historyFilePath -PathType Leaf) {
            $outputDirectory = Join-Path -Path $PowershellConsoleHistory -ChildPath $_.Name
             New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
            Copy-Item -Path $historyFilePath -Destination $outputDirectory -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-RecentlyInstalledSoftwareEventLogs {
    Write-Host "Collecting Recently Installed Software EventLogs..."
    $ApplicationFolder = Join-Path $FolderCreation "Applications"
    New-Folder $ApplicationFolder
    $ProcessOutput = Join-Path $ApplicationFolder "RecentlyInstalledSoftwareEventLogs.txt"
    $events = Get-WinEvent -ProviderName msiinstaller -ErrorAction SilentlyContinue |
        Where-Object id -eq 1033 |
        Select-Object TimeCreated, Message
    $events | Format-List * | Out-File -Force -FilePath $ProcessOutput
    Export-ToCsv -Object $events -FileName "InstalledSoftware.csv"
}

function Get-RunningServices {
    Write-Host "Collecting Running Services..."
    $ApplicationFolder = Join-Path $FolderCreation "Services"
    New-FolderIfMissing $ApplicationFolder
    $ProcessOutput = Join-Path $ApplicationFolder "RunningServices.txt"
    $svcs = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
    $svcs | Format-List | Out-File -Force -FilePath $ProcessOutput
    Export-ToCsv -Object $svcs -FileName "RunningServices.csv"
}

function Get-ScheduledTasks {
    Write-Host "Collecting Scheduled Tasks..."
    $ScheduledTaskFolder = Join-Path $FolderCreation "ScheduledTask"
    New-Folder $ScheduledTaskFolder
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { ($_.State -ne 'Disabled') -and (($null -eq $_.LastRunTime) -or ($_.LastRunTime -gt (Get-Date).AddDays(-7))) }

    $tasks | Format-List | Out-File -Force -FilePath (Join-Path $ScheduledTaskFolder "ScheduledTasksList.txt")
    Export-ToCsv -Object $tasks -FileName "ScheduledTasks.csv"
}

function Get-ScheduledTasksRunInfo {
    Write-Host "Collecting Scheduled Tasks Run Info..."
    $ScheduledTaskFolder = Join-Path $FolderCreation "ScheduledTask"
    New-FolderIfMissing $ScheduledTaskFolder
    $ProcessOutput = Join-Path $ScheduledTaskFolder "ScheduledTasksListRunInfo.txt"

    $info = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne "Disabled" } |
        Get-ScheduledTaskInfo -ErrorAction SilentlyContinue

    $info | Out-File -Force -FilePath $ProcessOutput
    Export-ToCsv -Object $info -FileName "ScheduledTasksRunInfo.csv"
}

function Get-ConnectedDevices {
    Write-Host "Collecting Information about Connected Devices..."
    $DeviceFolder = Join-Path $FolderCreation "ConnectedDevices"
    New-Folder $DeviceFolder
    $ConnectedDevicesOutput = Join-Path $DeviceFolder "ConnectedDevices.csv"
    $dev = Get-PnpDevice -ErrorAction SilentlyContinue
    $dev | Export-Csv -NoTypeInformation -Path $ConnectedDevicesOutput
    Export-ToCsv -Object $dev -FileName "ConnectedDevices.csv"
}

function Get-ChromiumFiles {
    param([Parameter(Mandatory=$true)][string]$Username)
    Write-Host "Collecting raw Chromium history and profile files..."
    $HistoryFolder = Join-Path $FolderCreation "Browsers\Chromium"
    New-Folder $HistoryFolder

    $filesToCopy = @('Preferences','History')
    $dirsToCopy  = @('IndexedDB')

    Get-ChildItem "C:\Users\$Username\AppData\Local\*\*\User Data\*" -Directory -ErrorAction SilentlyContinue | Where-Object {
        (Test-Path "$($_.FullName)\History") -and
        ([char[]](Get-Content "$($_.FullName)\History" -Encoding Byte -TotalCount ('SQLite format'.Length)) -join '') -eq 'SQLite format'
    } | ForEach-Object {
        $srcpath  = $_.FullName
        $destpath = $srcpath -replace "^C:\\Users\\$Username\\AppData\\Local", $HistoryFolder -replace "User Data\\", ""
        New-Folder $destpath

        foreach ($fname in $filesToCopy) {
            $srcfile = Join-Path $srcpath $fname
            if (Test-Path $srcfile) { Copy-Item -Path $srcfile -Destination $destpath -Force -ErrorAction SilentlyContinue }
        }

        foreach ($reldir in $dirsToCopy) {
            $srcdir = Join-Path $srcpath $reldir
            if (Test-Path $srcdir) {
                $destdir = Join-Path $destpath $reldir
                New-Folder $destdir
                Copy-Item -Path "$srcdir\*" -Destination $destdir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Get-EdgeFiles {
    param([Parameter(Mandatory=$true)][string]$Username)
    
    # Check if Edge is installed
    $edgeInstalled = Test-Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    if (-not $edgeInstalled) {
        Write-Host "Edge not installed; skipping Edge file collection."
        return
    }
    
    $profileRoot = "C:\Users\$Username\AppData\Local\Microsoft\Edge\User Data"
    if (Test-Path $profileRoot) {
        Write-Host "Collecting raw Edge history and profile files..."
        $HistoryFolder = Join-Path $FolderCreation "Browsers\Edge"
        New-FolderIfMissing $HistoryFolder

        $filesToCopy = @('Preferences','History')
        $dirsToCopy  = @('IndexedDB')

        Get-ChildItem $profileRoot -Directory -ErrorAction SilentlyContinue | Where-Object {
            (Test-Path "$($_.FullName)\History") -and
            ([char[]](Get-Content "$($_.FullName)\History" -Encoding Byte -TotalCount ('SQLite format'.Length)) -join '') -eq 'SQLite format'
        } | ForEach-Object {
            $srcpath  = $_.FullName
            $destpath = $srcpath -replace [regex]::Escape($profileRoot), $HistoryFolder

            foreach ($fname in $filesToCopy) {
                $srcfile = Join-Path $srcpath $fname
                if (Test-Path $srcfile) { Copy-Item -Path $srcfile -Destination $destpath -Force -ErrorAction SilentlyContinue }
            }

            foreach ($reldir in $dirsToCopy) {
                $srcdir = Join-Path $srcpath $reldir
                if (Test-Path $srcdir) {
                    $destdir = Join-Path $destpath $reldir
                    New-Folder $destdir
                    Copy-Item -Path "$srcdir\*" -Destination $destdir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

function Get-FirefoxFiles {
    param([Parameter(Mandatory=$true)][string]$Username)
    
    # Check if Firefox is installed
    $firefoxInstalled = (Test-Path "C:\Program Files\Mozilla Firefox\firefox.exe") -or (Test-Path "C:\Program Files (x86)\Mozilla Firefox\firefox.exe")
    if (-not $firefoxInstalled) {
        Write-Host "Firefox not installed; skipping Firefox file collection."
        return
    }
    
    $profileRoot = "C:\Users\$Username\AppData\Roaming\Mozilla\Firefox\Profiles"
    if (Test-Path $profileRoot) {
        Write-Host "Collecting raw Firefox history and profile files..."
        $HistoryFolder = Join-Path $FolderCreation "Browsers\Firefox"
        New-FolderIfMissing $HistoryFolder

        $filesToCopy = @('places.sqlite','permissions.sqlite','content-prefs.sqlite','extensions')

        Get-ChildItem $profileRoot -Directory -ErrorAction SilentlyContinue | Where-Object {
            (Test-Path "$($_.FullName)\places.sqlite") -and
            ([char[]](Get-Content "$($_.FullName)\places.sqlite" -Encoding Byte -TotalCount ('SQLite format'.Length)) -join '') -eq 'SQLite format'
        } | ForEach-Object {
            $srcpath  = $_.FullName
            $destpath = $srcpath -replace [regex]::Escape($profileRoot), $HistoryFolder
            # Ensure-Folder $destpath

            foreach ($fname in $filesToCopy) {
                $srcfile = Join-Path $srcpath $fname
                if (Test-Path $srcfile) { Copy-Item -Path $srcfile -Destination $destpath -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}

function Get-ChromeFiles {
    param([Parameter(Mandatory=$true)][string]$Username)
    
    # Check if Chrome is installed
    $chromeInstalled = (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe") -or (Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")
    if (-not $chromeInstalled) {
        Write-Host "Chrome not installed; skipping Chrome file collection."
        return
    }
    
    $profileRoot = "C:\Users\$Username\AppData\Local\Google\Chrome\User Data"
    if (Test-Path $profileRoot) {
        Write-Host "Collecting raw Chrome history and profile files..."
        $HistoryFolder = Join-Path $FolderCreation "Browsers\Chrome"
        New-FolderIfMissing $HistoryFolder

        $filesToCopy = @('Preferences','History')
        $dirsToCopy  = @('IndexedDB')

        Get-ChildItem $profileRoot -Directory -ErrorAction SilentlyContinue | Where-Object {
            (Test-Path "$($_.FullName)\History") -and
            ([char[]](Get-Content "$($_.FullName)\History" -Encoding Byte -TotalCount ('SQLite format'.Length)) -join '') -eq 'SQLite format'
        } | ForEach-Object {
            $srcpath  = $_.FullName
            $destpath = $srcpath -replace [regex]::Escape($profileRoot), $HistoryFolder

            foreach ($fname in $filesToCopy) {
                $srcfile = Join-Path $srcpath $fname
                if (Test-Path $srcfile) { Copy-Item -Path $srcfile -Destination $destpath -Force -ErrorAction SilentlyContinue }
            }

            foreach ($reldir in $dirsToCopy) {
                $srcdir = Join-Path $srcpath $reldir
                if (Test-Path $srcdir) {
                    $destdir = Join-Path $destpath $reldir
                    New-Folder $destdir
                    Copy-Item -Path "$srcdir\*" -Destination $destdir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

function Get-MPLogs {
    Write-Host "Collecting MPLogs..."
    $MPLogFolder = Join-Path $FolderCreation "MPLogs"
    New-Folder $MPLogFolder
    $MPLogLocation = "C:\ProgramData\Microsoft\Windows Defender\Support\"
    Get-ChildItem -Path $MPLogLocation -Filter "*.log" -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $MPLogFolder -Force -ErrorAction SilentlyContinue
    }
}

function Get-DefenderExclusions {
    Write-Host "Collecting Defender Exclusions..."
    $DefenderExclusionFolder = Join-Path $FolderCreation "DefenderExclusions"
    New-Folder $DefenderExclusionFolder

    Get-MpPreference | Select-Object -ExpandProperty ExclusionPath      | Out-File -Force -FilePath (Join-Path $DefenderExclusionFolder "ExclusionPath.txt")
    Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension | Out-File -Force -FilePath (Join-Path $DefenderExclusionFolder "ExclusionExtension.txt")
    Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress | Out-File -Force -FilePath (Join-Path $DefenderExclusionFolder "ExclusionIpAddress.txt")
    Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess   | Out-File -Force -FilePath (Join-Path $DefenderExclusionFolder "ExclusionProcess.txt")

    $data = @{
        ExclusionPath      = (Get-MpPreference | Select-Object -ExpandProperty ExclusionPath) -join "`n"
        ExclusionExtension = (Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension) -join "`n"
        ExclusionIpAddress = (Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress) -join "`n"
        ExclusionProcess   = (Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess) -join "`n"
    }

    $data.GetEnumerator() | ForEach-Object { "$($_.Key),$($_.Value)" } |
        Out-File -FilePath (Join-Path $CSVOutputFolder "DefenderExclusions.csv") -Encoding UTF8
}

function Get-ShimCache {
    Write-Host "Collecting ShimCache (AppCompatCache) data..., requires parser tooling (appcompatcacheparser)"
    $ShimFolder = Join-Path $FolderCreation "ShimCache"
    New-Folder $ShimFolder

    $shimKey   = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
    $shimValue = Get-ItemProperty -Path $shimKey -ErrorAction SilentlyContinue
    if ($shimValue) {
        $raw = $shimValue.AppCompatCache
        if ($raw) {
            $base64 = [Convert]::ToBase64String($raw)
            $base64 | Out-File -Force -FilePath (Join-Path $ShimFolder "AppCompatCache_Base64.txt")
        }
        $shimValue | Select-Object * | Export-Csv -NoTypeInformation -Path (Join-Path $ShimFolder "AppCompatCache.csv")
    }
}

function Get-Shellbags {
    Write-Host "Collecting Shellbags (BagMRU and Bags)..."
    $ShellbagsFolder = Join-Path $FolderCreation "Shellbags"
    New-Folder $ShellbagsFolder

    $keys = @(
        "HKCU:\Software\Microsoft\Windows\Shell\BagMRU",
        "HKCU:\Software\Microsoft\Windows\Shell\Bags",
        "HKCU:\Software\Microsoft\Windows\ShellNoRoam\BagMRU",
        "HKCU:\Software\Microsoft\Windows\ShellNoRoam\Bags"
    )

    foreach ($key in $keys) {
        try {
            $out = Get-ChildItem -Path $key -Recurse -ErrorAction Stop | Select-Object PSPath, Name, Property, Value
            if ($out) {
                $file = ($key -replace '[:\\]', '_') + ".csv"
                Export-ToCsv -Object $out -FileName $file
            }
            # reg export requires cmd.exe style quoting for some keys
            $regName = ($key -replace '^HKCU:', 'HKCU') -replace '^HKLM:', 'HKLM'
            $regFile = Join-Path $ShellbagsFolder (($key -replace '[:\\]', '_') + ".reg")
            cmd.exe /c "reg export `"$regName`" `"$regFile`" /y" 2>$null | Out-Null
        } catch {
            # key may not exist; ignore
        }
    }
}

function Invoke-DFIRTools {
    Write-Host "Checking for DFIR tools (kape/registry-extractor) in PATH or script folder..." -ForegroundColor Cyan

    $scriptDir = $PSScriptRoot
    if (-not $scriptDir -or -not (Test-Path $scriptDir)) {
        Write-Host "Unable to determine script directory; skipping local tool discovery." -ForegroundColor Yellow
        return
    }

    $candidates = @()

    # 1) Tools in PATH
    $candidates += (Get-Command kape.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    $candidates += (Get-Command registry-extractor.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)

    # 2) Tools next to script (safe Join-Path)
    $kapeLocal = Join-Path -Path $scriptDir -ChildPath "kape.exe"
    $regLocal  = Join-Path -Path $scriptDir -ChildPath "registry-extractor.exe"

    if (Test-Path $kapeLocal) { $candidates += $kapeLocal }
    if (Test-Path $regLocal)  { $candidates += $regLocal }

    $candidates = $candidates | Where-Object { $_ } | Select-Object -Unique

    if (-not $candidates) {
        Write-Host "No DFIR tools found (kape / registry-extractor)." -ForegroundColor Yellow
        return
    }

    foreach ($tool in $candidates) {
        Write-Host "Running DFIR tool: $tool" -ForegroundColor Green

        try {
            if ($tool -match 'kape\.exe$') {
                Start-Process -FilePath $tool `
                    -ArgumentList "--tsource C:\ --tdest `"$FolderCreation\KAPE`" --target Everything --mode S" `
                    -NoNewWindow -Wait
            }
            elseif ($tool -match 'registry-extractor\.exe$') {
                Start-Process -FilePath $tool `
                    -ArgumentList "--output `"$FolderCreation\RegistryExtractor`" --hive C:\Windows\System32\Config\SYSTEM --hive C:\Windows\System32\Config\SOFTWARE" `
                    -NoNewWindow -Wait
            }
        }
        catch {
            Write-Host "Failed to run DFIR tool $tool : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Get-RecycleBin {
    Write-Host "Collecting Recycle Bin contents..."
    $RecycleFolder = Join-Path $FolderCreation "RecycleBin"
    New-Folder $RecycleFolder
    $recycleBin = Get-ChildItem -Path "C:\`$Recycle.Bin" -Recurse -ErrorAction SilentlyContinue |
        Select-Object FullName, Name, LastWriteTime, Length
    $recycleBin | Export-Csv -NoTypeInformation -Path (Join-Path $RecycleFolder "RecycleBin.csv")
}

function Get-JumpLists {
    Write-Host "Collecting Jump Lists..."
    $JumpListFolder = Join-Path $FolderCreation "JumpLists"
    New-Folder $JumpListFolder
    $jumpLists = Get-ChildItem -Path "C:\Users\$currentUsername\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" -Filter *.automaticDestinations-ms -ErrorAction SilentlyContinue |
        Select-Object FullName, LastWriteTime, Length
    $jumpLists | Export-Csv -NoTypeInformation -Path (Join-Path $JumpListFolder "JumpLists.csv")
}

function Get-SRUM {
    Write-Host "Collecting SRUM data..."
    $SRUMFolder = Join-Path $FolderCreation "SRUM"
    New-Folder $SRUMFolder
    $srumPath = "C:\Windows\System32\sru\SRUDB.dat"
    if (Test-Path $srumPath) { Copy-Item -Path $srumPath -Destination $SRUMFolder -Force -ErrorAction SilentlyContinue }
}

function Get-WMIPersistence {
    Write-Host "Collecting WMI persistence..."
    $WMIFolder = Join-Path $FolderCreation "WMI"
    New-Folder $WMIFolder
    $wmiConsumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue | Select-Object Name, __CLASS
    $wmiConsumers | Export-Csv -NoTypeInformation -Path (Join-Path $WMIFolder "WMIConsumers.csv")
    $wmiFilters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Select-Object Name, Query
    $wmiFilters | Export-Csv -NoTypeInformation -Path (Join-Path $WMIFolder "WMIFilters.csv")
}

function Get-SystemRestorePoints {
    Write-Host "Collecting System Restore points..."
    $RestoreFolder = Join-Path $FolderCreation "SystemRestore"
    New-Folder $RestoreFolder
    $restorePoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue |
        Select-Object SequenceNumber, Description, CreationTime, EventType
    $restorePoints | Export-Csv -NoTypeInformation -Path (Join-Path $RestoreFolder "RestorePoints.csv")
}

function Get-ClipboardContents {
    Write-Host "Collecting Clipboard contents..."
    $ClipboardFolder = Join-Path $FolderCreation "Clipboard"
    New-Folder $ClipboardFolder
    $clipboard = Get-Clipboard -TextFormatType Text -ErrorAction SilentlyContinue
    $clipboard | Out-File -Force -FilePath (Join-Path $ClipboardFolder "Clipboard.txt")
}

function Get-MFT {
    Write-Host "Collecting MFT (requires external tool like MFTECmd)..."
    $MFTFolder = Join-Path $FolderCreation "MFT"
    New-Folder $MFTFolder

    $scriptDir = $PSScriptRoot
    $mfteCmd = Get-Command MFTECmd.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    if (-not $mfteCmd) { $mfteCmd = Join-Path $scriptDir "MFTECmd.exe" }
    if (Test-Path $mfteCmd) {
        Start-Process -FilePath $mfteCmd -ArgumentList "-f C:\`$MFT --csv `"$MFTFolder`"" -NoNewWindow -Wait
    }
}

function Get-MemoryDump {
    Write-Host "Collecting Memory dump (requires external tool like DumpIt)..."
    $MemoryFolder = Join-Path $FolderCreation "Memory"
    New-Folder $MemoryFolder

    $scriptDir = $PSScriptRoot
    $dumpIt = Get-Command DumpIt.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    if (-not $dumpIt) { $dumpIt = Join-Path $scriptDir "DumpIt.exe" }
    if (Test-Path $dumpIt) {
        Start-Process -FilePath $dumpIt -ArgumentList "/Q /O `"$MemoryFolder\memory.dmp`"" -NoNewWindow -Wait
    }
}

function Get-RecentFiles {
    Write-Host "Collecting Recent Files (Recent Items)..."
    $RecentFolder = Join-Path $FolderCreation "RecentFiles"
    New-Folder $RecentFolder

    # Windows recent items location (%APPDATA%\Microsoft\Windows\Recent)
    $recentPath = Join-Path $env:APPDATA "Microsoft\Windows\Recent"
    $items = Get-ChildItem -Path $recentPath -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending

    $items | Select-Object FullName, Name, LastWriteTime, Length |
        Export-Csv -NoTypeInformation -Path (Join-Path $RecentFolder "RecentFiles.csv")

    # Copy .lnk as raw artifacts
    $items | Where-Object Extension -eq ".lnk" | ForEach-Object {
        Copy-Item $_.FullName -Destination $RecentFolder -Force -ErrorAction SilentlyContinue
    }
}

function Get-InstalledUpdates {
    Write-Host "Collecting Installed Updates..."
    $UpdatesFolder = Join-Path $FolderCreation "Updates"
    New-Folder $UpdatesFolder

    $hotfix = Get-HotFix -ErrorAction SilentlyContinue
    $hotfix | Out-File -Force -FilePath (Join-Path $UpdatesFolder "InstalledUpdates.txt")
    Export-ToCsv -Object $hotfix -FileName "InstalledUpdates.csv"
}

function Get-WindowsFirewallRules {
    Write-Host "Collecting Windows Firewall Rules..."
    $FwFolder = Join-Path $FolderCreation "Firewall"
    New-Folder $FwFolder

    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Select-Object DisplayName, Enabled, Direction, Action, Profile, Owner, PolicyStoreSourceType

    $rules | Export-Csv -NoTypeInformation -Path (Join-Path $FwFolder "FirewallRules.csv")
    Export-ToCsv -Object $rules -FileName "FirewallRules.csv"
}

function Get-InstalledPrograms {
    Write-Host "Collecting Installed Programs..."
    $AppsFolder = Join-Path $FolderCreation "Applications"
    New-Folder $AppsFolder

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $apps = foreach ($p in $paths) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString
    }

    $apps = $apps | Sort-Object DisplayName -Unique
    $apps | Export-Csv -NoTypeInformation -Path (Join-Path $AppsFolder "InstalledPrograms.csv")
    Export-ToCsv -Object $apps -FileName "InstalledPrograms.csv"
}

function Get-USBDevices {
    Write-Host "Collecting USB Device Information..."
    $UsbFolder = Join-Path $FolderCreation "USB"
    New-Folder $UsbFolder

    $pnp = Get-PnpDevice -ErrorAction SilentlyContinue |
        Where-Object { $_.Class -match "USB|DiskDrive" } |
        Select-Object Class, FriendlyName, InstanceId, Status, Present

    $pnp | Export-Csv -NoTypeInformation -Path (Join-Path $UsbFolder "USBDevices.csv")
    Export-ToCsv -Object $pnp -FileName "USBDevices.csv"
}

function Get-LnkArtifacts {
    Write-Host "Collecting LNK Artifacts..."
    $LnkFolder = Join-Path $FolderCreation "LNK"
    New-Folder $LnkFolder

    $paths = @(
        (Join-Path $env:APPDATA "Microsoft\Windows\Recent"),
        (Join-Path $env:USERPROFILE "Desktop")
    ) | Where-Object { Test-Path $_ }

    $lnks = foreach ($p in $paths) { Get-ChildItem -Path $p -Filter *.lnk -File -ErrorAction SilentlyContinue }

    # Copy raw
    $lnks | ForEach-Object { Copy-Item $_.FullName -Destination $LnkFolder -Force -ErrorAction SilentlyContinue }

    # Resolve targets (best effort)
    $details = @()
    try {
        $wsh = New-Object -ComObject WScript.Shell
        foreach ($l in $lnks) {
            try {
                $sc = $wsh.CreateShortcut($l.FullName)
                $details += [PSCustomObject]@{
                    LnkPath       = $l.FullName
                    LastWriteTime = $l.LastWriteTime
                    TargetPath    = $sc.TargetPath
                    Arguments     = $sc.Arguments
                    WorkingDir    = $sc.WorkingDirectory
                }
            } catch { }
        }
    } catch { }

    if ($details.Count -gt 0) {
        $details | Export-Csv -NoTypeInformation -Path (Join-Path $LnkFolder "LnkDetails.csv")
        Export-ToCsv -Object $details -FileName "LnkDetails.csv"
    }
}

# --- Prefetch / Amcache / UserAssist (PowerForensics optional + fallbacks) ---
function Get-Prefetch {
    Write-Host "Collecting Prefetch..."
    $pfFolder = Join-Path $FolderCreation "Prefetch"
    New-Folder $pfFolder

    if ($PowerForensicsAvailable -and (Get-Command Get-Prefetch -ErrorAction SilentlyContinue)) {
        $pf = Microsoft.PowerShell.Core\Get-Command Get-Prefetch -ErrorAction SilentlyContinue | Out-Null
        $out = Get-Prefetch
        Export-ToCsv -Object $out -FileName "Prefetch.csv"
        $out | Out-File -Force -FilePath (Join-Path $pfFolder "Prefetch.txt")
        return
    }

    # Fallback: copy raw .pf files
    $src = Join-Path $env:WINDIR "Prefetch"
    if (Test-Path $src) {
        Get-ChildItem -Path $src -Filter *.pf -File -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item $_.FullName -Destination $pfFolder -Force -ErrorAction SilentlyContinue
        }
        Get-ChildItem -Path $src -Filter *.pf -File -ErrorAction SilentlyContinue |
            Select-Object FullName, Name, Length, CreationTime, LastWriteTime |
            Export-Csv -NoTypeInformation -Path (Join-Path $pfFolder "PrefetchFiles.csv")
    }
}

function Get-Amcache {
    Write-Host "Collecting Amcache... Requires parser tool to read (amcache-evilhunter, artifast)"
    $amFolder = Join-Path $FolderCreation "Amcache"
    New-Folder $amFolder

    if ($PowerForensicsAvailable -and (Get-Command Get-Amcache -ErrorAction SilentlyContinue)) {
        $out = Get-Amcache
        Export-ToCsv -Object $out -FileName "Amcache.csv"
        $out | Out-File -Force -FilePath (Join-Path $amFolder "Amcache.txt")
        return
    }

    # Fallback: copy amcache hive
    $amHive = "C:\Windows\AppCompat\Programs\Amcache.hve"
    if (Test-Path $amHive) {
        Copy-Item -Path $amHive -Destination (Join-Path $amFolder "Amcache.hve") -Force -ErrorAction SilentlyContinue
    }
}


function Get-UserAssist {
    Write-Host "Collecting UserAssist..."
    $uaFolder = Join-Path $FolderCreation "UserAssist"
    New-Folder $uaFolder

    if ($PowerForensicsAvailable -and (Get-Command Get-UserAssist -ErrorAction SilentlyContinue)) {
        $out = Get-UserAssist
        Export-ToCsv -Object $out -FileName "UserAssist.csv"
        $out | Out-File -Force -FilePath (Join-Path $uaFolder "UserAssist.txt")
        return
    }

    # Fallback: export the raw registry subtree (best effort)
    try {
        $key = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        $regFile = Join-Path $uaFolder "UserAssist.reg"
        cmd.exe /c "reg export `"$key`" `"$regFile`" /y" 2>$null | Out-Null
    } catch { }
}

function Compress-Results {
    if ($NoCompress) {
        Write-Host "Skipping compression (-NoCompress set)." -ForegroundColor Yellow
        return
    }
    Write-Host "Compressing results..." -ForegroundColor Cyan
    $zip = "$FolderCreation.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force -ErrorAction SilentlyContinue }
    try {
        Compress-Archive -Path $FolderCreation -DestinationPath $zip -Force
        Write-Host "Created: $zip" -ForegroundColor Green
    } catch {
        Write-Host "Compression failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --------------------------------------------------------
# Orchestration
# --------------------------------------------------------
function Start-WithoutAdminPrivilege {
    param(
        [Parameter(Mandatory=$false)][string]$UserSid,
        [Parameter(Mandatory=$false)][string]$Username
    )

    Invoke-SafeRun -Context "IP Info"                    -Script { Get-IPInfo }
    Invoke-SafeRun -Context "Open Connections"           -Script { Get-OpenConnections }
    Invoke-SafeRun -Context "AutoRuns"                   -Script { Get-AutoRunInfo }
    Invoke-SafeRun -Context "Active Users"               -Script { Get-ActiveUsers }
    Invoke-SafeRun -Context "Local Users"                -Script { Get-LocalUsers }
    Invoke-SafeRun -Context "Active Processes"           -Script { Get-ActiveProcesses }
    Invoke-SafeRun -Context "Office Connections"         -Script { Get-OfficeConnections -UserSid $UserSid }
    Invoke-SafeRun -Context "Network Shares"             -Script { Get-NetworkShares -UserSid $UserSid }
    Invoke-SafeRun -Context "SMB Shares"                 -Script { Get-SMBShares }
    Invoke-SafeRun -Context "RDP Sessions"               -Script { Get-RDPSessions }
    Invoke-SafeRun -Context "PowerShell History (User)"  -Script { Get-PowershellHistoryCurrentUser }
    Invoke-SafeRun -Context "DNS Cache"                  -Script { Get-DNSCache }
    Invoke-SafeRun -Context "Installed Drivers"          -Script { Get-InstalledDrivers }
    Invoke-SafeRun -Context "Recently Installed (MSI)"   -Script { Get-RecentlyInstalledSoftwareEventLogs }
    Invoke-SafeRun -Context "Running Services"           -Script { Get-RunningServices }
    Invoke-SafeRun -Context "Scheduled Tasks"            -Script { Get-ScheduledTasks }
    Invoke-SafeRun -Context "Scheduled Tasks RunInfo"    -Script { Get-ScheduledTasksRunInfo }
    Invoke-SafeRun -Context "Connected Devices"          -Script { Get-ConnectedDevices }
    Invoke-SafeRun -Context "Recent Files"               -Script { Get-RecentFiles }
    Invoke-SafeRun -Context "Prefetch"                   -Script { Get-Prefetch }
    Invoke-SafeRun -Context "UserAssist"                 -Script { Get-UserAssist }
    Invoke-SafeRun -Context "Installed Updates"          -Script { Get-InstalledUpdates }
    Invoke-SafeRun -Context "Firewall Rules"             -Script { Get-WindowsFirewallRules }
    Invoke-SafeRun -Context "Installed Programs"         -Script { Get-InstalledPrograms }
    Invoke-SafeRun -Context "USB Devices"                -Script { Get-USBDevices }
    Invoke-SafeRun -Context "LNK Artifacts"              -Script { Get-LnkArtifacts }
    Invoke-SafeRun -Context "Recycle Bin"                -Script { Get-RecycleBin }
    Invoke-SafeRun -Context "Jump Lists"                 -Script { Get-JumpLists }
    Invoke-SafeRun -Context "Clipboard"                  -Script { Get-ClipboardContents }

    if ($Username) {
        Invoke-SafeRun -Context "Chromium Files"         -Script { Get-ChromiumFiles -Username $Username }
        Invoke-SafeRun -Context "Firefox Files"          -Script { Get-FirefoxFiles -Username $Username }
        Invoke-SafeRun -Context "Chrome Files"           -Script { Get-ChromeFiles -Username $Username }
        Invoke-SafeRun -Context "Edge Files"             -Script { Get-EdgeFiles -Username $Username }
    }
}

function Start-WithAdminPrivileges {
    Invoke-SafeRun -Context "Security Event Count"       -Script { Get-SecurityEventCount -sw $sw }
    Invoke-SafeRun -Context "Security Events"            -Script { Get-SecurityEvents -sw $sw }
    Invoke-SafeRun -Context "Remotely Opened Files"      -Script { Get-RemotelyOpenedFiles }
    Invoke-SafeRun -Context "Shadow Copies"              -Script { Get-ShadowCopies }
    Invoke-SafeRun -Context "Event Viewer Files"         -Script { Get-EventViewerFiles }
    Invoke-SafeRun -Context "MPLogs"                     -Script { Get-MPLogs }
    Invoke-SafeRun -Context "Defender Exclusions"        -Script { Get-DefenderExclusions }
    Invoke-SafeRun -Context "PS History (All Users)"     -Script { Get-PowershellConsoleHistory-AllUsers }
    Invoke-SafeRun -Context "ShimCache"                  -Script { Get-ShimCache }
    Invoke-SafeRun -Context "Shellbags"                  -Script { Get-Shellbags }
    Invoke-SafeRun -Context "DFIR Tools"                 -Script { Invoke-DFIRTools }
    Invoke-SafeRun -Context "SRUM"                       -Script { Get-SRUM }
    Invoke-SafeRun -Context "WMI Persistence"            -Script { Get-WMIPersistence }
    Invoke-SafeRun -Context "System Restore Points"      -Script { Get-SystemRestorePoints }
    Invoke-SafeRun -Context "MFT"                        -Script { Get-MFT }
    Invoke-SafeRun -Context "Memory Dump"                -Script { Get-MemoryDump }
    Invoke-SafeRun -Context "Amcache"                    -Script { Get-Amcache }
}

# ---------------------------
# Execute
# ---------------------------
Start-WithoutAdminPrivilege -UserSid $currentUserSid -Username $currentUsername
if ($IsAdmin) { Start-WithAdminPrivileges }

Compress-Results
Write-Host "Done. Output: $FolderCreation" -ForegroundColor Green