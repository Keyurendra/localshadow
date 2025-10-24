#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Install and configure AccuKnox Omni for Windows
.DESCRIPTION
    Downloads, installs, and configures AccuKnox Omni with Windows Task Scheduler
.PARAMETER ExtraArgs
    Additional arguments to pass to the Omni agent scan command
.PARAMETER Version
    Version of Omni to install (default: latest)
.PARAMETER Url
    Custom URL to download Omni from
.PARAMETER InstallPath
    Installation path for Omni (default: C:\Program Files\AccuKnox\Omni)
.PARAMETER SkipDownload
    Skip downloading Omni binary
.PARAMETER ArtifactApiToken
    API token for artifact access
.PARAMETER TriggerImmediately
    Run scan immediately after installation (default: true)
.PARAMETER HomeDir
    Home directory for Omni data (default: C:\ProgramData\AccuKnox\Omni)
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments=$true)][string[]]$ExtraArgs = @(),
    [string]$Version = "latest",
    [string]$Url = "",
    [string]$InstallPath = "C:\Program Files\AccuKnox\Omni",
    [bool]$SkipDownload = $false,
    [Parameter(Mandatory=$true)][string]$ArtifactApiToken = "",
    [bool]$TriggerImmediately = $true,
    [string]$HomeDir = "C:\ProgramData\AccuKnox\Omni"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Message)
    Write-Warning "[WARN] $Message"
}

function Write-Fatal {
    param([string]$Message)
    Write-Error "[ERROR] $Message" -ErrorAction Stop
}

function Test-Architecture {
    $arch = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
    switch ($arch) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { Write-Fatal "Unsupported architecture: $arch" }
    }
}

function Get-FileFromUrl {
    param(
        [string]$Url,
        [string]$OutputPath
    )

    try {
        Write-Info "Downloading from $Url..."
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
        Write-Info "Download completed"
    }
    catch {
        Write-Fatal "Download failed: $_"
    }
}

function Install-ClamAV {
    $clamav = Get-Command clamscan -ErrorAction SilentlyContinue
    if (-not $clamav) {
        Write-Info "ClamAV not found. Installing via winget..."
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $winget) {
            Write-Fatal "winget is not installed. Please install Windows Package Manager (winget) first.`nVisit: https://aka.ms/getwinget"
        }
        try {
            & winget install --id=Cisco.ClamAV -e --silent --accept-package-agreements --accept-source-agreements
            Write-Info "ClamAV installed successfully"
            $clamPath = (Get-ChildItem "C:\Program Files" -Directory | Where-Object { $_.Name -match "ClamAV" }).FullName
            $oldPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
            if (-not ($oldPath -split ';' | Where-Object { $_ -eq $clamPath })) {
                [Environment]::SetEnvironmentVariable("Path", "$oldPath;$clamPath", [EnvironmentVariableTarget]::Machine)
                Write-Info "ClamAV path added to system PATH"
            }
            $script:ClamAVPath = $clamPath
            $script:FreshClamPath = Join-Path $clamPath "freshclam.exe"
        }
        catch {
            Write-Fatal "Failed to install ClamAV: $_"
        }
    }
    else {
        Write-Info "ClamAV is already installed at: $($clamav.Source)"
    }
}

function Update-ClamAVDatabase {
    Create-Freshclam-Conf
    Write-Info "Updating ClamAV virus definitions with freshclam..."

    try {
        $freshclamOutput = & $script:FreshClamPath --verbose 2>&1

        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) {
            # exit code 1 means database is already up to date
            Write-Info "ClamAV virus definitions updated successfully"
        }
        else {
            Write-Warn "freshclam completed with exit code $LASTEXITCODE. Output: $freshclamOutput"
        }
    }
    catch {
        Write-Warn "Failed to run freshclam: $_. Continuing with installation..."
    }
}

function New-FreshClamScheduledTask {
    $taskName = "ClamAV Database Update"

    Write-Info "Creating scheduled task for automatic ClamAV updates: $taskName"

    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    $action = New-ScheduledTaskAction `
        -Execute $script:FreshClamPath `
        -Argument "--verbose" `
        -WorkingDirectory $script:ClamAVPath

    $trigger = New-ScheduledTaskTrigger `
        -Once `
        -At 12am `
        -RepetitionInterval (New-TimeSpan -Hours 6)

    $trigger.Repetition.Duration = "" # empty string means indefinite

    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 5)

    $principal = New-ScheduledTaskPrincipal `
        -UserId "NT AUTHORITY\SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    $task = New-ScheduledTask `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "Automatically updates ClamAV virus definitions using freshclam"

    Register-ScheduledTask `
        -TaskName $taskName `
        -InputObject $task | Out-Null

    Write-Info "ClamAV update scheduled task created successfully"
    Write-Info "Updates will run every 6 hours"
}

function Initialize-Environment {
    $script:Arch = Test-Architecture
    Write-Info "Host architecture: $script:Arch"

    if ([string]::IsNullOrEmpty($script:Url)) {
        $script:Url = "https://accuknox-omni.s3.us-east-1.amazonaws.com/$Version/omni-windows-$($script:Arch).exe"
    }

    if ([string]::IsNullOrEmpty($script:ArtifactApiToken)) {
        Write-Fatal "OMNI_ARTIFACT_API_TOKEN cannot be empty"
    }

    $script:OmniBinPath = Join-Path $InstallPath "omni.exe"
    $script:TokenFile = Join-Path $HomeDir "artifact.tok"
    $script:UninstallScript = Join-Path $InstallPath "Uninstall-Omni.ps1"
    $script:LogDir = Join-Path $HomeDir "logs"
    $script:LogFile = Join-Path $script:LogDir "omni-scan.log"
    $script:LogWrapperScript = Join-Path $InstallPath "run-omni-with-logging.ps1"
}

function Test-Url {
    if (-not ($script:Url -match "^https?://")) {
        Write-Fatal "Only http:// and https:// URLs are supported for OMNI_URL (have $($script:Url))"
    }
}

function Save-Token {
    Write-Info "Creating home directory: $HomeDir"
    New-Item -ItemType Directory -Path $HomeDir -Force | Out-Null

    Write-Info "Saving token at $script:TokenFile"
    $script:ArtifactApiToken | Out-File -FilePath $script:TokenFile -NoNewline -Encoding ASCII

    $acl = Get-Acl $script:TokenFile
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null

    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "Allow"
    )
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "Allow"
    )

    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl -Path $script:TokenFile -AclObject $acl
}

function Install-OmniBinary {
    $tempFile = [System.IO.Path]::GetTempFileName()

    try {
        Get-FileFromUrl -Url $script:Url -OutputPath $tempFile

        Write-Info "Installing binary to $script:OmniBinPath"
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        Move-Item -Path $tempFile -Destination $script:OmniBinPath -Force

        if (-not (Test-Path $script:OmniBinPath)) {
            Write-Fatal "Executable omni binary not found at $script:OmniBinPath"
        }
    }
    catch {
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
        throw
    }
}

function New-OmniScheduledTask {
    $taskName = "AccuKnox Omni Scan"

    Write-Info "Removing existing scheduled task if present..."
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null

    Write-Info "Creating scheduled task: $taskName"

    $argsList = @(
        "agent", "scan",
        "--artifact-token-file=$script:TokenFile"
    )

    if ($ExtraArgs.Count -gt 0) {
        $argsList += $ExtraArgs
    }

    $argsString = $argsList -join " "

    $cmdArgument = "/c `"$script:OmniBinPath`" $argsString > $script:LogFile 2>&1"

    $action = New-ScheduledTaskAction `
        -Execute "cmd.exe" `
        -Argument $cmdArgument `
        -WorkingDirectory $HomeDir

    $trigger = New-ScheduledTaskTrigger `
        -Daily `
        -At 2am `
        -RandomDelay (New-TimeSpan -Minutes 10)

    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Hours 2)

    $principal = New-ScheduledTaskPrincipal `
        -UserId "NT AUTHORITY\SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "AccuKnox Omni malware scanning agent" | Out-Null

    Write-Info "Scheduled task created successfully"
    Write-Info "Logs will be written to: $script:LogFile"
}

function Create-Freshclam-Conf {
    Write-Info "Creating freshclam conf: C:\Program Files\ClamAV\freshclam.conf"
    $conf = @"
# Path to the database directory.
# WARNING: It must match clamd.conf's directive!
# WARNING: It must already exist, be an absolute path, be writeable by
# freshclam, and be readable by clamd/clamscan.
# Default: hardcoded (depends on installation options)
DatabaseDirectory "C:\Program Files\ClamAV\database"

# Path to the ClamAV CA certificates directory for verifying CVD signature
# archive digital signatures.
# WARNING: It must match clamd.conf's directive!
# WARNING: It must already exist, be an absolute path, be readable by
# freshclam, clamd, clamscan and sigtool.
# Default: "certs"
#CVDCertsDirectory "C:\Program Files\ClamAV\certs"

# Enforce FIPS-like limits on using hash algorithms for cryptographic purposes.
# Will disable MD5 & SHA1 FP sigs and will require '.sign' files to verify
# CVD authenticity.
# Default: no
#FIPSCryptoHashLimits yes

# Path to the log file (make sure it has proper permissions)
# Default: disabled
#UpdateLogFile "C:\Program Files\ClamAV\freshclam.log"

# Maximum size of the log file.
# Value of 0 disables the limit.
# You may use 'M' or 'm' for megabytes (1M = 1m = 1048576 bytes)
# and 'K' or 'k' for kilobytes (1K = 1k = 1024 bytes).
# in bytes just don't use modifiers. If LogFileMaxSize is enabled,
# log rotation (the LogRotate option) will always be enabled.
# Default: 1M
#LogFileMaxSize 2M

# Log time with each message.
# Default: no
#LogTime yes

# Enable verbose logging.
# Default: no
#LogVerbose yes

# Use system logger (can work together with UpdateLogFile).
# Default: no
#LogSyslog yes

# Specify the type of syslog messages - please refer to 'man syslog'
# for facility names.
# Default: LOG_LOCAL6
#LogFacility LOG_MAIL

# Enable log rotation. Always enabled when LogFileMaxSize is enabled.
# Default: no
#LogRotate yes

# Write the daemon's pid to the specified file.
# You must run freshclam with --daemon (-d) for freshclam to run as a daemon.
# Default: disabled
#PidFile "C:\Program Files\ClamAV\freshclam.pid"

# By default when started freshclam drops privileges and switches to the
# "clamav" user. This directive allows you to change the database owner.
# Default: clamav (may depend on installation options)
#DatabaseOwner clamav

# Use DNS to verify virus database version. FreshClam uses DNS TXT records
# to verify database and software versions. With this directive you can change
# the database verification domain.
# WARNING: Do not touch it unless you're configuring freshclam to use your
# own database verification domain.
# Default: current.cvd.clamav.net
#DNSDatabaseInfo current.cvd.clamav.net

# database.clamav.net is now the primary domain name to be used world-wide.
# Now that CloudFlare is being used as our Content Delivery Network (CDN),
# this one domain name works world-wide to direct freshclam to the closest
# geographic endpoint.
# If the old db.XY.clamav.net domains are set, freshclam will automatically
# use database.clamav.net instead.
DatabaseMirror database.clamav.net

# How many attempts to make before giving up.
# Default: 3 (per mirror)
#MaxAttempts 5

# With this option you can control scripted updates. It's highly recommended
# to keep it enabled.
# Default: yes
#ScriptedUpdates yes

# By default freshclam will keep the local databases (.cld) uncompressed to
# make their handling faster. With this option you can enable the compression;
# the change will take effect with the next database update.
# Default: no
#CompressLocalDatabase no

# With this option you can provide custom sources for database files.
# This option can be used multiple times. Support for:
#   http(s)://, ftp(s)://, or file://
# Default: no custom URLs
#DatabaseCustomURL http://myserver.example.com/mysigs.ndb
#DatabaseCustomURL https://myserver.example.com/mysigs.ndb
#DatabaseCustomURL https://myserver.example.com:4567/allow_list.wdb
#DatabaseCustomURL ftp://myserver.example.com/example.ldb
#DatabaseCustomURL ftps://myserver.example.com:4567/example.ndb
#DatabaseCustomURL file://E:\Share\local.hdb

# This option allows you to easily point freshclam to private mirrors.
# If PrivateMirror is set, freshclam does not attempt to use DNS
# to determine whether its databases are out-of-date, instead it will
# use the If-Modified-Since request or directly check the headers of the
# remote database files. For each database, freshclam first attempts
# to download the CLD file. If that fails, it tries to download the
# CVD file. This option overrides DatabaseMirror, DNSDatabaseInfo
# and ScriptedUpdates. It can be used multiple times to provide
# fall-back mirrors.
# Default: disabled
#PrivateMirror mirror1.example.com
#PrivateMirror mirror2.example.com

# Number of database checks per day.
# Default: 12 (every two hours)
#Checks 24

# Proxy settings
# The HTTPProxyServer may be prefixed with [scheme]:// to specify which kind
# of proxy is used.
#   http://     HTTP Proxy. Default when no scheme or proxy type is specified.
#   https://    HTTPS Proxy. (Added in 7.52.0 for OpenSSL, GnuTLS and NSS)
#   socks4://   SOCKS4 Proxy.
#   socks4a://  SOCKS4a Proxy. Proxy resolves URL hostname.
#   socks5://   SOCKS5 Proxy.
#   socks5h://  SOCKS5 Proxy. Proxy resolves URL hostname.
# Default: disabled
#HTTPProxyServer https://proxy.example.com
#HTTPProxyPort 1234
#HTTPProxyUsername myusername
#HTTPProxyPassword mypass

# If your servers are behind a firewall/proxy which applies User-Agent
# filtering you can use this option to force the use of a different
# User-Agent header.
# As of ClamAV 0.103.3, this setting may not be used when updating from the
# clamav.net CDN and can only be used when updating from a private mirror.
# Default: clamav/version_number (OS: ..., ARCH: ..., CPU: ..., UUID: ...)
#HTTPUserAgent SomeUserAgentIdString

# Use aaa.bbb.ccc.ddd as client address for downloading databases. Useful for
# multi-homed systems.
# Default: Use OS'es default outgoing IP address.
#LocalIPAddress aaa.bbb.ccc.ddd

# Send the RELOAD command to clamd.
# Default: no
#NotifyClamd "C:\Program Files\ClamAV\clamd.conf"

# Run command after successful database update.
# Use EXIT_1 to return 1 after successful database update.
# Default: disabled
#OnUpdateExecute command

# Run command when database update process fails.
# Default: disabled
#OnErrorExecute command

# Run command when freshclam reports outdated version.
# In the command string %v will be replaced by the new version number.
# Default: disabled
#OnOutdatedExecute command

# Don't fork into background.
# Default: no
#Foreground yes

# Enable debug messages in libclamav.
# Default: no
#Debug yes

# Timeout in seconds when connecting to database server.
# Default: 30
#ConnectTimeout 60

# Timeout in seconds when reading from database server. 0 means no timeout.
# Default: 60
#ReceiveTimeout 300

# With this option enabled, freshclam will attempt to load new databases into
# memory to make sure they are properly handled by libclamav before replacing
# the old ones.
# Tip: This feature uses a lot of RAM. If your system has limited RAM and you
# are actively running ClamD or ClamScan during the update, then you may need
# to set `TestDatabases no`.
# Default: yes
#TestDatabases no

# This option enables downloading of bytecode.cvd, which includes additional
# detection mechanisms and improvements to the ClamAV engine.
# Default: yes
#Bytecode no

# Include an optional signature databases (opt-in).
# This option can be used multiple times.
#ExtraDatabase dbname1
#ExtraDatabase dbname2

# Exclude a standard signature database (opt-out).
# This option can be used multiple times.
#ExcludeDatabase dbname1
#ExcludeDatabase dbname2
"@
    $conf | Out-File -FilePath "C:\Program Files\ClamAV\freshclam.conf" -Encoding UTF8
}

try {
    Write-Info "Starting AccuKnox Omni installation for Windows..."
    Initialize-Environment
    Test-Url
    Install-ClamAV
    Update-ClamAVDatabase
    New-FreshClamScheduledTask
    Save-Token
    if (-not $SkipDownload) {
        Install-OmniBinary
    }
    else {
        Write-Info "Skipping download as requested"
        if (-not (Test-Path $script:OmniBinPath)) {
            Write-Fatal "Omni binary not found at $script:OmniBinPath and download was skipped"
        }
    }
    New-OmniScheduledTask
    if ($TriggerImmediately) {
        Write-Info "Starting initial scan..."
        Start-ScheduledTask -TaskName "AccuKnox Omni Scan"
    }
    Write-Info "Installation completed successfully!"
    Write-Info ""
    Write-Info "Log File Location: $script:LogFile"
    Write-Info ""
    Write-Info "Omni Scan Commands:"
    Write-Info "  Check task status:     Get-ScheduledTask -TaskName 'AccuKnox Omni Scan'"
    Write-Info "  View task info:        Get-ScheduledTaskInfo -TaskName 'AccuKnox Omni Scan'"
    Write-Info "  Run scan manually:     Start-ScheduledTask -TaskName 'AccuKnox Omni Scan'"
    Write-Info "  View live log:         Get-Content '$script:LogFile' -Wait"
    Write-Info ""
    Write-Info "ClamAV Update Commands:"
    Write-Info "  Check update task:     Get-ScheduledTask -TaskName 'ClamAV Database Update'"
    Write-Info "  View update info:      Get-ScheduledTaskInfo -TaskName 'ClamAV Database Update'"
    Write-Info "  Update manually:       Start-ScheduledTask -TaskName 'ClamAV Database Update'"
}
catch {
    Write-Fatal $_.Exception.Message
}
