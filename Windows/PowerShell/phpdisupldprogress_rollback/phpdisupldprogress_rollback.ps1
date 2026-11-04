<#
Author: Security Research Team TRURisk Mitigate
Mitigation: Harden PHP session upload-progress handling on Windows (IIS
FastCGI and Apache httpd), across every configuration location PHP honours.
Windows port of phpdisupldprogress.py. Requires Windows PowerShell 3.0+.

Vulnerability:
PHP's session upload-progress feature tracks the state of in-flight file
uploads inside the user's session. When it is enabled the upload path can be
abused (session data growth / manipulation of session state driven purely by
unauthenticated multipart uploads). Disabling the feature and forcing session
identifiers to be carried only in cookies removes the exposed surface.

Settings enforced:
    session.upload_progress.enabled -> Off  [php.ini, drop-ins, .user.ini, .htaccess]
    session.use_only_cookies        -> On   [php.ini, drop-ins, .user.ini, .htaccess]
    memory_limit                    -> -1   [php.ini, drop-ins]
    expose_php                      -> 0    [php.ini, drop-ins]
    fatal_error_backtraces          -> 0    [php.ini, drop-ins]
    post_max_size                   -> 32M   [php.ini, drop-ins]
                                       (any other value -- smaller like 8M,
                                        larger, 0 = unlimited, or malformed --
                                        is rewritten to exactly 32M)
    upload_max_filesize             -> < post_max_size, per runtime
                                       (lowered to 1M under post_max_size)

Where they are applied:
    1. Every php.ini used by a PHP runtime on the host. Runtimes are found from
       IIS FastCGI applications (applicationHost.config: fullPath, -c argument,
       PHPRC / PHP_INI_SCAN_DIR environment variables), Apache services
       (PHPIniDir, LoadModule php*_module, FcgidWrapper, FcgidInitialEnv, the
       service registry Environment), running php-cgi.exe processes and common
       install locations. Each runtime binary is asked which php.ini it loads
       (php-cgi.exe -i / php.exe --ini, with that runtime's environment).
    2. conf.d drop-ins in every PHP_INI_SCAN_DIR: a line that sets an enforced
       directive to a non-compliant value is rewritten in place with a revert
       marker. Drop-ins that do not mention an enforced directive are untouched.
    3. With --PORT: the IIS site bound to that port (physical path of every
       application / virtual directory) and the Apache virtual host listening
       on it (DocumentRoot). Existing .user.ini files there get the session
       directives; existing .htaccess files (Apache only) that already carry
       php_* directives get them inside the same <IfModule> block. Files are
       never created. Reparse points (symlinks / junctions) are skipped.

Scoping:
    php.ini and drop-in changes are global by nature. --PORT scopes the
    per-directory changes. --SERVICE, --SSL, --PROTOCOL and --FQDN are accepted
    for compatibility and ignored. Options also accept --NAME=value.

Service restart:
    Before restarting, every PHP runtime is started with "-v" and its startup
    errors are compared with a baseline taken before the change; Apache is
    tested with "httpd.exe -n <service> -t". A new error during mitigation
    restores the original files and nothing is restarted. Then every IIS
    application pool hosting php-cgi.exe (plus the pools of the -PORT site) is
    recycled with appcmd, and every running Apache service that loads PHP is
    restarted with "httpd.exe -n <service> -k restart". Any standalone
    php-cgi.exe (one no web server manages - parent is not w3wp.exe, httpd.exe
    or a php-cgi.exe manager) is killed and relaunched with its original command
    line (so -b <addr:port>, -c <php.ini> and other arguments are preserved) once
    the old process has fully exited. Success requires every PHP worker
    (php-cgi.exe under w3wp/httpd, mod_php httpd children) to have started after
    the restart; any older worker keeps the previous state and the run FAILS.

Backup model:
    One manifest under %ProgramData%\Qualys\ holds the exact original bytes
    (base64) of every file about to be modified, written atomically, ACL'd to
    Administrators/SYSTEM and marked read-only. Rollback restores from it and
    falls back to the inline revert markers when it is missing or unreadable.
    Rollback runs whenever a backup or markers exist.

Concurrency and file safety:
    mitigate and rollback hold a global named mutex for the whole run. Every
    write goes to a temp file in the same directory and is swapped in with
    File.Replace (ReplaceFile keeps the original ACL and attributes); a file
    that changed after it was read is not overwritten. Bytes are handled as
    Latin-1 so line endings, BOMs and non-ASCII bytes round-trip exactly.

Usage:
    powershell.exe -ExecutionPolicy Bypass -File phpdisupldprogress_rollback.ps1

    This script only rolls back the mitigation. It takes no arguments and has no
    mitigate function; use phpdisupldprogress_mitigate.ps1 to apply the mitigation.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$SUCCESS = 0
$FAILURE = 1
$SKIP = 101
$UNMITIGATE = 201
$EXISTS = 33
# Internal (never used as exit codes)
$CORRUPT = -1
$CONFIG_INVALID = -2

# --------------------- MITIGATION DEFINITION ---------------------
# post_max_size: only exactly POST_MAX_CAP (32M) is compliant. Every other
# value -- a smaller one such as 8M, a larger one, 0 (= unlimited) or an
# unparseable one -- is rewritten to POST_MAX_CAP. upload_max_filesize must
# stay below the post_max_size in force; when it is not, it is lowered to 1M
# under it (PHP default: 2M).
$POST_MAX_CAP = '32M'
$UPLOAD_KEY = 'upload_max_filesize'
$PHP_DEFAULT_UPLOAD = '2M'

function New-Directive([string]$Key, [string]$Val, [string]$Mode, $Desired) {
    return @{ Key = $Key; Val = $Val; Mode = $Mode; Desired = $Desired }
}
$SESSION_INI = @(
    (New-Directive 'session.upload_progress.enabled' 'Off' 'bool' $false),
    (New-Directive 'session.use_only_cookies' 'On' 'bool' $true)
)
$ENGINE_INI = @(
    (New-Directive 'memory_limit' '-1' 'exact' $null),
    (New-Directive 'expose_php' '0' 'exact' $null),
    (New-Directive 'fatal_error_backtraces' '0' 'exact' $null),
    (New-Directive 'post_max_size' $POST_MAX_CAP 'eq_bytes' $null)
)
$INI_DIRECTIVES = $SESSION_INI + $ENGINE_INI
$USERINI_DIRECTIVES = $SESSION_INI
$HTACCESS_DIRECTIVES = $SESSION_INI
$HTACCESS_KEYWORDS = @('php_flag', 'php_value', 'php_admin_flag', 'php_admin_value')

$BACKUP_DIR = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Qualys'
$BACKUP_PATH = Join-Path $BACKUP_DIR 'phpdisupldprogress.qlys.bak'
$BACKUP_VERSION = 2
$MUTEX_NAME = 'Global\phpdisupldprogress.qlys'
$LOCK_TIMEOUT = 120
$CMD_TIMEOUT = 60
$RESTART_TIMEOUT = 180
$WORKER_FRESH_TIMEOUT = 150    # IIS shutdownTimeLimit defaults to 90s
$START_SLACK_SEC = 0.5

$TAG_MODIFIED = 'QLYS_UPLDPROG_ORIG:'
$TAG_ADDED = 'QLYS_UPLDPROG_ADDED'
$USER_INI_NAME = '.user.ini'
$HTACCESS_NAME = '.htaccess'
$EXCLUDED_DIRS = @('.git', 'node_modules', 'vendor', '__pycache__')

$ORD = [StringComparison]::Ordinal
$ORDI = [StringComparison]::OrdinalIgnoreCase
$LATIN1 = [Text.Encoding]::GetEncoding(28591)
$BOM_UTF8 = [string]([char]0xEF) + [char]0xBB + [char]0xBF
$RxIC = [Text.RegularExpressions.RegexOptions]::IgnoreCase
$LINE_RX = New-Object Text.RegularExpressions.Regex('[^\n]*\n|[^\n]+\z')
$KEY_RX = New-Object Text.RegularExpressions.Regex('^\s*(?:php_(?:admin_)?(?:flag|value)\s+)?([^\s=]+)', $RxIC)
$IFMOD_OPEN_RX = New-Object Text.RegularExpressions.Regex('^\s*<IfModule\b', $RxIC)
$IFMOD_CLOSE_RX = New-Object Text.RegularExpressions.Regex('^\s*</IfModule\s*>', $RxIC)
$HT_PHP_RX = New-Object Text.RegularExpressions.Regex(('^\s*(' + ($HTACCESS_KEYWORDS -join '|') + ')\s+'), $RxIC)

$script:AffectedPort = $null
$script:TargetService = $null
$script:Mutex = $null
$script:Env = $null        # discovered environment (runtimes, IIS, Apache)


# --------------------- LOGGING ---------------------
function Write-QLog([int]$Code, [string]$Fn, [string]$Msg) {
    $sym = switch ($Code) { 0 { '[x]' } 1 { '[+]' } 2 { '[!]' } 3 { '[i]' } default { '[-]' } }
    $m = (($Msg -split '\s+') | Where-Object { $_ -ne '' }) -join ' '
    if (-not $m) { return }
    # Console.Out, not Write-Output: logging must never leak into function return values.
    [Console]::Out.WriteLine(('[{0}] Function Name: {1} | Msg: {2} {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Fn, $sym, $m))
}


# --------------------- COMMAND HELPER ---------------------
function ConvertTo-ArgString([string[]]$Arguments) {
    # Quote per the MSVC/CommandLineToArgvW rules.
    $parts = foreach ($a in $Arguments) {
        if ($a -eq '') { '""' }
        elseif ($a -notmatch '[\s"]') { $a }
        else { '"' + (($a -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"' }
    }
    return ($parts -join ' ')
}

function Invoke-Cmd {
    <# Runs a program with a timeout and an explicit environment overlay.
       Returns @{RC; Out; Err}. Never throws. Env values of $null remove the
       variable for the child. #>
    param([string]$File, [string[]]$Arguments = @(), [hashtable]$EnvOverlay = @{},
          [string]$WorkDir = $null, [int]$TimeoutSec = $CMD_TIMEOUT)
    $outF = [IO.Path]::GetTempFileName()
    $errF = [IO.Path]::GetTempFileName()
    $saved = @{}
    try {
        foreach ($k in $EnvOverlay.Keys) {
            $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
            [Environment]::SetEnvironmentVariable($k, $EnvOverlay[$k], 'Process')
        }
        $sp = @{ FilePath = $File; NoNewWindow = $true; PassThru = $true
                 RedirectStandardOutput = $outF; RedirectStandardError = $errF }
        $argStr = ConvertTo-ArgString $Arguments
        if ($argStr) { $sp['ArgumentList'] = $argStr }
        if ($WorkDir) { $sp['WorkingDirectory'] = $WorkDir }
        $p = Start-Process @sp
        $null = $p.Handle          # cache the handle so ExitCode is available (PS 3.0 quirk)
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            try { $p.Kill() } catch { }
            return @{ RC = 124; Out = ''; Err = "timed out after ${TimeoutSec}s" }
        }
        $p.WaitForExit()
        return @{ RC = $p.ExitCode
                  Out = ([IO.File]::ReadAllText($outF)).Trim()
                  Err = ([IO.File]::ReadAllText($errF)).Trim() }
    } catch {
        return @{ RC = 1; Out = ''; Err = $_.Exception.Message }
    } finally {
        foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') }
        Remove-Item -LiteralPath $outF, $errF -Force -ErrorAction SilentlyContinue
    }
}


# --------------------- ADMIN CHECK / LOCK ---------------------
function Test-Admin {
    $fn = 'check_admin'
    try {
        Write-QLog 3 $fn 'Checking administrator privilege'
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-QLog 0 $fn 'This script must be run from an elevated (Administrator) session'
            return $FAILURE
        }
        Write-QLog 1 $fn 'Script is running with administrator privilege'
        return $SUCCESS
    } catch {
        Write-QLog 0 $fn "Error checking privilege: $($_.Exception.Message)"
        return $FAILURE
    }
}

function Get-RunLock([int]$TimeoutSec = $LOCK_TIMEOUT) {
    <# Global named mutex held for the whole run; released by the OS on exit. #>
    $fn = 'acquire_lock'
    try {
        $script:Mutex = New-Object Threading.Mutex($false, $MUTEX_NAME)
        $got = $false
        try {
            $got = $script:Mutex.WaitOne(0)
            if (-not $got) {
                Write-QLog 2 $fn "Another run holds $MUTEX_NAME; waiting up to ${TimeoutSec}s"
                $got = $script:Mutex.WaitOne([TimeSpan]::FromSeconds($TimeoutSec))
            }
        } catch [Threading.AbandonedMutexException] {
            $got = $true   # previous holder died; we own it now
        }
        if (-not $got) {
            Write-QLog 0 $fn "Timed out waiting for $MUTEX_NAME"
            return $FAILURE
        }
        Write-QLog 1 $fn "Acquired run lock $MUTEX_NAME"
        return $SUCCESS
    } catch {
        Write-QLog 0 $fn "Cannot acquire run lock: $($_.Exception.Message)"
        return $FAILURE
    }
}


# --------------------- SAFE FILE I/O ---------------------
function Split-Lines([string]$Text) {
    <# Lines keep their own endings, so joining gives the original back. A
       missing final newline is added so lines can be appended. #>
    $list = New-Object 'System.Collections.Generic.List[string]'
    foreach ($m in $LINE_RX.Matches($Text)) { $list.Add($m.Value) }
    $nl = "`n"
    if ($list.Count -gt 0 -and $list[0].EndsWith("`r`n", $ORD)) { $nl = "`r`n" }
    if ($list.Count -gt 0 -and -not $list[$list.Count - 1].EndsWith("`n", $ORD)) {
        $list[$list.Count - 1] = $list[$list.Count - 1] + $nl
    }
    return @{ Lines = $list; NL = $nl }
}

function Test-ReparsePoint([string]$Path) {
    return ([bool]([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint))
}

function Read-Lines([string]$Path) {
    <# Throws IO.FileNotFoundException when absent. Returns
       @{Lines; NL; Bom; Ticks; Length}. Bytes are decoded as Latin-1, a
       lossless 1:1 byte mapping. #>
    $fi = New-Object IO.FileInfo($Path)
    if (-not $fi.Exists) { throw (New-Object IO.FileNotFoundException('File not found', $Path)) }
    if ($fi.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing to read reparse point (symlink/junction): $Path" }
    $ticks = $fi.LastWriteTimeUtc.Ticks
    $len = $fi.Length
    $text = $LATIN1.GetString([IO.File]::ReadAllBytes($Path))
    $bom = ''
    if ($text.StartsWith($BOM_UTF8, $ORD)) { $bom = $BOM_UTF8; $text = $text.Substring(3) }
    $s = Split-Lines $text
    return @{ Lines = $s.Lines; NL = $s.NL; Bom = $bom; Ticks = $ticks; Length = $len }
}

function Write-FileAtomic([string]$Path, [byte[]]$Data, $Expected = $null) {
    <# Temp file in the same directory, flushed to disk, swapped in with
       File.Replace (keeps ACL/attributes) or moved into place when the target
       is new. Refuses reparse points and files that changed since read. #>
    $fn = 'write_atomic'
    $dir = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
    $exists = [IO.File]::Exists($Path)
    $tmp = $null
    try {
        $roWasSet = $false
        if ($exists) {
            $fi = New-Object IO.FileInfo($Path)
            if ($fi.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                Write-QLog 0 $fn "Refusing to write ${Path}: reparse point (symlink/junction)"
                return $FAILURE
            }
            if ($null -ne $Expected -and ($fi.LastWriteTimeUtc.Ticks -ne $Expected.Ticks -or $fi.Length -ne $Expected.Length)) {
                Write-QLog 0 $fn "Refusing to write ${Path}: it changed after it was read"
                return $FAILURE
            }
            $roWasSet = [bool]($fi.Attributes -band [IO.FileAttributes]::ReadOnly)
        } elseif ($null -ne $Expected) {
            Write-QLog 0 $fn "Refusing to write ${Path}: it was removed after it was read"
            return $FAILURE
        }
        $tmp = Join-Path $dir ('.qlys-' + [Guid]::NewGuid().ToString('N') + '.tmp')
        $fs = New-Object IO.FileStream($tmp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $fs.Write($Data, 0, $Data.Length); $fs.Flush($true) } finally { $fs.Dispose() }
        if ($exists) {
            if ($roWasSet) { [IO.File]::SetAttributes($Path, ([IO.File]::GetAttributes($Path) -band (-bnot [IO.FileAttributes]::ReadOnly))) }
            try {
                # NullString: a plain $null would be passed to .NET as "" (no backup file wanted)
                [IO.File]::Replace($tmp, $Path, [System.Management.Automation.Language.NullString]::Value)
            } finally {
                if ($roWasSet) { [IO.File]::SetAttributes($Path, ([IO.File]::GetAttributes($Path) -bor [IO.FileAttributes]::ReadOnly)) }
            }
        } else {
            [IO.File]::Move($tmp, $Path)
        }
        $tmp = $null
        return $SUCCESS
    } catch {
        Write-QLog 0 $fn "Error writing ${Path}: $($_.Exception.Message)"
        return $FAILURE
    } finally {
        if ($tmp -and [IO.File]::Exists($tmp)) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Write-Lines([string]$Path, $Lines, $Read) {
    $data = $LATIN1.GetBytes($Read.Bom + ($Lines -join ''))
    $rc = Write-FileAtomic $Path $data $Read
    if ($rc -eq $SUCCESS) { Write-QLog 1 'write_lines' "Updated $Path" }
    return $rc
}

function Read-Raw([string]$Path) {
    if (-not [IO.File]::Exists($Path)) { throw (New-Object IO.FileNotFoundException('File not found', $Path)) }
    if (Test-ReparsePoint $Path) { throw "Refusing to read reparse point (symlink/junction): $Path" }
    return ,[IO.File]::ReadAllBytes($Path)
}


# --------------------- VALUE / INI HELPERS ---------------------
function ConvertTo-PhpBool([string]$Value) {
    $v = $Value.Trim().Trim('"').Trim("'").ToLowerInvariant()
    if (@('1', 'on', 'true', 'yes') -contains $v) { return $true }
    if (@('0', 'off', 'false', 'no', '') -contains $v) { return $false }
    return $null
}

function ConvertFrom-PhpBytes([string]$Value) {
    <# PHP shorthand bytes (8M, 8192K, 8388608) -> [long]; $null when absent/malformed. #>
    if ($null -eq $Value) { return $null }
    $m = [regex]::Match($Value.Trim().Trim('"').Trim("'").ToLowerInvariant(), '^(\d+)\s*([kmg]?)$')
    if (-not $m.Success) { return $null }
    $unit = @{ '' = 1L; 'k' = 1024L; 'm' = 1048576L; 'g' = 1073741824L }[$m.Groups[2].Value]
    try { return ([long]$m.Groups[1].Value) * $unit } catch { return $null }
}

function Format-PhpBytes([long]$N) {
    if ($N % 1048576L -eq 0) { return ('{0}M' -f ($N / 1048576L)) }
    if ($N % 1024L -eq 0) { return ('{0}K' -f ($N / 1024L)) }
    return [string]$N
}

function Get-Below([long]$Limit) {
    <# 1M under the limit (half of it for limits of 2M or less). #>
    if ($Limit -gt 2097152L) { return ($Limit - 1048576L) }
    return [long][Math]::Max(1, [Math]::Floor($Limit / 2))
}

function Test-DirOk($Eff, $Directive) {
    <# bool -> boolean equals Desired; exact -> string equals Val;
       eq_bytes -> bytes exactly equals Val; max_bytes -> 0 < bytes <= Val;
       lt_bytes -> 0 < bytes < Desired (bytes). #>
    if ($null -eq $Eff) { return $false }
    if ($Directive.Mode -eq 'bool') {
        $b = ConvertTo-PhpBool $Eff
        return ($null -ne $b -and $b -eq $Directive.Desired)
    }
    if ($Directive.Mode -eq 'eq_bytes') {
        # Compliant only when the value is exactly Val (compared by byte count,
        # so 32M / 32768K / 33554432 are all treated as the same). Anything else
        # -- including a smaller value like 8M -- is rewritten to Val.
        $b = ConvertFrom-PhpBytes $Eff
        return ($null -ne $b -and $b -eq (ConvertFrom-PhpBytes $Directive.Val))
    }
    if ($Directive.Mode -eq 'max_bytes') {
        $b = ConvertFrom-PhpBytes $Eff
        return ($null -ne $b -and $b -gt 0 -and $b -le (ConvertFrom-PhpBytes $Directive.Val))
    }
    if ($Directive.Mode -eq 'lt_bytes') {
        $b = ConvertFrom-PhpBytes $Eff
        return ($null -ne $b -and $b -gt 0 -and $b -lt [long]$Directive.Desired)
    }
    return ($Eff.Trim().Trim('"').Trim("'").ToLowerInvariant() -ceq $Directive.Val.Trim().ToLowerInvariant())
}

function New-KeyRegex([string]$Key) {
    return (New-Object Text.RegularExpressions.Regex(('^\s*' + [regex]::Escape($Key) + '\s*=(.*)$')))
}

function Get-IniValue([string]$Raw) {
    return $Raw.Split([char]';')[0].Trim()
}

function Test-CommentOrBlank([string]$Line, [bool]$HashOnly = $false) {
    $s = $Line.Trim()
    if ($s -eq '') { return $true }
    if ($s.StartsWith('#', $ORD)) { return $true }
    if (-not $HashOnly -and $s.StartsWith(';', $ORD)) { return $true }
    return $false
}

function Get-EffectiveValue($Lines, [string]$Key) {
    $rx = New-KeyRegex $Key
    $value = $null
    foreach ($line in $Lines) {
        if (Test-CommentOrBlank $line) { continue }
        $m = $rx.Match($line)
        if ($m.Success) { $value = Get-IniValue $m.Groups[1].Value }
    }
    return $value
}

function New-HtaccessRegex([string]$Setting) {
    return (New-Object Text.RegularExpressions.Regex(('^(\s*)(' + ($HTACCESS_KEYWORDS -join '|') + ')\s+' + [regex]::Escape($Setting) + '\s+(\S+)\s*$'), $RxIC))
}

function Get-HtaccessEffective($Lines, [string]$Setting) {
    $rx = New-HtaccessRegex $Setting
    $value = $null
    foreach ($line in $Lines) {
        if (Test-CommentOrBlank $line $true) { continue }
        $m = $rx.Match($line)
        if ($m.Success) { $value = $m.Groups[3].Value }
    }
    if ($null -eq $value) { return $null }
    return (ConvertTo-PhpBool $value)
}

function Test-HtaccessHasPhp($Lines) {
    foreach ($line in $Lines) {
        if (Test-CommentOrBlank $line $true) { continue }
        if ($HT_PHP_RX.IsMatch($line)) { return $true }
    }
    return $false
}

function Get-HtaccessInsertPoint($Lines) {
    <# Where new php_* lines go so they share the guard of the first existing
       php_* directive. Returns @{Index; Indent}; Index -1 = append at end. #>
    $stack = New-Object 'System.Collections.Generic.Stack[int]'
    $target = -1
    $indent = ''
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i]
        if (Test-CommentOrBlank $line $true) { continue }
        if ($IFMOD_OPEN_RX.IsMatch($line)) { $stack.Push($i); continue }
        if ($IFMOD_CLOSE_RX.IsMatch($line)) {
            $opened = -2
            if ($stack.Count -gt 0) { $opened = $stack.Pop() }
            if ($target -ge 0 -and $opened -eq $target) { return @{ Index = $i; Indent = $indent } }
            continue
        }
        if ($target -lt 0 -and $HT_PHP_RX.IsMatch($line)) {
            $indent = $line.Substring(0, $line.Length - $line.TrimStart().Length)
            if ($stack.Count -eq 0) { return @{ Index = -1; Indent = $indent } }
            $target = $stack.Peek()
        }
    }
    return @{ Index = -1; Indent = $indent }
}


# --------------------- PROCESS / SERVICE DISCOVERY ---------------------
function Get-ProcTable {
    <# One WMI query for every process this script cares about. #>
    $rows = @{}
    $q = "Name='php-cgi.exe' OR Name='php.exe' OR Name='httpd.exe' OR Name='w3wp.exe'"
    foreach ($p in @(Get-WmiObject -Class Win32_Process -Filter $q)) {
        $start = $null
        if ($p.CreationDate) { $start = [Management.ManagementDateTimeConverter]::ToDateTime($p.CreationDate).ToUniversalTime() }
        $rows[[int]$p.ProcessId] = @{
            Id = [int]$p.ProcessId; ParentId = [int]$p.ParentProcessId
            Name = ([string]$p.Name).ToLowerInvariant(); Path = [string]$p.ExecutablePath
            Cmd = [string]$p.CommandLine; Start = $start
        }
    }
    return $rows
}

function Get-PhpWorkers($Table, $ModPhpExes) {
    <# php-cgi.exe children of w3wp/httpd, and httpd children of httpd when that
       httpd.exe build loads mod_php. #>
    $workers = New-Object 'System.Collections.Generic.List[object]'
    foreach ($p in $Table.Values) {
        if (-not $Table.ContainsKey($p.ParentId)) { continue }
        $parent = $Table[$p.ParentId]
        if ($p.Name -eq 'php-cgi.exe' -and @('w3wp.exe', 'httpd.exe') -contains $parent.Name) {
            $workers.Add($p)
        } elseif ($p.Name -eq 'httpd.exe' -and $parent.Name -eq 'httpd.exe' -and $p.Path -and
                  ($ModPhpExes -contains $p.Path.ToLowerInvariant())) {
            $workers.Add($p)
        }
    }
    return ,$workers
}

function Get-ArgValue([string]$CommandLine, [string]$Switch) {
    $m = [regex]::Match($CommandLine, ('(?:^|\s)' + [regex]::Escape($Switch) + '\s*(?:"([^"]+)"|(\S+))'))
    if (-not $m.Success) { return $null }
    if ($m.Groups[1].Success) { return $m.Groups[1].Value }
    return $m.Groups[2].Value
}

function Get-SystemPath([string]$Child) {
    $sys = 'System32'
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { $sys = 'sysnative' }
    return (Join-Path (Join-Path $env:windir $sys) $Child)
}

function Expand-Path([string]$Path, [string]$Base = $null) {
    if (-not $Path) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"')).Replace('/', '\')
    if ($Base -and -not [IO.Path]::IsPathRooted($p)) { $p = Join-Path $Base $p }
    try { return [IO.Path]::GetFullPath($p) } catch { return $p }
}

function Get-IisInfo {
    <# Parse applicationHost.config: FastCGI applications (PHP runtimes) and
       sites (bindings, applications, physical paths, app pools). #>
    $fn = 'get_iis_info'
    $info = @{ Present = $false; FastCgi = (New-Object 'System.Collections.Generic.List[object]'); Sites = (New-Object 'System.Collections.Generic.List[object]') }
    $cfg = Get-SystemPath 'inetsrv\config\applicationHost.config'
    if (-not [IO.File]::Exists($cfg)) { return $info }
    $info.Present = $true
    try {
        $xml = New-Object Xml.XmlDocument
        $xml.Load($cfg)
    } catch {
        Write-QLog 2 $fn "Cannot parse ${cfg}: $($_.Exception.Message)"
        return $info
    }
    foreach ($a in @($xml.SelectNodes('/configuration/system.webServer/fastCgi/application'))) {
        $envs = @{}
        foreach ($e in @($a.SelectNodes('environmentVariables/environmentVariable'))) { $envs[$e.GetAttribute('name').ToUpperInvariant()] = $e.GetAttribute('value') }
        $info.FastCgi.Add(@{ FullPath = (Expand-Path $a.GetAttribute('fullPath')); Arguments = $a.GetAttribute('arguments'); Env = $envs })
    }
    $defPool = 'DefaultAppPool'
    $d = $xml.SelectSingleNode('/configuration/system.applicationHost/sites/applicationDefaults')
    if ($null -ne $d -and $d.GetAttribute('applicationPool')) { $defPool = $d.GetAttribute('applicationPool') }
    foreach ($s in @($xml.SelectNodes('/configuration/system.applicationHost/sites/site'))) {
        $sitePool = $defPool
        $sd = $s.SelectSingleNode('applicationDefaults')
        if ($null -ne $sd -and $sd.GetAttribute('applicationPool')) { $sitePool = $sd.GetAttribute('applicationPool') }
        $ports = New-Object 'System.Collections.Generic.List[string]'
        foreach ($b in @($s.SelectNodes('bindings/binding'))) {
            if (@('http', 'https') -notcontains $b.GetAttribute('protocol').ToLowerInvariant()) { continue }
            $m = [regex]::Match($b.GetAttribute('bindingInformation'), ':(\d+):[^:]*$')
            if ($m.Success) { $ports.Add($m.Groups[1].Value) }
        }
        $pools = New-Object 'System.Collections.Generic.List[string]'
        $paths = New-Object 'System.Collections.Generic.List[string]'
        foreach ($app in @($s.SelectNodes('application'))) {
            $pool = $app.GetAttribute('applicationPool')
            if (-not $pool) { $pool = $sitePool }
            if (-not $pools.Contains($pool)) { $pools.Add($pool) }
            foreach ($v in @($app.SelectNodes('virtualDirectory'))) {
                $pp = Expand-Path $v.GetAttribute('physicalPath')
                if ($pp -and -not $paths.Contains($pp)) { $paths.Add($pp) }
            }
        }
        $info.Sites.Add(@{ Name = $s.GetAttribute('name'); Ports = $ports; Pools = $pools; Paths = $paths })
    }
    return $info
}

function Read-ApacheConf([string]$File, [string]$ServerRoot, $State, [int]$Depth = 0) {
    <# Minimal httpd.conf reader: Define/${VAR}, ServerRoot, Include(Optional),
       LoadModule php*, PHPIniDir, FcgidWrapper, FcgidInitialEnv, Listen,
       <VirtualHost> ports and DocumentRoot. #>
    $fn = 'read_apache_conf'
    if ($Depth -gt 16 -or $State.Files -contains $File) { return }
    $State.Files.Add($File)
    try { $raw = [IO.File]::ReadAllLines($File) } catch { Write-QLog 2 $fn "Cannot read ${File}: $($_.Exception.Message)"; return }
    $joined = New-Object 'System.Collections.Generic.List[string]'
    $buf = ''
    foreach ($l in $raw) {
        if ($l.EndsWith('\', $ORD)) { $buf += $l.Substring(0, $l.Length - 1) + ' '; continue }
        $joined.Add($buf + $l); $buf = ''
    }
    foreach ($line0 in $joined) {
        $line = $line0.Trim()
        if (-not $line -or $line.StartsWith('#', $ORD)) { continue }
        foreach ($k in @($State.Defines.Keys)) { $line = $line.Replace('${' + $k + '}', $State.Defines[$k]) }
        $tok = New-Object 'System.Collections.Generic.List[string]'
        foreach ($m in [regex]::Matches($line, '"([^"]*)"|(\S+)')) {
            if ($m.Groups[1].Success) { $tok.Add($m.Groups[1].Value) } else { $tok.Add($m.Groups[2].Value) }
        }
        $d = $tok[0].ToLowerInvariant()
        $root = $State.ServerRoot
        switch -regex ($d) {
            '^define$' { if ($tok.Count -ge 3) { $State.Defines[$tok[1]] = $tok[2] } }
            '^serverroot$' { if ($tok.Count -ge 2) { $State.ServerRoot = Expand-Path $tok[1] } }
            '^include(optional)?$' {
                if ($tok.Count -ge 2) {
                    $pattern = Expand-Path $tok[1] $root
                    foreach ($f in @(Resolve-Path -Path $pattern -ErrorAction SilentlyContinue)) {
                        if ([IO.File]::Exists($f.ProviderPath)) { Read-ApacheConf $f.ProviderPath $root $State ($Depth + 1) }
                    }
                }
            }
            '^loadmodule$' {
                if ($tok.Count -ge 3 -and $tok[1] -match '^php\d*_module$') { $State.ModPhp = $true; $State.ModPhpDll = Expand-Path $tok[2] $root }
            }
            '^phpinidir$' { if ($tok.Count -ge 2) { $State.PhpIniDir = Expand-Path $tok[1] $root } }
            '^fcgidwrapper$' { if ($tok.Count -ge 2) { $State.Fcgid.Add((Expand-Path $tok[1] $root)) } }
            '^fcgidinitialenv$' { if ($tok.Count -ge 3) { $State.FcgidEnv[$tok[1].ToUpperInvariant()] = $tok[2] } }
            '^listen$' {
                if ($tok.Count -ge 2) { $m = [regex]::Match($tok[1], '(\d+)$'); if ($m.Success) { $State.Listens.Add($m.Groups[1].Value) } }
            }
            '^<virtualhost' {
                $ports = New-Object 'System.Collections.Generic.List[string]'
                for ($i = 1; $i -lt $tok.Count; $i++) {
                    $m = [regex]::Match($tok[$i].TrimEnd('>'), ':(\d+)$')
                    if ($m.Success) { $ports.Add($m.Groups[1].Value) }
                }
                $State.CurrentVHost = @{ Ports = $ports; DocRoot = $null }
            }
            '^</virtualhost>$' {
                if ($State.CurrentVHost) { $State.VHosts.Add($State.CurrentVHost) }
                $State.CurrentVHost = $null
            }
            '^documentroot$' {
                if ($tok.Count -ge 2) {
                    $dr = Expand-Path $tok[1] $root
                    if ($State.CurrentVHost) { $State.CurrentVHost.DocRoot = $dr } else { $State.MainDocRoot = $dr }
                }
            }
        }
    }
}

function Get-ApacheInfo {
    <# Every Windows service whose binary is httpd.exe, with its parsed config. #>
    $fn = 'get_apache_info'
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($svc in @(Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -and $_.PathName -match '(?i)httpd\.exe' })) {
        $pn = [string]$svc.PathName
        $m = [regex]::Match($pn, '^\s*"([^"]+)"|^\s*(\S+?\.exe)', $RxIC)
        if (-not $m.Success) { continue }
        $exe = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
        $exe = Expand-Path $exe
        $root = Get-ArgValue $pn '-d'
        if ($root) { $root = Expand-Path $root } else { $root = Split-Path (Split-Path $exe -Parent) -Parent }
        $conf = Get-ArgValue $pn '-f'
        if ($conf) { $conf = Expand-Path $conf $root } else { $conf = Join-Path $root 'conf\httpd.conf' }
        $envs = @{}
        try {
            $reg = Get-ItemProperty -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $svc.Name) -Name Environment -ErrorAction Stop
            foreach ($kv in @($reg.Environment)) { $i = $kv.IndexOf('='); if ($i -gt 0) { $envs[$kv.Substring(0, $i).ToUpperInvariant()] = $kv.Substring($i + 1) } }
        } catch { }
        $state = @{
            Files = (New-Object 'System.Collections.Generic.List[string]'); Defines = @{}; ServerRoot = $root
            ModPhp = $false; ModPhpDll = $null; PhpIniDir = $null
            Fcgid = (New-Object 'System.Collections.Generic.List[string]'); FcgidEnv = @{}
            Listens = (New-Object 'System.Collections.Generic.List[string]')
            VHosts = (New-Object 'System.Collections.Generic.List[object]'); CurrentVHost = $null; MainDocRoot = $null
        }
        if ([IO.File]::Exists($conf)) { Read-ApacheConf $conf $root $state } else { Write-QLog 2 $fn "Apache service $($svc.Name): config $conf not found" }
        $list.Add(@{ Name = $svc.Name; State = $svc.State; Exe = $exe; Conf = $conf; ServiceEnv = $envs; Cfg = $state })
        Write-QLog 3 $fn "Apache service $($svc.Name) ($($svc.State)): $exe; mod_php=$($state.ModPhp); fcgid wrappers=$($state.Fcgid.Count)"
    }
    return ,$list
}

function Get-MachineEnv([string]$Name) {
    return [Environment]::GetEnvironmentVariable($Name, 'Machine')
}

function New-Runtime([string]$Source, [string]$Binary, [string]$CArg, [hashtable]$EnvVars) {
    <# A PHP runtime as a web server starts it: binary, -c argument and the
       PHPRC / PHP_INI_SCAN_DIR it receives (machine values unless overridden). #>
    $e = @{ PHPRC = (Get-MachineEnv 'PHPRC'); PHP_INI_SCAN_DIR = (Get-MachineEnv 'PHP_INI_SCAN_DIR') }
    foreach ($k in @('PHPRC', 'PHP_INI_SCAN_DIR')) { if ($EnvVars -and $EnvVars.ContainsKey($k)) { $e[$k] = $EnvVars[$k] } }
    return @{ Source = $Source; Binary = $Binary; CArg = $CArg; Env = $e }
}

function Get-Runtimes($Iis, $Apache, $Table) {
    $rt = New-Object 'System.Collections.Generic.List[object]'
    $seen = @{}
    $add = {
        param($r)
        if (-not $r.Binary) { return }
        $key = ($r.Binary + '|' + $r.CArg + '|' + $r.Env.PHPRC + '|' + $r.Env.PHP_INI_SCAN_DIR).ToLowerInvariant()
        if ($seen.ContainsKey($key)) { return }
        $seen[$key] = $true
        $rt.Add($r)
    }
    foreach ($a in $Iis.FastCgi) {
        if ($a.FullPath -and $a.FullPath -match '(?i)php-cgi\.exe$') {
            $c = Get-ArgValue ([string]$a.Arguments) '-c'
            & $add (New-Runtime 'IIS FastCGI' $a.FullPath (Expand-Path $c) $a.Env)
        }
    }
    foreach ($s in $Apache) {
        if ($s.Cfg.ModPhp -and $s.Cfg.ModPhpDll) {
            $cli = Join-Path (Split-Path $s.Cfg.ModPhpDll -Parent) 'php.exe'
            $c = $null
            if ($s.Cfg.PhpIniDir) { $c = Join-Path $s.Cfg.PhpIniDir 'php.ini' }
            & $add (New-Runtime "Apache mod_php ($($s.Name))" $cli $c $s.ServiceEnv)
        }
        foreach ($w in $s.Cfg.Fcgid) {
            $e = @{}
            foreach ($k in $s.ServiceEnv.Keys) { $e[$k] = $s.ServiceEnv[$k] }
            foreach ($k in $s.Cfg.FcgidEnv.Keys) { $e[$k] = $s.Cfg.FcgidEnv[$k] }
            & $add (New-Runtime "Apache mod_fcgid ($($s.Name))" $w $null $e)
        }
    }
    foreach ($p in $Table.Values) {
        if ($p.Name -eq 'php-cgi.exe' -and $p.Path) {
            & $add (New-Runtime "running php-cgi.exe PID $($p.Id)" $p.Path (Expand-Path (Get-ArgValue $p.Cmd '-c')) $null)
        }
    }
    return ,$rt
}

function Get-ReportValue([string]$Text, [string]$KeyPattern) {
    $m = [regex]::Match($Text, ('(?im)^\s*(?:' + $KeyPattern + ')\s*(?:=>|:)?\s*(.+?)\s*$'))
    if (-not $m.Success) { return $null }
    $v = $m.Groups[1].Value.Trim()
    if (-not $v -or $v -eq '(none)') { return $null }
    return $v
}

function ConvertFrom-PhpReport([string]$Text) {
    <# Accepts `php --ini` text, `php -i` text and `php-cgi -i` HTML. #>
    $t = $Text -replace '(?i)</td>\s*<td[^>]*>', ' => '
    $t = $t -replace '(?i)<br\s*/?>|</tr>', "`n"
    $t = [Net.WebUtility]::HtmlDecode(($t -replace '<[^>]+>', ''))
    $loaded = Get-ReportValue $t 'Loaded Configuration File'
    $scan = Get-ReportValue $t 'Scan for additional \.ini files in|Scan this dir for additional \.ini files'
    $dirs = @()
    if ($scan) { $dirs = @($scan.Split([char]';') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    return @{ Loaded = $loaded; ScanDirs = $dirs }
}

function Get-RuntimeArgs($Runtime) {
    $a = New-Object 'System.Collections.Generic.List[string]'
    if ($Runtime.CArg) { $a.Add('-c'); $a.Add($Runtime.CArg) }
    return ,$a
}

function Get-RuntimeProbe($Runtime) {
    <# Binary to run for a runtime: the runtime itself, or php.exe beside a mod_php DLL. #>
    if ([IO.File]::Exists($Runtime.Binary)) { return $Runtime.Binary }
    return $null
}

function Get-RuntimeReport($Runtime) {
    $bin = Get-RuntimeProbe $Runtime
    if (-not $bin) { return $null }
    $a = Get-RuntimeArgs $Runtime
    if ($bin -match '(?i)php-cgi\.exe$') { $a.Add('-i') } else { $a.Add('--ini') }
    $r = Invoke-Cmd -File $bin -Arguments $a.ToArray() -EnvOverlay $Runtime.Env -WorkDir (Split-Path $bin -Parent)
    if ($r.RC -ne 0 -or -not $r.Out) { return $null }
    return (ConvertFrom-PhpReport $r.Out)
}

function Get-StartupErrors($Runtime) {
    <# Start the runtime with -v and collect startup diagnostics. Returns
       @{RC; Lines} or $null when the binary is missing. #>
    $bin = Get-RuntimeProbe $Runtime
    if (-not $bin) { return $null }
    $a = Get-RuntimeArgs $Runtime
    $a.Add('-v')
    $r = Invoke-Cmd -File $bin -Arguments $a.ToArray() -EnvOverlay $Runtime.Env -WorkDir (Split-Path $bin -Parent)
    $lines = @((($r.Out + "`n" + $r.Err) -split "`r?`n") | Where-Object { $_ -match '(?i)(PHP\s+)?(Warning|Fatal error|Parse error|Startup)|syntax error' } | ForEach-Object { $_.Trim() })
    return @{ RC = $r.RC; Lines = $lines }
}


# --------------------- DISCOVERY: targets ---------------------
function Add-Unique($List, [string]$Path) {
    if (-not $Path) { return }
    foreach ($x in $List) { if ([string]::Equals($x, $Path, $ORDI)) { return } }
    $List.Add($Path)
}

function Get-DiscoveredEnvironment {
    $table = Get-ProcTable
    $iis = Get-IisInfo
    $apache = Get-ApacheInfo
    $runtimes = Get-Runtimes $iis $apache $table
    $modPhpExes = @($apache | Where-Object { $_.Cfg.ModPhp } | ForEach-Object { $_.Exe.ToLowerInvariant() })
    return @{ Iis = $iis; Apache = $apache; Runtimes = $runtimes; ModPhpExes = $modPhpExes }
}

function Find-PhpInis($Envr, $ScanDirs) {
    $fn = 'find_php_inis'
    Write-QLog 3 $fn 'Discovering php.ini files (shared SAPI baseline)'
    $found = New-Object 'System.Collections.Generic.List[string]'
    # One entry per runtime: the php.ini it loads and the dirs it scans, used to
    # evaluate upload_max_filesize < post_max_size per runtime.
    $Envr.Reports = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in $Envr.Runtimes) {
        $rIni = $null
        $rDirs = New-Object 'System.Collections.Generic.List[string]'
        $rep = Get-RuntimeReport $r
        if ($rep) {
            if ($rep.Loaded -and [IO.File]::Exists($rep.Loaded)) {
                $rIni = [IO.Path]::GetFullPath($rep.Loaded)
                $before = $found.Count
                Add-Unique $found $rIni
                if ($found.Count -gt $before) { Write-QLog 1 $fn "Discovered php.ini ($($r.Source)): $($rep.Loaded)" }
            }
            foreach ($d in $rep.ScanDirs) { Add-Unique $ScanDirs (Expand-Path $d); Add-Unique $rDirs (Expand-Path $d) }
        } else {
            Write-QLog 2 $fn "Could not query $($r.Source) runtime $($r.Binary)"
        }
        if ($r.CArg -and [IO.File]::Exists($r.CArg)) {
            Add-Unique $found ([IO.Path]::GetFullPath($r.CArg))
            if (-not $rIni) { $rIni = [IO.Path]::GetFullPath($r.CArg) }
        }
        if ($r.Env.PHPRC) {
            $p = Expand-Path $r.Env.PHPRC
            if ([IO.Directory]::Exists($p)) { $p = Join-Path $p 'php.ini' }
            if ([IO.File]::Exists($p)) { Add-Unique $found $p; if (-not $rIni) { $rIni = $p } }
        }
        if ($r.Env.PHP_INI_SCAN_DIR) {
            foreach ($d in $r.Env.PHP_INI_SCAN_DIR.Split([char]';')) {
                if ($d.Trim()) { Add-Unique $ScanDirs (Expand-Path $d); Add-Unique $rDirs (Expand-Path $d) }
            }
        }
        if ($rIni) { $Envr.Reports.Add(@{ Ini = $rIni; Dirs = $rDirs }) }
    }
    # Registry IniFilePath (HKLM\SOFTWARE\PHP and per-version subkeys)
    foreach ($k in @('HKLM:\SOFTWARE\PHP', 'HKLM:\SOFTWARE\WOW6432Node\PHP')) {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        foreach ($key in @(Get-Item -LiteralPath $k) + @(Get-ChildItem -LiteralPath $k -Recurse -ErrorAction SilentlyContinue)) {
            $v = $key.GetValue('IniFilePath')
            if ($v) { $p = Join-Path (Expand-Path $v) 'php.ini'; if ([IO.File]::Exists($p)) { Add-Unique $found $p } }
        }
    }
    $sd = $env:SystemDrive
    $globs = @("$sd\php*\php.ini", "$env:ProgramFiles\PHP\*\php.ini", "$env:ProgramFiles\PHP\php.ini",
               "${env:ProgramFiles(x86)}\PHP\*\php.ini", "${env:ProgramFiles(x86)}\PHP\php.ini",
               "$sd\xampp\php\php.ini", "$sd\wamp*\bin\php\php*\php.ini", "$sd\tools\php*\php.ini",
               "$env:windir\php.ini")
    foreach ($g in $globs) {
        if (-not $g -or $g.StartsWith('\', $ORD)) { continue }
        foreach ($f in @(Resolve-Path -Path $g -ErrorAction SilentlyContinue)) {
            $before = $found.Count
            Add-Unique $found $f.ProviderPath
            if ($found.Count -gt $before) { Write-QLog 1 $fn "Discovered php.ini (known-path): $($f.ProviderPath)" }
        }
    }
    return ,$found
}

function Test-MentionsDirective([string]$Path, $Directives) {
    try { $r = Read-Lines $Path } catch { Write-QLog 2 'mentions_directive' "Could not read ${Path}: $($_.Exception.Message)"; return $false }
    $rxs = @($Directives | ForEach-Object { New-KeyRegex $_.Key })
    foreach ($line in $r.Lines) {
        if (Test-CommentOrBlank $line) { continue }
        foreach ($rx in $rxs) { if ($rx.IsMatch($line)) { return $true } }
    }
    return $false
}

function Find-Dropins($ScanDirs, $PhpInis) {
    $fn = 'find_dropins'
    $found = New-Object 'System.Collections.Generic.List[string]'
    foreach ($d in (Get-MachineEnv 'PHP_INI_SCAN_DIR' | ForEach-Object { if ($_) { $_.Split([char]';') } })) {
        if ($d -and $d.Trim()) { Add-Unique $ScanDirs (Expand-Path $d) }
    }
    foreach ($d in $ScanDirs) {
        if (-not [IO.Directory]::Exists($d)) { continue }
        Write-QLog 3 $fn "PHP scans $d for additional .ini files"
        try { $names = [IO.Directory]::GetFiles($d, '*.ini') } catch { Write-QLog 2 $fn "Cannot list ${d}: $($_.Exception.Message)"; continue }
        [Array]::Sort($names, [StringComparer]::Ordinal)     # PHP's load order
        foreach ($p in $names) {
            if ($PhpInis -contains $p -or $found -contains $p) { continue }
            # upload_max_filesize counts too: a drop-in that sets only it can break
            # upload_max_filesize < post_max_size and must be backed up / fixable.
            if (Test-MentionsDirective $p ($INI_DIRECTIVES + @(New-Directive $UPLOAD_KEY '' 'exact' $null))) {
                $found.Add($p)
                Write-QLog 1 $fn "Drop-in sets an enforced directive: $p"
            }
        }
    }
    return ,$found
}

function Test-DeniedRoot([string]$Path) {
    $p = $Path.TrimEnd('\')
    if ($p -match '^[A-Za-z]:$') { return $true }
    $deny = @($env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
              "$env:SystemDrive\Users", "$env:SystemDrive\inetpub")
    foreach ($d in $deny) { if ($d -and [string]::Equals($p, $d.TrimEnd('\'), $ORDI)) { return $true } }
    return $false
}

function Find-PerDirFiles([string]$Root, [bool]$WantHtaccess) {
    <# Existing .user.ini / .htaccess under Root. Reparse-point directories and
       files are skipped (junction loops, links planted by a site user). #>
    $fn = 'find_perdir_files'
    $userInis = New-Object 'System.Collections.Generic.List[string]'
    $hts = New-Object 'System.Collections.Generic.List[string]'
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        foreach ($name in @($USER_INI_NAME, $HTACCESS_NAME)) {
            if ($name -eq $HTACCESS_NAME -and -not $WantHtaccess) { continue }
            $p = Join-Path $dir $name
            if (-not [IO.File]::Exists($p)) { continue }
            if (Test-ReparsePoint $p) { Write-QLog 2 $fn "Skipping linked ${name}: $p"; continue }
            if ($name -eq $USER_INI_NAME) { $userInis.Add($p); continue }
            try { $r = Read-Lines $p } catch { Write-QLog 2 $fn "Could not read ${p}: $($_.Exception.Message)"; continue }
            if (Test-HtaccessHasPhp $r.Lines) { $hts.Add($p) } else { Write-QLog 3 $fn "Skipping .htaccess without php_* directives: $p" }
        }
        try { $subs = [IO.Directory]::GetDirectories($dir) } catch { Write-QLog 2 $fn "Cannot list ${dir}: $($_.Exception.Message)"; continue }
        foreach ($s in $subs) {
            $leaf = [IO.Path]::GetFileName($s)
            if ($EXCLUDED_DIRS -contains $leaf) { continue }
            try { if ([IO.File]::GetAttributes($s) -band [IO.FileAttributes]::ReparsePoint) { continue } } catch { continue }
            $stack.Push($s)
        }
    }
    return @{ UserInis = $userInis; Htaccess = $hts }
}

function Get-ScopedRoots($Envr) {
    <# Physical paths of the IIS site and DocumentRoots of the Apache vhosts
       listening on -PORT, plus the IIS app pools of that site. #>
    $fn = 'get_scoped_roots'
    $roots = New-Object 'System.Collections.Generic.List[object]'
    $pools = New-Object 'System.Collections.Generic.List[string]'
    $port = [string]$script:AffectedPort
    foreach ($s in $Envr.Iis.Sites) {
        if ($s.Ports -notcontains $port) { continue }
        Write-QLog 1 $fn "Affected IIS site matched: $($s.Name) (pools: $($s.Pools -join ', '))"
        foreach ($p in $s.Pools) { if (-not $pools.Contains($p)) { $pools.Add($p) } }
        foreach ($p in $s.Paths) { $roots.Add(@{ Path = $p; Htaccess = $false; Source = "IIS site $($s.Name)" }) }
    }
    foreach ($a in $Envr.Apache) {
        if (-not ($a.Cfg.ModPhp -or $a.Cfg.Fcgid.Count -gt 0)) { continue }
        $matched = $false
        foreach ($v in $a.Cfg.VHosts) {
            if ($v.Ports -contains $port -and $v.DocRoot) {
                $roots.Add(@{ Path = $v.DocRoot; Htaccess = $true; Source = "Apache $($a.Name) vhost" }); $matched = $true
            }
        }
        if (-not $matched -and $a.Cfg.Listens -contains $port -and $a.Cfg.MainDocRoot) {
            $roots.Add(@{ Path = $a.Cfg.MainDocRoot; Htaccess = $true; Source = "Apache $($a.Name) main server" })
        }
    }
    return @{ Roots = $roots; Pools = $pools }
}

function Get-IniGroups($Reports, $PhpInis, $Dropins) {
    <# One group per runtime: [php.ini, drop-ins...] in PHP's load order (the
       last file that sets a key wins). A php.ini no runtime reported stands
       alone (Windows has no default scan dir). #>
    $groups = New-Object 'System.Collections.Generic.List[object]'
    $covered = New-Object 'System.Collections.Generic.List[string]'
    $seenKeys = New-Object 'System.Collections.Generic.List[string]'
    foreach ($rep in $Reports) {
        $files = New-Object 'System.Collections.Generic.List[string]'
        $files.Add($rep.Ini)
        foreach ($d in $rep.Dirs) {
            if (-not [IO.Directory]::Exists($d)) { continue }
            try { $names = [IO.Directory]::GetFiles($d, '*.ini') } catch { continue }
            [Array]::Sort($names, [StringComparer]::Ordinal)
            foreach ($n in $names) { if ($Dropins -contains $n -and $files -notcontains $n) { $files.Add($n) } }
        }
        $key = ($files -join '|').ToLowerInvariant()
        if ($seenKeys -notcontains $key) { $seenKeys.Add($key); $groups.Add($files) }
        Add-Unique $covered $rep.Ini
    }
    foreach ($ini in $PhpInis) {
        if ($covered -contains $ini) { continue }
        $files = New-Object 'System.Collections.Generic.List[string]'
        $files.Add($ini)
        $groups.Add($files)
    }
    return ,$groups
}

function Get-GroupEffective($Files, [string]$Key) {
    <# @{Value; Setter} of Key across a load-ordered group; last setter wins. #>
    $value = $null
    $setter = $null
    foreach ($p in $Files) {
        if (-not [IO.File]::Exists($p)) { continue }
        $v = Get-EffectiveValue (Read-Lines $p).Lines $Key
        if ($null -ne $v) { $value = $v; $setter = $p }
    }
    return @{ Value = $value; Setter = $setter }
}

function Get-UploadViolations {
    <# Every runtime whose upload_max_filesize is not below its post_max_size.
       Returns fix items @{Path; Limit; Add; Desc}; a runtime whose
       post_max_size is itself invalid is left to the per-file check. Throws
       when a file cannot be read. #>
    $items = @{}
    foreach ($g in $script:Env.Groups) {
        $pe = Get-GroupEffective $g 'post_max_size'
        $p = ConvertFrom-PhpBytes $pe.Value
        if ($null -eq $p -or $p -le 0) { continue }
        $ue = Get-GroupEffective $g $UPLOAD_KEY
        $raw = $ue.Value
        $shown = $raw
        if ($null -eq $raw) { $raw = $PHP_DEFAULT_UPLOAD; $shown = "$PHP_DEFAULT_UPLOAD (PHP default)" }
        $u = ConvertFrom-PhpBytes $raw
        if ($null -ne $u -and $u -gt 0 -and $u -lt $p) { continue }
        $path = $ue.Setter
        if (-not $path) { $path = $g[0] }
        $k = $path.ToLowerInvariant()
        if (-not $items.ContainsKey($k) -or $p -lt $items[$k].Limit) {
            $items[$k] = @{ Path = $path; Limit = $p; Add = [string]::Equals($path, $g[0], $ORDI)
                            Desc = "$UPLOAD_KEY = $shown is not below post_max_size = $($pe.Value) (runtime using $($g[0]); set in $path)" }
        }
    }
    return ,@($items.Values)
}

function Repair-UploadLimits($Targets) {
    <# Lower upload_max_filesize wherever it is not below post_max_size. Only
       files that are already targets (backed up) are written. #>
    $fn = 'fix_upload_limits'
    try {
        for ($attempt = 0; $attempt -lt 3; $attempt++) {
            $items = Get-UploadViolations
            if ($items.Count -eq 0) { return $SUCCESS }
            foreach ($it in $items) {
                $isTarget = $false
                foreach ($t in $Targets) { if ([string]::Equals($t.Path, $it.Path, $ORDI)) { $isTarget = $true } }
                if (-not $isTarget) { Write-QLog 0 $fn "$($it.Path) is not a backed-up target; not modifying it"; return $FAILURE }
                $new = Format-PhpBytes (Get-Below $it.Limit)
                Write-QLog 1 $fn "$($it.Desc); setting $UPLOAD_KEY = $new"
                $fix = @(New-Directive $UPLOAD_KEY $new 'lt_bytes' ([long]$it.Limit))
                if ((Set-IniHardening $it.Path $fix $it.Add) -ne $SUCCESS) { return $FAILURE }
            }
        }
        foreach ($it in (Get-UploadViolations)) { Write-QLog 0 $fn "Still not fixed: $($it.Desc)" }
        return $FAILURE
    } catch {
        Write-QLog 0 $fn "Error checking upload limits: $($_.Exception.Message)"
        return $FAILURE
    }
}

function Get-Targets {
    <# Returns a list of @{Path; Kind}; Kind in ini, dropin, userini, htaccess. #>
    $fn = 'discover_targets'
    $targets = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.List[string]'
    $add = { param($p, $k) foreach ($x in $seen) { if ([string]::Equals($x, $p, $ORDI)) { return } }; $seen.Add($p); $targets.Add(@{ Path = $p; Kind = $k }) }

    $scanDirs = New-Object 'System.Collections.Generic.List[string]'
    $inis = Find-PhpInis $script:Env $scanDirs
    foreach ($p in $inis) { & $add $p 'ini' }
    $dropins = Find-Dropins $scanDirs $inis
    foreach ($p in $dropins) { & $add $p 'dropin' }
    $script:Env.Groups = Get-IniGroups $script:Env.Reports $inis $dropins

    $script:Env.ScopedPools = New-Object 'System.Collections.Generic.List[string]'
    if ($script:AffectedPort) {
        $sc = Get-ScopedRoots $script:Env
        $script:Env.ScopedPools = $sc.Pools
        if ($sc.Roots.Count -eq 0) {
            Write-QLog 2 $fn "PORT provided but no IIS site or PHP-enabled Apache vhost listens on it; per-directory changes will be skipped"
        }
        foreach ($r in $sc.Roots) {
            if (-not [IO.Directory]::Exists($r.Path)) { Write-QLog 2 $fn "Document root not found: $($r.Path)"; continue }
            if (Test-DeniedRoot $r.Path) { Write-QLog 2 $fn "Refusing overly broad document root $($r.Path)"; continue }
            Write-QLog 3 $fn "Scanning application document root: $($r.Path) ($($r.Source))"
            $f = Find-PerDirFiles $r.Path $r.Htaccess
            foreach ($p in $f.UserInis) { & $add $p 'userini'; Write-QLog 1 $fn "Affected .user.ini: $p" }
            foreach ($p in $f.Htaccess) { & $add $p 'htaccess'; Write-QLog 1 $fn "Affected .htaccess: $p" }
        }
    } else {
        Write-QLog 2 $fn 'No PORT provided; cannot scope to an application; per-directory changes will be skipped'
    }
    if ($targets.Count -eq 0) { Write-QLog 2 $fn 'No target files found on this host' }
    else { Write-QLog 1 $fn "Total targets selected: $($targets.Count)" }
    return ,$targets
}


# --------------------- PER-FILE STATE ---------------------
function Get-IniState([string]$Path, $Directives) {
    $fn = 'ini_is_mitigated'
    try { $r = Read-Lines $Path } catch [IO.FileNotFoundException] { return $UNMITIGATE } catch { Write-QLog 0 $fn "Error reading ${Path}: $($_.Exception.Message)"; return $FAILURE }
    foreach ($d in $Directives) {
        $eff = Get-EffectiveValue $r.Lines $d.Key
        $shown = if ($null -eq $eff) { '(not set)' } else { $eff }
        if (-not (Test-DirOk $eff $d)) {
            Write-QLog 2 $fn "${Path}: $($d.Key) = $shown ; want $($d.Val) -> not mitigated"
            return $UNMITIGATE
        }
        Write-QLog 3 $fn "${Path}: $($d.Key) = $shown ; want $($d.Val) -> OK"
    }
    Write-QLog 3 $fn "${Path}: all required directives set correctly"
    return $EXISTS
}

function Get-DropinState([string]$Path) {
    <# Compliant when no uncommented line sets an enforced directive to a
       non-compliant value; absent directives come from php.ini. #>
    $fn = 'dropin_is_mitigated'
    try { $r = Read-Lines $Path } catch [IO.FileNotFoundException] { return $EXISTS } catch { Write-QLog 0 $fn "Error reading ${Path}: $($_.Exception.Message)"; return $FAILURE }
    $comp = @($INI_DIRECTIVES | ForEach-Object { @{ D = $_; Rx = (New-KeyRegex $_.Key) } })
    foreach ($line in $r.Lines) {
        if (Test-CommentOrBlank $line) { continue }
        foreach ($c in $comp) {
            $m = $c.Rx.Match($line)
            if ($m.Success -and -not (Test-DirOk (Get-IniValue $m.Groups[1].Value) $c.D)) {
                Write-QLog 3 $fn "${Path}: $($c.D.Key) overrides php.ini with a non-compliant value -> not mitigated"
                return $UNMITIGATE
            }
        }
    }
    Write-QLog 3 $fn "${Path}: no non-compliant overrides"
    return $EXISTS
}

function Get-HtaccessState([string]$Path) {
    $fn = 'htaccess_is_mitigated'
    try { $r = Read-Lines $Path } catch [IO.FileNotFoundException] { return $UNMITIGATE } catch { Write-QLog 0 $fn "Error reading ${Path}: $($_.Exception.Message)"; return $FAILURE }
    foreach ($d in $HTACCESS_DIRECTIVES) {
        $eff = Get-HtaccessEffective $r.Lines $d.Key
        if ($null -eq $eff -or $eff -ne $d.Desired) {
            Write-QLog 3 $fn "${Path}: $($d.Key) not set correctly -> not mitigated"
            return $UNMITIGATE
        }
    }
    Write-QLog 3 $fn "${Path}: all required directives set correctly"
    return $EXISTS
}

function Get-TargetState($T) {
    switch ($T.Kind) {
        'ini' { return (Get-IniState $T.Path $INI_DIRECTIVES) }
        'dropin' { return (Get-DropinState $T.Path) }
        'userini' { return (Get-IniState $T.Path $USERINI_DIRECTIVES) }
        'htaccess' { return (Get-HtaccessState $T.Path) }
    }
    return $FAILURE
}

function Get-ConfigCutoff($Targets) {
    $newest = $null
    foreach ($t in $Targets) {
        if (@('ini', 'dropin') -notcontains $t.Kind) { continue }
        if (-not [IO.File]::Exists($t.Path)) { continue }
        $w = [IO.File]::GetLastWriteTimeUtc($t.Path)
        if ($null -eq $newest -or $w -gt $newest) { $newest = $w }
    }
    return $newest
}

function Get-StaleWorkers([DateTime]$CutoffUtc) {
    $limit = $CutoffUtc.AddSeconds(-$START_SLACK_SEC)
    $stale = New-Object 'System.Collections.Generic.List[object]'
    foreach ($w in (Get-PhpWorkers (Get-ProcTable) $script:Env.ModPhpExes)) {
        if ($null -ne $w.Start -and $w.Start -lt $limit) { $stale.Add($w) }
    }
    return ,$stale
}


# --------------------- VERIFY ---------------------
function Invoke-Verify($Targets, [bool]$Runtime = $true) {
    $fn = 'verify'
    try {
        Write-QLog 3 $fn 'Verifying PHP upload-progress hardening state'
        if ($Targets.Count -eq 0) { Write-QLog 2 $fn 'No target files to verify; nothing to do'; return $SKIP }
        $allOk = $true
        foreach ($t in $Targets) {
            $st = Get-TargetState $t
            if ($st -eq $FAILURE) { return $FAILURE }
            if ($st -eq $UNMITIGATE) { Write-QLog 2 $fn "Not hardened ($($t.Kind)): $($t.Path)"; $allOk = $false }
            else { Write-QLog 1 $fn "Hardened ($($t.Kind)): $($t.Path)" }
        }
        if (-not $allOk) { Write-QLog 2 $fn 'One or more targets are not hardened'; return $UNMITIGATE }
        $viol = Get-UploadViolations
        if ($viol.Count -gt 0) {
            foreach ($v in $viol) { Write-QLog 2 $fn $v.Desc }
            Write-QLog 2 $fn "$UPLOAD_KEY must be below post_max_size -> not mitigated"
            return $UNMITIGATE
        }
        if ($Runtime) {
            $cut = Get-ConfigCutoff $Targets
            if ($null -ne $cut) {
                $stale = Get-StaleWorkers $cut
                if ($stale.Count -gt 0) {
                    foreach ($w in $stale) { Write-QLog 2 $fn "$($w.Name) PID $($w.Id) started before the last configuration change" }
                    Write-QLog 2 $fn "Configuration hardened but $($stale.Count) worker(s) still run the old configuration; restart required"
                    return $UNMITIGATE
                }
            }
        }
        Write-QLog 1 $fn 'All targets are hardened; affected application is mitigated'
        return $SUCCESS
    } catch {
        Write-QLog 0 $fn "Error during verification: $($_.Exception.Message)"
        return $FAILURE
    }
}


# --------------------- BACKUP ---------------------
function Set-BackupProtection([bool]$Enable) {
    if (-not [IO.File]::Exists($BACKUP_PATH)) { return }
    try {
        $a = [IO.File]::GetAttributes($BACKUP_PATH)
        if ($Enable) { $a = $a -bor [IO.FileAttributes]::ReadOnly } else { $a = $a -band (-bnot [IO.FileAttributes]::ReadOnly) }
        [IO.File]::SetAttributes($BACKUP_PATH, $a)
    } catch { Write-QLog 2 'set_backup_protection' "Could not change attributes on ${BACKUP_PATH}: $($_.Exception.Message)" }
}

function Initialize-BackupDir {
    <# Backup directory readable/writable by Administrators and SYSTEM only. #>
    if (-not [IO.Directory]::Exists($BACKUP_DIR)) { $null = [IO.Directory]::CreateDirectory($BACKUP_DIR) }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inh = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $prop = [Security.AccessControl.PropagationFlags]::None
    foreach ($sid in @('S-1-5-32-544', 'S-1-5-18')) {
        $id = New-Object Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id, 'FullControl', $inh, $prop, 'Allow')))
    }
    [IO.Directory]::SetAccessControl($BACKUP_DIR, $acl)
}

function Remove-Backup {
    Set-BackupProtection $false
    try {
        if ([IO.File]::Exists($BACKUP_PATH)) { [IO.File]::Delete($BACKUP_PATH); Write-QLog 1 'remove_backup' "Removed backup manifest: $BACKUP_PATH" }
        return $true
    } catch {
        Write-QLog 2 'remove_backup' "Could not remove backup ${BACKUP_PATH}: $($_.Exception.Message)"
        Set-BackupProtection $true
        return $false
    }
}

function New-Backup($Originals) {
    <# Returns @{RC; Created}. An existing backup is kept as-is. #>
    $fn = 'create_backup'
    try {
        if ([IO.File]::Exists($BACKUP_PATH)) {
            Write-QLog 3 $fn "Backup already exists; preserving single backup: $BACKUP_PATH"
            return @{ RC = $SUCCESS; Created = $false }
        }
        Initialize-BackupDir
        # Line format (no JSON: PS 3.0 ConvertFrom-Json caps input at 2 MB):
        #   QLYSBAK2 <created>
        #   base64(utf8 path) <TAB> base64(original bytes)
        $sb = New-Object Text.StringBuilder
        $null = $sb.Append("QLYSBAK$BACKUP_VERSION $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')`n")
        foreach ($k in $Originals.Keys) {
            $null = $sb.Append([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($k))).Append("`t").Append([Convert]::ToBase64String($Originals[$k])).Append("`n")
        }
        if ((Write-FileAtomic $BACKUP_PATH ([Text.Encoding]::ASCII.GetBytes($sb.ToString()))) -ne $SUCCESS) {
            Write-QLog 0 $fn "Could not write backup $BACKUP_PATH"
            return @{ RC = $FAILURE; Created = $false }
        }
        Set-BackupProtection $true
        Write-QLog 1 $fn "Single backup created for $($Originals.Count) file(s): $BACKUP_PATH"
        return @{ RC = $SUCCESS; Created = $true }
    } catch {
        Write-QLog 0 $fn "Error creating backup: $($_.Exception.Message)"
        return @{ RC = $FAILURE; Created = $false }
    }
}

function Restore-Backup {
    <# Returns SUCCESS, FAILURE, SKIP (no manifest) or CORRUPT. #>
    $fn = 'restore_backup'
    if (-not [IO.File]::Exists($BACKUP_PATH)) { Write-QLog 2 $fn 'No backup manifest present'; return $SKIP }
    # Decode every entry before writing anything, so a corrupt manifest never
    # leads to a partial restore.
    $entries = New-Object 'System.Collections.Generic.List[object]'
    try {
        $lines = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($BACKUP_PATH)) -split "`n"
        if (-not $lines[0].StartsWith("QLYSBAK$BACKUP_VERSION", $ORD)) { throw 'unknown manifest header' }
        for ($i = 1; $i -lt $lines.Count; $i++) {
            $l = $lines[$i].Trim()
            if (-not $l) { continue }
            $parts = $l.Split([char]"`t")
            if ($parts.Count -ne 2) { throw "malformed entry on line $($i + 1)" }
            $entries.Add(@{ Path = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[0]))
                            Data = [Convert]::FromBase64String($parts[1]) })
        }
        if ($entries.Count -eq 0) { throw 'manifest has no files' }
    } catch {
        Write-QLog 0 $fn "Backup manifest $BACKUP_PATH is unusable: $($_.Exception.Message)"
        return $CORRUPT
    }
    $ok = $true
    foreach ($e in $entries) {
        if ((Write-FileAtomic $e.Path $e.Data) -eq $SUCCESS) { Write-QLog 1 $fn "Restored original: $($e.Path)" }
        else { Write-QLog 0 $fn "Failed to restore $($e.Path)"; $ok = $false }
    }
    if ($ok) { $null = Remove-Backup; return $SUCCESS }
    return $FAILURE
}


# --------------------- DIRECTIVE WRITE / REVERT ---------------------
function Get-DirectiveKey([string]$Line) {
    $m = $KEY_RX.Match($Line)
    if ($m.Success) { return $m.Groups[1].Value.ToLowerInvariant() }
    return $null
}

function Get-MarkerKind([string]$Line) {
    $s = $Line.TrimStart()
    if (-not ($s.StartsWith(';', $ORD) -or $s.StartsWith('#', $ORD))) { return $null }
    $i = $Line.IndexOf($TAG_MODIFIED, $ORD)
    if ($i -ge 0) { return @{ Kind = 'mod'; Info = $Line.Substring($i + $TAG_MODIFIED.Length) } }
    $i = $Line.IndexOf($TAG_ADDED, $ORD)
    if ($i -ge 0) {
        $rest = $Line.Substring($i + $TAG_ADDED.Length).Trim()
        $key = $null
        if ($rest.StartsWith(':', $ORD)) { $k = $rest.Substring(1).Trim(); if ($k) { $key = $k } }
        return @{ Kind = 'add'; Info = $key }
    }
    return $null
}

function Undo-Tags($Lines) {
    <# Consecutive markers form one stack: the OLDEST decides the outcome and
       the governed line is consumed only when its key matches the marker. #>
    $out = New-Object 'System.Collections.Generic.List[string]'
    $changed = $false
    $mismatches = 0
    $i = 0
    $n = $Lines.Count
    while ($i -lt $n) {
        if ($null -eq (Get-MarkerKind $Lines[$i])) { $out.Add($Lines[$i]); $i++; continue }
        $run = New-Object 'System.Collections.Generic.List[object]'
        while ($i -lt $n) {
            $mk = Get-MarkerKind $Lines[$i]
            if ($null -eq $mk) { break }
            $run.Add($mk); $i++
        }
        $first = $run[0]
        $last = $run[$run.Count - 1]
        $expected = $null
        if ($last.Kind -eq 'mod') { $expected = Get-DirectiveKey $last.Info }
        elseif ($last.Info) { $expected = $last.Info.ToLowerInvariant() }
        if ($first.Kind -eq 'mod') { $out.Add($first.Info) }
        if ($i -lt $n -and ($null -eq $expected -or (Get-DirectiveKey $Lines[$i]) -eq $expected)) { $i++ }
        else { $mismatches++ }
        $changed = $true
    }
    return @{ Lines = $out; Changed = $changed; Mismatches = $mismatches }
}

function Test-FileHasTags([string]$Path) {
    <# $true / $false, or $null when the file cannot be read. #>
    if (-not [IO.File]::Exists($Path)) { return $false }
    try { $text = $LATIN1.GetString((Read-Raw $Path)) }
    catch { Write-QLog 0 'file_has_tags' "Error reading ${Path}: $($_.Exception.Message)"; return $null }
    return ($text.IndexOf($TAG_MODIFIED, $ORD) -ge 0 -or $text.IndexOf($TAG_ADDED, $ORD) -ge 0)
}

function Set-IniHardening([string]$Path, $Directives, [bool]$AddMissing = $true) {
    $fn = 'harden_ini'
    try { $r = Read-Lines $Path } catch { Write-QLog 0 $fn "Error reading ${Path}: $($_.Exception.Message)"; return $FAILURE }
    $nl = $r.NL
    $comp = @($Directives | ForEach-Object { @{ D = $_; Rx = (New-KeyRegex $_.Key) } })
    $out = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    $changed = $false
    foreach ($line in $r.Lines) {
        if (Test-CommentOrBlank $line) { $out.Add($line); continue }
        $matched = $false
        foreach ($c in $comp) {
            $m = $c.Rx.Match($line)
            if (-not $m.Success) { continue }
            $matched = $true
            $seen[$c.D.Key] = $true
            $old = Get-IniValue $m.Groups[1].Value
            if (-not (Test-DirOk $old $c.D)) {
                $indent = $line.Substring(0, $line.Length - $line.TrimStart().Length)
                $out.Add("; $TAG_MODIFIED$line")
                $out.Add("$indent$($c.D.Key) = $($c.D.Val)$nl")
                $changed = $true
                Write-QLog 1 $fn "${Path}: changed $($c.D.Key) from '$old' to '$($c.D.Val)'"
            } else {
                Write-QLog 3 $fn "${Path}: $($c.D.Key) = $old already compliant; left unchanged"
                $out.Add($line)
            }
            break
        }
        if (-not $matched) { $out.Add($line) }
    }
    if ($AddMissing) {
        foreach ($c in $comp) {
            if ($seen.ContainsKey($c.D.Key)) { continue }
            $out.Add("; ${TAG_ADDED}:$($c.D.Key)$nl")
            $out.Add("$($c.D.Key) = $($c.D.Val)$nl")
            $changed = $true
            Write-QLog 1 $fn "${Path}: added $($c.D.Key) = $($c.D.Val)"
        }
    }
    if (-not $changed) { Write-QLog 3 $fn "${Path}: already compliant; no change written"; return $SUCCESS }
    return (Write-Lines $Path $out $r)
}

function Set-HtaccessHardening([string]$Path) {
    $fn = 'harden_htaccess'
    try { $r = Read-Lines $Path } catch { Write-QLog 0 $fn "Error reading ${Path}: $($_.Exception.Message)"; return $FAILURE }
    if (-not (Test-HtaccessHasPhp $r.Lines)) { Write-QLog 2 $fn "${Path}: no php_* directives present; skipping to avoid breaking Apache"; return $SUCCESS }
    $nl = $r.NL
    $comp = @($HTACCESS_DIRECTIVES | ForEach-Object { @{ D = $_; Rx = (New-HtaccessRegex $_.Key) } })
    $present = @{}
    foreach ($line in $r.Lines) {
        if (Test-CommentOrBlank $line $true) { continue }
        foreach ($c in $comp) { if ($c.Rx.IsMatch($line)) { $present[$c.D.Key] = $true } }
    }
    $ins = Get-HtaccessInsertPoint $r.Lines
    $additions = New-Object 'System.Collections.Generic.List[string]'
    foreach ($c in $comp) {
        if ($present.ContainsKey($c.D.Key)) { continue }
        $additions.Add("$($ins.Indent)# ${TAG_ADDED}:$($c.D.Key)$nl")
        $additions.Add("$($ins.Indent)php_flag $($c.D.Key) $($c.D.Val)$nl")
        $where = ''
        if ($ins.Index -ge 0) { $where = " inside <IfModule> ending at line $($ins.Index + 1)" }
        Write-QLog 1 $fn "${Path}: added php_flag $($c.D.Key) $($c.D.Val)$where"
    }
    $out = New-Object 'System.Collections.Generic.List[string]'
    $changed = ($additions.Count -gt 0)
    for ($i = 0; $i -lt $r.Lines.Count; $i++) {
        $line = $r.Lines[$i]
        if ($i -eq $ins.Index) { $out.AddRange([string[]]$additions.ToArray()) }
        if (Test-CommentOrBlank $line $true) { $out.Add($line); continue }
        $matched = $false
        foreach ($c in $comp) {
            $m = $c.Rx.Match($line)
            if (-not $m.Success) { continue }
            $matched = $true
            $b = ConvertTo-PhpBool $m.Groups[3].Value
            if ($null -eq $b -or $b -ne $c.D.Desired) {
                $out.Add("$($m.Groups[1].Value)# $TAG_MODIFIED$line")
                $out.Add("$($m.Groups[1].Value)$($m.Groups[2].Value) $($c.D.Key) $($c.D.Val)$nl")
                $changed = $true
                Write-QLog 1 $fn "${Path}: set $($m.Groups[2].Value) $($c.D.Key) $($c.D.Val)"
            } else { $out.Add($line) }
            break
        }
        if (-not $matched) { $out.Add($line) }
    }
    if ($ins.Index -lt 0) { $out.AddRange([string[]]$additions.ToArray()) }
    if (-not $changed) { Write-QLog 3 $fn "${Path}: already compliant; no change written"; return $SUCCESS }
    return (Write-Lines $Path $out $r)
}

function Set-TargetHardening($T) {
    switch ($T.Kind) {
        'ini' { return (Set-IniHardening $T.Path $INI_DIRECTIVES $true) }
        'dropin' { return (Set-IniHardening $T.Path $INI_DIRECTIVES $false) }
        'userini' { return (Set-IniHardening $T.Path $USERINI_DIRECTIVES $true) }
        'htaccess' { return (Set-HtaccessHardening $T.Path) }
    }
    return $FAILURE
}

function Undo-File([string]$Path) {
    $fn = 'revert_file'
    try { $r = Read-Lines $Path } catch { Write-QLog 0 $fn "Error reading ${Path}: $($_.Exception.Message)"; return $FAILURE }
    $res = Undo-Tags $r.Lines
    if (-not $res.Changed) { Write-QLog 3 $fn "${Path}: no mitigation markers found; nothing to revert"; return $SKIP }
    if ($res.Mismatches -gt 0) {
        Write-QLog 2 $fn "${Path}: $($res.Mismatches) marker(s) no longer sit above the directive this script wrote; original restored, edited line left in place"
    }
    if ((Write-Lines $Path $res.Lines $r) -ne $SUCCESS) { return $FAILURE }
    Write-QLog 1 $fn "Reverted mitigation changes in $Path"
    return $SUCCESS
}


# --------------------- SERVICE RESTART ---------------------
function Get-StartupBaseline {
    $b = @{}
    foreach ($r in $script:Env.Runtimes) {
        $e = Get-StartupErrors $r
        if ($e) { $b[$r.Source + '|' + $r.Binary] = $e }
    }
    return $b
}

function Test-Configs($Baseline) {
    <# New PHP startup errors versus the baseline, and httpd -t for every
       running Apache service that loads PHP. #>
    $fn = 'config_tests'
    $ok = $true
    foreach ($r in $script:Env.Runtimes) {
        $key = $r.Source + '|' + $r.Binary
        $now = Get-StartupErrors $r
        if (-not $now) { continue }
        $before = $null
        if ($Baseline.ContainsKey($key)) { $before = $Baseline[$key] }
        $new = @($now.Lines | Where-Object { $null -eq $before -or $before.Lines -notcontains $_ })
        if (($null -ne $before -and $before.RC -eq 0 -and $now.RC -ne 0) -or $new.Count -gt 0) {
            Write-QLog 0 $fn "PHP startup test failed for $($r.Source) ($($r.Binary)): rc=$($now.RC) $($new -join ' | ')"
            $ok = $false
        } else {
            Write-QLog 1 $fn "PHP startup test passed: $($r.Source) ($($r.Binary))"
        }
    }
    foreach ($a in $script:Env.Apache) {
        if ($a.State -ne 'Running' -or -not ($a.Cfg.ModPhp -or $a.Cfg.Fcgid.Count -gt 0)) { continue }
        $r = Invoke-Cmd -File $a.Exe -Arguments @('-n', $a.Name, '-t') -WorkDir (Split-Path $a.Exe -Parent)
        if ($r.RC -eq 0) { Write-QLog 1 $fn "Config test passed: httpd -n $($a.Name) -t" }
        else { Write-QLog 0 $fn "Config test failed (rc=$($r.RC)): httpd -n $($a.Name) -t: $($r.Err) $($r.Out)"; $ok = $false }
    }
    return $ok
}

function Split-ExeAndArgs([string]$CommandLine, [string]$Exe) {
    <# Split a process command line into its argument tail, preserving the
       ORIGINAL quoting of the arguments so the process is relaunched exactly as
       it was started (e.g. -b 127.0.0.1:9000 -c "C:\Program Files\php\php.ini").
       Returns the raw argument string after the executable token. #>
    $cl = ([string]$CommandLine).Trim()
    if (-not $cl) { return '' }
    if ($cl.StartsWith('"', $ORD)) {
        $end = $cl.IndexOf('"', 1)
        if ($end -ge 0) { return $cl.Substring($end + 1).Trim() }
    }
    # Unquoted first token: drop it (prefer the known exe length when the line
    # begins with it, otherwise drop the first whitespace-delimited token).
    if ($Exe -and $cl.StartsWith($Exe, $ORDI)) { return $cl.Substring($Exe.Length).Trim() }
    $m = [regex]::Match($cl, '^\S+')
    return $cl.Substring($m.Length).Trim()
}

function Stop-ProcAndWait([int]$Id, [int]$TimeoutSec = 10) {
    <# Kill a process by id and wait for it to actually exit (so its listening
       FastCGI socket / port is released before a replacement is spawned).
       Returns $true when the process is gone. #>
    $fn = 'stop_proc'
    $proc = $null
    try { $proc = [Diagnostics.Process]::GetProcessById($Id) } catch { return $true }   # already gone
    try { $proc.Kill() } catch { Write-QLog 2 $fn "Kill on PID ${Id} raised: $($_.Exception.Message)" }
    try { if ($proc.WaitForExit($TimeoutSec * 1000)) { return $true } } catch { return $true }
    # Last check: it may have exited between the timeout and here.
    try { $null = [Diagnostics.Process]::GetProcessById($Id); return $false } catch { return $true }
}

function Get-StandalonePhpCgi($Table) {
    <# Running php-cgi.exe processes that NO web server manages: their parent is
       not w3wp.exe (IIS FastCGI) or httpd.exe (Apache mod_fcgid) -- which
       respawn their own workers on pool recycle / service restart -- and not
       another php-cgi.exe (a PHP_FCGI_CHILDREN manager, whose children die with
       it). Only these "root" standalone workers must be killed and respawned
       by this script. #>
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($p in $Table.Values) {
        if ($p.Name -ne 'php-cgi.exe' -or -not $p.Path) { continue }
        $parentName = ''
        if ($Table.ContainsKey($p.ParentId)) { $parentName = $Table[$p.ParentId].Name }
        if (@('w3wp.exe', 'httpd.exe', 'php-cgi.exe') -contains $parentName) { continue }
        $list.Add($p)
    }
    return ,$list
}

function Restart-StandalonePhpCgi($Table) {
    <# Pseudo-code of what this does, per standalone php-cgi.exe worker:
           cmd  <- exact CommandLine it was started with (args preserved)
           exe  <- its ExecutablePath
           kill the old PID and wait until it has fully exited (frees the port)
           relaunch exe with the SAME argument tail, detached, in exe's folder
       php-cgi may carry arguments (-b <addr:port>, -c <php.ini>, etc.); those
       are taken verbatim from the recorded command line so the replacement
       listens on the same address and loads the same ini. The replacement
       inherits this (elevated) process's environment, which carries the
       machine-level PHPRC / PHP_INI_SCAN_DIR; a per-process env override on the
       old worker cannot be read back from WMI and is not reproduced. #>
    $fn = 'restart_php_cgi'
    $ok = $true
    $procs = Get-StandalonePhpCgi $Table
    if ($procs.Count -eq 0) { Write-QLog 3 $fn 'No standalone php-cgi.exe workers to restart'; return @{ Ok = $true; Count = 0 } }
    foreach ($p in $procs) {
        $exe = $p.Path
        $argTail = Split-ExeAndArgs $p.Cmd $exe
        $wd = Split-Path $exe -Parent
        Write-QLog 3 $fn "Standalone php-cgi.exe PID $($p.Id) command line: $($p.Cmd)"
        Write-QLog 1 $fn "Restarting standalone php-cgi.exe PID $($p.Id): `"$exe`" $argTail"
        if (-not (Stop-ProcAndWait $p.Id)) {
            Write-QLog 0 $fn "Could not stop php-cgi.exe PID $($p.Id); leaving it running"
            $ok = $false
            continue
        }
        Write-QLog 1 $fn "Stopped old php-cgi.exe PID $($p.Id)"
        Start-Sleep -Milliseconds 500   # let the released socket/port settle
        try {
            $sp = @{ FilePath = $exe; WorkingDirectory = $wd; WindowStyle = 'Hidden'; PassThru = $true }
            if ($argTail) { $sp['ArgumentList'] = $argTail }
            $np = Start-Process @sp
            Write-QLog 1 $fn "Spawned new php-cgi.exe PID $($np.Id) (replacing old PID $($p.Id))"
        } catch {
            Write-QLog 0 $fn "Failed to spawn replacement php-cgi.exe for old PID $($p.Id): $($_.Exception.Message)"
            $ok = $false
        }
    }
    return @{ Ok = $ok; Count = $procs.Count }
}

function Restart-PhpServices($Baseline) {
    <# Returns SUCCESS, FAILURE or CONFIG_INVALID (nothing was restarted). #>
    $fn = 'restart_php_services'
    if (-not (Test-Configs $Baseline)) { return $CONFIG_INVALID }
    $ok = $true
    $table = Get-ProcTable
    $pools = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in $script:Env.ScopedPools) { if (-not $pools.Contains($p)) { $pools.Add($p) } }
    foreach ($w in (Get-PhpWorkers $table $script:Env.ModPhpExes)) {
        if (-not $table.ContainsKey($w.ParentId)) { continue }
        $parent = $table[$w.ParentId]
        if ($parent.Name -ne 'w3wp.exe') { continue }
        $pool = Get-ArgValue $parent.Cmd '-ap'
        if (-not $pool) { Write-QLog 0 $fn "Cannot determine the app pool of w3wp.exe PID $($parent.Id)"; $ok = $false; continue }
        if (-not $pools.Contains($pool)) { $pools.Add($pool) }
    }
    if ($pools.Count -gt 0) {
        $appcmd = Get-SystemPath 'inetsrv\appcmd.exe'
        foreach ($pool in $pools) {
            $st = Invoke-Cmd -File $appcmd -Arguments @('list', 'apppool', "/name:$pool", '/text:state')
            if ($st.RC -ne 0) { Write-QLog 0 $fn "Cannot query app pool ${pool}: $($st.Err) $($st.Out)"; $ok = $false; continue }
            if ($st.Out -ne 'Started') { Write-QLog 2 $fn "App pool $pool is $($st.Out); not recycled"; continue }
            $r = Invoke-Cmd -File $appcmd -Arguments @('recycle', 'apppool', "/apppool.name:$pool") -TimeoutSec $RESTART_TIMEOUT
            if ($r.RC -eq 0) { Write-QLog 1 $fn "Recycled IIS app pool $pool" }
            else { Write-QLog 0 $fn "Could not recycle app pool ${pool}: $($r.Err) $($r.Out)"; $ok = $false }
        }
    }
    foreach ($a in $script:Env.Apache) {
        if ($a.State -ne 'Running' -or -not ($a.Cfg.ModPhp -or $a.Cfg.Fcgid.Count -gt 0)) { continue }
        $r = Invoke-Cmd -File $a.Exe -Arguments @('-n', $a.Name, '-k', 'restart') -WorkDir (Split-Path $a.Exe -Parent) -TimeoutSec $RESTART_TIMEOUT
        if ($r.RC -eq 0) { Write-QLog 1 $fn "Restarted Apache service $($a.Name)" }
        else { Write-QLog 0 $fn "Could not restart Apache service $($a.Name): $($r.Err) $($r.Out)"; $ok = $false }
    }
    # Standalone php-cgi.exe workers (not managed by IIS/Apache) are not respawned
    # by any manager, so kill the old ones and relaunch them with the same args.
    $cgi = Restart-StandalonePhpCgi $table
    if (-not $cgi.Ok) { $ok = $false }
    $apacheRunning = @($script:Env.Apache | Where-Object { $_.State -eq 'Running' }).Count -gt 0
    if ($pools.Count -eq 0 -and -not $apacheRunning -and $cgi.Count -eq 0) {
        Write-QLog 2 $fn 'No IIS app pool, Apache service or standalone php-cgi.exe runs PHP; nothing to restart'
    }
    if ($ok) { return $SUCCESS }
    return $FAILURE
}

function Wait-FreshWorkers([DateTime]$CutoffUtc, [int]$TimeoutSec = $WORKER_FRESH_TIMEOUT) {
    $fn = 'wait_fresh_workers'
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    while ($true) {
        $stale = Get-StaleWorkers $CutoffUtc
        if ($stale.Count -eq 0) { Write-QLog 1 $fn 'Every PHP worker started after the restart'; return $true }
        if ([DateTime]::UtcNow -ge $deadline) {
            foreach ($w in $stale) { Write-QLog 0 $fn "Stale $($w.Name) PID $($w.Id) (parent $($w.ParentId)) predates the restart" }
            return $false
        }
        Start-Sleep -Seconds 1
    }
}

function Invoke-RestartAndConfirm($Baseline) {
    $cut = [DateTime]::UtcNow
    $rs = Restart-PhpServices $Baseline
    if ($rs -ne $SUCCESS) { return $rs }
    if (-not (Wait-FreshWorkers $cut)) {
        Write-QLog 0 'restart_and_confirm' 'PHP workers from before the restart are still running; they keep the previous state'
        return $FAILURE
    }
    return $SUCCESS
}


# --------------------- ROLLBACK ---------------------
function Invoke-Rollback($Targets) {
    $fn = 'rollback'
    try {
        Write-QLog 3 $fn 'Starting PHP upload-progress rollback'
        $state = Invoke-Verify $Targets $false
        if ($state -eq $FAILURE) { Write-QLog 0 $fn 'Initial verification failed; cannot proceed with rollback'; return $FAILURE }
        $tagged = 0
        foreach ($t in $Targets) {
            $h = Test-FileHasTags $t.Path
            if ($null -eq $h) { return $FAILURE }
            if ($h) { $tagged++ }
        }
        $hasBackup = [IO.File]::Exists($BACKUP_PATH)
        if (-not $hasBackup -and $tagged -eq 0) {
            if ($state -eq $SUCCESS) { Write-QLog 2 $fn 'Settings are hardened but not by this script (no backup, no markers); leaving them untouched' }
            else { Write-QLog 2 $fn 'No backup and no markers; nothing this script changed' }
            return $SKIP
        }
        $baseline = Get-StartupBaseline
        if ($hasBackup) {
            Write-QLog 1 $fn 'Backup manifest found; restoring original files'
            $r = Restore-Backup
            if ($r -eq $CORRUPT) { Write-QLog 2 $fn 'Backup unusable; falling back to marker-based revert' }
            elseif ($r -ne $SUCCESS) { Write-QLog 0 $fn 'Failed to restore from backup'; return $FAILURE }
        }
        foreach ($t in $Targets) {
            $h = Test-FileHasTags $t.Path
            if ($null -eq $h) { return $FAILURE }
            if ($h -and (Undo-File $t.Path) -eq $FAILURE) { Write-QLog 0 $fn "Failed to revert $($t.Path)"; return $FAILURE }
        }
        $rs = Invoke-RestartAndConfirm $baseline
        if ($rs -eq $CONFIG_INVALID) { Write-QLog 0 $fn 'Restored configuration failed the startup/config test; services were not restarted; fix the configuration manually'; return $FAILURE }
        if ($rs -ne $SUCCESS) { Write-QLog 0 $fn 'Files reverted but not every PHP worker was restarted'; return $FAILURE }
        $left = @($Targets | Where-Object { (Test-FileHasTags $_.Path) -ne $false })
        if ($left.Count -gt 0) {
            foreach ($t in $left) { Write-QLog 0 $fn "Mitigation markers still present or unreadable: $($t.Path)" }
            return $FAILURE
        }
        if ((Invoke-Verify $Targets $false) -eq $SUCCESS) { Write-QLog 2 $fn 'Files reverted; the original configuration was already compliant' }
        Write-QLog 1 $fn 'Rollback completed successfully'
        return $SUCCESS
    } catch {
        Write-QLog 0 $fn "Error during rollback: $($_.Exception.Message)"
        return $FAILURE
    }
}


# --------------------- MAIN ---------------------
function Show-Environment {
    $fn = 'print_environment'
    $parts = New-Object 'System.Collections.Generic.List[string]'
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem
        $parts.Add("OS=$($os.Caption) $($os.Version)"); $parts.Add("Arch=$($os.OSArchitecture)")
    } catch { $parts.Add('OS=Unknown') }
    $parts.Add("Host=$env:COMPUTERNAME")
    $parts.Add("PowerShell=$($PSVersionTable.PSVersion)")
    if ($script:TargetService) { $parts.Add("Service=$($script:TargetService)(ignored)") }
    if ($script:AffectedPort) { $parts.Add("Port=$($script:AffectedPort)") }
    Write-QLog 3 $fn ('Environment: ' + ($parts -join ' | '))
    foreach ($r in $script:Env.Runtimes) {
        $bin = Get-RuntimeProbe $r
        $v = 'not-detected'
        if ($bin) {
            $o = Invoke-Cmd -File $bin -Arguments @('-v') -EnvOverlay $r.Env -WorkDir (Split-Path $bin -Parent)
            if ($o.RC -eq 0 -and $o.Out) { $v = ($o.Out -split "`r?`n")[0].Trim() }
        }
        Write-QLog 3 $fn "PHP runtime ($($r.Source)): $($r.Binary) -> $v"
    }
}

function Show-Policy {
    <# Print the enforced policy so the run shows exactly what each directive is
       being driven to (and, for post_max_size, that the target is exactly 32M). #>
    $fn = 'print_policy'
    $modeText = @{ bool = 'must equal'; exact = 'must equal'; eq_bytes = 'must equal (exact)'
                   max_bytes = 'must be <='; lt_bytes = 'must be <' }
    Write-QLog 3 $fn 'Enforced php.ini / drop-in directives:'
    foreach ($d in $INI_DIRECTIVES) {
        $rule = $modeText[$d.Mode]; if (-not $rule) { $rule = 'must equal' }
        Write-QLog 3 $fn ("    {0} {1} {2}" -f $d.Key, $rule, $d.Val)
    }
    Write-QLog 3 $fn "Enforced upload rule: $UPLOAD_KEY must be below post_max_size (lowered to 1M under it when it is not)"
    Write-QLog 3 $fn 'Enforced .user.ini / .htaccess directives:'
    foreach ($d in $SESSION_INI) { Write-QLog 3 $fn ("    {0} must equal {1}" -f $d.Key, $d.Val) }
}

function Invoke-Main {
    <# Rollback-only entry point: takes no arguments and never mitigates. #>
    $fn = 'main'
    $exit = $SUCCESS
    try {
        Write-QLog 3 '__name__' 'Initializing Script'
        if ((Test-Admin) -ne $SUCCESS) { return $FAILURE }
        if ((Get-RunLock) -ne $SUCCESS) { return $FAILURE }

        $script:Env = Get-DiscoveredEnvironment
        Show-Environment
        Show-Policy
        $targets = Get-Targets
        $exit = Invoke-Rollback $targets
    } catch {
        Write-QLog 0 $fn "Unexpected error in main: $($_.Exception.Message)"
        $exit = $FAILURE
    } finally {
        if ($script:Mutex) { try { $script:Mutex.ReleaseMutex() } catch { } }
    }
    Write-QLog 3 $fn "Exiting with status code: $exit"
    return $exit
}

# Dot-sourcing (". .\phpdisupldprogress_rollback.ps1") loads the functions without running.
if ($MyInvocation.InvocationName -ne '.') {
    # Last element: the return value, even if something wrote to the pipeline.
    exit ([int](@(Invoke-Main)[-1]))
}