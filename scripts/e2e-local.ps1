<#
.SYNOPSIS
  Local end-to-end check with real binaries, loopback only (no real network needed):
  seed node + host (exposes an echo service) + joiner (local forward port).

.DESCRIPTION
  Steps:
    1. start wgp-node (seed + observer) on private ports
    2. start TCP/UDP echo services (stand-in for the host's game server)
    3. host:   wgp-client host ... --expose / --expose-udp
    4. joiner: wgp-client join ... --forward / --forward-udp
    5. verify TCP and UDP traffic through the joiner's local forward ports
    6. kill the joiner (simulated crash), start it again, verify traffic again (re-punch path)
  Exit code 0 = all checks passed.

  The script is ASCII-only on purpose: Windows PowerShell 5.1 reads BOM-less files as ANSI.
  Log patterns are written as \uXXXX regex escapes.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\e2e-local.ps1
  powershell -ExecutionPolicy Bypass -File scripts\e2e-local.ps1 -Configuration release -Bytes 67108864
#>
param(
    [ValidateSet('debug', 'release')]
    [string]$Configuration = 'debug',
    [int]$SeedPort = 21010,
    [int]$StunPort = 23478,
    [int]$TcpPort = 23481,
    [int]$ServicePort = 45565,
    [int]$ForwardPort = 45566,
    [int]$UdpServicePort = 45532,
    [int]$UdpForwardPort = 45533,
    [int]$Bytes = 4194304,
    # use wgp-node-hobby as the only seed (it refuses Forward relay)
    [switch]$Hobby,
    [switch]$SkipBuild,
    [switch]$SkipReconnect,
    [switch]$KeepLogs
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root "target\$Configuration"
$work = Join-Path ([IO.Path]::GetTempPath()) ('wgp-e2e-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null
$script:procs = @()
$script:failed = $false

# log patterns (regex, \uXXXX escapes)
$PatNodeReady = '\u5df2\u5c31\u7eea'                 # node: ready
$PatJoined = '\u5df2\u5165\u8868'                    # client: joined the room table
$PatTunnelReady = '\u96a7\u9053\] \u5c31\u7eea'      # client: tunnel ready

function Quote-Arg([string]$a) {
    if ($a -match '\s') { return '"' + $a + '"' }
    return $a
}

function Start-Bg([string]$name, [string]$exe, [string[]]$arguments) {
    $argLine = ($arguments | ForEach-Object { Quote-Arg $_ }) -join ' '
    $p = Start-Process -FilePath $exe -ArgumentList $argLine -WorkingDirectory $work `
        -RedirectStandardOutput (Join-Path $work "$name.out") `
        -RedirectStandardError (Join-Path $work "$name.err") `
        -NoNewWindow -PassThru
    $script:procs += $p
    Write-Host ("  started {0,-8} pid={1}" -f $name, $p.Id)
    return $p
}

function Read-Log([string]$name) {
    $path = Join-Path $work "$name.out"
    if (-not (Test-Path $path)) { return @() }
    # the file is still being written by the child process: open with shared read/write
    $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $reader = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
        $text = $reader.ReadToEnd()
    }
    finally { $fs.Dispose() }
    return $text -split "`r?`n"
}

function Wait-Log([string]$name, [string]$pattern, [int]$timeoutSec) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        $hit = Read-Log $name | Where-Object { $_ -match $pattern } | Select-Object -First 1
        if ($hit) { return $true }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

function Step([string]$title, [scriptblock]$body) {
    Write-Host "== $title"
    $ok = $false
    try { $ok = [bool](& $body) } catch { Write-Host "   error: $_" }
    if ($ok) { Write-Host '   PASS' } else { Write-Host '   FAIL'; $script:failed = $true }
    return $ok
}

function Run-Check([string[]]$arguments) {
    $tool = Join-Path $bin 'examples\echo_tool.exe'
    $out = & $tool @arguments 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    $out | ForEach-Object { Write-Host "   $_" }
    return ($code -eq 0)
}

function Stop-All {
    foreach ($p in $script:procs) {
        try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch { }
    }
}

function Client-Args([string]$command, [string]$identity, [string[]]$extra) {
    return @(
        $command, '--name', 'e2e-local', '--key', $script:roomKey,
        '--seed', "udp://127.0.0.1:$SeedPort",
        '--observer', "127.0.0.1:$StunPort",
        '-i', (Join-Path $work $identity)
    ) + $extra
}

try {
    if (-not $SkipBuild) {
        Write-Host "== build ($Configuration)"
        $buildArgs = @('build', '--workspace', '--bins', '--examples')
        if ($Configuration -eq 'release') { $buildArgs += '--release' }
        Push-Location $root
        try {
            # cargo prints progress on stderr; do not let it trip ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            & cargo @buildArgs 2>&1 | Select-Object -Last 3 | ForEach-Object { Write-Host "   $_" }
            $buildCode = $LASTEXITCODE
            $ErrorActionPreference = 'Stop'
        }
        finally { Pop-Location }
        if ($buildCode -ne 0) { throw "cargo build failed (exit $buildCode)" }
    }

    $script:roomKey = [Guid]::NewGuid().ToString('N').Substring(0, 12)
    $nodeExe = 'wgp-node.exe'
    if ($Hobby) { $nodeExe = 'wgp-node-hobby.exe' }
    Write-Host "== start processes (work dir: $work)"

    # On loopback every client shares the source IP 127.0.0.1, so they also share one
    # observer rate-limit bucket (default 12 requests / 10 s; one negotiation costs 4).
    # Raise the limit for this test seed, otherwise a re-punch right after the first
    # negotiation gets throttled and has to rely on the retry path.
    Start-Bg 'node' (Join-Path $bin $nodeExe) @(
        '--bind', "127.0.0.1:$SeedPort", '--stun', "$StunPort", '--tcp', "$TcpPort",
        '--observer-rate-limit', '1000',
        '--identity', (Join-Path $work 'node.key')) | Out-Null
    Start-Bg 'echo-tcp' (Join-Path $bin 'examples\echo_tool.exe') @('serve-tcp', "$ServicePort") | Out-Null
    Start-Bg 'echo-udp' (Join-Path $bin 'examples\echo_tool.exe') @('serve-udp', "$UdpServicePort") | Out-Null

    $ready = Step 'seed node ready' { Wait-Log 'node' $PatNodeReady 15 }
    if (-not $ready) { throw 'seed node did not become ready' }

    Start-Bg 'host' (Join-Path $bin 'wgp-client.exe') (Client-Args 'host' 'host.key' @(
            '--expose', "$ServicePort", '--expose-udp', "$UdpServicePort")) | Out-Null
    $hostJoined = Step 'host created the room' { Wait-Log 'host' $PatJoined 20 }
    if (-not $hostJoined) { throw 'host failed to create the room' }

    $joinerExtra = @('--forward', "${ForwardPort}:${ServicePort}", '--forward-udp', "${UdpForwardPort}:${UdpServicePort}")
    Start-Bg 'joiner' (Join-Path $bin 'wgp-client.exe') (Client-Args 'join' 'joiner.key' $joinerExtra) | Out-Null
    $joined = Step 'joiner entered the room table' { Wait-Log 'joiner' $PatJoined 30 }

    if ($joined) {
        $tunnel = Step 'tunnel ready on joiner (punch + handshake)' { Wait-Log 'joiner' $PatTunnelReady 60 }
        if ($tunnel) {
            Step "TCP forward: $Bytes bytes round trip through 127.0.0.1:$ForwardPort" {
                Run-Check @('check-tcp', "127.0.0.1:$ForwardPort", "$Bytes")
            } | Out-Null
            Step "UDP forward: datagrams through 127.0.0.1:$UdpForwardPort" {
                Run-Check @('check-udp', "127.0.0.1:$UdpForwardPort", '40')
            } | Out-Null

            if (-not $SkipReconnect) {
                Write-Host '== simulate joiner crash, then restart it'
                $old = $script:procs | Where-Object { -not $_.HasExited } | Select-Object -Last 1
                Stop-Process -Id $old.Id -Force
                Start-Sleep -Milliseconds 500
                Start-Bg 'joiner2' (Join-Path $bin 'wgp-client.exe') (Client-Args 'join' 'joiner.key' $joinerExtra) | Out-Null
                $again = Step 'tunnel ready again after restart (re-punch, new session key)' {
                    Wait-Log 'joiner2' $PatTunnelReady 90
                }
                if ($again) {
                    Step 'TCP forward works again after reconnect' {
                        Run-Check @('check-tcp', "127.0.0.1:$ForwardPort", '1048576')
                    } | Out-Null
                }
            }
        }
    }
}
catch {
    Write-Host "!! $_"
    $script:failed = $true
}
finally {
    Stop-All
    if ($script:failed -or $KeepLogs) {
        Write-Host "== logs kept in $work"
        foreach ($name in @('node', 'host', 'joiner', 'joiner2')) {
            $lines = Read-Log $name
            if ($lines.Count -gt 0) {
                Write-Host "---- $name (last 25 lines) ----"
                $lines | Where-Object { $_ -ne '' } | Select-Object -Last 25 | ForEach-Object { Write-Host "   $_" }
            }
        }
    }
    else {
        Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    }
}

if ($script:failed) {
    Write-Host 'RESULT: FAIL'
    exit 1
}
Write-Host 'RESULT: PASS'
exit 0
