# e2e-et-fallback.ps1 -- ET fallback end-to-end on ONE machine (S3 + S4).
#
# STATUS (2026-11-19): **NOT PASSING YET.** Signaling works end-to-end (two clients that only
# know et:// find each other, both bridges pair up, the room is created and joined, negotiation
# completes and punching starts), but the punch itself fails on one machine: the joiner's punch
# probe is addressed to the *peer's* bind IP (127.0.0.2), which on a single host is the host's
# bridge, so the joiner's own bridge never learns its app address; the link then dies with
# PeerGone and retries. A faithful run needs two machines (each binding 127.0.0.2 locally) or a
# proper address-translation step. Keep this script as a reproduction, not as a gate.
#
# Topology (two loopback aliases stand in for two machines):
#
#   host wgp-client -- bridge(127.0.0.2) -- ET frames -- byte-pipe relay -- bridge(127.0.0.4) -- joiner wgp-client
#        ^ in-process local seed 127.0.0.1:11010/3478                                     |
#        +------------------ --expose echo service                        --forward -------+
#
# Two bridges must bind different loopback addresses here: in a real deployment each side
# binds 127.0.0.2 on its own machine (no conflict); on one machine we use WGP_ET_FALLBACK_BIND.
#
# ASCII-only on purpose: Windows PowerShell 5.1 reads BOM-less files as ANSI and non-ASCII
# bytes break the parser (the same reason scripts/e2e-local.ps1 is ASCII).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\e2e-et-fallback.ps1 `
#       -BridgeBin bridge\wgp-et-bridge\target\debug\wgp-et-fallback.exe

param(
    [ValidateSet('debug', 'release')]
    [string]$Configuration = 'debug',
    [string]$BridgeBin = 'bridge\wgp-et-bridge\target\debug\wgp-et-fallback.exe',
    [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

function Say($m) { Write-Host "== $m" }
function Ok($m) { Write-Host "   PASS  $m" }
function Bad($m) { Write-Host "   FAIL  $m"; exit 1 }

$bin = Join-Path $root "target\$Configuration"
$client = Join-Path $bin 'wgp-client.exe'
if (-not (Test-Path $client)) { Bad "missing $client (run: cargo build -p wgp-client)" }
if (-not (Test-Path $BridgeBin)) { Bad "missing bridge $BridgeBin" }
# 上一轮被强杀的客户端可能留下桥进程（Kill 不会跑 Drop），先清干净再覆盖二进制
Get-Process -Name 'wgp-et-fallback' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300
Copy-Item -Force $BridgeBin (Join-Path $bin 'wgp-et-fallback.exe')

$work = Join-Path $root ("target\e2e-et-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force $work | Out-Null
Say "work dir: $work"

function Free-Port {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start(); $p = $l.LocalEndpoint.Port; $l.Stop(); return $p
}

$relayPort = Free-Port
$svcPort = Free-Port
$fwdPort = Free-Port

# byte-pipe relay: accept two connections, then poll-copy both directions
# (PowerShell thread-pool threads have no runspace, so avoid Task.Run + scriptblock)
$relayJob = Start-Job -ScriptBlock {
    param($port)
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
    $l.Start()
    $a = $l.AcceptSocket(); $b = $l.AcceptSocket()
    $buf = New-Object byte[] 65536
    while ($true) {
        if ($a.Available -gt 0) { $n = $a.Receive($buf); if ($n -le 0) { break }; $b.Send($buf, 0, $n, [System.Net.Sockets.SocketFlags]::None) | Out-Null }
        if ($b.Available -gt 0) { $n = $b.Receive($buf); if ($n -le 0) { break }; $a.Send($buf, 0, $n, [System.Net.Sockets.SocketFlags]::None) | Out-Null }
        Start-Sleep -Milliseconds 2
    }
} -ArgumentList $relayPort

$echoJob = Start-Job -ScriptBlock {
    param($port)
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
    $l.Start()
    while ($true) {
        $c = $l.AcceptSocket()
        $buf = New-Object byte[] 65536
        try {
            while ($true) { $n = $c.Receive($buf); if ($n -le 0) { break }; $c.Send($buf, 0, $n, [System.Net.Sockets.SocketFlags]::None) | Out-Null }
        } catch { }
        $c.Close()
    }
} -ArgumentList $svcPort
Start-Sleep -Milliseconds 600
Say "relay 127.0.0.1:$relayPort ; echo 127.0.0.1:$svcPort"

$procs = @()
function Start-Client($name, $argLine, $bindIp) {
    $env:WGP_ET_FALLBACK_BIND = $bindIp
    $p = Start-Process -FilePath $client -ArgumentList $argLine -WorkingDirectory $work `
        -RedirectStandardOutput (Join-Path $work "$name.out") `
        -RedirectStandardError (Join-Path $work "$name.err") -NoNewWindow -PassThru
    $script:procs += $p
    return $p
}

function Wait-For($file, $pattern, $proc, $seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 300
        if (Test-Path $file) {
            $text = Get-Content $file -Raw -ErrorAction SilentlyContinue
            if ($text -match $pattern) { return $true }
        }
        if ($proc.HasExited) { return $false }
    }
    return $false
}

try {
    Say "host: create room (no real seed, only et:// entry)"
    $hostProc = Start-Client 'host' "host -n et-e2e -k et-e2e -p et://127.0.0.1:$relayPort -i host.key --expose $svcPort" '127.0.0.2'
    $hostOut = Join-Path $work 'host.out'
    if (-not (Wait-For $hostOut '(U/[A-Z0-9-]{10,})' $hostProc $TimeoutSeconds)) {
        Get-Content $hostOut -ErrorAction SilentlyContinue
        Get-Content (Join-Path $work 'host.err') -ErrorAction SilentlyContinue
        Bad "host did not print a room code"
    }
    $text = Get-Content $hostOut -Raw
    $null = $text -match '(U/[A-Z0-9-]{10,})'
    $code = $Matches[1]
    Ok "room $code"

    Say "joiner: join + --forward (et:// only)"
    $joinProc = Start-Client 'join' "join $code -p et://127.0.0.1:$relayPort -i join.key --forward $fwdPort" '127.0.0.4'
    $joinOut = Join-Path $work 'join.out'
    if (-not (Wait-For $joinOut '\[隧道\]\s*就绪' $joinProc $TimeoutSeconds)) {
        Get-Content $joinOut -ErrorAction SilentlyContinue
        Get-Content (Join-Path $work 'join.err') -ErrorAction SilentlyContinue
        Bad "joiner tunnel never came up"
    }
    Ok "tunnel ready (punch + handshake through the bridges)"

    Say "TCP roundtrip through the forwarded port"
    $payload = New-Object byte[] 4096
    (New-Object Random).NextBytes($payload)
    $tcp = [System.Net.Sockets.TcpClient]::new()
    $tcp.Connect('127.0.0.1', $fwdPort)
    $s = $tcp.GetStream()
    $s.Write($payload, 0, $payload.Length); $s.Flush()
    $got = New-Object byte[] $payload.Length
    $read = 0
    $deadline = (Get-Date).AddSeconds(30)
    while ($read -lt $got.Length -and (Get-Date) -lt $deadline) {
        $n = $s.Read($got, $read, $got.Length - $read)
        if ($n -le 0) { break }
        $read += $n
    }
    $tcp.Close()
    if ($read -ne $payload.Length) { Bad "short read: $read / $($payload.Length)" }
    for ($i = 0; $i -lt $payload.Length; $i++) { if ($got[$i] -ne $payload[$i]) { Bad "byte mismatch at $i" } }
    Ok "$($payload.Length) bytes round-tripped byte-for-byte"
    Write-Host ""
    Write-Host "RESULT: PASS"
    exit 0
}
finally {
    foreach ($p in $procs) { try { if (-not $p.HasExited) { $p.Kill() } } catch { } }
    # 客户端被 Kill 时不会跑 Drop，桥会变成孤儿：按名字收掉
    Get-Process -Name 'wgp-et-fallback' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    foreach ($j in @($relayJob, $echoJob)) { try { Stop-Job $j -ErrorAction SilentlyContinue; Remove-Job $j -Force -ErrorAction SilentlyContinue } catch { } }
    Remove-Item Env:\WGP_ET_FALLBACK_BIND -ErrorAction SilentlyContinue
    Write-Host "logs kept in $work"
}
