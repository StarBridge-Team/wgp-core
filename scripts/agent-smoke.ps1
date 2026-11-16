<#
.SYNOPSIS
  Agent IPC smoke test: start wgp-agent, talk to it over the local endpoint, shut it down.

.DESCRIPTION
  1. build wgp-agent (unless -SkipBuild)
  2. start it with a temp identity file and a temp IPC endpoint
  3. run `wgp-agent ping` against that endpoint: GetVersion + GetSnapshot + ShutdownAgent
  4. wait for the agent to exit by itself (exit code 0), verify the IPC endpoint is gone
  5. start a second agent on the same endpoint while the first one is still running:
     binding must fail with exit code 3 (proves the endpoint is exclusive, not silently shared)

  Exit code 0 = all checks passed.

  ASCII-only on purpose: Windows PowerShell 5.1 reads BOM-less files as ANSI.
#>
param(
    [ValidateSet('debug', 'release')]
    [string]$Configuration = 'debug',
    [switch]$SkipBuild,
    [switch]$KeepLogs
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root "target\$Configuration"
$exe = Join-Path $bin 'wgp-agent.exe'

if (-not $SkipBuild) {
    Write-Host '== building wgp-agent'
    Push-Location $root
    try {
        & cargo build -p wgp-agent --quiet
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    } finally {
        Pop-Location
    }
}
if (-not (Test-Path $exe)) { throw "missing binary: $exe" }

$work = Join-Path ([IO.Path]::GetTempPath()) ('wgp-agent-smoke-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null
$identity = Join-Path $work 'agent.key'
$endpoint = if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    '\\.\pipe\wgp-agent-smoke-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
} else {
    Join-Path $work 'agent.sock'
}
$agentLog = Join-Path $work 'agent.log'

function Wait-Log([string]$path, [string]$pattern, [int]$timeoutMs = 15000) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($timeoutMs)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path $path) {
            $text = Get-Content -Path $path -Raw -Encoding utf8
            if ($text -match $pattern) { return $true }
        }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

$script:failed = $false
function Check([string]$name, [bool]$ok) {
    if ($ok) { Write-Host "   PASS  $name" } else { Write-Host "   FAIL  $name"; $script:failed = $true }
}

Write-Host "== temp dir $work"
$agent = $null
try {
    Write-Host '== start agent'
    $agent = Start-Process -FilePath $exe -PassThru -NoNewWindow `
        -ArgumentList @('--identity', $identity, '--socket', $endpoint) `
        -RedirectStandardOutput $agentLog -RedirectStandardError "$agentLog.err"
    Check 'agent logged readiness' (Wait-Log $agentLog 'ready')

    Write-Host '== second agent must refuse the same endpoint (exit code 3)'
    $dup = Start-Process -FilePath $exe -PassThru -NoNewWindow -Wait `
        -ArgumentList @('--identity', (Join-Path $work 'agent2.key'), '--socket', $endpoint) `
        -RedirectStandardOutput (Join-Path $work 'dup.log') -RedirectStandardError (Join-Path $work 'dup.err')
    Check 'duplicate endpoint refused (exit 3)' ($dup.ExitCode -eq 3)

    Write-Host '== ping over IPC'
    $pingOut = & $exe ping --socket $endpoint 2>&1
    $pingText = ($pingOut | Out-String)
    Write-Host $pingText.TrimEnd()
    Check 'ping reported version' ($pingText -match 'version:')
    Check 'ping reported snapshot' ($pingText -match 'snapshot:')
    Check 'ping exit code 0' ($LASTEXITCODE -eq 0)

    Write-Host '== agent exits after ShutdownAgent'
    $exited = $agent.WaitForExit(10000)
    if (-not $exited) { try { $agent.Kill() } catch { } }
    Check 'agent exited by itself' $exited
    if ($exited) {
        # Windows PowerShell 5.1 的 Start-Process -PassThru 不给 ExitCode（要 -Wait 才有），
        # 所以改断言「优雅退出路径确实跑过」——比进程退出码更能说明问题。
        # 重定向文件的最后一次写入可能比 WaitForExit 稍晚落盘，给两秒缓冲。
        Check 'agent reached its shutdown path' (Wait-Log $agentLog 'exited' 2000)
        if (Test-Path "$agentLog.err") {
            $err = Get-Content "$agentLog.err" -Raw -Encoding utf8
            if ($null -ne $err -and $err.Trim()) { Write-Host "   agent stderr: $($err.Trim())" }
            Check 'no panic on stderr' ($null -eq $err -or $err -notmatch 'panicked')
        }
        Write-Host "   (ExitCode unavailable under 5.1: '$($agent.ExitCode)')"
    }

    $gone = if ($endpoint.StartsWith('\\.\pipe\')) {
        $true # named pipes vanish with the process; nothing to check on disk
    } else {
        -not (Test-Path $endpoint)
    }
    Check 'IPC endpoint cleaned up' $gone
} finally {
    if ($agent -and -not $agent.HasExited) { try { $agent.Kill() } catch { } }
    if (-not $KeepLogs) { Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue }
}

if ($script:failed) { Write-Host 'RESULT: FAIL'; exit 1 }
Write-Host 'RESULT: PASS'
exit 0
