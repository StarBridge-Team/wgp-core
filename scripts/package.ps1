<#
.SYNOPSIS
  Build release binaries and assemble a distributable folder + zip under dist\.

.DESCRIPTION
  Steps:
    1. cargo build --release --locked   (wgp-client, wgp-node, wgp-node-hobby)
    2. smoke checks on the built binaries (version output, room-code test vector)
    3. copy binaries + README + LICENSE into dist\wgp-<version>-<commit>-<host triple>\
    4. write BUILD-INFO.txt and SHA256SUMS.txt, then zip the folder
  Nothing is uploaded or published: the output stays on this machine (dist\ is git-ignored).

  The script is ASCII-only on purpose: Windows PowerShell 5.1 reads BOM-less files as ANSI.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\package.ps1
  powershell -ExecutionPolicy Bypass -File scripts\package.ps1 -SkipBuild -NoZip
#>
param(
    [switch]$SkipBuild,
    [switch]$NoZip
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root 'target\release'
$binaries = @('wgp-client.exe', 'wgp-node.exe', 'wgp-node-hobby.exe')
$utf8 = New-Object Text.UTF8Encoding $false

# Run a native program and capture its output. Tools like cargo and git write progress to
# stderr; that must not trip ErrorActionPreference, so it is relaxed inside this function.
function Invoke-Native([string]$exe, [string[]]$arguments) {
    $ErrorActionPreference = 'Continue'
    $lines = @(& $exe @arguments 2>&1 | ForEach-Object { "$_" })
    return @{ Code = $LASTEXITCODE; Lines = $lines }
}

function First-Line($result) {
    if ($result.Lines.Count -gt 0) { return $result.Lines[0].Trim() }
    return ''
}

Push-Location $root
try {
    # ---- what are we packaging ----
    $versionLine = Get-Content (Join-Path $root 'Cargo.toml') -Encoding UTF8 |
        Where-Object { $_ -match '^\s*version\s*=\s*"[^"]+"' } | Select-Object -First 1
    if (-not $versionLine) { throw 'cannot find the workspace version in Cargo.toml' }
    $version = ([regex]::Match($versionLine, '"([^"]+)"')).Groups[1].Value

    $commit = 'nogit'
    $dirty = $false
    $rev = Invoke-Native 'git' @('rev-parse', '--short', 'HEAD')
    if ($rev.Code -eq 0 -and (First-Line $rev) -ne '') {
        $commit = First-Line $rev
        $status = Invoke-Native 'git' @('status', '--porcelain', '--untracked-files=no')
        $dirty = @($status.Lines | Where-Object { $_.Trim() -ne '' }).Count -gt 0
    }

    $rustc = Invoke-Native 'rustc' @('-vV')
    if ($rustc.Code -ne 0) { throw 'rustc not found' }
    $hostLine = $rustc.Lines | Where-Object { $_ -match '^host:\s*(\S+)' } | Select-Object -First 1
    $triple = ([regex]::Match("$hostLine", '^host:\s*(\S+)')).Groups[1].Value
    if ($triple -eq '') { throw 'cannot read the host triple from rustc -vV' }

    # ---- build ----
    if (-not $SkipBuild) {
        Write-Host '== build (release, locked)'
        $build = Invoke-Native 'cargo' @('build', '--release', '--locked', '--bins')
        $build.Lines | Select-Object -Last 3 | ForEach-Object { Write-Host "   $_" }
        if ($build.Code -ne 0) { throw "cargo build failed (exit $($build.Code))" }
    }

    # ---- smoke checks ----
    Write-Host '== smoke checks'
    foreach ($name in $binaries) {
        $exe = Join-Path $bin $name
        if (-not (Test-Path $exe)) { throw "missing binary: $exe" }
        $out = Invoke-Native $exe @('--version')
        $line = First-Line $out
        if ($out.Code -ne 0 -or $line -notmatch [regex]::Escape($version)) {
            throw "$name --version failed: '$line' (exit $($out.Code))"
        }
        Write-Host "   $line"
    }
    # room-code test vector (docs/13): name = U+793A U+4F8B U+623F U+95F4, key = 123456
    $roomName = -join ([char[]](0x793A, 0x4F8B, 0x623F, 0x95F4))
    $vector = Invoke-Native (Join-Path $bin 'wgp-client.exe') @('code', $roomName, '123456')
    $roomCode = First-Line $vector
    if ($roomCode -ne 'U/C2G9-GYET-311W-R636') { throw "room-code vector mismatch: '$roomCode'" }
    Write-Host "   room-code vector ok: $roomCode"

    # ---- assemble ----
    $label = "wgp-$version-$commit"
    if ($dirty) { $label += '-dirty' }
    $label += "-$triple"
    $dist = Join-Path $root 'dist'
    $pkg = Join-Path $dist $label
    Write-Host "== assemble $label"
    if (Test-Path $pkg) { Remove-Item -Recurse -Force $pkg }
    New-Item -ItemType Directory -Path $pkg -Force | Out-Null

    foreach ($name in $binaries) { Copy-Item (Join-Path $bin $name) $pkg }
    Copy-Item (Join-Path $root 'LICENSE') $pkg
    Copy-Item (Join-Path $PSScriptRoot 'package-readme.md') (Join-Path $pkg 'README.md')

    $rustcVersion = First-Line (Invoke-Native 'rustc' @('--version'))
    $info = @(
        "package : $label",
        "version : $version",
        "commit  : $commit",
        "dirty   : $dirty",
        "target  : $triple",
        "rustc   : $rustcVersion",
        'profile : release (lto, codegen-units=1), built with --locked'
    )
    [IO.File]::WriteAllLines((Join-Path $pkg 'BUILD-INFO.txt'), $info, $utf8)

    $sums = Get-ChildItem $pkg -File | Sort-Object Name | ForEach-Object {
        '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
    }
    [IO.File]::WriteAllLines((Join-Path $pkg 'SHA256SUMS.txt'), $sums, $utf8)

    Get-ChildItem $pkg -File | Sort-Object Name | ForEach-Object {
        Write-Host ('   {0,10}  {1}' -f $_.Length, $_.Name)
    }
    Write-Host "   folder: $pkg"

    if (-not $NoZip) {
        $zip = "$pkg.zip"
        if (Test-Path $zip) { Remove-Item -Force $zip }
        Compress-Archive -Path $pkg -DestinationPath $zip
        Write-Host "   zip   : $zip"
    }
    if ($dirty) { Write-Host '   note  : the working tree has uncommitted changes (package is marked -dirty)' }
}
finally { Pop-Location }

Write-Host 'RESULT: OK'
exit 0
