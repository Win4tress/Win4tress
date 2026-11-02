# Records a short ETW trace for the decoder regression test
# (crates/w4-etw/tests/replay.rs). Run from an ELEVATED terminal after building:
#
#   cargo build -p win4tress-svc
#   .\tools\dev\record-trace.ps1
#
# The trace contains this PC's real traffic (addresses, DNS names, program
# paths), so it is written to tools\traces\local.etl, which git ignores.
param(
    [string]$Out = (Join-Path $PSScriptRoot '..\traces\local.etl'),
    [int]$Seconds = 15,
    [string]$Svc = (Join-Path $PSScriptRoot '..\..\target\debug\win4tress-svc.exe')
)
$ErrorActionPreference = 'Stop'
$Out = [IO.Path]::GetFullPath($Out)
New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
Remove-Item $Out -ErrorAction SilentlyContinue
$data = Join-Path $env:TEMP "win4tress-record-$PID"

# Own pipe and data folder, so this never touches an installed service.
# ($Svc is the path; PowerShell names are case-insensitive, hence $process.)
$process = Start-Process $Svc -PassThru -NoNewWindow -ArgumentList @(
    'console', '--exit-after', $Seconds, '--record', $Out,
    '--pipe', '\\.\pipe\win4tress-record', '--data-dir', $data)
Start-Sleep -Seconds 3
# Known traffic: a DNS lookup and an HTTPS download.
& curl.exe -s -o NUL 'https://speed.cloudflare.com/__down?bytes=2000000'
$process.WaitForExit()
Remove-Item $data -Recurse -Force -ErrorAction SilentlyContinue
"Recorded $Out ($([math]::Round((Get-Item $Out).Length / 1KB)) KB)"
