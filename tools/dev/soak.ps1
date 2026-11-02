# Long-running health check for the Phase 1 exit criteria (docs/PLAN.md): samples
# the service once a minute into a CSV. Start the service first (installed, or
# `win4tress-svc console`), then run this in a normal terminal and leave it:
#
#   .\tools\dev\soak.ps1 -Out soak-72h.csv
#
# Columns: memory and CPU of the service, ETW events and losses, app bytes vs
# adapter bytes (accuracy), and history database size.
param(
    [string]$Out = 'soak.csv',
    [int]$IntervalSeconds = 60,
    [string]$Cli = (Join-Path $PSScriptRoot '..\..\target\release\win4tress.exe'),
    [string]$Pipe = '\\.\pipe\win4tress'
)
$ErrorActionPreference = 'Stop'
$cores = [Environment]::ProcessorCount
if (-not (Test-Path $Out)) {
    'time,uptime_s,working_set_mb,cpu_s,cpu_pct,events,events_lost,buffers_lost,parse_errors,app_in_mb,app_out_mb,adapter_in_mb,adapter_out_mb,history_mb' |
        Out-File -Encoding ascii $Out
}
$prev = $null
while ($true) {
    $json = & $Cli status --json --pipe $Pipe 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "$(Get-Date -Format s) service not answering"
    } else {
        $s = $json | ConvertFrom-Json
        $cpuPct = ''
        if ($prev) {
            $wallMs = $s.now_ms - $prev.now_ms
            if ($wallMs -gt 0) {
                $cpuPct = [math]::Round(100 * ($s.process.cpu_ms - $prev.process.cpu_ms) / ($wallMs * $cores), 3)
            }
        }
        $mb = { param($b) [math]::Round($b / 1MB, 2) }
        $row = @(
            (Get-Date -Format s),
            [int](($s.now_ms - $s.started_ms) / 1000),
            (& $mb $s.process.working_set),
            [math]::Round($s.process.cpu_ms / 1000, 1),
            $cpuPct,
            $s.collector.events,
            $s.collector.events_lost,
            $s.collector.buffers_lost,
            $s.collector.parse_errors,
            (& $mb $s.apps_bytes.recv), (& $mb $s.apps_bytes.sent),
            (& $mb $s.adapter_bytes.recv), (& $mb $s.adapter_bytes.sent),
            (& $mb $s.history.size_bytes)
        ) -join ','
        $row | Out-File -Encoding ascii -Append $Out
        Write-Output "$(Get-Date -Format T)  memory $(& $mb $s.process.working_set) MB  cpu $cpuPct%  lost $($s.collector.events_lost)  history $(& $mb $s.history.size_bytes) MB"
        $prev = $s
    }
    Start-Sleep -Seconds $IntervalSeconds
}
