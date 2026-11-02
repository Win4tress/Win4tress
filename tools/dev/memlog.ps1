# Logs win4tress's memory and handles over time, for leak hunting: the
# service, the DNS resolver, the app, and the WebView2 processes behind the
# app's window. Start win4tress first (installed, or a console run), then run
# this in a normal terminal and leave it:
#
#   .\tools\dev\memlog.ps1 -Out memlog.csv
#
# One row per sample: working set (RAM in use), private memory (what's
# committed) and handles, per part. Steady numbers overnight mean no leak; a
# column that only ever climbs means one. A part that isn't running is blank.
param(
    [string]$Out = 'memlog.csv',
    [int]$IntervalSeconds = 300
)
if (-not (Test-Path $Out)) {
    'time,svc_ws_mb,svc_private_mb,svc_handles,dns_ws_mb,dns_private_mb,dns_handles,app_ws_mb,app_private_mb,app_handles,webview_ws_mb,webview_private_mb,webview_processes' |
        Out-File -Encoding ascii $Out
}
function Part([string]$Name) {
    $p = @(Get-Process $Name -ErrorAction SilentlyContinue)[0]
    if (-not $p) { return @('', '', '') }
    @([math]::Round($p.WorkingSet64 / 1MB, 1), [math]::Round($p.PrivateMemorySize64 / 1MB, 1), $p.HandleCount)
}
while ($true) {
    $webview = @(Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" |
        Where-Object { $_.CommandLine -like '*com.win4tress.desktop*' } |
        ForEach-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue })
    $row = @((Get-Date -Format s)) + (Part 'win4tress-svc') + (Part 'win4tress-dns') + (Part 'win4tress-ui') + @(
        [math]::Round(($webview | Measure-Object WorkingSet64 -Sum).Sum / 1MB, 1),
        [math]::Round(($webview | Measure-Object PrivateMemorySize64 -Sum).Sum / 1MB, 1),
        $webview.Count
    )
    $line = $row -join ','
    $line | Out-File -Append -Encoding ascii $Out
    Write-Host $line
    Start-Sleep -Seconds $IntervalSeconds
}
