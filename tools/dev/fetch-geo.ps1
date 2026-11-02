# Downloads DB-IP's free IP-to-Country Lite and IP-to-ASN Lite databases
# (CC BY 4.0, monthly) to data\geo\. Not committed: they're ~8 MB each and
# change monthly. The service finds them there when run from this repository
# (see w4-geo).
#
#   .\tools\dev\fetch-geo.ps1
param([string]$Destination = (Join-Path $PSScriptRoot '..\..\data\geo'))

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Destination | Out-Null

function Get-DbIp([string]$Kind) {
    $target = Join-Path $Destination "dbip-$Kind-lite.mmdb"
    $gz = "$target.gz"
    # This month's file appears early in the month; fall back to last month's.
    $months = @((Get-Date), (Get-Date).AddMonths(-1)) | ForEach-Object { $_.ToString('yyyy-MM') }
    $downloaded = $false
    foreach ($month in $months) {
        $url = "https://download.db-ip.com/free/dbip-$Kind-lite-$month.mmdb.gz"
        try {
            Invoke-WebRequest -UseBasicParsing $url -OutFile $gz
            $downloaded = $true
            Write-Output "Downloaded $url"
            break
        } catch {
            Write-Output "Not available: $url"
        }
    }
    if (-not $downloaded) { throw "Could not download the DB-IP $Kind database." }

    $in = [IO.File]::OpenRead($gz)
    $out = [IO.File]::Create($target)
    try {
        $gzip = New-Object IO.Compression.GZipStream($in, [IO.Compression.CompressionMode]::Decompress)
        $gzip.CopyTo($out)
    } finally {
        $out.Dispose(); $in.Dispose()
    }
    Remove-Item $gz
    Write-Output "Saved $target ($([math]::Round((Get-Item $target).Length / 1MB, 1)) MB)"
}

Get-DbIp 'country'
Get-DbIp 'asn'
Write-Output 'IP geolocation by DB-IP.com, CC BY 4.0.'
