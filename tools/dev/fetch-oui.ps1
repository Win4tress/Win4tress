# Downloads the IEEE MA-L registry (who makes which hardware addresses) to
# data\oui\oui.csv, for the Network screen's "Maker" column. Not committed:
# it's ~4 MB and changes daily. The service finds it there when run from this
# repository (see w4-monitors' oui module).
#
#   .\tools\dev\fetch-oui.ps1
param([string]$Destination = (Join-Path $PSScriptRoot '..\..\data\oui'))

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Destination | Out-Null

$url = 'https://standards-oui.ieee.org/oui/oui.csv'
$target = Join-Path $Destination 'oui.csv'
$partial = "$target.part"
# IEEE's server refuses requests without a browser-like user agent.
Invoke-WebRequest -UseBasicParsing $url -OutFile $partial -UserAgent 'Mozilla/5.0 (win4tress fetch-oui)'
$lines = (Get-Content $partial -TotalCount 2)
if ($lines[0] -notmatch '^Registry,Assignment,Organization Name') {
    Remove-Item $partial
    throw "Unexpected content from $url"
}
Move-Item -Force $partial $target
Write-Output "Saved $target ($([math]::Round((Get-Item $target).Length / 1MB, 1)) MB)"
