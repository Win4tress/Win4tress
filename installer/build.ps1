<#
  Builds win4tress's installer, target\installer\win4tress-<version>-x64.msi,
  from installer\win4tress.wxs: the release programs and the app first,
  unless -SkipBuild.

  Needs, once:
    dotnet tool install --global wix                     # WiX Toolset v7
    wix eula accept wix7                                 # its OSMF EULA, by you
    wix extension add -g WixToolset.Util.wixext/7.0.0
    .\tools\dev\fetch-geo.ps1; .\tools\dev\fetch-oui.ps1  # the data it ships

    .\installer\build.ps1
    .\installer\build.ps1 -SkipBuild
#>
param([switch]$SkipBuild)
# Not 'Stop': cargo and npm report progress on stderr, which PowerShell would
# take for errors when the output is captured. Their exit codes decide.
$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot

$version = (Select-String -Path "$root\Cargo.toml" -Pattern '^version\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
foreach ($file in 'geo\dbip-country-lite.mmdb', 'geo\dbip-asn-lite.mmdb', 'oui\oui.csv') {
    if (-not (Test-Path "$root\data\$file")) {
        throw "data\$file is missing: run tools\dev\fetch-geo.ps1 and tools\dev\fetch-oui.ps1"
    }
}

if (-not $SkipBuild) {
    cargo build --release -p win4tress-svc -p win4tress-cli -p win4tress-dns
    if ($LASTEXITCODE) { throw 'cargo build failed' }
    Push-Location "$root\ui"
    try {
        npm run tauri build
        if ($LASTEXITCODE) { throw 'npm run tauri build failed' }
    } finally {
        Pop-Location
    }
}

$out = "$root\target\installer\win4tress-$version-x64.msi"
wix build "$root\installer\win4tress.wxs" -arch x64 -ext WixToolset.Util.wixext `
    -d "Version=$version" -d "Bin=$root\target\release" -d "Data=$root\data" -d "Icons=$root\ui\src-tauri\icons" `
    -o $out
if ($LASTEXITCODE) { throw 'wix build failed' }
"Built $out"
