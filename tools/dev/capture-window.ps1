# Saves a PNG of a window's contents, for UI review without touching the window.
# PrintWindow with PW_RENDERFULLCONTENT also captures WebView2 content that is
# partly covered by other windows.
#
#   .\tools\dev\capture-window.ps1 -Out shot.png                  # first win4tress-ui window
#   .\tools\dev\capture-window.ps1 -ProcessId 1234 -Out shot.png
param(
    [string]$ProcessName = 'win4tress-ui',
    [int]$ProcessId,
    [Parameter(Mandatory)][string]$Out
)

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class W4Capture {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
}
"@
[W4Capture]::SetProcessDPIAware() | Out-Null

$process = if ($ProcessId) { Get-Process -Id $ProcessId } else { Get-Process $ProcessName }
$process = $process | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
if (-not $process) { throw "no window found" }
$handle = $process.MainWindowHandle

if ([W4Capture]::IsIconic($handle)) {
    [W4Capture]::ShowWindow($handle, 9) | Out-Null   # SW_RESTORE
    Start-Sleep -Milliseconds 400
}

$rect = New-Object W4Capture+RECT
[W4Capture]::GetWindowRect($handle, [ref]$rect) | Out-Null
$bitmap = New-Object System.Drawing.Bitmap ($rect.Right - $rect.Left), ($rect.Bottom - $rect.Top)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$hdc = $graphics.GetHdc()
[W4Capture]::PrintWindow($handle, $hdc, 2) | Out-Null   # PW_RENDERFULLCONTENT
$graphics.ReleaseHdc($hdc)
$graphics.Dispose()
$bitmap.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$bitmap.Dispose()
Write-Output "$Out ($($rect.Right - $rect.Left) x $($rect.Bottom - $rect.Top))"
