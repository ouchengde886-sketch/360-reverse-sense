# 截取 DSMain 扫描结果窗口的图像
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Cap {
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
}
"@ -ErrorAction SilentlyContinue

$hwnd = [IntPtr]0x00D90732
$r = New-Object Cap+RECT
[void][Cap]::GetWindowRect($hwnd, [ref]$r)
$w = $r.R - $r.L
$h = $r.B - $r.T
Write-Host ("  窗口矩形: ({0},{1})-({2},{3})  尺寸={4}x{5}" -f $r.L, $r.T, $r.R, $r.B, $w, $h)

if ($w -le 0 -or $h -le 0) { Write-Host "  尺寸无效"; exit 1 }

[void][Cap]::SetForegroundWindow($hwnd)
Start-Sleep -Milliseconds 600

$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.L, $r.T, 0, 0, (New-Object System.Drawing.Size($w, $h)))
$out = Join-Path (Get-Location) "dsmain_scan_result.png"
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Host ("  已保存: {0}  ({1} 字节)" -f $out, (Get-Item $out).Length)