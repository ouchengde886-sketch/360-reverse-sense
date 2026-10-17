# 截取屏幕区域（含 360 扫描结果对话框）
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class PW2 {
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
}
"@ -ErrorAction SilentlyContinue

$hwnd = [IntPtr]0x00D90732
$r = New-Object PW2+RECT
[void][PW2]::GetWindowRect($hwnd, [ref]$r)
$w = $r.R - $r.L; $h = $r.B - $r.T
Write-Host ("  对话框矩形 ({0},{1})-({2},{3})  {4}x{5}" -f $r.L, $r.T, $r.R, $r.B, $w, $h)

# 前置窗口
[void][PW2]::SetForegroundWindow($hwnd)
Start-Sleep -Milliseconds 800

# 截取比对话框稍大的区域
$pad = 30
$x = [Math]::Max(0, $r.L - $pad)
$y = [Math]::Max(0, $r.T - $pad)
$cw = $w + $pad * 2
$ch = $h + $pad * 2

$bmp = New-Object System.Drawing.Bitmap($cw, $ch)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($x, $y, 0, 0, (New-Object System.Drawing.Size($cw, $ch)))
$g.Dispose()
$out = Join-Path (Get-Location) "dsmain_region.png"
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Host ("  保存: {0} ({1} 字节)" -f $out, (Get-Item $out).Length)

# 同时截整屏作为备份
$sb = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp2 = New-Object System.Drawing.Bitmap($sb.Width, $sb.Height)
$g2 = [System.Drawing.Graphics]::FromImage($bmp2)
$g2.CopyFromScreen(0, 0, 0, 0, $sb.Size)
$g2.Dispose()
$out2 = Join-Path (Get-Location) "dsmain_fullscreen.png"
$bmp2.Save($out2, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp2.Dispose()
Write-Host ("  整屏: {0} ({1} 字节)  屏幕={2}x{3}" -f $out2, (Get-Item $out2).Length, $sb.Width, $sb.Height)