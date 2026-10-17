# 用 PrintWindow 截取 DSMain 扫描结果窗口（解决 CopyFromScreen 空白问题）
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class PW {
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern IntPtr GetWindowDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h, IntPtr dc);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
}
"@ -ErrorAction SilentlyContinue

$hwnd = [IntPtr]0x00D90732
$r = New-Object PW+RECT
[void][PW]::GetWindowRect($hwnd, [ref]$r)
$w = $r.R - $r.L; $h = $r.B - $r.T
Write-Host ("  窗口尺寸 {0}x{1}" -f $w, $h)
if ($w -le 0 -or $h -le 0) { exit 1 }

# 方法1: PrintWindow with PW_RENDERFULLCONTENT (2)
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
$ok = [PW]::PrintWindow($hwnd, $hdc, 2)
$g.ReleaseHdc($hdc)
$g.Dispose()
Write-Host ("  PrintWindow(flags=2) -> {0}" -f $ok)

$out = Join-Path (Get-Location) "dsmain_pw2.png"
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Host ("  保存: {0} ({1} 字节)" -f $out, (Get-Item $out).Length)

# 方法2: flags=0
$bmp2 = New-Object System.Drawing.Bitmap($w, $h)
$g2 = [System.Drawing.Graphics]::FromImage($bmp2)
$hdc2 = $g2.GetHdc()
$ok2 = [PW]::PrintWindow($hwnd, $hdc2, 0)
$g2.ReleaseHdc($hdc2)
$g2.Dispose()
$out2 = Join-Path (Get-Location) "dsmain_pw0.png"
$bmp2.Save($out2, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp2.Dispose()
Write-Host ("  PrintWindow(flags=0) -> {0}  保存: {1} ({2} 字节)" -f $ok2, $out2, (Get-Item $out2).Length)

# 方法3: 整个屏幕（含对话框区域）
$sw = [System.Windows.Forms.Screen]::PrimaryScreen
Add-Type -AssemblyName System.Windows.Forms
$sw = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp3 = New-Object System.Drawing.Bitmap($r.L - 20 + 500, $r.T - 20 + 320)
$g3 = [System.Drawing.Graphics]::FromImage($bmp3)
$g3.CopyFromScreen([Math]::Max(0,$r.L-20), [Math]::Max(0,$r.T-20), 0, 0, $bmp3.Size)
$g3.Dispose()
$out3 = Join-Path (Get-Location) "dsmain_screen.png"
$bmp3.Save($out3, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp3.Dispose()
Write-Host ("  屏幕区域保存: {0} ({1} 字节)" -f $out3, (Get-Item $out3).Length)