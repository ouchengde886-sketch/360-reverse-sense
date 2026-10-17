# 用 GetWindowDC + BitBlt 截取窗口（不依赖屏幕，绕过 headless 黑屏）
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WB {
  [DllImport("user32.dll")] public static extern IntPtr GetWindowDC(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h, IntPtr dc);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("gdi32.dll")] public static extern bool BitBlt(IntPtr dst,int dx,int dy,int w,int h,IntPtr src,int sx,int sy,int rop);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public const int SRCCOPY = 0x00CC0020;
  public const uint WM_PRINT = 0x0317;
  public const uint WM_PRINTCLIENT = 0x0318;
  public const int PRF_CLIENT = 0x4, PRF_CHILDREN = 0x10, PRF_NONCLIENT = 0x2, PRF_ERASEBKGND = 0x8, PRF_OWNED = 0x20;
}
"@ -ErrorAction SilentlyContinue

$hwnd = [IntPtr]0x00D90732
$r = New-Object WB+RECT
[void][WB]::GetWindowRect($hwnd, [ref]$r)
$w = $r.R - $r.L; $h = $r.B - $r.T
Write-Host ("  窗口 {0}x{1}" -f $w, $h)

# --- 方法A: GetWindowDC + BitBlt ---
$src = [WB]::GetWindowDC($hwnd)
Write-Host ("  GetWindowDC -> 0x{0:X8}" -f $src.ToInt64())
if ($src -ne [IntPtr]::Zero) {
  $bmp = New-Object System.Drawing.Bitmap($w, $h)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $dst = $g.GetHdc()
  $ok = [WB]::BitBlt($dst, 0, 0, $w, $h, $src, 0, 0, [WB]::SRCCOPY)
  $g.ReleaseHdc($dst); $g.Dispose()
  [void][WB]::ReleaseDC($hwnd, $src)
  $out = Join-Path (Get-Location) "dlg_bitblt.png"
  $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
  $bmp.Dispose()
  Write-Host ("  [A] BitBlt={0}  保存 {1} ({2} 字节)" -f $ok, $out, (Get-Item $out).Length)
}

# --- 方法B: WM_PRINT 让窗口自绘 ---
$flags = [WB]::PRF_CLIENT -bor [WB]::PRF_CHILDREN -bor [WB]::PRF_NONCLIENT -bor [WB]::PRF_ERASEBKGND -bor [WB]::PRF_OWNED
$bmp2 = New-Object System.Drawing.Bitmap($w, $h)
$g2 = [System.Drawing.Graphics]::FromImage($bmp2)
$g2.Clear([System.Drawing.Color]::White)
$hdc2 = $g2.GetHdc()
[void][WB]::SendMessageW($hwnd, [WB]::WM_PRINT, $hdc2, [IntPtr]$flags)
$g2.ReleaseHdc($hdc2); $g2.Dispose()
$out2 = Join-Path (Get-Location) "dlg_wmprint.png"
$bmp2.Save($out2, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp2.Dispose()
Write-Host ("  [B] WM_PRINT 保存 {0} ({1} 字节)" -f $out2, (Get-Item $out2).Length)

# --- 方法C: 对 ShadowEdge 子窗口也试 WM_PRINT ---
$child = [IntPtr]0x02060680
$cr = New-Object WB+RECT
[void][WB]::GetWindowRect($child, [ref]$cr)
$cw = $cr.R - $cr.L; $ch = $cr.B - $cr.T
Write-Host ("  ShadowEdge 子窗口 {0}x{1}" -f $cw, $ch)
if ($cw -gt 0 -and $ch -gt 0) {
  $bmp3 = New-Object System.Drawing.Bitmap($cw, $ch)
  $g3 = [System.Drawing.Graphics]::FromImage($bmp3)
  $g3.Clear([System.Drawing.Color]::White)
  $hdc3 = $g3.GetHdc()
  [void][WB]::SendMessageW($child, [WB]::WM_PRINTCLIENT, $hdc3, [IntPtr]([WB]::PRF_CLIENT -bor [WB]::PRF_CHILDREN -bor [WB]::PRF_ERASEBKGND))
  $g3.ReleaseHdc($hdc3); $g3.Dispose()
  $out3 = Join-Path (Get-Location) "dlg_child.png"
  $bmp3.Save($out3, [System.Drawing.Imaging.ImageFormat]::Png)
  $bmp3.Dispose()
  Write-Host ("  [C] 子窗口保存 {0} ({1} 字节)" -f $out3, (Get-Item $out3).Length)
}