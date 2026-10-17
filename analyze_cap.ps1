# 分析截图内容 + 尝试更多捕获方式
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WB2 {
  [DllImport("user32.dll")] public static extern IntPtr GetWindowDC(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h, IntPtr dc);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("gdi32.dll")] public static extern bool BitBlt(IntPtr dst,int dx,int dy,int w,int h,IntPtr src,int sx,int sy,int rop);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public const int SRCCOPY = 0x00CC0020;
  public const int SRCCOPY_CAPTUREBLT = 0x40CC0020;
}
"@ -ErrorAction SilentlyContinue

function Analyze($path) {
  if (-not (Test-Path $path)) { Write-Host ("  {0}: 不存在" -f $path); return }
  $b = New-Object System.Drawing.Bitmap($path)
  $colors = @{}
  $nonBlack = 0
  for ($y = 0; $y -lt $b.Height; $y += 4) {
    for ($x = 0; $x -lt $b.Width; $x += 4) {
      $c = $b.GetPixel($x, $y)
      $k = "{0},{1},{2}" -f $c.R, $c.G, $c.B
      if (-not $colors.ContainsKey($k)) { $colors[$k] = 0 }
      $colors[$k]++
      if ($c.R -gt 20 -or $c.G -gt 20 -or $c.B -gt 20) { $nonBlack++ }
    }
  }
  $b.Dispose()
  Write-Host ("  {0}: 不同颜色数={1}  非黑采样点={2}" -f (Split-Path $path -Leaf), $colors.Count, $nonBlack)
  $top = $colors.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
  foreach ($t in $top) { Write-Host ("      颜色 {0} x{1}" -f $t.Key, $t.Value) }
}

Write-Host "=== 已有截图内容分析 ==="
Analyze ".\dlg_bitblt.png"
Analyze ".\dlg_wmprint.png"
Analyze ".\dlg_child.png"
Analyze ".\dsmain_fullscreen.png"

Write-Host "=== 尝试从桌面 DC 捕获（CAPTUREBLT）==="
$hwnd = [IntPtr]0x00D90732
$r = New-Object WB2+RECT
[void][WB2]::GetWindowRect($hwnd, [ref]$r)
$w = $r.R - $r.L; $h = $r.B - $r.T
$desk = [WB2]::GetDC([IntPtr]::Zero)
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$dst = $g.GetHdc()
$ok = [WB2]::BitBlt($dst, 0, 0, $w, $h, $desk, $r.L, $r.T, [WB2]::SRCCOPY_CAPTUREBLT)
$g.ReleaseHdc($dst); $g.Dispose()
[void][WB2]::ReleaseDC([IntPtr]::Zero, $desk)
$out = Join-Path (Get-Location) "dlg_desk.png"
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Host ("  桌面DC BitBlt={0} 保存 {1} ({2} 字节)" -f $ok, $out, (Get-Item $out).Length)
Analyze $out