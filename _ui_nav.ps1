# 360 UI 点击测试 —— 点击导航项并验证
#
# 已探明（BitBlt 截图 + 像素分析）：
#   窗口 920x580，位于屏幕 (1031,317)
#   绿色导航栏 y=0..110
#   导航文字块 x 中心: ~75, ~190, ~294, ~402, ~519
#
# 本脚本：点击指定导航项，然后重新截图，看内容区是否变化。
# 用法: _ui_nav.ps1 <x中心> [y]

param([int]$CX, [int]$CY)

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
if (-not $CY) { $CY = 55 }

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class NV {
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern IntPtr GetWindowDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h, IntPtr dc);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint x, uint y, uint d, IntPtr e);
  [DllImport("gdi32.dll")] public static extern bool BitBlt(IntPtr dst,int dx,int dy,int w,int h,IntPtr src,int sx,int sy,int rop);
  public struct RECT { public int L,T,R,B; }
  public delegate bool EnumProc(IntPtr h, IntPtr l);
}
"@ -ErrorAction Stop
Add-Type -AssemblyName System.Drawing -ErrorAction Stop

function Find-360Main {
  $script:mw = [IntPtr]::Zero
  $cb = [NV+EnumProc]{
    param($h, $l)
    $sb = New-Object System.Text.StringBuilder 256
    [void][NV]::GetClassNameW($h, $sb, 256)
    if ($sb.ToString() -eq 'Q360SafeMainClass') { $script:mw = $h }
    return $true
  }
  [void][NV]::EnumWindows($cb, [IntPtr]::Zero)
  return $script:mw
}

function Capture($h, $r, $tag) {
  $w = $r.R - $r.L; $ht = $r.B - $r.T
  $bmp = New-Object System.Drawing.Bitmap $w, $ht
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $dst = $g.GetHdc()
  $src = [NV]::GetWindowDC($h)
  [void][NV]::BitBlt($dst, 0, 0, $w, $ht, $src, 0, 0, 0x00CC0020)
  [void][NV]::ReleaseDC($h, $src)
  $g.ReleaseHdc($dst); $g.Dispose()
  $p = Join-Path (Get-Location) ("360_nav_" + $tag + ".png")
  $bmp.Save($p, [System.Drawing.Imaging.ImageFormat]::Png)
  # 内容区指纹：统计非白像素数 + 颜色分布（比求和更敏感）
  $nonwhite = 0
  $sig = 0
  for ($y = 120; $y -lt 500; $y += 6) {
    for ($x = 10; $x -lt 910; $x += 6) {
      $c = $bmp.GetPixel($x, $y)
      if ($c.R -lt 250 -or $c.G -lt 250 -or $c.B -lt 250) {
        $nonwhite++
        $sig = ($sig * 31 + $c.R + $c.G * 3 + $c.B * 7 + $x + $y) -band 0x7FFFFFFF
      }
    }
  }
  $bmp.Dispose()
  return @{ Path = $p; Sig = $sig; NonWhite = $nonwhite }
}

$h = Find-360Main
if ($h -eq [IntPtr]::Zero) { Write-Output "  未找到主窗口"; exit 0 }

if ([NV]::ShowWindow($h, 9) -eq $false) { }
[void][NV]::ShowWindow($h, 5)
[void][NV]::BringWindowToTop($h)
[void][NV]::SetForegroundWindow($h)
Start-Sleep -Seconds 2

$r = New-Object NV+RECT
[void][NV]::GetWindowRect($h, [ref]$r)
Write-Output ("  窗口 ({0},{1}) {2}x{3}" -f $r.L,$r.T,($r.R-$r.L),($r.B-$r.T))

$before = Capture $h $r "before"
Write-Output ("  点击前指纹: " + $before.Sig)

# 屏幕绝对坐标 = 窗口左上 + 相对坐标
$absX = $r.L + $CX
$absY = $r.T + $CY
Write-Output ("  点击屏幕坐标 ({0},{1})  [窗口内 {2},{3}]" -f $absX,$absY,$CX,$CY)

[void][NV]::SetCursorPos($absX, $absY)
Start-Sleep -Milliseconds 400
[NV]::mouse_event(0x0002, 0, 0, 0, [IntPtr]::Zero)   # LEFTDOWN
Start-Sleep -Milliseconds 100
[NV]::mouse_event(0x0004, 0, 0, 0, [IntPtr]::Zero)   # LEFTUP
Start-Sleep -Seconds 3

$after = Capture $h $r "after"
Write-Output ("  点击后指纹: " + $after.Sig)
Write-Output ("  内容是否变化: " + ($before.Sig -ne $after.Sig))
Write-Output ("  截图: " + $after.Path)