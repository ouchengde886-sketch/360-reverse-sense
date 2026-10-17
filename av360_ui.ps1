# 360 UI 驱动（PostMessage 异步版）
#
# 关键教训：SendMessageTimeoutW 会阻塞在 360 的自定义窗口上（实测挂起）。
# 必须用 PostMessageW（异步投递，立即返回）。
#
# 已探明的 360 窗口（360Safe.exe 进程内）：
#   Q360SafeMainClass        <- 主窗口
#   Qh360ExpClient           <- 体验客户端
#   Qh360UCenterWnd          <- 用户中心
#   CAdvToolExecutorAdaptWnd <- 广告工具执行器
#   SitesUI / ATL:* / tooltips_class32
#
# 360 注册的窗口消息：
#   360ScanMsg=0xC4F6  360SafeScanMsg=0xC40D  360SafeCommand=0xC451
#   360SafeMainWndMsg=0xC3AF  360SafeMsg=0xC423  360SafeTrayMsg=0xC439

param([string]$Action)

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
if (-not $Action) { $Action = 'list' }

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class UIP {
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern uint RegisterWindowMessageW(string s);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  public delegate bool EnumProc(IntPtr h, IntPtr l);
}
"@ -ErrorAction Stop

function Get-ProcWindows($name) {
  $script:acc = @()
  $script:want = $name
  # 关键：不能在 EnumWindows 回调里调 Get-Process —— 极慢且会挂起。
  # 先一次性取好目标 PID，回调里只做整数比较。
  $script:wantPids = @(Get-Process -Name $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
  if ($script:wantPids.Count -eq 0) { return @() }
  $cb = [UIP+EnumProc]{
    param($h, $l)
    $pid2 = 0
    [void][UIP]::GetWindowThreadProcessId($h, [ref]$pid2)
    if ($script:wantPids -contains $pid2) {
      $cl = New-Object System.Text.StringBuilder 256
      [void][UIP]::GetClassNameW($h, $cl, 256)
      $tx = New-Object System.Text.StringBuilder 256
      [void][UIP]::GetWindowTextW($h, $tx, 256)
      $script:acc += [PSCustomObject]@{
        Handle = $h; Class = $cl.ToString(); Title = $tx.ToString()
        Visible = [UIP]::IsWindowVisible($h); Pid = $pid2
      }
    }
    return $true
  }
  [void][UIP]::EnumWindows($cb, [IntPtr]::Zero)
  return $script:acc
}

$log = "$env:APPDATA\360Safe\360ScanLog\360safeScanLog.txt"
function LogTime { if (Test-Path $log) { (Get-Item $log).LastWriteTime } else { [datetime]::MinValue } }

if ($Action -eq 'list') {
  Write-Output "=== 360 窗口清单 ==="
  foreach ($pn in @('360Safe', '360Tray', 'ZhuDongFangYu')) {
    $ws = Get-ProcWindows $pn
    if ($ws.Count -eq 0) { Write-Output "  [$pn] 无窗口"; continue }
    Write-Output "  [$pn] $($ws.Count) 个窗口:"
    foreach ($w in $ws) {
      $mark = if ($w.Class -match 'Q360SafeMainClass') { ' <== 主窗口' } else { '' }
      Write-Output ("    0x{0:X} vis={1} '{2}' '{3}'{4}" -f $w.Handle.ToInt64(), $w.Visible, $w.Class, $w.Title, $mark)
    }
  }
  exit 0
}

if ($Action -eq 'scan') {
  $before = LogTime
  Write-Output ("  日志时间（前）: " + $before)

  $msgs = @{}
  foreach ($n in @('360ScanMsg','360SafeScanMsg','360SafeCommand','360SafeMainWndMsg','360SafeMsg','360SafeTrayMsg')) {
    $msgs[$n] = [UIP]::RegisterWindowMessageW($n)
  }

  # 只对主窗口和 360Tray 发 PostMessage（异步，不阻塞）
  $sent = 0
  foreach ($pn in @('360Safe', '360Tray')) {
    foreach ($w in (Get-ProcWindows $pn)) {
      if ($w.Class -notmatch 'Q360SafeMainClass|ATL:|Qh360') { continue }
      foreach ($mn in @('360ScanMsg','360SafeScanMsg','360SafeCommand')) {
        [void][UIP]::PostMessageW($w.Handle, $msgs[$mn], [IntPtr]::Zero, [IntPtr]::Zero)
        $sent++
      }
    }
  }
  Write-Output "  已异步投递 $sent 条消息"

  Start-Sleep -Seconds 5
  $after = LogTime
  Write-Output ("  日志时间（后）: " + $after)
  Write-Output ("  日志更新: " + ($after -gt $before))
  Write-Output ""
  Write-Output "  当前 360 进程:"
  Get-Process | Where-Object { $_.ProcessName -match '360|ZhuDong|DSMain' } |
    Select-Object Id, ProcessName | Format-Table -AutoSize
  exit 0
}