# 实测 SendMainCommand(0x820,0,0) —— 检查全局对象 + 触发命令
#
# ============================================================================
# 第 85 轮逆向结果：
#   SendMainCommand(cmd, p2, p3) ret 0xC，RVA 0xA69A2
#   内部: mov eax,[0x101A9B2C]; test eax,eax; jz skip
#         push p3; push p2; push cmd; push [eax+0x3C]; call [0x10139638]
#   唯一调用点用 cmd=0x820
#
# 本轮：
#   1. 检查全局对象 [0x101A9B2C] 是否非空（空则函数直接返回，什么都不做）
#   2. 调用 SendMainCommand(0x820,0,0)
#   3. 也测试其他候选命令码
#   4. 验证日志时间戳/ScanCache 是否变化
# ============================================================================

param([string]$Root)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }

$cs = @"
using System;
using System.Runtime.InteropServices;
public static class SM {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi, EntryPoint="GetProcAddress")]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] public delegate int D3(IntPtr a, IntPtr b, IntPtr c);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] public delegate int D2(IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] public delegate int D1(IntPtr a);
}
"@
Add-Type -TypeDefinition $cs -ErrorAction Stop
$rd = [System.Runtime.InteropServices.Marshal]

$log = "$env:APPDATA\360Safe\360ScanLog\360safeScanLog.txt"
$cache = 'C:\ProgramData\360Safe\ScanCache'

function Snap {
  $o = @{ logLen = 0; logTime = [datetime]::MinValue; cacheTime = [datetime]::MinValue; cacheLen = 0 }
  if (Test-Path $log) { $f = Get-Item $log; $o.logLen = $f.Length; $o.logTime = $f.LastWriteTime }
  $c = Join-Path $cache 'Data_2026_10_18.dat'
  if (Test-Path $c) { $f2 = Get-Item $c; $o.cacheLen = $f2.Length; $o.cacheTime = $f2.LastWriteTime }
  return $o
}

$b = Snap
Write-Output ("  基线: 日志={0}/{1}  ScanCache={2}/{3}" -f $b.logLen, $b.logTime, $b.cacheLen, $b.cacheTime)

# 加载
[void][SM]::SetDllDirectoryW($Root)
[void][SM]::LoadLibraryW((Join-Path $Root '360Base.dll'))
$h = [SM]::LoadLibraryW((Join-Path $Root 'Utils\360SafeChecker.dll'))
Write-Output ("  360SafeChecker.dll = 0x{0:X8}" -f $h.ToInt64())
if ($h -eq [IntPtr]::Zero) { exit 1 }

# ★ 检查全局对象 [0x101A9B2C]
# 模块基址 + RVA 0x1A9B2C
$gv = [IntPtr]($h.ToInt64() + 0x1A9B2C)
$gval = [IntPtr]$rd::ReadIntPtr($gv)
Write-Output ("  ★ 全局对象 [0x{0:X8}] = 0x{1:X8}" -f $gv.ToInt64(), $gval.ToInt64())
if ($gval -ne [IntPtr]::Zero) {
  $chan = [IntPtr]$rd::ReadIntPtr([IntPtr]($gval.ToInt64() + 0x3C))
  Write-Output ("     对象+0x3C (通道) = 0x{0:X8}" -f $chan.ToInt64())
} else {
  Write-Output "     ★ 全局对象为空 -> SendMainCommand 会直接返回，什么都不做"
}

# 调用 SendMainCommand
$p = [SM]::GetProcAddress($h, 'SendMainCommand')
Write-Output ("  SendMainCommand = 0x{0:X8}" -f $p.ToInt64())
if ($p -eq [IntPtr]::Zero) { exit 1 }

$cmds = @(0x820, 0x821, 0x81F, 1, 2, 0x100, 0x200)
foreach ($cmd in $cmds) {
  $r = 'EXC'
  try {
    $g = $rd::GetDelegateForFunctionPointer($p, [SM+D3])
    $r = $g.Invoke([IntPtr]$cmd, [IntPtr]::Zero, [IntPtr]::Zero)
  } catch { $r = 'EXC:' + $_.Exception.GetType().Name }
  Start-Sleep -Milliseconds 800
  $s = Snap
  $chg = ($s.logLen -ne $b.logLen) -or ($s.cacheLen -ne $b.cacheLen)
  Write-Output ("    SendMainCommand(0x{0:X}) -> {1}  日志={2} 缓存={3} 变化={4}" -f $cmd, $r, $s.logLen, $s.cacheLen, $chg)
  if ($chg) { $b = $s }
}

Write-Output "  --- 等待 5 秒后最终检查 ---"
Start-Sleep -Seconds 5
$f = Snap
Write-Output ("    日志: {0}/{1}" -f $f.logLen, $f.logTime)
Write-Output ("    缓存: {0}/{1}" -f $f.cacheLen, $f.cacheTime)