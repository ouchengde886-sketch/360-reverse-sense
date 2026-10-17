# 直接调用 360SafeChecker.dll 的导出 —— 扫描编排层
#
# ============================================================================
# 第 81 轮发现：360SafeChecker.dll 含 '自定义扫描'/'扫描类型' 字符串，
#   且导出 OperateScanLog(0xA5069) / NotifyScanArk(0xA491D) /
#   NotifyScanArk2(0xA4812) / ProcessDS(0xA4D52) / SendMainCommand(0xA69A2)
#
# 这是 360 自己的扫描编排模块，内部会加载并配置所有引擎。
# 本轮：LoadLibrary 并逐个调用这些导出，记录返回值和日志变化。
#
# 用法: -Root <360目录> -Target <扫描目标>
# ============================================================================

param([string]$Root, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { $Target = 'D:\troyr2\tools\vendor\sRDI-master\lib\PowerShell' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class CK {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi, EntryPoint="GetProcAddress")]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern int GetLastError();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int I1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int I0();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int I2(IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int I3(IntPtr a, IntPtr b, IntPtr c);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

$rd = [System.Runtime.InteropServices.Marshal]
$log = "$env:APPDATA\360Safe\360ScanLog\360safeScanLog.txt"

function Log-State {
  if (Test-Path $log) {
    $fi = Get-Item $log
    return @{ len = $fi.Length; time = $fi.LastWriteTime }
  }
  return @{ len = 0; time = [datetime]::MinValue }
}

$b = Log-State
Write-Output ("  日志基线: 大小={0} 时间={1}" -f $b.len, $b.time)
Write-Output ("  目标: {0}" -f $Target)

# 加载依赖
[void][CK]::SetDllDirectoryW((Join-Path $Root 'Utils'))
[void][CK]::SetDllDirectoryW($Root)
$hBase = [CK]::LoadLibraryW((Join-Path $Root '360Base.dll'))
Write-Output ("  360Base.dll = 0x{0:X8}" -f $hBase.ToInt64())

$dll = Join-Path $Root 'Utils\360SafeChecker.dll'
$h = [CK]::LoadLibraryW($dll)
$err = [CK]::GetLastError()
Write-Output ("  360SafeChecker.dll = 0x{0:X8}  err={1}" -f $h.ToInt64(), $err)
if ($h -eq [IntPtr]::Zero) { Write-Output "  ★ 加载失败"; exit 1 }

# 枚举导出
$names = @('OperateScanLog','NotifyScanArk','NotifyScanArk2','ProcessDS',
           'SendMainCommand','GetEmpStage','IsEngSupportEmp','PreExitProcess',
           'RunnedTDWS','SEHS','ScanOFFPWR','IsFeatureSupport')
Write-Output "  --- 导出地址 ---"
$addrs = @{}
foreach ($n in $names) {
  $a = [CK]::GetProcAddress($h, $n)
  $addrs[$n] = $a
  Write-Output ("    {0,-20} 0x{1:X8}" -f $n, $a.ToInt64())
}

# 逐个调用（每个都在 try 里，避免崩溃影响其他）
Write-Output "  --- 逐个调用（每个调用后检查日志）---"

# 1. OperateScanLog(1) / (2) / (0)
foreach ($code in @(0,1,2)) {
  $a = $addrs['OperateScanLog']
  if ($a -eq [IntPtr]::Zero) { continue }
  $r = 'EXC'
  try {
    $g = $rd::GetDelegateForFunctionPointer($a, [CK+I1])
    $r = $g.Invoke([IntPtr]$code)
  } catch { $r = 'EXC:' + $_.Exception.GetType().Name }
  $s = Log-State
  Write-Output ("    OperateScanLog({0}) -> {1}   日志={2}/{3} 变化={4}" -f $code, $r, $s.len, $s.time, ($s.len -ne $b.len))
}

# 2. NotifyScanArk / NotifyScanArk2 —— 传目标路径
$targetPtr = $rd::StringToHGlobalUni($Target)
foreach ($n in @('NotifyScanArk','NotifyScanArk2')) {
  $a = $addrs[$n]
  if ($a -eq [IntPtr]::Zero) { continue }
  foreach ($sigName in @('I1','I2','I3')) {
    $r = 'EXC'
    try {
      switch ($sigName) {
        'I1' { $g = $rd::GetDelegateForFunctionPointer($a, [CK+I1]); $r = $g.Invoke($targetPtr) }
        'I2' { $g = $rd::GetDelegateForFunctionPointer($a, [CK+I2]); $r = $g.Invoke($targetPtr, [IntPtr]::Zero) }
        'I3' { $g = $rd::GetDelegateForFunctionPointer($a, [CK+I3]); $r = $g.Invoke($targetPtr, [IntPtr]::Zero, [IntPtr]::Zero) }
      }
    } catch { $r = 'EXC:' + $_.Exception.GetType().Name }
    $s = Log-State
    Write-Output ("    {0}({1}) -> {2}   日志={3} 变化={4}" -f $n, $sigName, $r, $s.len, ($s.len -ne $b.len))
  }
}

# 3. ProcessDS
$a = $addrs['ProcessDS']
if ($a -ne [IntPtr]::Zero) {
  foreach ($sigName in @('I1','I2')) {
    $r = 'EXC'
    try {
      if ($sigName -eq 'I1') { $g = $rd::GetDelegateForFunctionPointer($a, [CK+I1]); $r = $g.Invoke($targetPtr) }
      else { $g = $rd::GetDelegateForFunctionPointer($a, [CK+I2]); $r = $g.Invoke([IntPtr]1, $targetPtr) }
    } catch { $r = 'EXC:' + $_.Exception.GetType().Name }
    $s = Log-State
    Write-Output ("    ProcessDS({0}) -> {1}   日志={2} 变化={3}" -f $sigName, $r, $s.len, ($s.len -ne $b.len))
  }
}

# 最终检查
Write-Output "  --- 最终 ---"
$f = Log-State
Write-Output ("    日志: 大小={0} 时间={1}  相比基线变化={2}" -f $f.len, $f.time, ($f.len -ne $b.len -or $f.time -gt $b.time))