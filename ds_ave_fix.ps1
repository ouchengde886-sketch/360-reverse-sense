# AVEI CreateScannerEx 正确调用 —— 返回值即是对像指针
#
# ============================================================================
# 上一轮发现：CreateScannerEx 返回 0xA5B0000 / 0xA1E0000 这类指针值，
# 不是 HRESULT。说明它**直接返回 scanner 对象指针**，不是 out-param。
#
# 本脚本：
#   1. 正确拿 scanner 指针（返回值）
#   2. SetScannerConfig
#   3. ScanW(scanner, path, ?, result) 扫描
#   4. 解析结果结构的 status / size / name
#
# 结果结构（已确认）：
#   +0x000 BYTE  status   （0=clean, 4=engine_error, 其他=威胁）
#   +0x004 DWORD size
#   +0x008 CHAR[] threat name
#   +0x108 BYTE  substatus
#
# 用法: -Target <文件> [-NoDsInit]
# ============================================================================

param([string]$Root, [string]$Target, [switch]$NoDsInit)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { Write-Output "need -Target"; exit 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class AV {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr P0();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr P1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F2(IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F3(IntPtr a, IntPtr b, IntPtr c);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][AV]::SetDllDirectoryW((Join-Path $Root 'deepscan\ave'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][AV]::LoadLibraryW($p) }
}
$rd = [System.Runtime.InteropServices.Marshal]

# BAPIInitialize
$hEng0 = [AV]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pBapi = [AV]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pBapi -ne [IntPtr]::Zero) {
    $rp = $rd::StringToHGlobalUni($Root)
    try { $gb = $rd::GetDelegateForFunctionPointer($pBapi, [AV+F1]); [void]$gb.Invoke($rp) } catch { }
    $rd::FreeHGlobal($rp)
  }
}
# 可选：deepscan EngLib_Init
if (-not $NoDsInit) {
  $hDs = [AV]::GetModuleHandleW('deepscan.dll')
  if ($hDs -ne [IntPtr]::Zero) {
    $pEng = [AV]::GetProcAddress($hDs, 'EngLib_Init')
    if ($pEng -ne [IntPtr]::Zero) {
      $dsDir = $rd::StringToHGlobalUni((Join-Path $Root 'deepscan'))
      try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [AV+F1]); [void]$ge.Invoke($dsDir) } catch { }
      $rd::FreeHGlobal($dsDir)
    }
  }
}

$hAve = [AV]::GetModuleHandleW('AVEI.dll')
if ($hAve -eq [IntPtr]::Zero) { Write-Output "no AVEI"; exit 0 }

# AveInitialize 填函数表
$pInit = [AV]::GetProcAddress($hAve, 'AveInitialize')
if ($pInit -ne [IntPtr]::Zero) {
  $tbl = $rd::AllocHGlobal(8192)
  for ($i = 0; $i -lt 8192; $i++) { $rd::WriteByte($tbl, $i, 0) }
  $rd::WriteInt32($tbl, 0, 0x2000)
  try { $gi = $rd::GetDelegateForFunctionPointer($pInit, [AV+F1]); [void]$gi.Invoke($tbl) } catch { }
  $rd::FreeHGlobal($tbl)
}

$pCreate = [AV]::GetProcAddress($hAve, 'CreateScannerEx')
$pScan = [AV]::GetProcAddress($hAve, 'ScanW')
$pCfg = [AV]::GetProcAddress($hAve, 'SetScannerConfig')

# CreateScannerEx 直接返回指针（0 参数）
$scan = [IntPtr]::Zero
try {
  $gc = $rd::GetDelegateForFunctionPointer($pCreate, [AV+P0])
  $scan = $gc.Invoke()
} catch {
  try {
    $gc1 = $rd::GetDelegateForFunctionPointer($pCreate, [AV+P1])
    $scan = $gc1.Invoke([IntPtr]::Zero)
  } catch { }
}
Write-Output ("  CreateScannerEx -> 0x{0:X}" -f $scan.ToInt64())
if ($scan -eq [IntPtr]::Zero) { Write-Output "  scanner 为空，退出"; exit 0 }

if ($pCfg -ne [IntPtr]::Zero) {
  try { $gf = $rd::GetDelegateForFunctionPointer($pCfg, [AV+F2]); [void]$gf.Invoke($scan, [IntPtr]6) } catch { }
}

$res = $rd::AllocHGlobal(2048)
for ($i = 0; $i -lt 2048; $i++) { $rd::WriteByte($res, $i, 0) }
$pathPtr = $rd::StringToHGlobalUni($Target)

$rcS = "EXC"
try {
  $gs = $rd::GetDelegateForFunctionPointer($pScan, [AV+F4])
  $rcS = $gs.Invoke($scan, $pathPtr, [IntPtr]::Zero, $res)
} catch { $rcS = "EXC:" + $_.Exception.GetType().Name }

$status = $rd::ReadByte($res, 0)
$size = $rd::ReadInt32($res, 4)
$name = ""
try { $name = $rd::PtrToStringAnsi([IntPtr]($res.ToInt64() + 8), 260) } catch { }
$sub = $rd::ReadByte($res, 0x108)

Write-Output ("RESULT" + [char]0x1f + (Split-Path $Target -Leaf) + [char]0x1f + "rc=" + $rcS + [char]0x1f + "status=" + $status + [char]0x1f + "sub=" + $sub + [char]0x1f + "size=" + $size + [char]0x1f + "name=" + $name)

$rd::FreeHGlobal($res)
$rd::FreeHGlobal($pathPtr)