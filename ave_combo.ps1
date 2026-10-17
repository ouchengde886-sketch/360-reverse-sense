# avescan.dll!QueryFileInAVE + AVE 引擎初始化 —— 组合两条已验证的路径
#
# ============================================================================
# 已验证事实：
#  1) av_ave_scan32.ps1 的 AVE 初始化流程可用（PE 能出 clean/threat）
#     SetDllDirectoryW(root\deepscan\ave) -> 360Base.dll, deepscan\BAPI.dll,
#     deepscan\ave\AVEngine.dll -> BAPIInitialize(root) -> AveInitialize(表)
#     -> AVEI.dll -> CreateScannerEx(0) -> SetScannerConfig -> ScanW
#  2) avescan.dll!QueryFileInAVE 内部走 CreateFileW -> 扫描 -> CloseHandle
#     但单独调用返回 0（引擎未初始化）
#
# 本轮假设：先初始化 AVE，再调 QueryFileInAVE，它可能给出判定。
#   avescan.dll 是 AVE 的官方封装 —— 它比我更懂怎么调 AVE。
#
# 用法: -Target <文件>
# ============================================================================

param([string]$Root, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { $Target = 'D:\troyr2\tools\vendor\srdi-master.zip' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class AX {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi, EntryPoint="GetProcAddress")]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int S2(IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr P0();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr P1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int I0();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int I1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
  public delegate int C1(IntPtr a);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

$rd = [System.Runtime.InteropServices.Marshal]
$aveDir = Join-Path $Root 'deepscan\ave'

# --- 阶段 1: 按 av_ave_scan32.ps1 的顺序初始化 AVE ---
Write-Output "  --- 阶段1: 初始化 AVE 引擎 ---"
[void][AX]::SetDllDirectoryW($aveDir)
$hBase = [AX]::LoadLibraryW((Join-Path $Root '360Base.dll'))
$hBapi = [AX]::LoadLibraryW((Join-Path $Root 'deepscan\BAPI.dll'))
$hAv   = [AX]::LoadLibraryW((Join-Path $aveDir 'AVEngine.dll'))
Write-Output ("  360Base=0x{0:X8} BAPI=0x{1:X8} AVEngine=0x{2:X8}" -f $hBase.ToInt64(), $hBapi.ToInt64(), $hAv.ToInt64())

$pBapiInit = [AX]::GetProcAddress($hAv, 'BAPIInitialize')
Write-Output ("  BAPIInitialize(AVEngine) = 0x{0:X8}" -f $pBapiInit.ToInt64())
if ($pBapiInit -ne [IntPtr]::Zero) {
  $rootPtr = $rd::StringToHGlobalUni($Root)
  try {
    $g = $rd::GetDelegateForFunctionPointer($pBapiInit, [AX+I1])
    $r = $g.Invoke($rootPtr)
    Write-Output ("    BAPIInitialize -> {0}" -f $r)
  } catch { Write-Output ("    BAPIInitialize 异常: " + $_.Exception.GetType().Name) }
}

$pAveInit = [AX]::GetProcAddress($hAv, 'AveInitialize')
Write-Output ("  AveInitialize = 0x{0:X8}" -f $pAveInit.ToInt64())
if ($pAveInit -ne [IntPtr]::Zero) {
  # 表: 0x40 字节，首 DWORD = 0x18
  $tbl = $rd::AllocHGlobal(0x40)
  for ($i = 0; $i -lt 0x40; $i++) { $rd::WriteByte($tbl, $i, 0) }
  $rd::WriteInt32($tbl, 0, 0x18)
  try {
    $g = $rd::GetDelegateForFunctionPointer($pAveInit, [AX+I1])
    $r = $g.Invoke($tbl)
    Write-Output ("    AveInitialize(表) -> {0}" -f $r)
  } catch { Write-Output ("    AveInitialize 异常: " + $_.Exception.GetType().Name) }
}

# --- 阶段 2: 加载 avescan.dll 并调 QueryFileInAVE ---
Write-Output "  --- 阶段2: avescan!QueryFileInAVE ---"
[void][AX]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
$hAs = [AX]::LoadLibraryW((Join-Path $Root 'deepscan\avescan.dll'))
Write-Output ("  avescan=0x{0:X8}" -f $hAs.ToInt64())
if ($hAs -eq [IntPtr]::Zero) { exit 0 }
$abase = $hAs.ToInt64()

$pC = [AX]::GetProcAddress($hAs, 'CreateADSAVEScanInstance')
$inst = [IntPtr]::Zero
if ($pC -ne [IntPtr]::Zero) {
  try {
    $g = $rd::GetDelegateForFunctionPointer($pC, [AX+P0])
    $inst = $g.Invoke()
  } catch { Write-Output ("    CreateADSAVEScanInstance 异常: " + $_.Exception.GetType().Name) }
}
Write-Output ("  CreateADSAVEScanInstance -> 0x{0:X8}" -f $inst.ToInt64())

$pQ = [AX]::GetProcAddress($hAs, 'QueryFileInAVE')
Write-Output ("  QueryFileInAVE = 0x{0:X8}" -f $pQ.ToInt64())

$pathPtr = $rd::StringToHGlobalUni($Target)
$outBuf = $rd::AllocHGlobal(4096)
Write-Output ("  目标 = {0}" -f $Target)

$gq = $rd::GetDelegateForFunctionPointer($pQ, [AX+S2])
foreach ($c in @(@('path,out', 0), @('out,path', 1), @('path,0', 2), @('0,path', 3))) {
  $nm = $c[0]; $m = $c[1]
  for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($outBuf, $i, 0xCC) }
  Write-Output ("    TRY {0}" -f $nm)
  [Console]::Out.Flush()
  $r = "EXC"
  try {
    if ($m -eq 0) { $r = $gq.Invoke($pathPtr, $outBuf) }
    if ($m -eq 1) { $r = $gq.Invoke($outBuf, $pathPtr) }
    if ($m -eq 2) { $r = $gq.Invoke($pathPtr, [IntPtr]::Zero) }
    if ($m -eq 3) { $r = $gq.Invoke([IntPtr]::Zero, $pathPtr) }
  } catch { $r = "EXC:" + $_.Exception.GetType().Name }
  $ch = 0
  for ($i = 0; $i -lt 512; $i++) { if ($rd::ReadByte($outBuf, $i) -ne 0xCC) { $ch++ } }
  Write-Output ("      {0,-10} rc=0x{1:X8} ({1})  输出变化={2}" -f $nm, $r, $ch)
  [Console]::Out.Flush()
  if ($ch -gt 0) {
    $rv = @()
    for ($i = 0; $i -lt 32; $i += 4) { $rv += ("{0:X8}" -f $rd::ReadInt32($outBuf, $i)) }
    Write-Output ("        前 32 字节: " + ($rv -join ' '))
    [Console]::Out.Flush()
  }
}