# 测试 SetScannerConfig 是否能改变 status=4 —— 验证"空引擎"假设
#
# ============================================================================
# 已验证事实：
#   - ScanW 对非 PE 返回 status=4
#   - status=4 在 0x931F/0x971F 处写入，前面有 call 0x9DA3（虚表调用）
#   - 0x9DA3 是虚表调用包装，依赖引擎内部状态
#
# 本轮假设：status=4 是因为扫描器**未配置**。
#   360 的 .def 文件里有配置 GUID: fece107a-b540-4526-a77c-55cf4f01ccb0
#   配置结构: 首 WORD=0x13, cfg+8 = 路径
#
# 实验：对同一个非 PE 文件，
#   1. 不配置直接扫 -> 记录 status
#   2. SetScannerConfig 后扫 -> 记录 status
#   3. 对比
#
# 用法: -Target <文件>
# ============================================================================

param([string]$Root, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { $Target = 'D:\troyr2\tools\vendor\srdi-master.zip' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class AC {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi, EntryPoint="GetProcAddress")]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int I1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int S2(IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int S3(IntPtr a, IntPtr b, IntPtr c);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int S5(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

$rd = [System.Runtime.InteropServices.Marshal]
$aveDir = Join-Path $Root 'deepscan\ave'

[void][AC]::SetDllDirectoryW($aveDir)
[void][AC]::LoadLibraryW((Join-Path $Root '360Base.dll'))
[void][AC]::LoadLibraryW((Join-Path $Root 'deepscan\BAPI.dll'))
$hAv = [AC]::LoadLibraryW((Join-Path $aveDir 'AVEngine.dll'))

$pBapi = [AC]::GetProcAddress($hAv, 'BAPIInitialize')
if ($pBapi -ne [IntPtr]::Zero) {
  $rp = $rd::StringToHGlobalUni($Root)
  $g = $rd::GetDelegateForFunctionPointer($pBapi, [AC+I1])
  Write-Output ("  BAPIInitialize -> {0}" -f $g.Invoke($rp))
}
$pAve = [AC]::GetProcAddress($hAv, 'AveInitialize')
if ($pAve -ne [IntPtr]::Zero) {
  $tbl = $rd::AllocHGlobal(0x40)
  for ($i = 0; $i -lt 0x40; $i++) { $rd::WriteByte($tbl, $i, 0) }
  $rd::WriteInt32($tbl, 0, 0x18)
  $g = $rd::GetDelegateForFunctionPointer($pAve, [AC+I1])
  Write-Output ("  AveInitialize -> {0}" -f $g.Invoke($tbl))
}

$hI = [AC]::LoadLibraryW((Join-Path $aveDir 'AVEI.dll'))
$pCreate = [AC]::GetProcAddress($hI, 'CreateScannerEx')
$pScan   = [AC]::GetProcAddress($hI, 'ScanW')
$pCfg    = [AC]::GetProcAddress($hI, 'SetScannerConfig')
Write-Output ("  CreateScannerEx=0x{0:X8} ScanW=0x{1:X8} SetScannerConfig=0x{2:X8}" -f `
  $pCreate.ToInt64(), $pScan.ToInt64(), $pCfg.ToInt64())

$gCreate = $rd::GetDelegateForFunctionPointer($pCreate, [AC+I1])
$gScan   = $rd::GetDelegateForFunctionPointer($pScan, [AC+S5])
$scanner = [IntPtr]$gCreate.Invoke([IntPtr]::Zero)
Write-Output ("  扫描器 = 0x{0:X8}" -f $scanner.ToInt64())
if ($scanner -eq [IntPtr]::Zero) { exit 0 }

$pathPtr = $rd::StringToHGlobalUni($Target)
$resBuf = $rd::AllocHGlobal(0x300)

function Do-Scan($label) {
  for ($i = 0; $i -lt 0x300; $i++) { $rd::WriteByte($resBuf, $i, 0) }
  $r = "EXC"
  try { $r = $gScan.Invoke($scanner, $pathPtr, [IntPtr]::Zero, [IntPtr]::Zero, $resBuf) }
  catch { $r = "EXC:" + $_.Exception.GetType().Name }
  $st = $rd::ReadByte($resBuf, 0)
  $nm = $rd::PtrToStringAnsi([IntPtr]($resBuf.ToInt64()+8), 128)
  Write-Host ("    {0,-24} rc=0x{1:X8} status={2} 名='{3}'" -f $label, $r, $st, $nm.Trim())
  [Console]::Out.Flush()
  return $st
}

Write-Output "  --- 阶段1: 未配置直接扫描 ---"
$s1 = Do-Scan "未配置"

Write-Output "  --- 阶段2: SetScannerConfig 后扫描 ---"
if ($pCfg -ne [IntPtr]::Zero) {
  # 配置结构: 首 WORD=0x13, cfg+8 = 路径
  $cfg = $rd::AllocHGlobal(0x100)
  for ($i = 0; $i -lt 0x100; $i++) { $rd::WriteByte($cfg, $i, 0) }
  $rd::WriteInt16($cfg, 0, 0x13)
  $dirPtr = $rd::StringToHGlobalUni((Join-Path $Root 'deepscan\ave'))
  $rd::WriteIntPtr($cfg, 8, $dirPtr)

  # SetScannerConfig(scanner, cfg) 或 (scanner, guid, cfg) 两种签名都试
  foreach ($sig in @('S2','S3')) {
    $rc = "EXC"
    try {
      if ($sig -eq 'S2') {
        $g = $rd::GetDelegateForFunctionPointer($pCfg, [AC+S2])
        $rc = $g.Invoke($scanner, $cfg)
      } else {
        $g = $rd::GetDelegateForFunctionPointer($pCfg, [AC+S3])
        $rc = $g.Invoke($scanner, [IntPtr]::Zero, $cfg)
      }
    } catch { $rc = "EXC:" + $_.Exception.GetType().Name }
    Write-Output ("    SetScannerConfig({0}) -> 0x{1:X8}" -f $sig, $rc)
    $s2 = Do-Scan ("配置后(" + $sig + ")")
  }
} else {
  Write-Output "    SetScannerConfig 未找到"
}