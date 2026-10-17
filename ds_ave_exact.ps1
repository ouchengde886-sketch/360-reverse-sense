# deepscan 初始化 + 已验证的 AVEI 签名 —— 测试非 PE 是否被接受
#
# ============================================================================
# 采用 av_ave_scan32.ps1 中**已验证可用**的签名（逐字照抄，不自己猜）：
#   CreateScannerExFn(int cfg) -> IntPtr
#   ScanWFn(IntPtr scanner, string path, IntPtr a3, IntPtr a4, IntPtr a5) -> int
#   SetScannerConfigFn(IntPtr scanner, IntPtr guid, IntPtr cfg) -> int
#   CloseScannerFn(IntPtr scanner) -> int
#   BapiInitFn(string root) -> int
#
# 唯一变量：是否先调 deepscan.dll!EngLib_Init(deepscan 目录)。
# 目的：验证编排层初始化能否让 AVE 接受非 PE。
#
# 用法: -Target <文件> [-DsInit]
# ============================================================================

param([string]$Root, [string]$Target, [switch]$DsInit)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { Write-Output "need -Target"; exit 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class AW {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int AveInitializeFn(IntPtr tbl);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr CreateScannerExFn(int cfg);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int ScanWFn(IntPtr scanner, string path, IntPtr a3, IntPtr a4, IntPtr a5);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int SetScannerConfigFn(IntPtr scanner, IntPtr guid, IntPtr cfg);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int CloseScannerFn(IntPtr scanner);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int BapiInitFn(string root);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int DsInitFn(string dir);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][AW]::SetDllDirectoryW((Join-Path $Root 'deepscan\ave'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][AW]::LoadLibraryW($p) }
}
$rd = [System.Runtime.InteropServices.Marshal]

# BAPIInitialize(string root)
$hEng0 = [AW]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pBapi = [AW]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pBapi -ne [IntPtr]::Zero) {
    try {
      $gb = $rd::GetDelegateForFunctionPointer($pBapi, [AW+BapiInitFn])
      [void]$gb.Invoke($Root)
    } catch { }
  }
}

# 可选：deepscan EngLib_Init(string dir)
if ($DsInit) {
  $hDs = [AW]::GetModuleHandleW('deepscan.dll')
  if ($hDs -ne [IntPtr]::Zero) {
    $pEng = [AW]::GetProcAddress($hDs, 'EngLib_Init')
    if ($pEng -ne [IntPtr]::Zero) {
      try {
        $ge = $rd::GetDelegateForFunctionPointer($pEng, [AW+DsInitFn])
        $rcE = $ge.Invoke((Join-Path $Root 'deepscan'))
        Write-Output ("  EngLib_Init rc=" + $rcE)
      } catch { Write-Output "  EngLib_Init EXC" }
    }
  }
}

$h = [AW]::GetModuleHandleW('AVEI.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "no AVEI"; exit 0 }

$pInit = [AW]::GetProcAddress($h, 'AveInitialize')
if ($pInit -ne [IntPtr]::Zero) {
  $tbl = $rd::AllocHGlobal(8192)
  for ($i = 0; $i -lt 8192; $i++) { $rd::WriteByte($tbl, $i, 0) }
  $rd::WriteInt32($tbl, 0, 0x2000)
  try { $gi = $rd::GetDelegateForFunctionPointer($pInit, [AW+AveInitializeFn]); [void]$gi.Invoke($tbl) } catch { }
  $rd::FreeHGlobal($tbl)
}

$pCreate = [AW]::GetProcAddress($h, 'CreateScannerEx')
$pScan = [AW]::GetProcAddress($h, 'ScanW')
$pCfg = [AW]::GetProcAddress($h, 'SetScannerConfig')
$pClose = [AW]::GetProcAddress($h, 'CloseScanner')

$create = $rd::GetDelegateForFunctionPointer($pCreate, [AW+CreateScannerExFn])
$scanF = $rd::GetDelegateForFunctionPointer($pScan, [AW+ScanWFn])
$setcfg = $rd::GetDelegateForFunctionPointer($pCfg, [AW+SetScannerConfigFn])

$scanner = $create.Invoke(6)
Write-Output ("  CreateScannerEx(6) -> 0x{0:X}" -f $scanner.ToInt64())
if ($scanner -eq [IntPtr]::Zero) { Write-Output "  scanner 空"; exit 0 }

$res = $rd::AllocHGlobal(2048)
for ($i = 0; $i -lt 2048; $i++) { $rd::WriteByte($res, $i, 0) }

$rc = $scanF.Invoke($scanner, $Target, [IntPtr]::Zero, $res, [IntPtr]::Zero)
$status = $rd::ReadByte($res, 0)
$size = $rd::ReadInt32($res, 4)
$name = ""
try { $name = $rd::PtrToStringAnsi([IntPtr]($res.ToInt64() + 8), 260) } catch { }
$sub = $rd::ReadByte($res, 0x108)

Write-Output ("RESULT" + [char]0x1f + (Split-Path $Target -Leaf) + [char]0x1f + "dsinit=" + [int]$DsInit + [char]0x1f + "rc=" + $rc + [char]0x1f + "status=" + $status + [char]0x1f + "sub=" + $sub + [char]0x1f + "size=" + $size + [char]0x1f + "name=" + $name)

try { $close = $rd::GetDelegateForFunctionPointer($pClose, [AW+CloseScannerFn]); [void]$close.Invoke($scanner) } catch { }
$rd::FreeHGlobal($res)