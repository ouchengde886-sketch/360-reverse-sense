# deepscan.dll 编排层初始化 + AVEI 完整扫描流程（含特征库加载）
#
# ============================================================================
# 逐字照抄 av_ave_scan32.ps1 的**已验证流程**，唯一新增：
#   在 AVEI 扫描前，先调 deepscan.dll!EngLib_Init(deepscan 目录)
#
# 已验证流程的关键点（之前我搞错的地方）：
#   - AveInitialize 函数表首 DWORD 预置 **0x18**（不是 0x2000）
#   - AVEI.dll 必须在函数表获取**之后**才加载
#   - CreateScannerEx(0)（不是 6）
#   - **必须调 SetScannerConfig 加载 deepscan\ave\*.def 特征库**
#     GUID fece107a-b540-4526-a77c-55cf4f01ccb0，cfg 首 WORD 0x13，
#     cfg+8 放 .def 文件路径
#   - 结果缓冲用 GCHandle 固定的托管数组（不是 AllocHGlobal）
#   - ScanW(scanner, path, 0, 0, resPtr)
#
# 用法: -Target <文件> [-DsInit]
# ============================================================================

param([string]$Root, [string]$Target, [switch]$DsInit)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { Write-Output "need -Target"; exit 0 }
$US = [char]0x1f

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class HY {
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
try { Add-Type -TypeDefinition $sig -ErrorAction Stop } catch { }

[void][HY]::SetDllDirectoryW((Join-Path $Root 'deepscan\ave'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\ave\AVEngine.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][HY]::LoadLibraryW($p) }
}

# 0) BAPIInitialize
$bapiRc = "n/a"
$hEng0 = [HY]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pBapi = [HY]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pBapi -ne [IntPtr]::Zero) {
    $bapi = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pBapi, [HY+BapiInitFn])
    foreach ($bp in @($Root, (Join-Path $Root 'deepscan'), (Join-Path $Root 'deepscan\ave'))) {
      try { $bapiRc = $bapi.Invoke($bp); break } catch { $bapiRc = "EXC" }
    }
  }
}

# 0b) deepscan.dll!EngLib_Init(deepscan 目录) —— 新增的编排层初始化
$dsRc = "skip"
if ($DsInit) {
  $pDs = Join-Path $Root 'deepscan\deepscan.dll'
  if (Test-Path $pDs) { [void][HY]::LoadLibraryW($pDs) }
  $hDs = [HY]::GetModuleHandleW('deepscan.dll')
  if ($hDs -ne [IntPtr]::Zero) {
    $pEng = [HY]::GetProcAddress($hDs, 'EngLib_Init')
    if ($pEng -ne [IntPtr]::Zero) {
      try {
        $ge = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pEng, [HY+DsInitFn])
        $dsRc = $ge.Invoke((Join-Path $Root 'deepscan'))
      } catch { $dsRc = "EXC" }
    }
  }
}

# 1) AveInitialize 函数表（首 DWORD 0x18）
$hEng = [HY]::GetModuleHandleW('AVEngine.dll')
$initRc = "n/a"
if ($hEng -ne [IntPtr]::Zero) {
  $tbl = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x40)
  for ($i = 0; $i -lt 0x40; $i++) { [System.Runtime.InteropServices.Marshal]::WriteByte($tbl, $i, 0) }
  [System.Runtime.InteropServices.Marshal]::WriteInt32($tbl, 0, 0x18)
  $pInit = [HY]::GetProcAddress($hEng, 'AveInitialize')
  if ($pInit -ne [IntPtr]::Zero) {
    $init = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pInit, [HY+AveInitializeFn])
    try { $initRc = $init.Invoke($tbl) } catch { $initRc = -1 }
  }
}

# 2) 加载 AVEI.dll（必须在函数表之后）
[void][HY]::LoadLibraryW((Join-Path $Root 'deepscan\ave\AVEI.dll'))
$h = [HY]::GetModuleHandleW('AVEI.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output ("RESULT" + $US + $Target + $US + "NO_AVEI"); exit 5 }

$pCreate = [HY]::GetProcAddress($h, 'CreateScannerEx')
$pScan = [HY]::GetProcAddress($h, 'ScanW')
$pCfg = [HY]::GetProcAddress($h, 'SetScannerConfig')
$pClose = [HY]::GetProcAddress($h, 'CloseScanner')
if ($pCreate -eq [IntPtr]::Zero -or $pScan -eq [IntPtr]::Zero) {
  Write-Output ("RESULT" + $US + $Target + $US + "NO_EXPORT"); exit 6
}

$create = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pCreate, [HY+CreateScannerExFn])
$scan = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pScan, [HY+ScanWFn])
$setcfg = $null
if ($pCfg -ne [IntPtr]::Zero) {
  $setcfg = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pCfg, [HY+SetScannerConfigFn])
}
$close = $null
if ($pClose -ne [IntPtr]::Zero) {
  $close = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pClose, [HY+CloseScannerFn])
}

$scanner = [IntPtr]::Zero
$resBuf = New-Object byte[] 0x200
$ghRes = [System.Runtime.InteropServices.GCHandle]::Alloc($resBuf, [System.Runtime.InteropServices.GCHandleType]::Pinned)

try {
  $scanner = $create.Invoke(0)
  if ($scanner -eq [IntPtr]::Zero) { Write-Output ("RESULT" + $US + $Target + $US + "CREATE_NULL"); exit 7 }

  # 3) 加载特征库
  $cfgRc = "no-def"
  if ($setcfg) {
    $defFiles = @(Get-ChildItem (Join-Path $Root 'deepscan\ave') -Filter '*.def' -ErrorAction SilentlyContinue |
                  Select-Object -ExpandProperty FullName)
    $okCount = 0
    foreach ($df in $defFiles) {
      $guidBuf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(16)
      [System.Runtime.InteropServices.Marshal]::WriteInt32($guidBuf, 0, [int]0xfece107a)
      [System.Runtime.InteropServices.Marshal]::WriteInt32($guidBuf, 4, [int]0x4526b540)
      [System.Runtime.InteropServices.Marshal]::WriteInt32($guidBuf, 8, [int]0xcf557ca7)
      [System.Runtime.InteropServices.Marshal]::WriteInt32($guidBuf, 12, [int]0xb0cc014f)
      $cfgBuf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x40)
      for ($i = 0; $i -lt 0x40; $i++) { [System.Runtime.InteropServices.Marshal]::WriteByte($cfgBuf, $i, 0) }
      [System.Runtime.InteropServices.Marshal]::WriteInt16($cfgBuf, 0, 0x13)
      $pathPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($df)
      [System.Runtime.InteropServices.Marshal]::WriteIntPtr($cfgBuf, 8, $pathPtr)
      try { if ($setcfg.Invoke($scanner, $guidBuf, $cfgBuf) -ne 0) { $okCount++ } } catch { }
      [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pathPtr)
      [System.Runtime.InteropServices.Marshal]::FreeHGlobal($cfgBuf)
      [System.Runtime.InteropServices.Marshal]::FreeHGlobal($guidBuf)
    }
    $cfgRc = "$okCount/$($defFiles.Count)"
  }

  for ($i = 0; $i -lt $resBuf.Length; $i++) { $resBuf[$i] = 0 }
  $resPtr = $ghRes.AddrOfPinnedObject()
  $rc = $scan.Invoke($scanner, $Target, [IntPtr]::Zero, [IntPtr]::Zero, $resPtr)

  $status = $resBuf[0]
  $sub = $resBuf[0x108]
  $fsize = [BitConverter]::ToUInt32($resBuf, 4)
  $name = [System.Text.Encoding]::Default.GetString($resBuf, 8, 0xFF)
  $z = $name.IndexOf([char]0)
  if ($z -ge 0) { $name = $name.Substring(0, $z) }
  $name = $name.Trim()

  $verdict = switch ($status) {
    0 { "clean" } 1 { "threat" } 4 { "engine_error" }
    0xFC { "error" } 0xFD { "invalid_args" } default { "unknown" }
  }

  Write-Output ("RESULT" + $US + (Split-Path $Target -Leaf) + $US + $verdict + $US +
    ("status={0} sub={1} size={2} name={3} init={4} cfg={5} rc={6} bapi={7} ds={8}" -f `
     $status, $sub, $fsize, $name, $initRc, $cfgRc, $rc, $bapiRc, $dsRc))
} catch {
  Write-Output ("RESULT" + $US + (Split-Path $Target -Leaf) + $US + "EXC" + $US + $_.Exception.Message)
} finally {
  $ghRes.Free()
  if ($scanner -ne [IntPtr]::Zero -and $close) { try { [void]$close.Invoke($scanner) } catch { } }
}