# 用 deepscan.dll 初始化后，再走 AVEI 的 CreateScannerEx + ScanW
#
# ============================================================================
# 假设：AVE 对非 PE 返回 status=4，是因为**引擎库没被正确初始化**。
#       deepscan.dll 的 EngLib_Init 是编排层的初始化入口，
#       调用它之后，AVEI 可能就能处理非 PE 了。
#
# 本脚本：
#   1. BAPIInitialize(产品根目录)
#   2. deepscan.dll!EngLib_Init(deepscan 目录)   <- 编排层初始化
#   3. AVEI.dll!CreateScannerEx / SetScannerConfig / ScanW
#   4. 对 PE 和非 PE 分别扫描，比较 status
#
# 用法: -Target <文件>
# ============================================================================

param([string]$Root, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { Write-Output "need -Target"; exit 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class DX {
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
  public delegate int F2(IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F3(IntPtr a, IntPtr b, IntPtr c);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][DX]::SetDllDirectoryW((Join-Path $Root 'deepscan\ave'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][DX]::LoadLibraryW($p) }
}
$rd = [System.Runtime.InteropServices.Marshal]

# --- 1. BAPIInitialize ---
$hEng0 = [DX]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pBapi = [DX]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pBapi -ne [IntPtr]::Zero) {
    $rp = $rd::StringToHGlobalUni($Root)
    try { $gb = $rd::GetDelegateForFunctionPointer($pBapi, [DX+F1]); [void]$gb.Invoke($rp) } catch { }
    $rd::FreeHGlobal($rp)
  }
}

# --- 2. deepscan.dll!EngLib_Init(deepscan 目录) ---
$hDs = [DX]::GetModuleHandleW('deepscan.dll')
if ($hDs -ne [IntPtr]::Zero) {
  $pEng = [DX]::GetProcAddress($hDs, 'EngLib_Init')
  if ($pEng -ne [IntPtr]::Zero) {
    $dsDir = $rd::StringToHGlobalUni((Join-Path $Root 'deepscan'))
    try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [DX+F1]); [void]$ge.Invoke($dsDir) } catch { }
    $rd::FreeHGlobal($dsDir)
  }
}

# --- 3. AVEI 扫描 ---
$hAve = [DX]::GetModuleHandleW('AVEI.dll')
if ($hAve -eq [IntPtr]::Zero) { Write-Output "no AVEI"; exit 0 }

# AveInitialize 填函数表
$pInit = [DX]::GetProcAddress($hAve, 'AveInitialize')
if ($pInit -ne [IntPtr]::Zero) {
  $tbl = $rd::AllocHGlobal(4096)
  for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($tbl, $i, 0) }
  $rd::WriteInt32($tbl, 0, 0x1000)
  try { $gi = $rd::GetDelegateForFunctionPointer($pInit, [DX+F1]); [void]$gi.Invoke($tbl) } catch { }
  $rd::FreeHGlobal($tbl)
}

$pCreate = [DX]::GetProcAddress($hAve, 'CreateScannerEx')
$pScan = [DX]::GetProcAddress($hAve, 'ScanW')
$pClose = [DX]::GetProcAddress($hAve, 'CloseScanner')
$pCfg = [DX]::GetProcAddress($hAve, 'SetScannerConfig')

# 结果结构：+0x000 BYTE status, +0x004 DWORD size, +0x008 CHAR[] name
$res = $rd::AllocHGlobal(1024)
for ($i = 0; $i -lt 1024; $i++) { $rd::WriteByte($res, $i, 0) }

# scanner 对象
$sc = $rd::AllocHGlobal(16)
for ($i = 0; $i -lt 16; $i++) { $rd::WriteByte($sc, $i, 0) }

$rcC = "EXC"
try {
  $gc = $rd::GetDelegateForFunctionPointer($pCreate, [DX+F2])
  $rcC = $gc.Invoke($sc, [IntPtr]::Zero)
} catch { $rcC = "EXC:" + $_.Exception.GetType().Name }

$scan = $rd::ReadIntPtr($sc, 0)
Write-Output ("  CreateScannerEx rc=" + $rcC + " scanner=0x" + $scan.ToString("X"))

if ($scan -ne [IntPtr]::Zero) {
  if ($pCfg -ne [IntPtr]::Zero) {
    try { $gf = $rd::GetDelegateForFunctionPointer($pCfg, [DX+F2]); [void]$gf.Invoke($scan, [IntPtr]6) } catch { }
  }
  $pathPtr = $rd::StringToHGlobalUni($Target)
  $rcS = "EXC"
  try {
    $gs = $rd::GetDelegateForFunctionPointer($pScan, [DX+F4])
    $rcS = $gs.Invoke($scan, $pathPtr, [IntPtr]::Zero, $res)
  } catch { $rcS = "EXC:" + $_.Exception.GetType().Name }

  $status = $rd::ReadByte($res, 0)
  $size = $rd::ReadInt32($res, 4)
  $name = ""
  try { $name = $rd::PtrToStringAnsi([IntPtr]($res.ToInt64() + 8), 260) } catch { }
  $sub = $rd::ReadByte($res, 0x108)
  Write-Output ("RESULT" + [char]0x1f + (Split-Path $Target -Leaf) + [char]0x1f + "rc=" + $rcS + [char]0x1f + "status=" + $status + [char]0x1f + "sub=" + $sub + [char]0x1f + "size=" + $size + [char]0x1f + "name=" + $name)

  if ($pClose -ne [IntPtr]::Zero) {
    try { $gx = $rd::GetDelegateForFunctionPointer($pClose, [DX+F1]); [void]$gx.Invoke($scan) } catch { }
  }
  $rd::FreeHGlobal($pathPtr)
}
$rd::FreeHGlobal($res)
$rd::FreeHGlobal($sc)