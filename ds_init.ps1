# deepscan.dll 初始化 —— EngLib_Init 传产品根目录
#
# ============================================================================
# 关键线索：已工作的 AVE 路径（av_ave_scan32.ps1）必须先调
#   AVEngine.dll!BAPIInitialize(LPCWSTR 产品根目录)
# 传的是**字符串路径**，不是 0 也不是 1。
#
# 之前测 EngLib_Init 时：
#   form=1 (传 0)   rc=0
#   form=6 (传 base) rc=0
#   form=2 (传 1)   崩溃
#   form=3 (传 0x204) 崩溃
#   form=4 (传 0x100) 崩溃
# 传 0 能返回 0 说明它**容忍 NULL**，但可能没真正初始化。
#
# 本次：传产品根目录宽字符串，然后再调 ScanAveMemory。
#
# 用法: -Path <产品根目录>  -Target <扫描目标>
# ============================================================================

param([string]$Root, [string]$Target, [int]$Form)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Form) { $Form = 1 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class DP {
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
  public delegate int F4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][DP]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
# 按依赖顺序加载
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][DP]::LoadLibraryW($p) }
}
$h = [DP]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

# BAPIInitialize(产品根目录) —— 与 AVE 路径一致
$hEng0 = [DP]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pBapi = [DP]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pBapi -ne [IntPtr]::Zero) {
    $rootPtr = $rd::StringToHGlobalUni($Root)
    $rcB = "EXC"
    try {
      $gb = $rd::GetDelegateForFunctionPointer($pBapi, [DP+F1])
      $rcB = $gb.Invoke($rootPtr)
    } catch { $rcB = "EXC:" + $_.Exception.GetType().Name }
    Write-Output ("  BAPIInitialize -> rc=" + $rcB)
    $rd::FreeHGlobal($rootPtr)
  }
}

# EngLib_Init 传产品根目录
$pEng = [DP]::GetProcAddress($h, 'EngLib_Init')
$engArg = switch ($Form) {
  1 { $rd::StringToHGlobalUni($Root) }
  2 { $rd::StringToHGlobalUni((Join-Path $Root 'deepscan')) }
  3 { [IntPtr]::Zero }
  default { $rd::StringToHGlobalUni($Root) }
}
$rcE = "EXC"
try {
  $ge = $rd::GetDelegateForFunctionPointer($pEng, [DP+F1])
  $rcE = $ge.Invoke($engArg)
} catch { $rcE = "EXC:" + $_.Exception.GetType().Name }
Write-Output ("  EngLib_Init(form=" + $Form + ") -> rc=" + $rcE)

# 现在调 ScanAveMemory
$dataBuf = $rd::AllocHGlobal(131072)
for ($i = 0; $i -lt 131072; $i++) { $rd::WriteByte($dataBuf, $i, 0) }
$size = 0
if ($Target -and (Test-Path $Target)) {
  $bytes = [System.IO.File]::ReadAllBytes($Target)
  $size = [Math]::Min($bytes.Length, 131072)
  $rd::Copy($bytes, 0, $dataBuf, $size)
}
$pathPtr = $rd::StringToHGlobalUni($Target)
$st = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, 1)
$rd::WriteInt32($st, 4, 1)

$pScan = [DP]::GetProcAddress($h, 'ScanAveMemory')
$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($pScan, [DP+F4])
  $rc = $g.Invoke($dataBuf, [IntPtr]$size, $pathPtr, $st)
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }
Write-Output ("  ScanAveMemory(buf,size,path,out) -> rc=" + $rc + " size=" + $size)

$vals = @()
for ($i = 0; $i -lt 64; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($st, $i)) }
Write-Output ("  out: " + ($vals -join ' '))

$rd::FreeHGlobal($st)
$rd::FreeHGlobal($dataBuf)
$rd::FreeHGlobal($pathPtr)