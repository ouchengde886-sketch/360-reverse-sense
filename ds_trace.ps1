# 逐步定位 ScanAveMemory 崩溃点 —— 每步输出标记
#
# 目的：确认崩溃发生在
#   (a) BAPIInitialize
#   (b) EngLib_Init
#   (c) 读文件/分配缓冲
#   (d) ScanAveMemory 本身
#
# 之前 ds_init.ps1 form=2 曾返回 rc=0，但不可复现。本脚本用标记精确定位。

param([string]$Root, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class ST {
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
Write-Output "STEP 1: Add-Type ok"

[void][ST]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) {
    $r = [ST]::LoadLibraryW($p)
    Write-Output ("STEP 2: load {0} -> 0x{1:X}" -f (Split-Path $p -Leaf), $r.ToInt64())
  }
}
$h = [ST]::GetModuleHandleW('deepscan.dll')
Write-Output ("STEP 3: deepscan handle = 0x{0:X}" -f $h.ToInt64())
if ($h -eq [IntPtr]::Zero) { exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]

$hEng0 = [ST]::GetModuleHandleW('AVEngine.dll')
Write-Output ("STEP 4: AVEngine handle = 0x{0:X}" -f $hEng0.ToInt64())
if ($hEng0 -ne [IntPtr]::Zero) {
  $pBapi = [ST]::GetProcAddress($hEng0, 'BAPIInitialize')
  Write-Output ("STEP 5: BAPIInitialize = 0x{0:X}" -f $pBapi.ToInt64())
  if ($pBapi -ne [IntPtr]::Zero) {
    $rp = $rd::StringToHGlobalUni($Root)
    try {
      $gb = $rd::GetDelegateForFunctionPointer($pBapi, [ST+F1])
      $rcB = $gb.Invoke($rp)
      Write-Output ("STEP 6: BAPIInitialize rc=" + $rcB)
    } catch { Write-Output ("STEP 6: BAPIInitialize EXC " + $_.Exception.GetType().Name) }
    $rd::FreeHGlobal($rp)
  }
}

$pEng = [ST]::GetProcAddress($h, 'EngLib_Init')
Write-Output ("STEP 7: EngLib_Init = 0x{0:X}" -f $pEng.ToInt64())
$dsDir = $rd::StringToHGlobalUni((Join-Path $Root 'deepscan'))
try {
  $ge = $rd::GetDelegateForFunctionPointer($pEng, [ST+F1])
  $rcE = $ge.Invoke($dsDir)
  Write-Output ("STEP 8: EngLib_Init rc=" + $rcE)
} catch { Write-Output ("STEP 8: EngLib_Init EXC " + $_.Exception.GetType().Name) }

Write-Output "STEP 9: 分配缓冲"
$cap = 131072
$dataBuf = $rd::AllocHGlobal($cap)
Write-Output ("STEP 10: buf = 0x{0:X}" -f $dataBuf.ToInt64())
for ($i = 0; $i -lt $cap; $i++) { $rd::WriteByte($dataBuf, $i, 0) }
Write-Output "STEP 11: 缓冲清零完成"

$size = 0
if ($Target -and (Test-Path $Target)) {
  $bytes = [System.IO.File]::ReadAllBytes($Target)
  $size = [Math]::Min($bytes.Length, $cap)
  $rd::Copy($bytes, 0, $dataBuf, $size)
  Write-Output ("STEP 12: 读文件 {0} 字节 (文件共 {1})" -f $size, $bytes.Length)
} else {
  Write-Output "STEP 12: 无目标文件，size=0"
}
$pathPtr = $rd::StringToHGlobalUni($Target)
Write-Output ("STEP 13: path ptr = 0x{0:X}" -f $pathPtr.ToInt64())

$st = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($st, $i, 0xCC) }
Write-Output ("STEP 14: out struct = 0x{0:X}" -f $st.ToInt64())

$pScan = [ST]::GetProcAddress($h, 'ScanAveMemory')
Write-Output ("STEP 15: ScanAveMemory = 0x{0:X}" -f $pScan.ToInt64())

$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($pScan, [ST+F4])
  Write-Output "STEP 16: 即将调用 ScanAveMemory"
  $rc = $g.Invoke($dataBuf, [IntPtr]$size, $pathPtr, $st)
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }
Write-Output ("STEP 17: ScanAveMemory rc=" + $rc)

$changed = 0
for ($i = 0; $i -lt 256; $i++) { if ($rd::ReadByte($st, $i) -ne 0xCC) { $changed++ } }
Write-Output ("STEP 18: changed=" + $changed)
$vals = @()
for ($i = 0; $i -lt 32; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($st, $i)) }
Write-Output ("STEP 19: raw=" + ($vals -join ' '))