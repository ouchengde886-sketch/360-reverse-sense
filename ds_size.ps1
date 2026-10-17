# ScanAveMemory size 参数语义测试
#
# ============================================================================
# 观察到的现象：
#   ds_init.ps1 form=2 传 (dataBuf 1MB, size=131072, path, out) -> rc=0 成功
#   ds_verdict.ps1 传 (dataBuf 1MB, size=实际文件大小, path, out) -> 崩溃
#
# 假设：第 2 个参数**不是文件大小，而是缓冲区容量**。
#   131072 是 2 的幂，成功；6409/710/973565 不是，崩溃。
#
# 本脚本验证：固定传 131072（或 2 的幂），对不同文件测试。
# 用法: -Target <文件> -Size <N>
# ============================================================================

param([string]$Root, [string]$Target, [int]$Size)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Size) { $Size = 131072 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class SZ {
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

[void][SZ]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][SZ]::LoadLibraryW($p) }
}
$h = [SZ]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]

$hEng0 = [SZ]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pBapi = [SZ]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pBapi -ne [IntPtr]::Zero) {
    $rp = $rd::StringToHGlobalUni($Root)
    try { $gb = $rd::GetDelegateForFunctionPointer($pBapi, [SZ+F1]); [void]$gb.Invoke($rp) } catch { }
    $rd::FreeHGlobal($rp)
  }
}
$pEng = [SZ]::GetProcAddress($h, 'EngLib_Init')
$dsDir = $rd::StringToHGlobalUni((Join-Path $Root 'deepscan'))
try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [SZ+F1]); [void]$ge.Invoke($dsDir) } catch { }

# 缓冲区固定 1MB，全部填 0
$cap = 1048576
$dataBuf = $rd::AllocHGlobal($cap)
for ($i = 0; $i -lt $cap; $i++) { $rd::WriteByte($dataBuf, $i, 0) }
$fileSize = 0
if ($Target -and (Test-Path $Target)) {
  $bytes = [System.IO.File]::ReadAllBytes($Target)
  $fileSize = [Math]::Min($bytes.Length, $cap)
  $rd::Copy($bytes, 0, $dataBuf, $fileSize)
}
$pathPtr = $rd::StringToHGlobalUni($Target)

$st = $rd::AllocHGlobal(512)
for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($st, $i, 0xCC) }

$pScan = [SZ]::GetProcAddress($h, 'ScanAveMemory')
$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($pScan, [SZ+F4])
  $rc = $g.Invoke($dataBuf, [IntPtr]$Size, $pathPtr, $st)
} catch { $rc = "EXC" }

Write-Output ("SZ" + [char]0x1f + (Split-Path $Target -Leaf) + [char]0x1f + "file=" + $fileSize + [char]0x1f + "size=" + $Size + [char]0x1f + "rc=" + $rc)
$changed = 0
for ($i = 0; $i -lt 256; $i++) { if ($rd::ReadByte($st, $i) -ne 0xCC) { $changed++ } }
Write-Output ("  changed=" + $changed)
$vals = @()
for ($i = 0; $i -lt 48; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($st, $i)) }
Write-Output ("  raw: " + ($vals -join ' '))

$rd::FreeHGlobal($st)
$rd::FreeHGlobal($dataBuf)
$rd::FreeHGlobal($pathPtr)