# dump 引擎对象虚表 + 反汇编 vtable+0x18
#
# ============================================================================
# 引擎对象在调用 ScanAveMemoryWithCode 后被创建于 0x2A6830。
# 0x95 来自 +0x306: call [eax+0x18]，即引擎对象虚表 +0x18 的方法。
#
# 本脚本：
#   1. 调一次 ScanAveMemoryWithCode 触发引擎对象创建
#   2. dump 0x2A6830 指向对象的虚表（前 32 项）
#   3. 把 vtable+0x18 的函数地址和 RVA 打出来
#   4. dump 该函数前 64 字节机器码（供离线反汇编）
#
# 用法: -Target <文件>
# ============================================================================

param([string]$Root, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class VT {
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
  public delegate int F6(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int BapiFn(string root);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][VT]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][VT]::LoadLibraryW($p) }
}
$h = [VT]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$base = $h.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]
Write-Output ("  deepscan base = 0x{0:X8}" -f $base)

$hEng0 = [VT]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [VT]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [VT+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}

$st = $rd::AllocHGlobal(0x204)
for ($i = 0; $i -lt 0x204; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, 0x204)
$pEng = [VT]::GetProcAddress($h, 'EngLib_Init')
try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [VT+F1]); [void]$ge.Invoke($st) } catch { }

$dataBuf = $rd::AllocHGlobal(1048576)
for ($i = 0; $i -lt 1048576; $i++) { $rd::WriteByte($dataBuf, $i, 0) }
$size = 0
if ($Target -and (Test-Path $Target)) {
  $bytes = [System.IO.File]::ReadAllBytes($Target)
  $size = [Math]::Min($bytes.Length, 1048576)
  $rd::Copy($bytes, 0, $dataBuf, $size)
}
$pathPtr = $rd::StringToHGlobalUni($Target)

$resBuf = $rd::AllocHGlobal(4096)
for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
$p6 = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($p6, $i, 0) }
$rd::WriteInt32($p6, 0, 0x18)
$rd::WriteInt32($p6, 8, 1)
$rd::WriteIntPtr($p6, 0x0C, $resBuf)
$magic = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($magic, $i, 0) }
$rd::WriteInt32($magic, 0, 0x7979726C)
$rd::WriteInt32($magic, 4, $size)

$pWC = [VT]::GetProcAddress($h, 'ScanAveMemoryWithCode')
$g = $rd::GetDelegateForFunctionPointer($pWC, [VT+F6])
try { [void]$g.Invoke($dataBuf, [IntPtr]$size, $pathPtr, $resBuf, $magic, [IntPtr]32) } catch { }

# dump 引擎对象
$obj = $rd::ReadInt32([IntPtr]($base + 0x2A6830))
$fac = $rd::ReadInt32([IntPtr]($base + 0x2A682C))
Write-Output ("  引擎对象 0x2A6830 = 0x{0:X8}" -f $obj)
Write-Output ("  工厂     0x2A682C = 0x{0:X8}" -f $fac)

foreach ($pair in @(@('obj', $obj), @('fac', $fac))) {
  $name = $pair[0]; $p = [int]$pair[1]
  if ($p -eq 0) { continue }
  Write-Output ("  --- {0} = 0x{1:X8} 内容 ---" -f $name, $p)
  $vals = @()
  for ($i = 0; $i -lt 32; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32([IntPtr]$p, $i)) }
  Write-Output ("    " + ($vals -join ' '))
  $vtp = $rd::ReadInt32([IntPtr]$p)
  Write-Output ("    虚表 = 0x{0:X8}" -f $vtp)
  if ($vtp -gt 0x10000 -and $vtp -lt 0x7FFFFFFF) {
    Write-Output ("    虚表前 32 项:")
    for ($i = 0; $i -lt 32; $i++) {
      $fn = $rd::ReadInt32([IntPtr]($vtp + $i*4))
      $rva = $fn - $base
      $mk = ""
      if ($rva -gt 0 -and $rva -lt 0x2D0000) { $mk = " deepscan+0x{0:X}" -f $rva }
      Write-Output ("      [{0,2}] 0x{1:X8}{2}" -f $i, $fn, $mk)
    }
  }
}

# 反汇编 vtable+0x18
if ($obj -ne 0) {
  $vtp = $rd::ReadInt32([IntPtr]$obj)
  if ($vtp -gt 0x10000 -and $vtp -lt 0x7FFFFFFF) {
    $fn18 = $rd::ReadInt32([IntPtr]($vtp + 0x18))
    Write-Output ("  vtable+0x18 = 0x{0:X8}  (RVA 0x{1:X})" -f $fn18, ($fn18 - $base))
    if ($fn18 -gt 0x10000 -and $fn18 -lt 0x7FFFFFFF) {
      Write-Output "  该函数前 96 字节机器码:"
      for ($i = 0; $i -lt 96; $i += 16) {
        $bs = @()
        for ($j = 0; $j -lt 16; $j++) { $bs += ("{0:X2}" -f $rd::ReadByte([IntPtr]($fn18 + $i + $j))) }
        Write-Output ("    +{0:X3}: {1}" -f $i, ($bs -join ' '))
      }
    }
  }
}