# QEX inner 虚表方法逐个调用（单槽位，隔离崩溃）
#
# 已探明（硬证据）：
#   obj+4 指向 inner 对象，其虚表在 QEX 模块内（RVA 基址 0x6E390000）。
#   inner 的前 0x60 字节全部是 QEX 内的函数指针 —— 它是一个
#   24 方法的 C++ 接口对象，不是数据对象。
#
#   inner 虚表 RVA 表：
#     [0x00] 0x39EA0  [0x04] 0x20180  [0x08] 0x39ED0  [0x0C] 0x38860
#     [0x10] 0x38870  [0x14] 0x38880  [0x18] 0x38890  [0x1C] 0x388A0
#     [0x20] 0x388B0  [0x24] 0x39E80  [0x28] 0x39EE0  [0x2C] 0x39EB0
#     [0x30] 0x39430  [0x34] 0x38E90  [0x38] 0x39000  [0x3C] 0x396E0
#     [0x40] 0x39730  [0x44] 0x39770  [0x48] 0x391C0  [0x4C] 0x392E0
#     [0x50] 0x394E0  [0x54] 0x395A0  [0x58] 0x39620  [0x5C] 0x36F20
#
# 反汇编提示：
#   0x394E0  mov edx,[ebp+8]; cmp edx,-1; mov eax,[ecx+0x14]; ret 8
#            -> 2 参数，返回 this+0x14 的字段值（疑似判定/状态）
#   0x391C0 / 0x392E0  读 [edi+8] 与 -1 比较（句柄检查）
#
# 本脚本：对指定槽位尝试 0 参 / 1 参 / 2 参调用，打印返回值。

param([string]$Target, [string]$Root, [int]$Slot)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Slot) { $Slot = 0x50 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QO {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int CreateFn(IntPtr a, IntPtr b, IntPtr c);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int ScanFn(IntPtr self, IntPtr path, IntPtr access, IntPtr disposition);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int InitFn(IntPtr buf);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int G0(IntPtr self);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int G1(IntPtr self, IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int G2(IntPtr self, IntPtr a, IntPtr b);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][QO]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QO]::LoadLibraryW($p) }
}
$h = [QO]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

foreach ($nm in @('QexScanExportsInit', 'QexResourceExportsInit')) {
  $pf = [QO]::GetProcAddress($h, $nm)
  if ($pf -eq [IntPtr]::Zero) { continue }
  $ib = $rd::AllocHGlobal(512)
  for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($ib, $i, 0) }
  $rd::WriteInt32($ib, 0, 0x58)
  $fi = $rd::GetDelegateForFunctionPointer($pf, [QO+InitFn])
  try { [void]$fi.Invoke($ib) } catch { }
  $rd::FreeHGlobal($ib)
}

$out = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($out, $i, 0) }
$fCreate = $rd::GetDelegateForFunctionPointer(
  [QO]::GetProcAddress($h, 'QEXCreateInstance'), [QO+CreateFn])
[void]$fCreate.Invoke([IntPtr]($base + 0x1C2364), [IntPtr]($base + 0x1C2354), $out)
$obj = $rd::ReadIntPtr($out, 0)
if ($obj -eq [IntPtr]::Zero) { Write-Output "null_obj"; exit 0 }
$vt = $rd::ReadIntPtr($obj, 0)

$pathPtr = $rd::StringToHGlobalUni($Target)
$fn = $rd::ReadIntPtr($vt, 0x10)
$scan = $rd::GetDelegateForFunctionPointer($fn, [QO+ScanFn])
try { [void]$scan.Invoke($obj, $pathPtr, [IntPtr][int]0x80000000, [IntPtr]3) } catch { }

$inner = $rd::ReadIntPtr($obj, 4)
if ($inner -eq [IntPtr]::Zero) { Write-Output "inner_null"; exit 0 }

# 重要修正：obj+4 指向的对象，其**前 0x60 字节本身就是函数指针表**，
# 不是"虚表指针 + 数据"。也就是说 inner 直接就是方法表，
# 取方法应读 ReadIntPtr(inner, slot)，而不是 ReadIntPtr(ReadIntPtr(inner,0), slot)。
# 之前多解了一层，读到的是未初始化内存（0xCCCC...）。
$f = $rd::ReadIntPtr($inner, $Slot)
$rva = $f.ToInt64() - $base

Write-Output ("SLOT" + [char]0x1f + ("0x{0:X2}" -f $Slot) + [char]0x1f +
              ("fn=0x{0:X}" -f $f.ToInt64()) + [char]0x1f + ("rva=0x{0:X}" -f $rva))

$r0 = "EXC"
try { $g = $rd::GetDelegateForFunctionPointer($f, [QO+G0]); $r0 = $g.Invoke($inner) }
catch { $r0 = "EXC:" + $_.Exception.GetType().Name }
Write-Output ("  0arg -> " + $r0)

$r1 = "EXC"
try { $g1 = $rd::GetDelegateForFunctionPointer($f, [QO+G1]); $r1 = $g1.Invoke($inner, [IntPtr]0) }
catch { $r1 = "EXC:" + $_.Exception.GetType().Name }
Write-Output ("  1arg(0) -> " + $r1)

$r2 = "EXC"
try { $g2 = $rd::GetDelegateForFunctionPointer($f, [QO+G2]); $r2 = $g2.Invoke($inner, [IntPtr]0, [IntPtr]0) }
catch { $r2 = "EXC:" + $_.Exception.GetType().Name }
Write-Output ("  2arg(0,0) -> " + $r2)

$rd::FreeHGlobal($pathPtr)
$rd::FreeHGlobal($out)