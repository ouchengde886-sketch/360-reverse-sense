# QEX obj 虚表方法穷举调用（单槽位隔离进程）
#
# 目的：找出返回"威胁名"或非零判定的方法。
#
# 已确认：
#   obj 虚表 RVA 0x1BFCC4（每次运行地址固定）
#   obj+0x1C 指向扫描上下文，+0x34 是文件路径指针
#   obj+0x0C / +0x20 = 文件字节数
#   obj+0x10 / +0x14 恒为 0（对干净与恶意文件都一样）
#
# 本脚本：对指定槽位尝试 0/1/2/3 参调用，打印返回值与可能的字符串。

param([string]$Target, [string]$Root, [int]$Slot)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Slot) { $Slot = 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QX {
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
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int G3(IntPtr self, IntPtr a, IntPtr b, IntPtr c);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][QX]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QX]::LoadLibraryW($p) }
}
$h = [QX]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

foreach ($nm in @('QexScanExportsInit', 'QexResourceExportsInit')) {
  $pf = [QX]::GetProcAddress($h, $nm)
  if ($pf -eq [IntPtr]::Zero) { continue }
  $ib = $rd::AllocHGlobal(512)
  for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($ib, $i, 0) }
  $rd::WriteInt32($ib, 0, 0x58)
  $fi = $rd::GetDelegateForFunctionPointer($pf, [QX+InitFn])
  try { [void]$fi.Invoke($ib) } catch { }
  $rd::FreeHGlobal($ib)
}

$out = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($out, $i, 0) }
$fCreate = $rd::GetDelegateForFunctionPointer(
  [QX]::GetProcAddress($h, 'QEXCreateInstance'), [QX+CreateFn])
[void]$fCreate.Invoke([IntPtr]($base + 0x1C2364), [IntPtr]($base + 0x1C2354), $out)
$obj = $rd::ReadIntPtr($out, 0)
if ($obj -eq [IntPtr]::Zero) { Write-Output "null_obj"; exit 0 }
$vt = $rd::ReadIntPtr($obj, 0)

$pathPtr = $rd::StringToHGlobalUni($Target)
$fn = $rd::ReadIntPtr($vt, 0x10)
$scan = $rd::GetDelegateForFunctionPointer($fn, [QX+ScanFn])
try { [void]$scan.Invoke($obj, $pathPtr, [IntPtr][int]0x80000000, [IntPtr]3) } catch { }

$f = $rd::ReadIntPtr($vt, $Slot)
$rva = $f.ToInt64() - $base
Write-Output ("SLOT" + [char]0x1f + ("0x{0:X2}" -f $Slot) + [char]0x1f +
              ("rva=0x{0:X}" -f $rva))

# 依次尝试不同参数个数，每次调用后读 obj 关键字段
$ctx = $rd::ReadIntPtr($obj, 0x1C)
foreach ($n in 0, 1, 2, 3) {
  $r = "EXC"
  try {
    switch ($n) {
      0 { $g = $rd::GetDelegateForFunctionPointer($f, [QX+G0]); $r = $g.Invoke($obj) }
      1 { $g = $rd::GetDelegateForFunctionPointer($f, [QX+G1]); $r = $g.Invoke($obj, [IntPtr]0) }
      2 { $g = $rd::GetDelegateForFunctionPointer($f, [QX+G2]); $r = $g.Invoke($obj, [IntPtr]0, [IntPtr]0) }
      3 { $g = $rd::GetDelegateForFunctionPointer($f, [QX+G3]); $r = $g.Invoke($obj, [IntPtr]0, [IntPtr]0, [IntPtr]0) }
    }
  } catch { $r = "EXC" }
  Write-Output ("  {0}arg -> {1}" -f $n, $r)
}

# 调用后重新读 obj 与 ctx 关键字段，看是否被填充
Write-Output "  --- 调用后 obj 字段 ---"
foreach ($off in @(0x0C, 0x10, 0x14, 0x18, 0x20, 0x28, 0x30, 0x38, 0x3C, 0x40, 0x44)) {
  Write-Output ("    obj+0x{0:X2} = {1}" -f $off, $rd::ReadInt32($obj, $off))
}
if ($ctx -ne [IntPtr]::Zero) {
  Write-Output "  --- 调用后 ctx 字段 ---"
  foreach ($off in @(0x04, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x38, 0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50)) {
    Write-Output ("    ctx+0x{0:X2} = {1}" -f $off, $rd::ReadInt32($ctx, $off))
  }
}

$rd::FreeHGlobal($pathPtr)
$rd::FreeHGlobal($out)