# 找出哪个 QEX API 函数执行实际扫描（会改变上下文状态）
#
# 判据：调用某函数后，上下文里的字段发生变化（尤其是 +0x0C/+0x10/+0x14/+0x30
# 这些被 0xD1520 重置方法清零的字段，以及 +0x1C 附近的指针）。
# 改变字段的那个函数就是扫描函数。
#
# 用法：-Mode 0 -Slot N  探测单个槽位（独立进程，隔离 AccessViolationException）
#       -Mode 1          基线：创建后不调用任何函数，dump 上下文

param([string]$Target, [string]$Root, [int]$Mode, [int]$Slot)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Mode) { $Mode = 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QS {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int InitFn(IntPtr buf);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int CtxCreate(IntPtr outPtr);
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

[void][QS]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QS]::LoadLibraryW($p) }
}
$h = [QS]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

$ib = $rd::AllocHGlobal(512)
for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($ib, $i, 0) }
$rd::WriteInt32($ib, 0, 0x58)
$fi = $rd::GetDelegateForFunctionPointer(
  [QS]::GetProcAddress($h, 'QexScanExportsInit'), [QS+InitFn])
try { [void]$fi.Invoke($ib) } catch { }

$tbl = @{}
foreach ($off in 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54) {
  $tbl[$off] = $rd::ReadIntPtr($ib, $off)
}

$ctxOut = $rd::AllocHGlobal(16)
for ($i = 0; $i -lt 16; $i++) { $rd::WriteByte($ctxOut, $i, 0) }
$fCtx = $rd::GetDelegateForFunctionPointer($tbl[0x08], [QS+CtxCreate])
try { [void]$fCtx.Invoke($ctxOut) } catch { }
$ctx = $rd::ReadIntPtr($ctxOut, 0)
if ($ctx -eq [IntPtr]::Zero) { Write-Output "ctx null"; exit 0 }

# 上下文指纹：读取关键字段
function Get-Fingerprint {
  param($p)
  $vals = @()
  foreach ($o in 0x04, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x28, 0x2C, 0x30, 0x34, 0x38) {
    $vals += ("{0:X8}" -f $rd::ReadInt32($p, $o))
  }
  return ($vals -join ' ')
}

$before = Get-Fingerprint $ctx
$pathPtr = $rd::StringToHGlobalUni($Target)

if ($Mode -eq 1) {
  Write-Output ("BASE" + [char]0x1f + $before)
  exit 0
}

$off = $Slot
$fp = $tbl[$off]
if ($fp -eq [IntPtr]::Zero) { Write-Output ("    +0x{0:X2} 空" -f $off); exit 0 }
$rva = $fp.ToInt64() - $base

# 用 3 参形式调用（ctx, path, 0），这是最可能触发扫描的形式
$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($fp, [QS+F3])
  $rc = $g.Invoke($ctx, $pathPtr, [IntPtr]0)
} catch { $rc = "EXC" }

$after = Get-Fingerprint $ctx
$changed = if ($before -ne $after) { "★变化★" } else { "无变化" }
Write-Output ("    +0x{0:X2} (0x{1:X}) rc={2} {3}" -f $off, $rva, $rc, $changed)
if ($before -ne $after) {
  Write-Output ("      before: " + $before)
  Write-Output ("      after : " + $after)
}

$rd::FreeHGlobal($pathPtr)
$rd::FreeHGlobal($ib)