# 探测 QexResourceExportsInit 填充的 15 个函数 —— 寻找触发解析/扫描的入口
#
# ============================================================================
# QexResourceExportsInit (RVA 0xD49F0) 填充表大小 0x40，15 个有效函数指针：
#   +0x04 0xD2220   +0x08 0xD2320   +0x0C 0xD2620   +0x10 0xD2720
#   +0x14 0xD28C0   +0x18 0xD28F0   +0x1C 0xD2A00   +0x20 0xD2A70
#   +0x24 0xD2520   +0x28 0xD2B30   +0x2C 0xD2B60   +0x30 0xD2B90
#   +0x34 0xD2C50   +0x38 0xD2CF0   +0x3C 0xD2D80
#
# 这是唯一还没探测过的 API 面。本脚本逐个调用，观察：
#   - 返回值
#   - 是否改变 qex1 上下文
#   - 是否向输出缓冲区写入数据
#
# 用法：-Mode 0 -Slot N   探测单个槽位（独立进程隔离崩溃）
#       -Mode 1          只创建上下文，打印基线
# ============================================================================

param([string]$Target, [string]$Root, [int]$Mode, [int]$Slot)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Mode) { $Mode = 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QRes {
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

[void][QRes]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QRes]::LoadLibraryW($p) }
}
$h = [QRes]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

# 初始化两张表
$scanTbl = $rd::AllocHGlobal(512)
for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($scanTbl, $i, 0) }
$rd::WriteInt32($scanTbl, 0, 0x58)
$f1 = $rd::GetDelegateForFunctionPointer(
  [QRes]::GetProcAddress($h, 'QexScanExportsInit'), [QRes+InitFn])
try { [void]$f1.Invoke($scanTbl) } catch { }

$resTbl = $rd::AllocHGlobal(512)
for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($resTbl, $i, 0) }
$rd::WriteInt32($resTbl, 0, 0x40)
$f2 = $rd::GetDelegateForFunctionPointer(
  [QRes]::GetProcAddress($h, 'QexResourceExportsInit'), [QRes+InitFn])
try { [void]$f2.Invoke($resTbl) } catch { }

# 创建上下文
$pCreate = $rd::ReadIntPtr($scanTbl, 0x08)
$ctxOut = $rd::AllocHGlobal(16)
for ($i = 0; $i -lt 16; $i++) { $rd::WriteByte($ctxOut, $i, 0) }
$fCtx = $rd::GetDelegateForFunctionPointer($pCreate, [QRes+CtxCreate])
try { [void]$fCtx.Invoke($ctxOut) } catch { }
$ctx = $rd::ReadIntPtr($ctxOut, 0)
if ($ctx -eq [IntPtr]::Zero) { Write-Output "ctx null"; exit 0 }

function Get-Fp {
  param($p)
  $v = @()
  foreach ($o in 0x04, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x28, 0x2C, 0x30, 0x34, 0x38) {
    $v += ("{0:X8}" -f $rd::ReadInt32($p, $o))
  }
  return ($v -join ' ')
}

if ($Mode -eq 1) {
  Write-Output ("BASE" + [char]0x1f + (Get-Fp $ctx))
  exit 0
}

$off = $Slot
$fp = $rd::ReadIntPtr($resTbl, $off)
if ($fp -eq [IntPtr]::Zero) { Write-Output ("    +0x{0:X2} 空" -f $off); exit 0 }
$rva = $fp.ToInt64() - $base

$before = Get-Fp $ctx
$outBuf = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($outBuf, $i, 0xCC) }
$pathPtr = $rd::StringToHGlobalUni($Target)

# 尝试多种参数组合，取第一个不崩溃的
$rc = "EXC"
foreach ($form in 1, 2, 3, 4) {
  try {
    if ($form -eq 1) { $g = $rd::GetDelegateForFunctionPointer($fp, [QRes+F1]); $rc = $g.Invoke($ctx) }
    elseif ($form -eq 2) { $g = $rd::GetDelegateForFunctionPointer($fp, [QRes+F2]); $rc = $g.Invoke($ctx, $outBuf) }
    elseif ($form -eq 3) { $g = $rd::GetDelegateForFunctionPointer($fp, [QRes+F3]); $rc = $g.Invoke($ctx, $pathPtr, $outBuf) }
    else { $g = $rd::GetDelegateForFunctionPointer($fp, [QRes+F4]); $rc = $g.Invoke($ctx, $pathPtr, $outBuf, [IntPtr]0) }
    $rc = ("{0}:{1}" -f $form, $rc)
    break
  } catch { $rc = "EXC" }
}

$after = Get-Fp $ctx
$chg = if ($before -ne $after) { "★ctx变化★" } else { "ctx无变化" }
$n = 0
for ($i = 0; $i -lt 128; $i++) { if ($rd::ReadByte($outBuf, $i) -ne 0xCC) { $n++ } }
Write-Output ("    +0x{0:X2} (0x{1:X}) rc={2} {3} out={4}" -f $off, $rva, $rc, $chg, $n)

$rd::FreeHGlobal($pathPtr)
$rd::FreeHGlobal($outBuf)
$rd::FreeHGlobal($scanTbl)
$rd::FreeHGlobal($resTbl)