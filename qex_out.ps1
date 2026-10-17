# QEX selector 输出捕获 —— 输出结构是字符串容器
#
# ============================================================================
# 逆向结论（本轮）：
#   vtable[0x48] (0xDF9D0) 的每个 case 都调用同一组辅助函数：
#     0xB5030  检查 word[ecx]==8，返回 [ecx+8] 指针（宽字符串 getter）
#     0xB5070  检查 word[ecx]==0x1E，返回 [ecx+8] 指针（ANSI 字符串 getter）
#     0x4C40   字符串赋值（mov [edi+0x10],eax）
#     0x36710  字符串拷贝（检查 [esi+0x14] 容量）
#   => **输出结构是一个字符串容器**，每个 selector 写入不同的字符串字段。
#
#   所以判定结果（如威胁名）应该以**字符串**形式出现在输出结构里。
#   本脚本：为每个 selector 准备一个足够大的输出缓冲区，
#   调用后把缓冲区按宽字符和 ANSI 两种方式解读，寻找可读字符串。
# ============================================================================

param([string]$Target, [string]$Root, [int]$Sel)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { Write-Output "need -Target"; exit 0 }
if (-not $Sel) { $Sel = 2 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QOut {
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
  public delegate int F3(IntPtr a, IntPtr b, IntPtr c);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][QOut]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QOut]::LoadLibraryW($p) }
}
$h = [QOut]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

$ib = $rd::AllocHGlobal(512)
for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($ib, $i, 0) }
$rd::WriteInt32($ib, 0, 0x58)
$fi = $rd::GetDelegateForFunctionPointer(
  [QOut]::GetProcAddress($h, 'QexScanExportsInit'), [QOut+InitFn])
try { [void]$fi.Invoke($ib) } catch { }

$pCreate = $rd::ReadIntPtr($ib, 0x08)
$p1640 = $rd::ReadIntPtr($ib, 0x14)

$ctxOut = $rd::AllocHGlobal(16)
for ($i = 0; $i -lt 16; $i++) { $rd::WriteByte($ctxOut, $i, 0) }
$fCtx = $rd::GetDelegateForFunctionPointer($pCreate, [QOut+CtxCreate])
try { [void]$fCtx.Invoke($ctxOut) } catch { }
$ctx = $rd::ReadIntPtr($ctxOut, 0)
if ($ctx -eq [IntPtr]::Zero) { Write-Output "ctx null"; exit 0 }

# 输出缓冲区：预填 0xCC，大小 1024 字节
$outBuf = $rd::AllocHGlobal(1024)
for ($i = 0; $i -lt 1024; $i++) { $rd::WriteByte($outBuf, $i, 0xCC) }

$pathPtr = $rd::StringToHGlobalUni($Target)

# 调用 0xD1640(ctx, selector, 0)
$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($p1640, [QOut+F3])
  $rc = $g.Invoke($ctx, [IntPtr]$Sel, [IntPtr]0)
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

Write-Output ("SEL" + [char]0x1f + $Sel + [char]0x1f + "rc=" + $rc)

# 收集可读字符串（宽字符）
$wstr = ""
for ($i = 0; $i -lt 512; $i += 2) {
  $c = $rd::ReadInt16($outBuf, $i)
  if ($c -ge 32 -and $c -lt 127) { $wstr += [char]$c }
  elseif ($c -eq 0) { if ($wstr.Length -ge 3) { break } else { $wstr = "" } }
  elseif ($wstr.Length -ge 3) { break }
  else { $wstr = "" }
}
if ($wstr.Length -ge 3) { Write-Output ("  W: " + $wstr) }

# 收集可读字符串（ANSI）
$astr = ""
for ($i = 0; $i -lt 512; $i++) {
  $c = $rd::ReadByte($outBuf, $i)
  if ($c -ge 32 -and $c -lt 127) { $astr += [char]$c }
  elseif ($c -eq 0) { if ($astr.Length -ge 3) { break } else { $astr = "" } }
  elseif ($astr.Length -ge 3) { break }
  else { $astr = "" }
}
if ($astr.Length -ge 3) { Write-Output ("  A: " + $astr) }

# 统计非 0xCC 字节
$n = 0
for ($i = 0; $i -lt 256; $i++) { if ($rd::ReadByte($outBuf, $i) -ne 0xCC) { $n++ } }
Write-Output ("  changed=$n")

$rd::FreeHGlobal($pathPtr)
$rd::FreeHGlobal($outBuf)
$rd::FreeHGlobal($ib)