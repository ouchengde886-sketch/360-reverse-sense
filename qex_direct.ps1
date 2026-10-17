# 直接调用 vtable[0x48]，传入调用方自己的输出缓冲区
#
# ============================================================================
# 根因（本轮逆向确认）：
#   0xD1640 把**它自己的栈帧**（[ebp-0x10]）作为输出结构传给 vtable[0x48]：
#     case_0: 66 89 45 F0   mov [ebp-0x10],ax     <- 栈上临时结构
#     汇合:   8D 45 F0      lea eax,[ebp-0x10]
#             50            push eax              <- 作为输出结构传入
#   函数返回后栈帧失效，所以外部缓冲区永远 changed=0。
#
# 解决办法：**绕过 0xD1640，直接调用 vtable[0x48]**，
#   自己传一个持久缓冲区作为输出结构。
#
# vtable[0x48] = RVA 0xDF9D0，thiscall，签名（从 push 顺序）：
#   call(ecx=inner, selector, outStruct, extra)
#   inner = ctx+4（真实 QEX 内部对象，虚表 RVA 0x1C0C1C）
#
# outStruct 需要按 QEX 的字符串容器布局初始化。
# 从 0xB5030/0xB5070 反汇编看，容器布局是：
#   +0x00  word  类型标记（宽字符=8，ANSI=0x1E）
#   +0x04  ?     其他
#   +0x08  ptr   字符串数据指针
#   +0x14  dword 容量
# 本脚本用两种初始化方式各试一次。
# ============================================================================

param([string]$Target, [string]$Root, [int]$Sel, [int]$Init)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { Write-Output "need -Target"; exit 0 }
if (-not $Sel) { $Sel = 2 }
if (-not $Init) { $Init = 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QDirect {
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
  // vtable[0x48]: thiscall(inner, selector, outStruct, extra) -> ret 0x10 (4 参数)
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int VT48(IntPtr self, IntPtr selector, IntPtr outStruct, IntPtr extra);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][QDirect]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QDirect]::LoadLibraryW($p) }
}
$h = [QDirect]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

$ib = $rd::AllocHGlobal(512)
for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($ib, $i, 0) }
$rd::WriteInt32($ib, 0, 0x58)
$fi = $rd::GetDelegateForFunctionPointer(
  [QDirect]::GetProcAddress($h, 'QexScanExportsInit'), [QDirect+InitFn])
try { [void]$fi.Invoke($ib) } catch { }

$pCreate = $rd::ReadIntPtr($ib, 0x08)
$ctxOut = $rd::AllocHGlobal(16)
for ($i = 0; $i -lt 16; $i++) { $rd::WriteByte($ctxOut, $i, 0) }
$fCtx = $rd::GetDelegateForFunctionPointer($pCreate, [QDirect+CtxCreate])
try { [void]$fCtx.Invoke($ctxOut) } catch { }
$ctx = $rd::ReadIntPtr($ctxOut, 0)
if ($ctx -eq [IntPtr]::Zero) { Write-Output "ctx null"; exit 0 }
$inner = $rd::ReadIntPtr($ctx, 4)
if ($inner -eq [IntPtr]::Zero) { Write-Output "inner null"; exit 0 }
$ivt = $rd::ReadIntPtr($inner, 0)
$fn48 = $rd::ReadIntPtr($ivt, 0x48)
Write-Output ("  inner=0x{0:X} vtable=0x{1:X} [0x48]=0x{2:X} (RVA 0x{3:X})" -f `
  $inner.ToInt64(), $ivt.ToInt64(), $fn48.ToInt64(), ($fn48.ToInt64() - $base))

# 输出结构缓冲区：512 字节，按不同方式初始化
$outBuf = $rd::AllocHGlobal(512)
if ($Init -eq 0) {
  # 方式 0：全 0
  for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($outBuf, $i, 0) }
} elseif ($Init -eq 1) {
  # 方式 1：word[0]=8（宽字符标记），+0x14 容量
  for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($outBuf, $i, 0) }
  $rd::WriteInt16($outBuf, 0, 8)
  $rd::WriteInt32($outBuf, 0x14, 0x100)
} else {
  # 方式 2：全 0xCC
  for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($outBuf, $i, 0xCC) }
}

$pathPtr = $rd::StringToHGlobalUni($Target)

$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($fn48, [QDirect+VT48])
  $rc = $g.Invoke($inner, [IntPtr]$Sel, $outBuf, [IntPtr]0)
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

Write-Output ("  SEL=" + $Sel + " init=" + $Init + " rc=" + $rc)

# 收集可读字符串
$wstr = ""
for ($i = 0; $i -lt 256; $i += 2) {
  $c = $rd::ReadInt16($outBuf, $i)
  if ($c -ge 32 -and $c -lt 127) { $wstr += [char]$c }
  elseif ($c -eq 0) { if ($wstr.Length -ge 3) { break } else { $wstr = "" } }
  elseif ($wstr.Length -ge 3) { break }
  else { $wstr = "" }
}
if ($wstr.Length -ge 3) { Write-Output ("  W: " + $wstr) }

$astr = ""
for ($i = 0; $i -lt 256; $i++) {
  $c = $rd::ReadByte($outBuf, $i)
  if ($c -ge 32 -and $c -lt 127) { $astr += [char]$c }
  elseif ($c -eq 0) { if ($astr.Length -ge 3) { break } else { $astr = "" } }
  elseif ($astr.Length -ge 3) { break }
  else { $astr = "" }
}
if ($astr.Length -ge 3) { Write-Output ("  A: " + $astr) }

$n = 0
for ($i = 0; $i -lt 256; $i++) { if ($rd::ReadByte($outBuf, $i) -ne 0) { $n++ } }
Write-Output ("  nonzero=$n")

$rd::FreeHGlobal($pathPtr)
$rd::FreeHGlobal($outBuf)
$rd::FreeHGlobal($ib)