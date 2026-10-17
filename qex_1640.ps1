# QEX 0xD1640 调用 —— param_3 是受限枚举（0 或 1）
#
# ============================================================================
# 反汇编 0xD1640（表 +0x14），3 参数：
#   8B 45 08          mov eax,[ebp+8]        ; ctx
#   81 38 71 65 78 31 cmp dword[eax],0x31786571   ; 魔数校验
#   8B 78 04          mov edi,[eax+4]        ; ctx+4 对象
#   85 FF             test edi,edi
#   75 0C             jnz 继续
#   B8 FF FF 00 80    mov eax,0x8000FFFF     ; E_UNEXPECTED
#   8B 45 10          mov eax,[ebp+0x10]     ; param_3 = 枚举
#   83 E8 00 / 74 1F  sub eax,0; jz case_0
#   83 E8 01 / 74 0C  sub eax,1; jz case_1
#   B8 57 00 07 80    mov eax,0x80070057     ; 其他值 -> E_INVALIDARG
# case_0: 构造结构（word 0x0B，or eax,-1）
# case_1: 构造结构（word 0x0B，xor eax,eax）
# 汇合:   lea eax,[ebp-0x10]; push esi; push eax; push [ebp+0x0C]
#         mov esi,[eax+0x48]; call esi        ; vtable[0x48] 分发
#
# param_3 = 0 或 1 是**合法的**，其他值报 E_INVALIDARG。
# 之前用 (ctx,path,0) 调用命中 case_0，所以返回 S_OK 是正常的。
#
# vtable[0x48] 的签名（从 push 顺序看）：
#   call(ecx=esi, [ebp+0x0C], &struct, esi)
# 即 thiscall(this, arg1, arg2, arg3)
# ============================================================================

param([string]$Target, [string]$Root, [int]$Case)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { Write-Output "need -Target"; exit 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QT {
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
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][QT]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QT]::LoadLibraryW($p) }
}
$h = [QT]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

$ib = $rd::AllocHGlobal(512)
for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($ib, $i, 0) }
$rd::WriteInt32($ib, 0, 0x58)
$fi = $rd::GetDelegateForFunctionPointer(
  [QT]::GetProcAddress($h, 'QexScanExportsInit'), [QT+InitFn])
try { [void]$fi.Invoke($ib) } catch { }

$pCreate = $rd::ReadIntPtr($ib, 0x08)
$p1640 = $rd::ReadIntPtr($ib, 0x14)
$p15d0 = $rd::ReadIntPtr($ib, 0x10)

$ctxOut = $rd::AllocHGlobal(16)
for ($i = 0; $i -lt 16; $i++) { $rd::WriteByte($ctxOut, $i, 0) }
$fCtx = $rd::GetDelegateForFunctionPointer($pCreate, [QT+CtxCreate])
try { [void]$fCtx.Invoke($ctxOut) } catch { }
$ctx = $rd::ReadIntPtr($ctxOut, 0)
if ($ctx -eq [IntPtr]::Zero) { Write-Output "ctx null"; exit 0 }

$pathPtr = $rd::StringToHGlobalUni($Target)

# 为 vtable[0x48] 的输出准备缓冲区（结构里可能有指针）
$outBuf = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($outBuf, $i, 0) }

Write-Output ("TARGET" + [char]0x1f + $Target)
Write-Output ("  ctx=0x{0:X}" -f $ctx.ToInt64())

foreach ($c in 0, 1) {
  $rc = "EXC"
  try {
    $g = $rd::GetDelegateForFunctionPointer($p1640, [QT+F3])
    $rc = $g.Invoke($ctx, $pathPtr, [IntPtr]$c)
  } catch { $rc = "EXC:" + $_.Exception.GetType().Name }
  Write-Output ("  --- 0xD1640 case={0} rc={1} ---" -f $c, $rc)

  # 看 ctx+4 对象是否被填充
  $inner = $rd::ReadIntPtr($ctx, 4)
  if ($inner -ne [IntPtr]::Zero) {
    $ivt = $rd::ReadIntPtr($inner, 0)
    Write-Output ("    ctx+4=0x{0:X} vtable=0x{1:X} (RVA 0x{2:X})" -f $inner.ToInt64(), $ivt.ToInt64(), ($ivt.ToInt64() - $base))
  }
}

# 也试 0xD15D0（表 +0x10），它同样 dispatch 到 vtable[0x48]
Write-Output "  --- 0xD15D0 (ctx, path, 0) ---"
$rc2 = "EXC"
try {
  $g2 = $rd::GetDelegateForFunctionPointer($p15d0, [QT+F3])
  $rc2 = $g2.Invoke($ctx, $pathPtr, [IntPtr]0)
} catch { $rc2 = "EXC:" + $_.Exception.GetType().Name }
Write-Output ("    rc={0}" -f $rc2)

# dump ctx 完整内容
Write-Output "  --- ctx 最终内容 ---"
for ($o = 0; $o -lt 0x44; $o += 16) {
  $vals = @()
  for ($j = 0; $j -lt 16; $j += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($ctx, $o + $j)) }
  Write-Output ("    +{0:X2}: {1}" -f $o, ($vals -join ' '))
}

$rd::FreeHGlobal($pathPtr)
$rd::FreeHGlobal($outBuf)
$rd::FreeHGlobal($ib)