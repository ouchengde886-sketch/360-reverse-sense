# QEX 真实 API 调用 v2 —— 按反汇编确定的签名传参
#
# ============================================================================
# 已确定的函数签名（反汇编 [ebp+N] 读取得出，非 ret N 扫描）
# ============================================================================
# 所有函数入口都做 `cmp dword[ecx],0x31786571` / `cmp dword[eax],0x31786571`
# 魔数校验（"qex1"），校验失败返回 0x80070057。
#
# 0xD1520 (表+0x0C)  4 参 -> 实测只传 ctx 也返回 S_OK
#   反汇编: mov edi,[ebp+8]; 校验魔数; 然后
#     [edi+0x04]=0  [edi+0x0C]=0  [edi+0x10]=0  [edi+0x14]=0  [edi+0x30]=-1
#   => **重置/清空方法**，忽略多余参数，故返回 S_OK。
#
# 0xD15D0 (表+0x10)  4 参 -> 实测返回 0x8000FFFF
#   反汇编: mov eax,[ebp+8]; 校验魔数; mov edi,[eax+4];
#     ... mov edx,[ebp+0x10]; mov [ebp-8],edx; lea eax,[ebp-0x10]; push eax;
#     push [ebp+0x0C]; mov esi,[edi+0x48]; call [esi]  <- **vtable 分发**
#   => 对 ctx+4 对象的 vtable[0x48] 做调用，需要 2 个真实参数。
#
# 0xD1820 (表+0x1C)  4 参 -> 返回 0x80070057
#   反汇编: 校验魔数后 push [ebp+0x14]; push [ebp+0x10]; push [ebp+0x0C]; call
#   => 3 参转发器。
# ============================================================================

param([string]$Target, [string]$Root, [int]$Mode, [int]$Slot)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { Write-Output "need -Target"; exit 0 }
if (-not $Mode) { $Mode = 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QB2 {
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

[void][QB2]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QB2]::LoadLibraryW($p) }
}
$h = [QB2]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

$ib = $rd::AllocHGlobal(512)
for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($ib, $i, 0) }
$rd::WriteInt32($ib, 0, 0x58)
$fi = $rd::GetDelegateForFunctionPointer(
  [QB2]::GetProcAddress($h, 'QexScanExportsInit'), [QB2+InitFn])
try { [void]$fi.Invoke($ib) } catch { }

$tbl = @{}
foreach ($off in 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54) {
  $tbl[$off] = $rd::ReadIntPtr($ib, $off)
}

# 创建上下文
$ctxOut = $rd::AllocHGlobal(16)
for ($i = 0; $i -lt 16; $i++) { $rd::WriteByte($ctxOut, $i, 0) }
$fCtx = $rd::GetDelegateForFunctionPointer($tbl[0x08], [QB2+CtxCreate])
try { [void]$fCtx.Invoke($ctxOut) } catch { }
$ctx = $rd::ReadIntPtr($ctxOut, 0)
Write-Output ("CTX" + [char]0x1f + ("0x{0:X}" -f $ctx.ToInt64()))
if ($ctx -eq [IntPtr]::Zero) { Write-Output "ctx null"; exit 0 }

$pathPtr = $rd::StringToHGlobalUni($Target)
$pathAnsi = $rd::StringToHGlobalAnsi($Target)

# 模式 0：对**单个**表项做多种参数组合探测
# 注意：AccessViolationException 在 PowerShell 里 try/catch 抓不住，
# 所以每次只探测一个槽位，由调用方逐个起独立进程。
if ($Mode -eq 0) {
  $off = $Slot
  $fp = $tbl[$off]
  if ($fp -eq [IntPtr]::Zero) { Write-Output ("    +0x{0:X2} 空" -f $off); exit 0 }
  $rva = $fp.ToInt64() - $base
  $res = @()
  # (ctx)
  try { $g = $rd::GetDelegateForFunctionPointer($fp, [QB2+F1]); $res += "1:" + $g.Invoke($ctx) } catch { $res += "1:EXC" }
  # (ctx, pathW)
  try { $g = $rd::GetDelegateForFunctionPointer($fp, [QB2+F2]); $res += "2W:" + $g.Invoke($ctx, $pathPtr) } catch { $res += "2W:EXC" }
  # (ctx, pathA)
  try { $g = $rd::GetDelegateForFunctionPointer($fp, [QB2+F2]); $res += "2A:" + $g.Invoke($ctx, $pathAnsi) } catch { $res += "2A:EXC" }
  # (ctx, pathW, 0)
  try { $g = $rd::GetDelegateForFunctionPointer($fp, [QB2+F3]); $res += "3:" + $g.Invoke($ctx, $pathPtr, [IntPtr]0) } catch { $res += "3:EXC" }
  Write-Output ("    +0x{0:X2} (0x{1:X}) {2}" -f $off, $rva, ($res -join '  '))
}

# 模式 1：调用后 dump 上下文，看是否被填充
if ($Mode -eq 1) {
  $fp = $tbl[0x10]
  $g = $rd::GetDelegateForFunctionPointer($fp, [QB2+F3])
  $r = "EXC"
  try { $r = $g.Invoke($ctx, $pathPtr, [IntPtr]0) } catch { }
  Write-Output ("  call +0x10(ctx,path,0) -> {0}" -f $r)
  Write-Output "  --- ctx 内容 ---"
  for ($o = 0; $o -lt 0x44; $o += 16) {
    $vals = @()
    for ($j = 0; $j -lt 16; $j += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($ctx, $o + $j)) }
    Write-Output ("    +{0:X2}: {1}" -f $o, ($vals -join ' '))
  }
}

$rd::FreeHGlobal($pathPtr)
$rd::FreeHGlobal($pathAnsi)
$rd::FreeHGlobal($ib)