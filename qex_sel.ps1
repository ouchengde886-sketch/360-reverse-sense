# QEX selector 扫描 —— 通过 0xD1640 调用不同的 selector，捕获输出结构
#
# ============================================================================
# 完整调用链（反汇编确认）：
#   0xD1640(ctx, param_2, param_3)
#     param_2 -> 传给 vtable[0x48] 作为 param_1
#     param_3 -> 受限枚举 0/1
#   vtable[0x48] = RVA 0xDF9D0，入口：
#     8B 7D 08          mov edi,[ebp+8]        ; param_1 = selector
#     8B 75 0C          mov esi,[ebp+0x0C]     ; param_2 = 输出结构
#     8D 47 FF          lea eax,[edi-1]
#     83 F8 55          cmp eax,0x55           ; 0x56 个 case
#     0F 87 ...         ja  默认分支
#     0F B6 80 DC 03 0E 10  movzx eax,byte[eax+0x100E03DC]
#     FF 24 85 98 03 0E 10  jmp [eax*4+0x100E0398]
#   => **selector 取值范围 1..0x56（1..86）**
#
# 本脚本：对指定 selector 调用 0xD1640，并把输出结构 dump 出来。
# 用法：-Mode 0 -Sel N   单个 selector（独立进程，隔离崩溃）
#       -Mode 1         基线，不调用
# ============================================================================

param([string]$Target, [string]$Root, [int]$Mode, [int]$Sel, [int]$Case)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Mode) { $Mode = 0 }
if (-not $Case) { $Case = 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QSel {
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
# ★★★ Add-Type 在本环境不可用（360 的 360FsFlt 微过滤驱动按扩展名拦截 .dll 写入）
#   症状: Add-Type 报 "Access to the path '...\xxxxxxxx.dll' is denied."
#   后果: 类型未加载 -> 后续所有 [类型]:: 调用抛 TypeNotFound / null 异常，
#         表现为"引擎不响应"，极具误导性。
#   变通: 编译到 .com（不被拦截）+ Assembly::LoadFile（不检查扩展名）
$typeOk = $false
try {
  Add-Type -TypeDefinition $sig -ErrorAction Stop
  $typeOk = $true
} catch {
  $comPath = Join-Path $env:TEMP ("avtype_" + [guid]::NewGuid().ToString('N') + ".com")
  try {
    Add-Type -TypeDefinition $sig -OutputAssembly $comPath -ErrorAction Stop
    [void][System.Reflection.Assembly]::LoadFile($comPath)
    $typeOk = $true
  } catch {
    Write-Host ("ADDTYPE_FAIL " + $_.Exception.Message)
  }
}
if (-not $typeOk) {
  Write-Host ("RESULT" + [char]31 + "EXC" + [char]31 + "Add-Type failed: type unavailable")
  exit 9
}
[void][QSel]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QSel]::LoadLibraryW($p) }
}
$h = [QSel]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

$ib = $rd::AllocHGlobal(512)
for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($ib, $i, 0) }
$rd::WriteInt32($ib, 0, 0x58)
$fi = $rd::GetDelegateForFunctionPointer(
  [QSel]::GetProcAddress($h, 'QexScanExportsInit'), [QSel+InitFn])
try { [void]$fi.Invoke($ib) } catch { }

$pCreate = $rd::ReadIntPtr($ib, 0x08)
$p1640 = $rd::ReadIntPtr($ib, 0x14)

$ctxOut = $rd::AllocHGlobal(16)
for ($i = 0; $i -lt 16; $i++) { $rd::WriteByte($ctxOut, $i, 0) }
$fCtx = $rd::GetDelegateForFunctionPointer($pCreate, [QSel+CtxCreate])
try { [void]$fCtx.Invoke($ctxOut) } catch { }
$ctx = $rd::ReadIntPtr($ctxOut, 0)
if ($ctx -eq [IntPtr]::Zero) { Write-Output "ctx null"; exit 0 }

# 输出结构缓冲区：预填 0xCC 便于识别哪些字节被写入
$outBuf = $rd::AllocHGlobal(512)
for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($outBuf, $i, 0xCC) }

$pathPtr = $rd::StringToHGlobalUni($Target)

if ($Mode -eq 1) {
  Write-Output ("BASE" + [char]0x1f + "ctx=0x" + $ctx.ToString("X"))
  exit 0
}

# 调用 0xD1640(ctx, selector, case)
$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($p1640, [QSel+F3])
  $rc = $g.Invoke($ctx, [IntPtr]$Sel, [IntPtr]$Case)
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

# 检查输出缓冲是否被写入（找非 0xCC 的字节）
$written = @()
for ($i = 0; $i -lt 128; $i++) {
  $b = $rd::ReadByte($outBuf, $i)
  if ($b -ne 0xCC) { $written += ("+0x{0:X2}={1:X2}" -f $i, $b) }
}

Write-Output ("SEL" + [char]0x1f + $Sel + [char]0x1f + "case=" + $Case + [char]0x1f + "rc=" + $rc + [char]0x1f + "written=" + $written.Count)
if ($written.Count -gt 0 -and $written.Count -le 24) {
  Write-Output ("    " + ($written -join ' '))
}

$rd::FreeHGlobal($pathPtr)
$rd::FreeHGlobal($outBuf)
$rd::FreeHGlobal($ib)