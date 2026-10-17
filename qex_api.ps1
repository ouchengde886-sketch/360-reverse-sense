# QEX 真实扫描 API 调用 —— 通过 QexScanExportsInit 填充的函数表
#
# ============================================================================
# 重大发现（本轮逆向）
# ============================================================================
# QexScanExportsInit (RVA 0xD48D0) 填充一张 21 项函数表，这才是 QEX 扫描 API。
# 表中每个函数都以魔数校验开头：
#     81 39 71 65 78 31    cmp dword[ecx],0x31786571   ; "qex1"
#     75 xx                jne 失败 -> 返回 0x80070057
#
# 表项与 RVA 对应：
#   +0x04 0xD1230   +0x08 0xD1330(创建上下文,1参)   +0x0C 0xD1520
#   +0x10 0xD15D0   +0x14 0xD1640   +0x18 0xD16D0   +0x1C 0xD1820
#   +0x20 0xD1850   +0x24 0xD1A40   +0x28 0xD1B70   +0x2C 0xD1BA0
#   +0x30 0xD1BD0   +0x34 0xD1C20   +0x38 0xD1C60   +0x3C 0xD1CA0
#   +0x40 0xD1CD0   +0x44 0xD1D00   +0x48 0xD1E80   +0x4C 0xD2010
#   +0x50 0xD2040   +0x54 0xD20F0
#
# 0xD1330 反汇编（上下文创建）：
#   83 7D 08 00        cmp dword[ebp+8],0     ; param_1
#   75 19              jne 继续
#   B8 57 00 07 80     mov eax,0x80070057     ; E_INVALIDARG
#   C2 04 00           ret 4                  ; 1 个栈参数
#   68 28 F5 21 10     push 类型描述符
#   6A 44              push 0x44              ; 分配 68 字节
#   E8 ...             call operator new
#   C7 03 71 65 78 31  mov dword[ebx],0x31786571   ; 写入 "qex1" 魔数
#   C7 47 20 07 00 00 00  mov dword[edi+0x20],7
# ============================================================================

param([string]$Target, [string]$Root)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { Write-Output "need -Target"; exit 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QA {
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
  // 0xD1330: 创建 qex1 上下文。
  // 入口 `cmp dword[ebp+8],0; jne 继续` 说明 param_1 是**输出指针**
  // （不能为 NULL），函数返回 HRESULT，把上下文写回 param_1。
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int CtxCreate(IntPtr outPtr);
  // 通用 3 参数（多数表项是这个形状）
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F3(IntPtr a, IntPtr b, IntPtr c);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F5(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][QA]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QA]::LoadLibraryW($p) }
}
$h = [QA]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

# 1) 初始化导出表，拿到真实 API 地址
$ib = $rd::AllocHGlobal(512)
for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($ib, $i, 0) }
$rd::WriteInt32($ib, 0, 0x58)
$fi = $rd::GetDelegateForFunctionPointer(
  [QA]::GetProcAddress($h, 'QexScanExportsInit'), [QA+InitFn])
$initRc = "EXC"
try { $initRc = $fi.Invoke($ib) } catch { }
Write-Output ("INIT" + [char]0x1f + "rc=" + $initRc)

# 读取表里的函数指针
$tbl = @{}
foreach ($off in 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54) {
  $fp = $rd::ReadIntPtr($ib, $off)
  $tbl[$off] = $fp
  if ($fp -ne [IntPtr]::Zero) {
    Write-Output ("  +0x{0:X2} -> RVA 0x{1:X}" -f $off, ($fp.ToInt64() - $base))
  }
}

# 2) 调用 0xD1330 创建 qex1 上下文
$pCreate = $tbl[0x08]
if ($pCreate -eq [IntPtr]::Zero) { Write-Output "no ctx creator"; exit 0 }
$fCtx = $rd::GetDelegateForFunctionPointer($pCreate, [QA+CtxCreate])
# 0xD1330 的 param_1 是输出指针（不能为 NULL），函数返回 HRESULT。
$ctxOut = $rd::AllocHGlobal(16)
for ($i = 0; $i -lt 16; $i++) { $rd::WriteByte($ctxOut, $i, 0) }
$crc = "EXC"
try { $crc = $fCtx.Invoke($ctxOut); } catch { $crc = "EXC:" + $_.Exception.GetType().Name }
$ctx = $rd::ReadIntPtr($ctxOut, 0)
Write-Output ("CTX" + [char]0x1f + "rc=" + $crc + [char]0x1f + ("ptr=0x{0:X}" -f $ctx.ToInt64()))

if ($ctx -ne [IntPtr]::Zero) {
  # 验证魔数
  $magic = $rd::ReadInt32($ctx, 0)
  Write-Output ("  magic = 0x{0:X8} ({1})" -f $magic, $(if ($magic -eq 0x31786571) { 'qex1 正确' } else { '不匹配' }))
  Write-Output "  --- 上下文内容 (0x00-0x44) ---"
  for ($o = 0; $o -lt 0x44; $o += 16) {
    $vals = @()
    for ($j = 0; $j -lt 16; $j += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($ctx, $o + $j)) }
    Write-Output ("    +{0:X2}: {1}" -f $o, ($vals -join ' '))
  }

  # 3) 对每个表项尝试调用（传入上下文）
  Write-Output "  --- 调用各表项 (ctx, 0, 0) ---"
  foreach ($off in 0x04, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54) {
    $fp = $tbl[$off]
    if ($fp -eq [IntPtr]::Zero) { continue }
    $rva = $fp.ToInt64() - $base
    $r = "EXC"
    try {
      $g = $rd::GetDelegateForFunctionPointer($fp, [QA+F3])
      $r = $g.Invoke($ctx, [IntPtr]0, [IntPtr]0)
    } catch { $r = "EXC" }
    Write-Output ("    +0x{0:X2} (RVA 0x{1:X}) -> {2}" -f $off, $rva, $r)
  }
}

$rd::FreeHGlobal($ib)