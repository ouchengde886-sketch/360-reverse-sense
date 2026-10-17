# 直接调用 ScanAveMemory 的内部实现 (RVA 0x3FEE1) —— 7 参数
#
# ============================================================================
# ScanAveMemory (RVA 0x3FEC8) 只是 4 参数 thunk，它把最后两个内部参数硬编码为 0：
#   +003: 6A 00        push 0        -> 内部 [ebp+0x18] = 0
#   +005: 6A 00        push 0        -> 内部 [ebp+0x1C] = 0
#   +007: FF 75 14     push [ebp+0x14]  thunk param_6 -> 内部 [ebp+0x14]
#   +00A: FF 75 10     push [ebp+0x10]  thunk param_5 -> 内部 [ebp+0x10]
#   +00D: FF 75 0C     push [ebp+0x0C]  thunk param_4 -> 内部 [ebp+0x0C]
#   +010: FF 75 08     push [ebp+0x08]  thunk param_3 -> 内部 [ebp+0x08]
#   +013: E8 04 00 00 00  call 0x3FEE1
#   +019: C2 10 00     ret 0x10
#
# 内部实现 (RVA 0x3FEE1)：
#   +012: 83 7D 0C 00   cmp dword[ebp+0x0C],0
#   +016: 75 08         jnz 继续
#   +018: 6A 9A / 58    push 0x9A; pop eax   <- 返回 0x9A = -102
#   +020: 8B 7D 1C      mov edi,[ebp+0x1C]   param_7
#   +026: test edi,edi / jz 跳过
#   +02A: 39 1F         cmp [edi],ebx        ; 必须非0
#   +02E: 39 5F 04      cmp [edi+4],ebx      ; 必须非0
#   +034: 6A 99         push 0x99            <- 返回 0x99
#
# 所以必须直接调 0x3FEE1，传 7 个参数：
#   param_2 = ?            (被读)
#   param_3 = [ebp+0x0C]   **必须非 0**
#   param_4 = ?
#   param_5 = ?
#   param_6 = [ebp+0x18]   (被读)
#   param_7 = [ebp+0x1C]   指向结构，前两个 DWORD 非 0
#
# 用法: -Form N 组合尝试
# ============================================================================

param([string]$Root, [int]$Form, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Form) { $Form = 1 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class SI {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F7(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F8(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h2);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][SI]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][SI]::LoadLibraryW($p) }
}
$h = [SI]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

$pEng = [SI]::GetProcAddress($h, 'EngLib_Init')
try {
  $ge = $rd::GetDelegateForFunctionPointer($pEng, [SI+F1])
  [void]$ge.Invoke([IntPtr]::Zero)
} catch { }

# 文件数据
$dataBuf = $rd::AllocHGlobal(65536)
for ($i = 0; $i -lt 65536; $i++) { $rd::WriteByte($dataBuf, $i, 0) }
$size = 0
if ($Target -and (Test-Path $Target)) {
  $bytes = [System.IO.File]::ReadAllBytes($Target)
  $size = [Math]::Min($bytes.Length, 65536)
  $rd::Copy($bytes, 0, $dataBuf, $size)
}
$pathPtr = $rd::StringToHGlobalUni($Target)

# param_7 结构
$st = $rd::AllocHGlobal(128)
for ($i = 0; $i -lt 128; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, $size)
$rd::WriteInt32($st, 4, $size)

# 直接调内部实现。
# ScanAveMemory thunk 的 call 位于 RVA 0x3FEC8+0x013，E8 指令长 5，
# 相对位移 +4，所以目标 = 0x3FEC8 + 0x013 + 5 + 4 = 0x3FEE4。
$pInner = [IntPtr]($base + 0x3FEE4)

# 参数组合：param_3 必须非 0
$combos = @{
  1 = @($dataBuf, [IntPtr]$size, [IntPtr]1, [IntPtr]::Zero, [IntPtr]::Zero, $st, $pathPtr)
  2 = @($dataBuf, [IntPtr]$size, [IntPtr]1, $st, [IntPtr]::Zero, $pathPtr, $st)
  3 = @($pathPtr, [IntPtr]$size, [IntPtr]1, [IntPtr]::Zero, [IntPtr]::Zero, $st, $dataBuf)
  4 = @($dataBuf, [IntPtr]$size, [IntPtr]1, [IntPtr]::Zero, [IntPtr]::Zero, $st, [IntPtr]::Zero)
}

$args7 = $combos[$Form]
if (-not $args7) { $args7 = $combos[1] }

$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($pInner, [SI+F7])
  $rc = $g.Invoke($args7[0], $args7[1], $args7[2], $args7[3], $args7[4], $args7[5], $args7[6])
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

Write-Output ("INNER" + [char]0x1f + "form=" + $Form + [char]0x1f + "rc=" + $rc)
$vals = @()
for ($i = 0; $i -lt 48; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($st, $i)) }
Write-Output ("  struct: " + ($vals -join ' '))

$rd::FreeHGlobal($st)
$rd::FreeHGlobal($dataBuf)
$rd::FreeHGlobal($pathPtr)