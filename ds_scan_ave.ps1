# ScanAveMemory 真实调用 —— 7 参数扫描入口
#
# ============================================================================
# ScanAveMemory (RVA 0x3FEC8) 是 thunk：
#   +000: 55 8B EC        push ebp; mov ebp,esp
#   +003: 6A 00           push 0
#   +005: 6A 00           push 0
#   +007: FF 75 14        push [ebp+0x14]   param_6
#   +00A: FF 75 10        push [ebp+0x10]   param_5
#   +00D: FF 75 0C        push [ebp+0x0C]   param_4
#   +010: FF 75 08        push [ebp+0x08]   param_3
#   +013: E8 04 00 00 00  call 内部实现
#   +018: 5D              pop ebp
#   +019: C2 10 00        ret 0x10          <- 4 个栈参数
#
# 内部实现 (RVA 0x3FEE1) 读到 param_2/param_6/param_7，说明真实签名 ≥7 参数。
# 关键校验（+020）：
#   mov edi,[ebp+0x1C]   ; param_7
#   xor ebx,ebx
#   test edi,edi / jz 跳过
#   cmp [edi],ebx / jz 跳过
#   cmp [edi+4],ebx / jnz 跳过
#   push 0x99            ; 错误码
# => param_7 必须指向一个前两个 DWORD 都非零的结构。
#
# 本脚本按 7 参数调用，param_7 指向预置结构。
# 用法: -Form N
#   1: (0,0,0,0,0,0,struct)   7 参数
#   2: (buf,size,0,0,0,0,struct)  7 参数，前两个像 buffer/size
#   3: 只传 7 参数但 struct 全 0
# ============================================================================

param([string]$Root, [int]$Form, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Form) { $Form = 1 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class SA {
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
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][SA]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][SA]::LoadLibraryW($p) }
}
$h = [SA]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

# EngLib_Init(NULL)
$pEng = [SA]::GetProcAddress($h, 'EngLib_Init')
try {
  $ge = $rd::GetDelegateForFunctionPointer($pEng, [SA+F1])
  [void]$ge.Invoke([IntPtr]::Zero)
} catch { }

# param_7 结构：前两个 DWORD 非零
$st = $rd::AllocHGlobal(64)
for ($i = 0; $i -lt 64; $i++) { $rd::WriteByte($st, $i, 0) }
if ($Form -ne 3) {
  $rd::WriteInt32($st, 0, 1)
  $rd::WriteInt32($st, 4, 1)
}

# 数据缓冲
$dataBuf = $rd::AllocHGlobal(4096)
for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($dataBuf, $i, 0x90) }
$size = 0
if ($Target -and (Test-Path $Target)) {
  $bytes = [System.IO.File]::ReadAllBytes($Target)
  $size = $bytes.Length
  if ($size -gt 4096) { $size = 4096 }
  $rd::Copy($bytes, 0, $dataBuf, $size)
}
$pathPtr = $rd::StringToHGlobalUni($Target)

$pScan = [SA]::GetProcAddress($h, 'ScanAveMemory')
$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($pScan, [SA+F7])
  if ($Form -eq 2) {
    $rc = $g.Invoke($dataBuf, [IntPtr]$size, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, $pathPtr, $st)
  } else {
    $rc = $g.Invoke([IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, $pathPtr, $st)
  }
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

Write-Output ("SCAN" + [char]0x1f + "form=" + $Form + [char]0x1f + "rc=" + $rc)
# dump param_7 结构
$vals = @()
for ($i = 0; $i -lt 32; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($st, $i)) }
Write-Output ("  struct: " + ($vals -join ' '))

$rd::FreeHGlobal($st)
$rd::FreeHGlobal($dataBuf)
$rd::FreeHGlobal($pathPtr)