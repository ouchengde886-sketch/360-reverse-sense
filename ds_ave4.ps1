# ScanAveMemory 4 参数正确调用尝试
#
# ============================================================================
# 导出 thunk (RVA 0x3FEC8) 只有 4 个栈参数，映射到内部：
#   thunk p3 -> 内部 param_2
#   thunk p4 -> 内部 param_3   **必须非 0**（否则返回 0x9A = -102）
#   thunk p5 -> 内部 param_4
#   thunk p6 -> 内部 param_5
#   内部 param_6 = 0（thunk 硬编码）
#   内部 param_7 = 0（thunk 硬编码）
#
# 之前 rc=-102 证明**调用成功**，只是第 2 个参数为 0。
# 本次扫描参数组合，找返回 0（成功）的那个。
#
# 用法: -Form N
#   1: (buf, size, 0, 0)
#   2: (buf, size, path, 0)
#   3: (buf, size, 0, out)
#   4: (buf, size, path, out)
#   5: (path, size, 0, 0)
#   6: (buf, size, path, out) 但 out 预置
# ============================================================================

param([string]$Root, [int]$Form, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Form) { $Form = 1 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class SM {
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
  public delegate int F4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][SM]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][SM]::LoadLibraryW($p) }
}
$h = [SM]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

$pEng = [SM]::GetProcAddress($h, 'EngLib_Init')
try {
  $ge = $rd::GetDelegateForFunctionPointer($pEng, [SM+F1])
  [void]$ge.Invoke([IntPtr]::Zero)
} catch { }

# 文件数据
$dataBuf = $rd::AllocHGlobal(131072)
for ($i = 0; $i -lt 131072; $i++) { $rd::WriteByte($dataBuf, $i, 0) }
$size = 0
if ($Target -and (Test-Path $Target)) {
  $bytes = [System.IO.File]::ReadAllBytes($Target)
  $size = [Math]::Min($bytes.Length, 131072)
  $rd::Copy($bytes, 0, $dataBuf, $size)
}
$pathPtr = $rd::StringToHGlobalUni($Target)

# 输出结构（预填非零，满足 param_7 校验）
$st = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, 1)
$rd::WriteInt32($st, 4, 1)

$pScan = [SM]::GetProcAddress($h, 'ScanAveMemory')

$a = switch ($Form) {
  1 { @($dataBuf, [IntPtr]$size, [IntPtr]::Zero, [IntPtr]::Zero) }
  2 { @($dataBuf, [IntPtr]$size, $pathPtr, [IntPtr]::Zero) }
  3 { @($dataBuf, [IntPtr]$size, [IntPtr]::Zero, $st) }
  4 { @($dataBuf, [IntPtr]$size, $pathPtr, $st) }
  5 { @($pathPtr, [IntPtr]$size, [IntPtr]::Zero, [IntPtr]::Zero) }
  6 { @($dataBuf, [IntPtr]$size, $st, $pathPtr) }
  default { @($dataBuf, [IntPtr]$size, [IntPtr]::Zero, [IntPtr]::Zero) }
}

$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($pScan, [SM+F4])
  $rc = $g.Invoke($a[0], $a[1], $a[2], $a[3])
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

Write-Output ("AVE" + [char]0x1f + "form=" + $Form + [char]0x1f + "size=" + $size + [char]0x1f + "rc=" + $rc)
# dump 输出结构
$vals = @()
for ($i = 0; $i -lt 64; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($st, $i)) }
Write-Output ("  out: " + ($vals -join ' '))
# 尝试读结构里的字符串
for ($off = 0; $off -lt 64; $off += 4) {
  $pv = $rd::ReadIntPtr($st, $off)
  if ($pv -ne [IntPtr]::Zero -and $pv.ToInt64() -gt 0x10000) {
    try {
      $s = $rd::PtrToStringUni($pv, 64)
      if ($s -and $s.Length -ge 2 -and $s[0] -ge ' ') {
        Write-Output ("  str@+0x{0:X2}: {1}" -f $off, $s)
      }
    } catch { }
  }
}

$rd::FreeHGlobal($st)
$rd::FreeHGlobal($dataBuf)
$rd::FreeHGlobal($pathPtr)