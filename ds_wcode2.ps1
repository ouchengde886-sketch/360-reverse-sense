# ScanAveMemoryWithCode 正确调用 —— 构造 param_6 结果结构
#
# ============================================================================
# 内部实现 0x3FEE4 关键校验（逐条机器码）：
#   +015: 6A 9A 58        push 0x9A; pop eax   -> -102  param_3 == 0
#   +02F: 6A 99 EB E4     push 0x99; jmp      -> -103  param_7 结构非法
#   +0D2: 83 3E 18        cmp dword[esi],0x18 ; esi = param_6
#   +0D6: 72 3B           jb  错误            -> param_6 首 DWORD 必须 >= 0x18
#   +0D8: 83 7E 08 00     cmp dword[esi+8],0
#   +0DC: 76 35           jbe 错误            -> param_6+8 必须非 0
#   +0DE: 8B 4E 0C        mov ecx,[esi+0x0C]
#   +0E1: 8B 45 DC        mov eax,[ebp-0x24]
#   +0E4: 89 01           mov [ecx],eax       ; 写结果到 [esi+0x0C] 指向的缓冲
#   +0F6: 6A 9B 5B        push 0x9B; pop ebx  -> -101
#
# 所以 param_6 是**结果输出结构**：
#   +0x00 DWORD  容量/版本，必须 >= 0x18
#   +0x08 DWORD  必须非 0
#   +0x0C PTR    结果写入地址
#
# 本脚本按此构造并调用，尝试拿到判定。
# 用法: -Target <文件> -Form N
# ============================================================================

param([string]$Root, [string]$Target, [int]$Form)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Form) { $Form = 1 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class WC2 {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int BapiFn(string root);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int DsInitFn(string dir);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F6(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][WC2]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][WC2]::LoadLibraryW($p) }
}
$rd = [System.Runtime.InteropServices.Marshal]

$hEng0 = [WC2]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [WC2]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [WC2+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}
$hDs = [WC2]::GetModuleHandleW('deepscan.dll')
if ($hDs -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$pEng = [WC2]::GetProcAddress($hDs, 'EngLib_Init')
if ($pEng -ne [IntPtr]::Zero) {
  try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [WC2+DsInitFn]); [void]$ge.Invoke((Join-Path $Root 'deepscan')) } catch { }
}

# 文件数据
$dataBuf = $rd::AllocHGlobal(1048576)
for ($i = 0; $i -lt 1048576; $i++) { $rd::WriteByte($dataBuf, $i, 0) }
$size = 0
if ($Target -and (Test-Path $Target)) {
  $bytes = [System.IO.File]::ReadAllBytes($Target)
  $size = [Math]::Min($bytes.Length, 1048576)
  $rd::Copy($bytes, 0, $dataBuf, $size)
}
$pathPtr = $rd::StringToHGlobalUni($Target)

# 结果写入缓冲
$resBuf = $rd::AllocHGlobal(1024)
for ($i = 0; $i -lt 1024; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }

# param_6 结果结构：+0=容量(>=0x18) +8=非0 +0xC=写入地址
$p6 = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($p6, $i, 0) }
$rd::WriteInt32($p6, 0, 0x18)
$rd::WriteInt32($p6, 4, 0)
$rd::WriteInt32($p6, 8, 1)
$rd::WriteIntPtr($p6, 0x0C, $resBuf)

# param_7 "lryy" 结构
$magic = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($magic, $i, 0) }
$rd::WriteInt32($magic, 0, 0x7979726C)
$rd::WriteInt32($magic, 4, $size)
$rd::WriteInt32($magic, 8, $size)

$pWC = [WC2]::GetProcAddress($hDs, 'ScanAveMemoryWithCode')

$a = switch ($Form) {
  1 { @($dataBuf, [IntPtr]$size, $pathPtr, $p6, $magic, [IntPtr]16) }
  2 { @($dataBuf, [IntPtr]$size, $pathPtr, $p6, $magic, [IntPtr]64) }
  3 { @($dataBuf, [IntPtr]$size, $pathPtr, $p6, [IntPtr]::Zero, [IntPtr]::Zero) }
  4 { @($dataBuf, [IntPtr]$size, $p6, $magic, [IntPtr]16, [IntPtr]::Zero) }
  5 { @($dataBuf, [IntPtr]$size, $pathPtr, $magic, $p6, [IntPtr]16) }
  6 { @($dataBuf, [IntPtr]$size, $pathPtr, [IntPtr]::Zero, $magic, [IntPtr]16) }
  default { @($dataBuf, [IntPtr]$size, $pathPtr, $p6, $magic, [IntPtr]16) }
}

$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($pWC, [WC2+F6])
  $rc = $g.Invoke($a[0], $a[1], $a[2], $a[3], $a[4], $a[5])
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

Write-Output ("WC2" + [char]0x1f + "form=" + $Form + [char]0x1f + "size=" + $size + [char]0x1f + "rc=" + $rc)
$ch = 0
for ($i = 0; $i -lt 256; $i++) { if ($rd::ReadByte($resBuf, $i) -ne 0xCC) { $ch++ } }
Write-Output ("  res_changed=" + $ch)
$rvals = @()
for ($i = 0; $i -lt 48; $i += 4) { $rvals += ("{0:X8}" -f $rd::ReadInt32($resBuf, $i)) }
Write-Output ("  res: " + ($rvals -join ' '))
$p6v = @()
for ($i = 0; $i -lt 32; $i += 4) { $p6v += ("{0:X8}" -f $rd::ReadInt32($p6, $i)) }
Write-Output ("  p6: " + ($p6v -join ' '))
# 尝试读字符串
for ($off = 0; $off -lt 64; $off += 4) {
  $pv = $rd::ReadIntPtr($resBuf, $off)
  if ($pv.ToInt64() -gt 0x10000 -and $pv.ToInt64() -lt 0x7FFFFFFF) {
    try {
      $s = $rd::PtrToStringAnsi($pv, 100)
      if ($s -and $s.Length -ge 2) {
        $ok=$true; foreach($c in $s.ToCharArray()){ if([int]$c -lt 32 -or [int]$c -gt 126){$ok=$false;break} }
        if ($ok) { Write-Output ("  A@+{0:X2}: {1}" -f $off, $s) }
      }
    } catch { }
  }
}