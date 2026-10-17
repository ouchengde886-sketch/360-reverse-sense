# 初始化成功后重调扫描函数 —— 关键验证
#
# ============================================================================
# 上一轮突破：EngLib_Init 需要首 DWORD = 0x204 的输出结构，
# 传对之后 rc=1，全局 0x2A67AC 被置 1，15 个函数指针被填入。
#
# 本轮：在**正确初始化**的前提下重调
#   ScanAveMemoryWithCode (RVA 0x4001E)
#   ScanAveMemory         (RVA 0x3FEC8)
# 并检查：
#   1. 全局 0x2A682C / 0x2A6830 是否被自动填充
#   2. 是否拿到真实判定（威胁名 / clean）
#
# 用法: -Target <文件> -Fn <wc|ave> -Form N
# ============================================================================

param([string]$Root, [string]$Target, [string]$Fn, [int]$Form)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Fn) { $Fn = 'wc' }
if (-not $Form) { $Form = 1 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class IV {
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
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F6(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int BapiFn(string root);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][IV]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][IV]::LoadLibraryW($p) }
}
$h = [IV]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$base = $h.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]

# BAPIInitialize
$hEng0 = [IV]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [IV]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [IV+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}

# ★ 正确初始化 EngLib_Init：首 DWORD = 0x204
$st = $rd::AllocHGlobal(0x204)
for ($i = 0; $i -lt 0x204; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, 0x204)
$pEng = [IV]::GetProcAddress($h, 'EngLib_Init')
$rcE = "EXC"
try {
  $ge = $rd::GetDelegateForFunctionPointer($pEng, [IV+F1])
  $rcE = $ge.Invoke($st)
} catch { $rcE = "EXC" }
Write-Output ("  EngLib_Init rc=" + $rcE)
$g67ac = $rd::ReadInt32([IntPtr]($base + 0x2A67AC))
Write-Output ("  0x2A67AC = " + $g67ac)

if ($g67ac -ne 1) { Write-Output "  初始化未成功，退出"; exit 0 }

# 读文件
$dataBuf = $rd::AllocHGlobal(1048576)
for ($i = 0; $i -lt 1048576; $i++) { $rd::WriteByte($dataBuf, $i, 0) }
$size = 0
if ($Target -and (Test-Path $Target)) {
  $bytes = [System.IO.File]::ReadAllBytes($Target)
  $size = [Math]::Min($bytes.Length, 1048576)
  $rd::Copy($bytes, 0, $dataBuf, $size)
}
$pathPtr = $rd::StringToHGlobalUni($Target)

# 结果缓冲
$resBuf = $rd::AllocHGlobal(1024)
for ($i = 0; $i -lt 1024; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }

# param_6 结构
$p6 = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($p6, $i, 0) }
$rd::WriteInt32($p6, 0, 0x18)
$rd::WriteInt32($p6, 8, 1)
$rd::WriteIntPtr($p6, 0x0C, $resBuf)

# "lryy" 魔数
$magic = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($magic, $i, 0) }
$rd::WriteInt32($magic, 0, 0x7979726C)
$rd::WriteInt32($magic, 4, $size)

$rc = "EXC"
if ($Fn -eq 'wc') {
  $pF = [IV]::GetProcAddress($h, 'ScanAveMemoryWithCode')
  # ★ 修正：param_6 是 "lryy" 魔数指针，param_7 是长度（必须 > 4）。
  #   之前把两者搞反，导致 cmp [eax],'lryy' 永远失败，走降级路径。
  $a = switch ($Form) {
    1 { @($dataBuf, [IntPtr]$size, $pathPtr, $magic, [IntPtr]16, $p6) }
    2 { @($dataBuf, [IntPtr]$size, $pathPtr, $magic, [IntPtr]64, $p6) }
    3 { @($dataBuf, [IntPtr]$size, $pathPtr, $magic, [IntPtr]128, $p6) }
    4 { @($dataBuf, [IntPtr]$size, $magic, [IntPtr]16, $p6, $pathPtr) }
    5 { @($dataBuf, [IntPtr]$size, $pathPtr, $magic, [IntPtr]16, [IntPtr]::Zero) }
    default { @($dataBuf, [IntPtr]$size, $pathPtr, $magic, [IntPtr]16, $p6) }
  }
  try {
    $g = $rd::GetDelegateForFunctionPointer($pF, [IV+F6])
    $rc = $g.Invoke($a[0], $a[1], $a[2], $a[3], $a[4], $a[5])
  } catch { $rc = "EXC:" + $_.Exception.GetType().Name }
} else {
  $pF = [IV]::GetProcAddress($h, 'ScanAveMemory')
  $a = switch ($Form) {
    1 { @($dataBuf, [IntPtr]$size, $pathPtr, $resBuf) }
    2 { @($dataBuf, [IntPtr]$size, $p6, $magic) }
    3 { @($p6, [IntPtr]$size, $pathPtr, $resBuf) }
    default { @($dataBuf, [IntPtr]$size, $pathPtr, $resBuf) }
  }
  try {
    $g = $rd::GetDelegateForFunctionPointer($pF, [IV+F4])
    $rc = $g.Invoke($a[0], $a[1], $a[2], $a[3])
  } catch { $rc = "EXC:" + $_.Exception.GetType().Name }
}

Write-Output ("RUN" + [char]0x1f + $Fn + [char]0x1f + "form=" + $Form + [char]0x1f + "size=" + $size + [char]0x1f + "rc=" + $rc)
Write-Output ("  0x2A682C = 0x{0:X8}   0x2A6830 = 0x{1:X8}" -f `
  $rd::ReadInt32([IntPtr]($base + 0x2A682C)), $rd::ReadInt32([IntPtr]($base + 0x2A6830)))
$ch = 0
for ($i = 0; $i -lt 256; $i++) { if ($rd::ReadByte($resBuf, $i) -ne 0xCC) { $ch++ } }
Write-Output ("  res_changed=" + $ch)
$rv = @()
for ($i = 0; $i -lt 48; $i += 4) { $rv += ("{0:X8}" -f $rd::ReadInt32($resBuf, $i)) }
Write-Output ("  res: " + ($rv -join ' '))
$p6v = @()
for ($i = 0; $i -lt 32; $i += 4) { $p6v += ("{0:X8}" -f $rd::ReadInt32($p6, $i)) }
Write-Output ("  p6: " + ($p6v -join ' '))
# 读字符串
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
# 结果缓冲里的可打印字符串
for ($off = 0; $off -lt 256; $off += 4) {
  try {
    $s = $rd::PtrToStringAnsi([IntPtr]($resBuf.ToInt64()+$off), 60)
    if ($s -and $s.Length -ge 3) {
      $ok=$true; foreach($c in $s.ToCharArray()){ if([int]$c -lt 32 -or [int]$c -gt 126){$ok=$false;break} }
      if ($ok) { Write-Output ("  S@+{0:X2}: {1}" -f $off, $s) }
    }
  } catch { }
}