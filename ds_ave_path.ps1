# 初始化后走 ScanAveMemory 降级路径 + 引擎对象虚表探测
#
# ============================================================================
# 上一轮突破：EngLib_Init 传首 DWORD=0x204 的结构后 rc=1，
# 引擎对象全局 0x2A682C / 0x2A6830 被填充。
#
# 本轮两条路：
#   A. 走 ScanAveMemory 降级路径（引擎已初始化，可能直接出结果）
#   B. dump 引擎对象虚表，反汇编 vtable+0x18，看它要什么参数
#
# 用法: -Target <文件> -Mode <ave|vt>
# ============================================================================

param([string]$Root, [string]$Target, [string]$Mode, [int]$Form)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Mode) { $Mode = 'ave' }
if (-not $Form) { $Form = 1 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class FA {
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
  public delegate int F2(IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F3(IntPtr a, IntPtr b, IntPtr c);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F5(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F6(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int BapiFn(string root);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][FA]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][FA]::LoadLibraryW($p) }
}
$h = [FA]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$base = $h.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]

$hEng0 = [FA]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [FA]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [FA+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}

# ★ 正确初始化
$st = $rd::AllocHGlobal(0x204)
for ($i = 0; $i -lt 0x204; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, 0x204)
$pEng = [FA]::GetProcAddress($h, 'EngLib_Init')
$rcE = "EXC"
try {
  $ge = $rd::GetDelegateForFunctionPointer($pEng, [FA+F1])
  $rcE = $ge.Invoke($st)
} catch { $rcE = "EXC" }
Write-Output ("  EngLib_Init rc=" + $rcE)
if ($rd::ReadInt32([IntPtr]($base + 0x2A67AC)) -ne 1) { Write-Output "  初始化失败"; exit 0 }

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

if ($Mode -eq 'vt') {
  # 探测引擎对象虚表
  $obj = $rd::ReadInt32([IntPtr]($base + 0x2A6830))
  Write-Output ("  引擎对象 0x2A6830 = 0x{0:X8}" -f $obj)
  if ($obj -ne 0) {
    $vt = $rd::ReadInt32([IntPtr]$obj)
    Write-Output ("  虚表 = 0x{0:X8}" -f $vt)
    if ($vt -gt 0x10000 -and $vt -lt 0x7FFFFFFF) {
      Write-Output "  虚表前 24 个方法:"
      for ($i = 0; $i -lt 24; $i++) {
        $fn = $rd::ReadInt32([IntPtr]($vt + $i*4))
        $rva = $fn - $base
        $mark = ""
        if ($rva -gt 0 -and $rva -lt 0x2D0000) { $mark = " (deepscan+0x{0:X})" -f $rva }
        Write-Output ("    [{0,2}] 0x{1:X8}{2}" -f $i, $fn, $mark)
      }
    }
  }
  $obj2 = $rd::ReadInt32([IntPtr]($base + 0x2A682C))
  Write-Output ("  工厂 0x2A682C = 0x{0:X8}" -f $obj2)
  exit 0
}

# 结果缓冲
$resBuf = $rd::AllocHGlobal(1024)
for ($i = 0; $i -lt 1024; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
$p6 = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($p6, $i, 0) }
$rd::WriteInt32($p6, 0, 0x18)
$rd::WriteInt32($p6, 8, 1)
$rd::WriteIntPtr($p6, 0x0C, $resBuf)
$magic = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($magic, $i, 0) }
$rd::WriteInt32($magic, 0, 0x7979726C)
$rd::WriteInt32($magic, 4, $size)

# 走 ScanAveMemoryWithCode 降级路径：param_6=0（不匹配魔数）
$pWC = [FA]::GetProcAddress($h, 'ScanAveMemoryWithCode')
$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($pWC, [FA+F6])
  $a = switch ($Form) {
    1 { @($dataBuf, [IntPtr]$size, $pathPtr, $p6, [IntPtr]::Zero, [IntPtr]::Zero) }
    2 { @($dataBuf, [IntPtr]$size, $pathPtr, $resBuf, [IntPtr]::Zero, [IntPtr]::Zero) }
    3 { @($dataBuf, [IntPtr]$size, $pathPtr, $p6, $magic, [IntPtr]4) }
    4 { @($dataBuf, [IntPtr]$size, $pathPtr, $p6, $magic, [IntPtr]8) }
    default { @($dataBuf, [IntPtr]$size, $pathPtr, $p6, [IntPtr]::Zero, [IntPtr]::Zero) }
  }
  $rc = $g.Invoke($a[0], $a[1], $a[2], $a[3], $a[4], $a[5])
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

Write-Output ("AVE" + [char]0x1f + "form=" + $Form + [char]0x1f + "size=" + $size + [char]0x1f + "rc=" + $rc)
$ch = 0
for ($i = 0; $i -lt 256; $i++) { if ($rd::ReadByte($resBuf, $i) -ne 0xCC) { $ch++ } }
Write-Output ("  res_changed=" + $ch)
$rv = @()
for ($i = 0; $i -lt 48; $i += 4) { $rv += ("{0:X8}" -f $rd::ReadInt32($resBuf, $i)) }
Write-Output ("  res: " + ($rv -join ' '))
for ($off = 0; $off -lt 256; $off += 4) {
  try {
    $s = $rd::PtrToStringAnsi([IntPtr]($resBuf.ToInt64()+$off), 60)
    if ($s -and $s.Length -ge 3) {
      $ok=$true; foreach($c in $s.ToCharArray()){ if([int]$c -lt 32 -or [int]$c -gt 126){$ok=$false;break} }
      if ($ok) { Write-Output ("  S@+{0:X2}: {1}" -f $off, $s) }
    }
  } catch { }
}