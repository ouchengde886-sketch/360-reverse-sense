# 方法 [9] 返回的是指针 —— 追踪它指向什么
#
# ============================================================================
# 方法 [9] 0x56DC4A50：
#   T2(path,resBuf) = 0 且 resBuf[0] = 0x0B142024（堆指针）
#   => 它是 getter，把某个对象的指针写到输出
#
# 本轮：解引用该指针，看它指向什么结构，能否找到威胁名。
# 并对比 clean 文件与恶意文件，看指针内容是否不同。
#
# 用法: -Target <文件>
# ============================================================================

param([string]$Root, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class D9 {
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
  public delegate int F6(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int BapiFn(string root);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr P0();
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int T2(IntPtr self, IntPtr a, IntPtr b);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][D9]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][D9]::LoadLibraryW($p) }
}
$h = [D9]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$base = $h.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]

$hEng0 = [D9]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [D9]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [D9+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}

$st = $rd::AllocHGlobal(0x204)
for ($i = 0; $i -lt 0x204; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, 0x204)
$pEng = [D9]::GetProcAddress($h, 'EngLib_Init')
try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [D9+F1]); [void]$ge.Invoke($st) } catch { }

$dataBuf = $rd::AllocHGlobal(1048576)
for ($i = 0; $i -lt 1048576; $i++) { $rd::WriteByte($dataBuf, $i, 0) }
$size = 0
if ($Target -and (Test-Path $Target)) {
  $bytes = [System.IO.File]::ReadAllBytes($Target)
  $size = [Math]::Min($bytes.Length, 1048576)
  $rd::Copy($bytes, 0, $dataBuf, $size)
}
$pathPtr = $rd::StringToHGlobalUni($Target)

$resBuf = $rd::AllocHGlobal(4096)
$p6 = $rd::AllocHGlobal(256)
$magic = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($p6, $i, 0) }
$rd::WriteInt32($p6, 0, 0x18)
$rd::WriteInt32($p6, 8, 1)
$rd::WriteIntPtr($p6, 0x0C, $resBuf)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($magic, $i, 0) }
$rd::WriteInt32($magic, 0, 0x7979726C)
$rd::WriteInt32($magic, 4, $size)

$pWC = [D9]::GetProcAddress($h, 'ScanAveMemoryWithCode')
$g = $rd::GetDelegateForFunctionPointer($pWC, [D9+F6])
try { [void]$g.Invoke($dataBuf, [IntPtr]$size, $pathPtr, $resBuf, $magic, [IntPtr]32) } catch { }

$fac = $rd::ReadInt32([IntPtr]($base + 0x2A682C))
$gf = $rd::GetDelegateForFunctionPointer([IntPtr]$fac, [D9+P0])
$obj = $gf.Invoke()
$vtp = $rd::ReadInt32($obj)
$fn = $rd::ReadInt32([IntPtr]($vtp + 9*4))

Write-Output ("  文件: " + $Target)
Write-Output ("  大小: " + $size)

# 调 [9] 拿指针
for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
$d9 = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [D9+T2])
$r = $d9.Invoke($obj, $pathPtr, $resBuf)
$ptr = $rd::ReadInt32($resBuf, 0)
Write-Output ("  [9] rc={0}  out=0x{1:X8}" -f $r, $ptr)

if ($ptr -gt 0x10000 -and $ptr -lt 0x7FFFFFFF) {
  Write-Output "  --- 解引用 0x$('{0:X8}' -f $ptr) 前 64 字节 ---"
  $vals = @()
  for ($i = 0; $i -lt 64; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32([IntPtr]$ptr, $i)) }
  Write-Output ("    " + ($vals -join ' '))
  # 尝试当字符串读
  for ($off = 0; $off -lt 128; $off += 4) {
    try {
      $s = $rd::PtrToStringAnsi([IntPtr]($ptr + $off), 100)
      if ($s -and $s.Length -ge 3) {
        $ok=$true; foreach($c in $s.ToCharArray()){ if([int]$c -lt 32 -or [int]$c -gt 126){$ok=$false;break} }
        if ($ok) { Write-Output ("    A@+{0:X2}: {1}" -f $off, $s) }
      }
    } catch { }
  }
  # 尝试当宽字符串读
  for ($off = 0; $off -lt 128; $off += 4) {
    try {
      $s = $rd::PtrToStringUni([IntPtr]($ptr + $off), 60)
      if ($s -and $s.Length -ge 3) {
        $ok=$true; foreach($c in $s.ToCharArray()){ if([int]$c -lt 32 -or [int]$c -gt 126){$ok=$false;break} }
        if ($ok) { Write-Output ("    W@+{0:X2}: {1}" -f $off, $s) }
      }
    } catch { }
  }
  # 指针里是否有指向别处的指针
  Write-Output "  --- 结构内的指针 ---"
  for ($off = 0; $off -lt 64; $off += 4) {
    $pv = $rd::ReadInt32([IntPtr]($ptr + $off))
    if ($pv -gt 0x10000 -and $pv -lt 0x7FFFFFFF) {
      $s1 = ""
      try {
        $t = $rd::PtrToStringAnsi([IntPtr]$pv, 60)
        if ($t -and $t.Length -ge 2) {
          $ok=$true; foreach($c in $t.ToCharArray()){ if([int]$c -lt 32 -or [int]$c -gt 126){$ok=$false;break} }
          if ($ok) { $s1 = " ANSI='" + $t + "'" }
        }
      } catch { }
      Write-Output ("    +{0:X2}: 0x{1:X8}{2}" -f $off, $pv, $s1)
    }
  }
}