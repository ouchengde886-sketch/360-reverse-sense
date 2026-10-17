# 解引用 [15]/[17] 返回的指针 + 深入 [12]
#
# ============================================================================
# 上一轮结果：
#   [15] 0x56DCCA00 返回 141677576 (0x8721B08) —— 像指针
#   [17] 0x56DCE850 返回 136472992 (0x8226D20) —— 像指针
#   [12] 0x56DC3AD0 所有参数组合返回 0
#
# 本轮：
#   1. 解引用 [15]/[17] 的返回值，找威胁名
#   2. 对 [12] 试更多参数（含结构化结果缓冲）
#   3. 对比恶意文件与 clean 文件的返回值差异
#
# 用法: -Target <文件>
# ============================================================================

param([string]$Root, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class D15 {
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
  public delegate int T1(IntPtr self, IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int T2(IntPtr self, IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int T3(IntPtr self, IntPtr a, IntPtr b, IntPtr c);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][D15]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][D15]::LoadLibraryW($p) }
}
$h = [D15]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$base = $h.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]

$hEng0 = [D15]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [D15]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [D15+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}

$st = $rd::AllocHGlobal(0x204)
for ($i = 0; $i -lt 0x204; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, 0x204)
$pEng = [D15]::GetProcAddress($h, 'EngLib_Init')
try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [D15+F1]); [void]$ge.Invoke($st) } catch { }

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

$pWC = [D15]::GetProcAddress($h, 'ScanAveMemoryWithCode')
$g = $rd::GetDelegateForFunctionPointer($pWC, [D15+F6])
try { [void]$g.Invoke($dataBuf, [IntPtr]$size, $pathPtr, $resBuf, $magic, [IntPtr]32) } catch { }

$fac = $rd::ReadInt32([IntPtr]($base + 0x2A682C))
$gf = $rd::GetDelegateForFunctionPointer([IntPtr]$fac, [D15+P0])
$obj = $gf.Invoke()
$vtp = $rd::ReadInt32($obj)
Write-Output ("  文件: " + $Target + "  size=" + $size)
Write-Output ("  引擎对象=0x{0:X8} 虚表=0x{1:X8}" -f $obj.ToInt64(), $vtp)

# 先调 [9] 让引擎读文件（可能为后续方法准备状态）
$fn9 = $rd::ReadInt32([IntPtr]($vtp + 9*4))
for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
$d9 = $rd::GetDelegateForFunctionPointer([IntPtr]$fn9, [D15+T2])
try { [void]$d9.Invoke($obj, $pathPtr, $resBuf) } catch { }
Write-Output ("  [9] 已调用，out=0x{0:X8}" -f $rd::ReadInt32($resBuf, 0))

# 解引用 [15]/[17]
foreach ($idx in 15, 17) {
  $fn = $rd::ReadInt32([IntPtr]($vtp + $idx*4))
  Write-Output ("  --- [{0}] 0x{1:X8} ---" -f $idx, $fn)
  foreach ($nm in @('T1', 'T2', 'T3')) {
    $r = "EXC"
    try {
      if ($nm -eq 'T1') { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [D15+T1]); $r = $d.Invoke($obj, $pathPtr) }
      if ($nm -eq 'T2') { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [D15+T2]); $r = $d.Invoke($obj, $pathPtr, $resBuf) }
      if ($nm -eq 'T3') { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [D15+T3]); $r = $d.Invoke($obj, $pathPtr, [IntPtr]$size, $resBuf) }
    } catch { $r = "EXC" }
    Write-Output ("    {0}={1}" -f $nm, $r)
    $pv = [int]$r
    if ($pv -gt 0x10000 -and $pv -lt 0x7FFFFFFF) {
      # 解引用
      try {
        $vals = @()
        for ($k = 0; $k -lt 32; $k += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32([IntPtr]$pv, $k)) }
        Write-Output ("      deref: " + ($vals -join ' '))
      } catch { }
      for ($off = 0; $off -lt 96; $off += 4) {
        try {
          $s = $rd::PtrToStringAnsi([IntPtr]($pv + $off), 80)
          if ($s -and $s.Length -ge 3) {
            $ok=$true; foreach($c in $s.ToCharArray()){ if([int]$c -lt 32 -or [int]$c -gt 126){$ok=$false;break} }
            if ($ok) { Write-Output ("      A@+{0:X2}: {1}" -f $off, $s) }
          }
        } catch { }
      }
    }
  }
}

# 深入 [12]：试更多参数
$fn12 = $rd::ReadInt32([IntPtr]($vtp + 12*4))
Write-Output ("  --- [12] 0x{0:X8} 多参数 ---" -f $fn12)
$combos = @(
  @('T1(path)', 1),
  @('T1(resBuf)', 2),
  @('T2(resBuf,p6)', 3),
  @('T2(p6,resBuf)', 4),
  @('T3(path,resBuf,p6)', 5),
  @('T3(resBuf,p6,magic)', 6)
)
foreach ($c in $combos) {
  $nm = $c[0]; $k = $c[1]
  for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
  $r = "EXC"
  try {
    if ($k -eq 1) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn12, [D15+T1]); $r = $d.Invoke($obj, $pathPtr) }
    if ($k -eq 2) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn12, [D15+T1]); $r = $d.Invoke($obj, $resBuf) }
    if ($k -eq 3) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn12, [D15+T2]); $r = $d.Invoke($obj, $resBuf, $p6) }
    if ($k -eq 4) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn12, [D15+T2]); $r = $d.Invoke($obj, $p6, $resBuf) }
    if ($k -eq 5) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn12, [D15+T3]); $r = $d.Invoke($obj, $pathPtr, $resBuf, $p6) }
    if ($k -eq 6) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn12, [D15+T3]); $r = $d.Invoke($obj, $resBuf, $p6, $magic) }
  } catch { $r = "EXC" }
  $ch = 0
  for ($i = 0; $i -lt 512; $i++) { if ($rd::ReadByte($resBuf, $i) -ne 0xCC) { $ch++ } }
  Write-Output ("    {0} = {1}  changed={2}" -f $nm, $r, $ch)
  if ($ch -gt 0) {
    $rv = @()
    for ($i = 0; $i -lt 32; $i += 4) { $rv += ("{0:X8}" -f $rd::ReadInt32($resBuf, $i)) }
    Write-Output ("      res: " + ($rv -join ' '))
  }
}