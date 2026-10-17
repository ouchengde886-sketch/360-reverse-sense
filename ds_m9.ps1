# 深入方法 [9] —— 唯一返回 0 且写结果缓冲的方法
#
# ============================================================================
# 上一轮逐个试引擎对象 18 个方法，唯一有实质响应的：
#   [9] 0x56DC4A50
#     T1(0)=-2147024809 (0x80070057 E_INVALIDARG)
#     T1(path)=-2147418113 (0x8000FFFF E_UNEXPECTED)
#     T2(path,res)=0          ★ 成功！
#     res_changed=4           ★ 写了 4 字节
#
# 本轮：精确 dump 方法 [9] 写的内容，并试更多参数组合，
# 特别是把结果缓冲换成结构化缓冲，看能否拿到威胁名。
#
# 用法: -Target <文件>
# ============================================================================

param([string]$Root, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class M9 {
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
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int T4(IntPtr self, IntPtr a, IntPtr b, IntPtr c, IntPtr d);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int T5(IntPtr self, IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][M9]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][M9]::LoadLibraryW($p) }
}
$h = [M9]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$base = $h.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]

$hEng0 = [M9]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [M9]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [M9+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}

$st = $rd::AllocHGlobal(0x204)
for ($i = 0; $i -lt 0x204; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, 0x204)
$pEng = [M9]::GetProcAddress($h, 'EngLib_Init')
try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [M9+F1]); [void]$ge.Invoke($st) } catch { }

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

# 触发工厂
$pWC = [M9]::GetProcAddress($h, 'ScanAveMemoryWithCode')
$g = $rd::GetDelegateForFunctionPointer($pWC, [M9+F6])
for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($p6, $i, 0) }
$rd::WriteInt32($p6, 0, 0x18)
$rd::WriteInt32($p6, 8, 1)
$rd::WriteIntPtr($p6, 0x0C, $resBuf)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($magic, $i, 0) }
$rd::WriteInt32($magic, 0, 0x7979726C)
$rd::WriteInt32($magic, 4, $size)
try { [void]$g.Invoke($dataBuf, [IntPtr]$size, $pathPtr, $resBuf, $magic, [IntPtr]32) } catch { }

$fac = $rd::ReadInt32([IntPtr]($base + 0x2A682C))
$gf = $rd::GetDelegateForFunctionPointer([IntPtr]$fac, [M9+P0])
$obj = $gf.Invoke()
$vtp = $rd::ReadInt32($obj)
$fn = $rd::ReadInt32([IntPtr]($vtp + 9*4))
Write-Output ("  引擎对象=0x{0:X8} 虚表=0x{1:X8} [9]=0x{2:X8}" -f $obj.ToInt64(), $vtp, $fn)

# 对每个候选缓冲，单独试 T2(path, buf)
$cands = @(
  @('resBuf', $resBuf),
  @('p6', $p6),
  @('magic', $magic),
  @('dataBuf', $dataBuf)
)
foreach ($c in $cands) {
  $nm = $c[0]; $buf = [IntPtr]$c[1]
  # 重置
  for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
  $r = "EXC"
  try {
    $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [M9+T2])
    $r = $d.Invoke($obj, $pathPtr, $buf)
  } catch { $r = "EXC:" + $_.Exception.GetType().Name }
  Write-Output ("  T2(path,{0}) = {1}" -f $nm, $r)
  # dump resBuf 变化
  $ch = 0; $firstOff = -1
  for ($i = 0; $i -lt 512; $i++) {
    if ($rd::ReadByte($resBuf, $i) -ne 0xCC) { $ch++; if ($firstOff -lt 0) { $firstOff = $i } }
  }
  if ($ch -gt 0) {
    Write-Output ("    resBuf changed={0} firstOff=+0x{1:X}" -f $ch, $firstOff)
    $rv = @()
    for ($i = 0; $i -lt 64; $i += 4) { $rv += ("{0:X8}" -f $rd::ReadInt32($resBuf, $i)) }
    Write-Output ("    resBuf: " + ($rv -join ' '))
    for ($off = 0; $off -lt 512; $off += 4) {
      try {
        $s = $rd::PtrToStringAnsi([IntPtr]($resBuf.ToInt64()+$off), 80)
        if ($s -and $s.Length -ge 3) {
          $ok=$true; foreach($ch2 in $s.ToCharArray()){ if([int]$ch2 -lt 32 -or [int]$ch2 -gt 126){$ok=$false;break} }
          if ($ok) { Write-Output ("    S@+{0:X2}: {1}" -f $off, $s) }
        }
      } catch { }
    }
  }
}

# 也试 T3/T4/T5 传路径+大小
Write-Output "  --- 更多参数组合 ---"
for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
foreach ($t in @(
  @('T3(path,size,res)', 3),
  @('T4(path,size,res,p6)', 4),
  @('T5(path,size,res,p6,magic)', 5)
)) {
  $nm = $t[0]; $n = $t[1]
  $r = "EXC"
  try {
    if ($n -eq 3) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [M9+T3]); $r = $d.Invoke($obj, $pathPtr, [IntPtr]$size, $resBuf) }
    if ($n -eq 4) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [M9+T4]); $r = $d.Invoke($obj, $pathPtr, [IntPtr]$size, $resBuf, $p6) }
    if ($n -eq 5) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [M9+T5]); $r = $d.Invoke($obj, $pathPtr, [IntPtr]$size, $resBuf, $p6, $magic) }
  } catch { $r = "EXC" }
  $ch = 0
  for ($i = 0; $i -lt 512; $i++) { if ($rd::ReadByte($resBuf, $i) -ne 0xCC) { $ch++ } }
  Write-Output ("  {0} = {1}  changed={2}" -f $nm, $r, $ch)
}