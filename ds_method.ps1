# 直接调用引擎对象的方法 —— 逐个试虚表，找扫描方法
#
# ============================================================================
# 上一轮拿到真实引擎对象和完整虚表：
#   工厂 0x2A682C -> call -> 引擎对象 0x08707200
#   虚表 0x56E2B124，18 个有效方法
#
# 本轮：直接调用引擎对象的各方法，传文件路径，看哪个返回判定。
# 方法签名未知，用 __thiscall（ecx=this）试多种参数组合。
#
# 用法: -Target <文件> -Idx N
# ============================================================================

param([string]$Root, [string]$Target, [int]$Idx)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Idx) { $Idx = 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class MC {
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
  // thiscall 模拟：ecx 由 ThisCall 约定传
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int T1(IntPtr self, IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int T2(IntPtr self, IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int T3(IntPtr self, IntPtr a, IntPtr b, IntPtr c);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int T4(IntPtr self, IntPtr a, IntPtr b, IntPtr c, IntPtr d);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][MC]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][MC]::LoadLibraryW($p) }
}
$h = [MC]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$base = $h.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]

$hEng0 = [MC]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [MC]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [MC+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}

$st = $rd::AllocHGlobal(0x204)
for ($i = 0; $i -lt 0x204; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, 0x204)
$pEng = [MC]::GetProcAddress($h, 'EngLib_Init')
try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [MC+F1]); [void]$ge.Invoke($st) } catch { }

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
for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
$p6 = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($p6, $i, 0) }
$rd::WriteInt32($p6, 0, 0x18)
$rd::WriteInt32($p6, 8, 1)
$rd::WriteIntPtr($p6, 0x0C, $resBuf)
$magic = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($magic, $i, 0) }
$rd::WriteInt32($magic, 0, 0x7979726C)
$rd::WriteInt32($magic, 4, $size)

# 触发工厂填充
$pWC = [MC]::GetProcAddress($h, 'ScanAveMemoryWithCode')
$g = $rd::GetDelegateForFunctionPointer($pWC, [MC+F6])
try { [void]$g.Invoke($dataBuf, [IntPtr]$size, $pathPtr, $resBuf, $magic, [IntPtr]32) } catch { }

# 调工厂拿对象
$fac = $rd::ReadInt32([IntPtr]($base + 0x2A682C))
if ($fac -eq 0) { Write-Output "  工厂未填充"; exit 0 }
$gf = $rd::GetDelegateForFunctionPointer([IntPtr]$fac, [MC+P0])
$obj = $gf.Invoke()
Write-Output ("  引擎对象 = 0x{0:X8}" -f $obj.ToInt64())
if ($obj -eq [IntPtr]::Zero) { exit 0 }
$vtp = $rd::ReadInt32($obj)
Write-Output ("  虚表 = 0x{0:X8}" -f $vtp)

# 调用指定索引的方法，试多种参数
$fn = $rd::ReadInt32([IntPtr]($vtp + $Idx*4))
Write-Output ("  [{0}] 方法 = 0x{1:X8}" -f $Idx, $fn)
if ($fn -lt 0x10000) { exit 0 }

$results = @()
# 试 0 参数
try {
  $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [MC+T1])
  $r = $d.Invoke($obj, [IntPtr]::Zero)
  $results += ("T1(0)=$r")
} catch { $results += "T1(0)=EXC" }
# 试 1 参数路径
try {
  $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [MC+T1])
  $r = $d.Invoke($obj, $pathPtr)
  $results += ("T1(path)=$r")
} catch { $results += "T1(path)=EXC" }
# 试 2 参数
try {
  $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [MC+T2])
  $r = $d.Invoke($obj, $pathPtr, $resBuf)
  $results += ("T2(path,res)=$r")
} catch { $results += "T2(path,res)=EXC" }
# 试 3 参数
try {
  $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [MC+T3])
  $r = $d.Invoke($obj, $pathPtr, [IntPtr]$size, $resBuf)
  $results += ("T3(path,size,res)=$r")
} catch { $results += "T3(path,size,res)=EXC" }
# 试 4 参数
try {
  $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [MC+T4])
  $r = $d.Invoke($obj, $pathPtr, [IntPtr]$size, $resBuf, $p6)
  $results += ("T4(path,size,res,p6)=$r")
} catch { $results += "T4(...)=EXC" }

Write-Output ("  " + ($results -join '  '))
$ch = 0
for ($i = 0; $i -lt 512; $i++) { if ($rd::ReadByte($resBuf, $i) -ne 0xCC) { $ch++ } }
Write-Output ("  res_changed=" + $ch)
if ($ch -gt 0) {
  $rv = @()
  for ($i = 0; $i -lt 64; $i += 4) { $rv += ("{0:X8}" -f $rd::ReadInt32($resBuf, $i)) }
  Write-Output ("  res: " + ($rv -join ' '))
  for ($off = 0; $off -lt 512; $off += 4) {
    try {
      $s = $rd::PtrToStringAnsi([IntPtr]($resBuf.ToInt64()+$off), 80)
      if ($s -and $s.Length -ge 3) {
        $ok=$true; foreach($c in $s.ToCharArray()){ if([int]$c -lt 32 -or [int]$c -gt 126){$ok=$false;break} }
        if ($ok) { Write-Output ("  S@+{0:X2}: {1}" -f $off, $s) }
      }
    } catch { }
  }
}