# 枚举模块，定位引擎对象虚表属于哪个 DLL
#
# ============================================================================
# 引擎对象虚表 = 0x56E2B124，方法 [6] = 0x56DC4720。
# deepscan.dll base = 0x6C2A0000，所以这些地址不在 deepscan.dll 里。
# 需要确认它们属于哪个模块，才能反汇编方法 [6]。
#
# 用法: 无参数
# ============================================================================

$Root = 'C:\Program Files (x86)\360\360Safe'

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class MM {
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
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][MM]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][MM]::LoadLibraryW($p) }
}
$h = [MM]::GetModuleHandleW('deepscan.dll')
$base = $h.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]

$hEng0 = [MM]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [MM]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [MM+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}

$st = $rd::AllocHGlobal(0x204)
for ($i = 0; $i -lt 0x204; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, 0x204)
$pEng = [MM]::GetProcAddress($h, 'EngLib_Init')
try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [MM+F1]); [void]$ge.Invoke($st) } catch { }

# 触发工厂
$dataBuf = $rd::AllocHGlobal(1048576)
for ($i = 0; $i -lt 1048576; $i++) { $rd::WriteByte($dataBuf, $i, 0) }
$tgt = 'D:\troyr2\build\dist\t2-2610A\MicrosoftEdgeUpdate.ps1'
$size = 0
if (Test-Path $tgt) {
  $bytes = [System.IO.File]::ReadAllBytes($tgt)
  $size = [Math]::Min($bytes.Length, 1048576)
  $rd::Copy($bytes, 0, $dataBuf, $size)
}
$pathPtr = $rd::StringToHGlobalUni($tgt)
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

$pWC = [MM]::GetProcAddress($h, 'ScanAveMemoryWithCode')
$g = $rd::GetDelegateForFunctionPointer($pWC, [MM+F6])
try { [void]$g.Invoke($dataBuf, [IntPtr]$size, $pathPtr, $resBuf, $magic, [IntPtr]32) } catch { }

$fac = $rd::ReadInt32([IntPtr]($base + 0x2A682C))
$gf = $rd::GetDelegateForFunctionPointer([IntPtr]$fac, [MM+P0])
$obj = $gf.Invoke()
$vtp = $rd::ReadInt32($obj)
$fn6 = $rd::ReadInt32([IntPtr]($vtp + 6*4))

Write-Output ("  deepscan base = 0x{0:X8}" -f $base)
Write-Output ("  引擎对象 = 0x{0:X8}" -f $obj.ToInt64())
Write-Output ("  虚表 = 0x{0:X8}" -f $vtp)
Write-Output ("  方法[6] = 0x{0:X8}" -f $fn6)

Write-Output "  --- 进程内 0x56000000-0x58000000 的模块 ---"
$mods = (Get-Process -Id $PID).Modules
foreach ($m in $mods) {
  $ba = $m.BaseAddress.ToInt64()
  if ($ba -ge 0x56000000 -and $ba -le 0x58000000) {
    Write-Output ("    0x{0:X8}  {1}" -f $ba, $m.ModuleName)
  }
}

# 判断虚表和方法属于哪个模块
Write-Output "  --- 归属判定 ---"
foreach ($addr in @($vtp, $fn6)) {
  $found = $false
  foreach ($m in $mods) {
    $ba = $m.BaseAddress.ToInt64()
    $sz = $m.ModuleMemorySize
    if ($addr -ge $ba -and $addr -lt ($ba + $sz)) {
      Write-Output ("    0x{0:X8} 属于 {1} (base=0x{2:X8}, RVA=0x{3:X})" -f $addr, $m.ModuleName, $ba, ($addr - $ba))
      $found = $true
      break
    }
  }
  if (-not $found) { Write-Output ("    0x{0:X8} 未匹配任何模块" -f $addr) }
}

# dump 方法 [6] 前 160 字节
Write-Output "  --- 方法[6] 前 160 字节 ---"
for ($i = 0; $i -lt 160; $i += 16) {
  $bs = @()
  for ($j = 0; $j -lt 16; $j++) { $bs += ("{0:X2}" -f $rd::ReadByte([IntPtr]($fn6 + $i + $j))) }
  Write-Output ("    +{0:X3}: {1}" -f $i, ($bs -join ' '))
}