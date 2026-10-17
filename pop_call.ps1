# PopSoftEng.dll!Create360Object —— 官方导出，加载 sc.con 的脚本引擎
#
# ============================================================================
# PopSoftEng.dll:
#   ImageBase=0x10000000, PE32, 662920 字节
#   导出: Create360Object RVA=0xDFF0   ★ 唯一的导出
#   引用 "..\sc.con"（宽字符）
#
# 这是**脚本查杀引擎**（Pop = PowerShell/脚本，Soft = 软件/脚本，Eng = 引擎）。
# 与 deepscan.dll 的 Create360Object 同名但不同实现。
#
# 本轮：直接调 PopSoftEng!Create360Object，遍历返回对象的虚表。
#
# 用法: -Target <文件> -Idx N
# ============================================================================

param([string]$Root, [string]$Target, [int]$Idx)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Idx) { $Idx = -1 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class PE {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi, EntryPoint="GetProcAddress")]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern int GetLastError();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr P0();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int P1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int P2(IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int P3(IntPtr a, IntPtr b, IntPtr c);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int P4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int T0(IntPtr self);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int T1(IntPtr self, IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int T2(IntPtr self, IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int T3(IntPtr self, IntPtr a, IntPtr b, IntPtr c);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][PE]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\ScChecker.dll', 'deepscan\PopSoftEng.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][PE]::LoadLibraryW($p) }
}
$hp = [PE]::GetModuleHandleW('PopSoftEng.dll')
if ($hp -eq [IntPtr]::Zero) { Write-Output "  no PopSoftEng.dll"; exit 0 }
$pbase = $hp.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]
Write-Output ("  PopSoftEng base = 0x{0:X8}" -f $pbase)

$pC = [PE]::GetProcAddress($hp, 'Create360Object')
Write-Output ("  Create360Object = 0x{0:X8} (RVA 0x{1:X})" -f $pC.ToInt64(), ($pC.ToInt64() - $pbase))
if ($pC -eq [IntPtr]::Zero) { exit 0 }

# 试多种参数组合调 Create360Object
$objs = @()
foreach ($n in 0,1,2,3,4) {
  $obj = [IntPtr]::Zero
  $err = ""
  try {
    if ($n -eq 0) { $g = $rd::GetDelegateForFunctionPointer($pC, [PE+P0]); $obj = $g.Invoke() }
    if ($n -eq 1) { $g = $rd::GetDelegateForFunctionPointer($pC, [PE+P1]); $obj = [IntPtr]$g.Invoke([IntPtr]::Zero) }
    if ($n -eq 2) { $g = $rd::GetDelegateForFunctionPointer($pC, [PE+P2]); $obj = [IntPtr]$g.Invoke([IntPtr]::Zero, [IntPtr]::Zero) }
    if ($n -eq 3) { $g = $rd::GetDelegateForFunctionPointer($pC, [PE+P3]); $obj = [IntPtr]$g.Invoke([IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero) }
    if ($n -eq 4) { $g = $rd::GetDelegateForFunctionPointer($pC, [PE+P4]); $obj = [IntPtr]$g.Invoke([IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero) }
  } catch { $err = $_.Exception.GetType().Name }
  $ev = $obj.ToInt64()
  Write-Output ("    argc=$n -> 0x{0:X8} {1}" -f $ev, $err)
  if ($ev -gt 0x10000 -and $ev -lt 0x7FFFFFFF) { $objs += $ev }
}

foreach ($ov in ($objs | Select-Object -Unique)) {
  Write-Output ("  --- 对象 0x{0:X8} ---" -f $ov)
  try {
    $vtp = $rd::ReadInt32([IntPtr]$ov)
    Write-Output ("    虚表 = 0x{0:X8} (RVA 0x{1:X})" -f $vtp, ($vtp - $pbase))
    $vals = @()
    for ($i = 0; $i -lt 24; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32([IntPtr]$ov, $i)) }
    Write-Output ("    对象前 24 字节: " + ($vals -join ' '))
    if ($vtp -gt 0x10000 -and $vtp -lt 0x7FFFFFFF) {
      for ($i = 0; $i -lt 16; $i++) {
        $fn = $rd::ReadInt32([IntPtr]($vtp + $i*4))
        $rva = $fn - $pbase
        $tag = ""
        if ($rva -gt 0 -and $rva -lt 0x81388) { $tag = " .text" }
        Write-Output ("      [{0,2}] 0x{1:X8} RVA=0x{2:X}{3}" -f $i, $fn, $rva, $tag)
      }
    }
  } catch { Write-Output ("    读取异常: " + $_.Exception.GetType().Name) }
}