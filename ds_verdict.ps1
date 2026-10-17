# ScanAveMemory 判定提取 —— 关键验证
#
# ============================================================================
# 上一轮突破：EngLib_Init 必须传 deepscan 目录路径，之后
#   ScanAveMemory(buf, size, path, out) -> rc=0
#
# 本轮目标：确认输出结构是否被引擎写入，以及是否**有区分性**
#（已知报毒文件 vs 干净文件给出不同结果）。
#
# 方法：
#   1. 输出结构预填 0xCC，调用后看哪些字节被改写
#   2. 对已知报毒的 5 个文件 和 干净文件分别调用，比较结果
#   3. 如果结构里有指针，解引用读字符串（威胁名）
#
# 用法: -Target <文件> [-Size N]
# ============================================================================

param([string]$Root, [string]$Target, [int]$BufSize)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $BufSize) { $BufSize = 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class SV {
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

[void][SV]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][SV]::LoadLibraryW($p) }
}
$h = [SV]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]

# BAPIInitialize(产品根目录)
$hEng0 = [SV]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pBapi = [SV]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pBapi -ne [IntPtr]::Zero) {
    $rp = $rd::StringToHGlobalUni($Root)
    try { $gb = $rd::GetDelegateForFunctionPointer($pBapi, [SV+F1]); [void]$gb.Invoke($rp) } catch { }
    $rd::FreeHGlobal($rp)
  }
}
# EngLib_Init(deepscan 目录) —— 关键
$pEng = [SV]::GetProcAddress($h, 'EngLib_Init')
$dsDir = $rd::StringToHGlobalUni((Join-Path $Root 'deepscan'))
try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [SV+F1]); [void]$ge.Invoke($dsDir) } catch { }

# 读文件
$dataBuf = $rd::AllocHGlobal(1048576)
for ($i = 0; $i -lt 1048576; $i++) { $rd::WriteByte($dataBuf, $i, 0) }
$size = 0
if ($Target -and (Test-Path $Target)) {
  $bytes = [System.IO.File]::ReadAllBytes($Target)
  $size = [Math]::Min($bytes.Length, 1048576)
  $rd::Copy($bytes, 0, $dataBuf, $size)
}
if ($BufSize -gt 0) { $size = $BufSize }
$pathPtr = $rd::StringToHGlobalUni($Target)

# 输出结构：预填 0xCC 以便识别写入
$st = $rd::AllocHGlobal(512)
for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($st, $i, 0xCC) }

$pScan = [SV]::GetProcAddress($h, 'ScanAveMemory')
$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($pScan, [SV+F4])
  $rc = $g.Invoke($dataBuf, [IntPtr]$size, $pathPtr, $st)
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

Write-Output ("RES" + [char]0x1f + (Split-Path $Target -Leaf) + [char]0x1f + "size=" + $size + [char]0x1f + "rc=" + $rc)

# 哪些字节被改写（非 0xCC）
$changed = @()
for ($i = 0; $i -lt 256; $i++) {
  $b = $rd::ReadByte($st, $i)
  if ($b -ne 0xCC) { $changed += ("+{0:X2}={1:X2}" -f $i, $b) }
}
Write-Output ("  changed=" + $changed.Count)
if ($changed.Count -gt 0 -and $changed.Count -le 32) {
  Write-Output ("  " + ($changed -join ' '))
}

# dump 前 16 个 DWORD
$vals = @()
for ($i = 0; $i -lt 64; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($st, $i)) }
Write-Output ("  raw: " + ($vals -join ' '))

# 尝试解引用指针读字符串
for ($off = 0; $off -lt 64; $off += 4) {
  $pv = $rd::ReadIntPtr($st, $off)
  $pvi = $pv.ToInt64()
  if ($pvi -gt 0x10000 -and $pvi -lt 0x7FFFFFFF) {
    try {
      $s = $rd::PtrToStringUni($pv, 80)
      if ($s -and $s.Length -ge 2) {
        $ok = $true
        foreach ($ch in $s.ToCharArray()) { if ([int]$ch -lt 32 -or [int]$ch -gt 126) { $ok = $false; break } }
        if ($ok) { Write-Output ("  W@+{0:X2}: {1}" -f $off, $s) }
      }
    } catch { }
    try {
      $sa = $rd::PtrToStringAnsi($pv, 80)
      if ($sa -and $sa.Length -ge 2) {
        $ok = $true
        foreach ($ch in $sa.ToCharArray()) { if ([int]$ch -lt 32 -or [int]$ch -gt 126) { $ok = $false; break } }
        if ($ok) { Write-Output ("  A@+{0:X2}: {1}" -f $off, $sa) }
      }
    } catch { }
  }
}

$rd::FreeHGlobal($st)
$rd::FreeHGlobal($dataBuf)
$rd::FreeHGlobal($pathPtr)