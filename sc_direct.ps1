# 直接调用 ScChecker.dll!SCC_Create —— 绕开 deepscan.dll
#
# ============================================================================
# SCC_Create (RVA 0x65C60) 反汇编确认：
#   +039: 6A 40             push 0x40           ; 分配 0x40 字节
#   +057: C7 03 24 B1 13 10  mov [ebx],0x1013B124  ; 虚表
# 虚表 0x1013B124 - 0x10100000 + 0x56CF0000 = 0x56E2B124（与运行时吻合）
#
# 本轮：直接 LoadLibrary ScChecker.dll + SCC_Create()，不依赖 deepscan.dll。
# 然后遍历虚表方法，重点试 [6]（键值对插入）和找扫描方法。
#
# 用法: -Target <文件> -Idx N
# ============================================================================

param([string]$Root, [string]$Target, [int]$Idx)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Idx) { $Idx = -1 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class SC {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi, EntryPoint="GetProcAddress")]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr PC0();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int PC1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int T0(IntPtr self);
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

[void][SC]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\ScChecker.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][SC]::LoadLibraryW($p) }
}
$hs = [SC]::GetModuleHandleW('ScChecker.dll')
if ($hs -eq [IntPtr]::Zero) { Write-Output "  no ScChecker.dll"; exit 0 }
$sbase = $hs.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]
Write-Output ("  ScChecker base = 0x{0:X8}" -f $sbase)

$pCreate = [SC]::GetProcAddress($hs, 'SCC_Create')
Write-Output ("  SCC_Create = 0x{0:X8} (RVA 0x{1:X})" -f $pCreate.ToInt64(), ($pCreate.ToInt64() - $sbase))
if ($pCreate -eq [IntPtr]::Zero) { exit 0 }

# ★ 直接创建引擎对象
$obj = [IntPtr]::Zero
try {
  $gc = $rd::GetDelegateForFunctionPointer($pCreate, [SC+PC0])
  $obj = $gc.Invoke()
} catch { Write-Output ("  SCC_Create 异常: " + $_.Exception.GetType().Name) }
Write-Output ("  引擎对象 = 0x{0:X8}" -f $obj.ToInt64())
if ($obj -eq [IntPtr]::Zero) { exit 0 }

$vtp = $rd::ReadInt32($obj)
Write-Output ("  虚表 = 0x{0:X8} (RVA 0x{1:X})" -f $vtp, ($vtp - $sbase))
$vals = @()
for ($i = 0; $i -lt 32; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($obj, $i)) }
Write-Output ("  对象前 32 字节: " + ($vals -join ' '))

# 准备文件
$dataBuf = $rd::AllocHGlobal(1048576)
for ($i = 0; $i -lt 1048576; $i++) { $rd::WriteByte($dataBuf, $i, 0) }
$size = 0
if ($Target -and (Test-Path $Target)) {
  $bytes = [System.IO.File]::ReadAllBytes($Target)
  $size = [Math]::Min($bytes.Length, 1048576)
  $rd::Copy($bytes, 0, $dataBuf, $size)
}
$pathPtr = $rd::StringToHGlobalUni($Target)
$resBuf = $rd::AllocHGlobal(8192)

if ($Idx -ge 0) {
  $fn = $rd::ReadInt32([IntPtr]($vtp + $Idx*4))
  Write-Output ("  [{0}] 方法 = 0x{1:X8} (RVA 0x{2:X})" -f $Idx, $fn, ($fn - $sbase))
  if ($fn -lt 0x10000) { exit 0 }
  $outs = @()
  foreach ($k in 0,1,2,3,4) {
    for ($i = 0; $i -lt 8192; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
    $r = "EXC"
    try {
      if ($k -eq 0) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [SC+T0]); $r = $d.Invoke($obj) }
      if ($k -eq 1) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [SC+T1]); $r = $d.Invoke($obj, $pathPtr) }
      if ($k -eq 2) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [SC+T2]); $r = $d.Invoke($obj, $pathPtr, $resBuf) }
      if ($k -eq 3) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [SC+T3]); $r = $d.Invoke($obj, $pathPtr, [IntPtr]$size, $resBuf) }
      if ($k -eq 4) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [SC+T4]); $r = $d.Invoke($obj, $pathPtr, [IntPtr]$size, $resBuf, $dataBuf) }
    } catch { $r = "EXC" }
    $ch = 0
    for ($i = 0; $i -lt 1024; $i++) { if ($rd::ReadByte($resBuf, $i) -ne 0xCC) { $ch++ } }
    $outs += ("k$k=$r/ch$ch")
    if ($ch -gt 0) {
      $rv = @()
      for ($i = 0; $i -lt 32; $i += 4) { $rv += ("{0:X8}" -f $rd::ReadInt32($resBuf, $i)) }
      Write-Output ("    k$k res: " + ($rv -join ' '))
      for ($off = 0; $off -lt 512; $off += 4) {
        try {
          $s = $rd::PtrToStringAnsi([IntPtr]($resBuf.ToInt64()+$off), 80)
          if ($s -and $s.Length -ge 3) {
            $ok=$true; foreach($c in $s.ToCharArray()){ if([int]$c -lt 32 -or [int]$c -gt 126){$ok=$false;break} }
            if ($ok) { Write-Output ("      S@+{0:X2}: {1}" -f $off, $s) }
          }
        } catch { }
      }
    }
  }
  Write-Output ("    " + ($outs -join '  '))
  exit 0
}

# 遍历全部方法
Write-Output "  --- 遍历虚表方法 ---"
for ($idx = 0; $idx -lt 20; $idx++) {
  $fn = $rd::ReadInt32([IntPtr]($vtp + $idx*4))
  if ($fn -lt 0x10000 -or $fn -gt 0x7FFFFFFF) {
    Write-Output ("    [{0,2}] 0x{1:X8} (非代码)" -f $idx, $fn)
    continue
  }
  $rva = $fn - $sbase
  $outs = @()
  foreach ($k in 0,1,2,3) {
    for ($i = 0; $i -lt 1024; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
    $r = "EXC"
    try {
      if ($k -eq 0) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [SC+T0]); $r = $d.Invoke($obj) }
      if ($k -eq 1) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [SC+T1]); $r = $d.Invoke($obj, $pathPtr) }
      if ($k -eq 2) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [SC+T2]); $r = $d.Invoke($obj, $pathPtr, $resBuf) }
      if ($k -eq 3) { $d = $rd::GetDelegateForFunctionPointer([IntPtr]$fn, [SC+T3]); $r = $d.Invoke($obj, $pathPtr, [IntPtr]$size, $resBuf) }
    } catch { $r = "EXC" }
    $ch = 0
    for ($i = 0; $i -lt 1024; $i++) { if ($rd::ReadByte($resBuf, $i) -ne 0xCC) { $ch++ } }
    $outs += ("k$k=$r" + $(if($ch -gt 0){"*"}else{""}))
  }
  Write-Output ("    [{0,2}] 0x{1:X8} RVA=0x{2,-7:X} {3}" -f $idx, $fn, $rva, ($outs -join ' '))
}