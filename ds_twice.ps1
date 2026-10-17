# 第二次调用 —— 引擎对象已缓存，可能跳过初始化直接扫描
#
# ============================================================================
# 上一轮发现：第一次调用 ScanAveMemoryWithCode 会**填充**引擎对象全局：
#   [pre]  0x2A682C=0x00000000  0x2A6830=0x00000000  0x2A68C0=0
#   [post] 0x2A682C=0x56D55C60  0x2A6830=0x56D55C40  0x2A68C0=1
#
# 0x40073 反汇编：
#   +044: 80 3D C0 68 2A 10 00  cmp byte[0x102A68C0],0
#   +04B: 0F 85 97 00 00 00     jnz +0xE8      ; 已初始化 -> 跳过
#   +051: push 0x208                            ; 未初始化 -> 走初始化
#
# 所以第二次调用会走 +0xE8 分支，跳过初始化，可能直接进入扫描。
#
# 本脚本在同一进程里**连续调用多次**，观察 rc 是否变化。
# 用法: -Target <文件> -Times N
# ============================================================================

param([string]$Root, [string]$Target, [int]$Times)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Times) { $Times = 3 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class T2 {
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
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][T2]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][T2]::LoadLibraryW($p) }
}
$h = [T2]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$base = $h.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]

$hEng0 = [T2]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [T2]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [T2+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}

$st = $rd::AllocHGlobal(0x204)
for ($i = 0; $i -lt 0x204; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, 0x204)
$pEng = [T2]::GetProcAddress($h, 'EngLib_Init')
try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [T2+F1]); [void]$ge.Invoke($st) } catch { }

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

$pWC = [T2]::GetProcAddress($h, 'ScanAveMemoryWithCode')
$g = $rd::GetDelegateForFunctionPointer($pWC, [T2+F6])

for ($t = 1; $t -le $Times; $t++) {
  # 每轮重置
  for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
  for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($p6, $i, 0) }
  $rd::WriteInt32($p6, 0, 0x18)
  $rd::WriteInt32($p6, 8, 1)
  $rd::WriteIntPtr($p6, 0x0C, $resBuf)
  for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($magic, $i, 0) }
  $rd::WriteInt32($magic, 0, 0x7979726C)
  $rd::WriteInt32($magic, 4, $size)
  $rd::WriteIntPtr($magic, 8, $pathPtr)
  $rd::WriteIntPtr($magic, 0x0C, $dataBuf)
  $rd::WriteInt32($magic, 0x10, $size)

  $rc = "EXC"
  try {
    $rc = $g.Invoke($dataBuf, [IntPtr]$size, $pathPtr, $resBuf, $magic, [IntPtr]32)
  } catch { $rc = "EXC:" + $_.Exception.GetType().Name }

  $gC = $rd::ReadByte([IntPtr]($base + 0x2A68C0))
  $ch = 0
  for ($i = 0; $i -lt 512; $i++) { if ($rd::ReadByte($resBuf, $i) -ne 0xCC) { $ch++ } }
  Write-Output ("T2" + [char]0x1f + "times=" + $t + [char]0x1f + "rc=" + $rc + [char]0x1f + "flag=" + $gC + [char]0x1f + "changed=" + $ch)
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
}