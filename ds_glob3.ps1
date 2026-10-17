# 验证 0x2A682C / 0x2A6830 / 0x2A68C0 是否在调用中被填充
#
# ============================================================================
# 0x40073 反汇编（+0xE0 区域）：
#   +0E0: 85 C0                 test eax,eax
#   +0E2: 74 0D                 jz +0xF1
#   +0E4: 89 3D 2C 68 2A 10    mov [0x102A682C],edi   ★ 填充
#   +0EA: A3 30 68 2A 10       mov [0x102A6830],eax   ★ 填充
#   +0EF: EB 06                 jmp +0xF7
#   +0F1: 8B 3D 2C 68 2A 10    mov edi,[0x102A682C]
#   +0F7: 88 1D C0 68 2A 10    mov byte[0x102A68C0],bl ★ 置标志
#
# 本脚本在调用前后分别读这三个全局，确认是否被填充。
# 用法: -Target <文件> -Form N
# ============================================================================

param([string]$Root, [string]$Target, [int]$Form)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Form) { $Form = 1 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class GL {
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

[void][GL]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][GL]::LoadLibraryW($p) }
}
$h = [GL]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$base = $h.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]

$hEng0 = [GL]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [GL]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [GL+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}

$st = $rd::AllocHGlobal(0x204)
for ($i = 0; $i -lt 0x204; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, 0x204)
$pEng = [GL]::GetProcAddress($h, 'EngLib_Init')
try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [GL+F1]); [void]$ge.Invoke($st) } catch { }

function DumpG([string]$tag) {
  $a = $rd::ReadInt32([IntPtr]($base + 0x2A682C))
  $b = $rd::ReadInt32([IntPtr]($base + 0x2A6830))
  $c = $rd::ReadByte([IntPtr]($base + 0x2A68C0))
  Write-Output ("  [{0}] 0x2A682C=0x{1:X8} 0x2A6830=0x{2:X8} 0x2A68C0={3}" -f $tag,$a,$b,$c)
}

Write-Output "--- 调用前 ---"
DumpG "pre"

$dataBuf = $rd::AllocHGlobal(1048576)
for ($i = 0; $i -lt 1048576; $i++) { $rd::WriteByte($dataBuf, $i, 0) }
$size = 0
if ($Target -and (Test-Path $Target)) {
  $bytes = [System.IO.File]::ReadAllBytes($Target)
  $size = [Math]::Min($bytes.Length, 1048576)
  $rd::Copy($bytes, 0, $dataBuf, $size)
}
$pathPtr = $rd::StringToHGlobalUni($Target)

$resBuf = $rd::AllocHGlobal(2048)
for ($i = 0; $i -lt 2048; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
$p6 = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($p6, $i, 0) }
$rd::WriteInt32($p6, 0, 0x18)
$rd::WriteInt32($p6, 8, 1)
$rd::WriteIntPtr($p6, 0x0C, $resBuf)

$magic = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($magic, $i, 0) }
$rd::WriteInt32($magic, 0, 0x7979726C)
$rd::WriteInt32($magic, 4, $size)
$rd::WriteIntPtr($magic, 8, $pathPtr)
$rd::WriteIntPtr($magic, 0x0C, $dataBuf)
$rd::WriteInt32($magic, 0x10, $size)

$pWC = [GL]::GetProcAddress($h, 'ScanAveMemoryWithCode')
$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($pWC, [GL+F6])
  # param_5 非 0（resBuf），param_6 = magic，param_7 = 32
  $rc = $g.Invoke($dataBuf, [IntPtr]$size, $pathPtr, $resBuf, $magic, [IntPtr]32)
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

Write-Output ("  rc=" + $rc)
Write-Output "--- 调用后 ---"
DumpG "post"

$ch = 0
for ($i = 0; $i -lt 512; $i++) { if ($rd::ReadByte($resBuf, $i) -ne 0xCC) { $ch++ } }
Write-Output ("  res_changed=" + $ch)
$rv = @()
for ($i = 0; $i -lt 64; $i += 4) { $rv += ("{0:X8}" -f $rd::ReadInt32($resBuf, $i)) }
Write-Output ("  res: " + ($rv -join ' '))