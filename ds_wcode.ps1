# ScanAveMemoryWithCode 调用 —— 带 "lryy" 魔数
#
# ============================================================================
# 反汇编 (RVA 0x4001E)：
#   +000: 55 8B EC        push ebp; mov ebp,esp
#   +003: 51 51           push ecx; push ecx      ; 两个局部变量
#   +005: 8B 45 18        mov eax,[ebp+0x18]      ; param_6
#   +008: 8B 4D 1C        mov ecx,[ebp+0x1C]      ; param_7
#   +00B: 85 C0           test eax,eax
#   +00D: 74 25           jz  +0x34               ; param_6==0 -> 走 +0x34 分支
#   +00F: 83 F9 04        cmp ecx,4
#   +012: 76 20           jbe +0x34               ; param_7<=4 -> 走 +0x34 分支
#   +014: 81 38 6C 72 79 79  cmp dword[eax],"lryy"  ; ★ 魔数 0x7979726C
#   +01A: 75 18           jnz +0x34
#   +01C: 51              push ecx
#   +01D: 50              push eax
#   +01E: FF 75 14        push [ebp+0x14]
#   +021: FF 75 10        push [ebp+0x10]
#   +024: FF 75 0C        push [ebp+0x0C]
#   +027: FF 75 08        push [ebp+0x08]
#   +02A: E8 26 00 00 00  call 内部实现
#   +02F: 83 C4 18        add esp,0x18
#   +032: EB 1D           jmp 返回
#   +034: 89 45 F8        mov [ebp-8],eax         ; 魔数不匹配分支
#   +037: 8D 45 F8        lea eax,[ebp-8]
#   +03A: 50              push eax
#   +03B: 6A 00           push 0
#   +03D: FF 75 14        push [ebp+0x14]
#   +040: 89 4D FC        mov [ebp-4],ecx
#   +043: FF 75 10        push [ebp+0x10]
#   +046: FF 75 0C        push [ebp+0x0C]
#   +049: FF 75 08        push [ebp+0x08]
#   +04C: E8 75 FE FF FF  call 0x3FEC8 (ScanAveMemory)
#
# 所以：
#   param_6 = 指向以 "lryy" 开头的结构的指针
#   param_7 = 该结构的长度（必须 > 4）
#   走魔数匹配分支 -> 调内部实现（6 参数）
#   不匹配 -> 退化为调 ScanAveMemory
#
# 本脚本构造 "lryy" 结构并调用。
# 用法: -Target <文件> -Form N
# ============================================================================

param([string]$Root, [string]$Target, [int]$Form)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Form) { $Form = 1 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class WC {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int AveInitFn(IntPtr tbl);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int BapiFn(string root);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int DsInitFn(string dir);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F6(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F7(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][WC]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][WC]::LoadLibraryW($p) }
}
$rd = [System.Runtime.InteropServices.Marshal]

# BAPIInitialize
$hEng0 = [WC]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [WC]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [WC+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}
# EngLib_Init(deepscan 目录)
$hDs = [WC]::GetModuleHandleW('deepscan.dll')
if ($hDs -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$pEng = [WC]::GetProcAddress($hDs, 'EngLib_Init')
if ($pEng -ne [IntPtr]::Zero) {
  try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [WC+DsInitFn]); [void]$ge.Invoke((Join-Path $Root 'deepscan')) } catch { }
}

# 读文件
$dataBuf = $rd::AllocHGlobal(1048576)
for ($i = 0; $i -lt 1048576; $i++) { $rd::WriteByte($dataBuf, $i, 0) }
$size = 0
if ($Target -and (Test-Path $Target)) {
  $bytes = [System.IO.File]::ReadAllBytes($Target)
  $size = [Math]::Min($bytes.Length, 1048576)
  $rd::Copy($bytes, 0, $dataBuf, $size)
}
$pathPtr = $rd::StringToHGlobalUni($Target)

# "lryy" 魔数结构
$magic = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($magic, $i, 0) }
$rd::WriteInt32($magic, 0, 0x7979726C)   # "lryy"
$rd::WriteInt32($magic, 4, $size)        # +4 放大小
$rd::WriteInt32($magic, 8, $size)

$out = $rd::AllocHGlobal(512)
for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($out, $i, 0xCC) }

$pWC = [WC]::GetProcAddress($hDs, 'ScanAveMemoryWithCode')

# 6 参数：(p2, p3, p4, p5, p6=magic, p7=len)
$magicLen = 16
$a = switch ($Form) {
  1 { @($dataBuf, [IntPtr]$size, $pathPtr, $out, $magic, [IntPtr]$magicLen) }
  2 { @($dataBuf, [IntPtr]$size, [IntPtr]::Zero, $out, $magic, [IntPtr]$magicLen) }
  3 { @($pathPtr, [IntPtr]$size, $dataBuf, $out, $magic, [IntPtr]$magicLen) }
  4 { @($dataBuf, [IntPtr]$size, $pathPtr, [IntPtr]::Zero, $magic, [IntPtr]$magicLen) }
  5 { @($dataBuf, [IntPtr]$size, $pathPtr, $out, $magic, [IntPtr]128) }
  default { @($dataBuf, [IntPtr]$size, $pathPtr, $out, $magic, [IntPtr]$magicLen) }
}

$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($pWC, [WC+F6])
  $rc = $g.Invoke($a[0], $a[1], $a[2], $a[3], $a[4], $a[5])
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

Write-Output ("WC" + [char]0x1f + "form=" + $Form + [char]0x1f + "size=" + $size + [char]0x1f + "rc=" + $rc)
$changed = 0
for ($i = 0; $i -lt 256; $i++) { if ($rd::ReadByte($out, $i) -ne 0xCC) { $changed++ } }
Write-Output ("  out_changed=" + $changed)
$vals = @()
for ($i = 0; $i -lt 48; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($out, $i)) }
Write-Output ("  out: " + ($vals -join ' '))
$mvals = @()
for ($i = 0; $i -lt 32; $i += 4) { $mvals += ("{0:X8}" -f $rd::ReadInt32($magic, $i)) }
Write-Output ("  magic: " + ($mvals -join ' '))