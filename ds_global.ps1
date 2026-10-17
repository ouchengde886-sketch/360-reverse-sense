# 读取 EngLib_Init 初始化的全局对象 0x102A6770 / 0x102A67AC
#
# ============================================================================
# EngLib_Init (RVA 0x3996E) 反汇编揭示：
#   +020: 83 3D AC 67 2A 10 00   cmp dword[0x102A67AC],0
#   +027: 0F 85 B0 00 00 00      jnz 已初始化
#   +02D: BE 70 67 2A 10         mov esi,0x102A6770
#   +032: 56                     push esi
#   +033: FF 15 D0 53 1C 10      call [导入函数]
#   +039: 89 B5 D8 FD FF FF      mov [ebp-0x228],esi
#
# 而 ScanAveMemoryWithCode 需要的是 [0x102A682C] / [0x102A6830]。
# 两者不同 —— 说明 EngLib_Init 初始化的是**另一个**对象。
#
# 本脚本：调 EngLib_Init 后读取这些全局，看它们被填成什么。
# 用法: -Root <产品目录> -Mode <1|2|3>
# ============================================================================

param([string]$Root, [int]$Mode)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Mode) { $Mode = 1 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class GG {
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
  public delegate int BapiFn(string root);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][GG]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][GG]::LoadLibraryW($p) }
}
$h = [GG]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$base = $h.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]

function DumpGlobals([string]$tag) {
  # 全局变量 RVA
  $globals = @{
    '0x2A6770' = 0x2A6770
    '0x2A67AC' = 0x2A67AC
    '0x2A682C' = 0x2A682C
    '0x2A6830' = 0x2A6830
  }
  foreach ($k in $globals.Keys) {
    $addr = [IntPtr]($base + $globals[$k])
    $v = $rd::ReadInt32($addr)
    Write-Output ("  [{0}] {1} = 0x{2:X8}" -f $tag, $k, $v)
  }
}

Write-Output "--- 加载后（未初始化）---"
DumpGlobals "pre"

# BAPIInitialize
$hEng0 = [GG]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [GG]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [GG+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}

$pEng = [GG]::GetProcAddress($h, 'EngLib_Init')
$arg = switch ($Mode) {
  1 { $rd::StringToHGlobalUni((Join-Path $Root 'deepscan')) }
  2 { $rd::StringToHGlobalUni($Root) }
  3 { [IntPtr]::Zero }
  default { $rd::StringToHGlobalUni((Join-Path $Root 'deepscan')) }
}
$rcE = "EXC"
try {
  $ge = $rd::GetDelegateForFunctionPointer($pEng, [GG+F1])
  $rcE = $ge.Invoke($arg)
} catch { $rcE = "EXC:" + $_.Exception.GetType().Name }
Write-Output ("  EngLib_Init(mode=" + $Mode + ") rc=" + $rcE)

Write-Output "--- EngLib_Init 之后 ---"
DumpGlobals "post"

# 如果 0x2A6770 非空，dump 它指向的内容
$v6770 = $rd::ReadInt32([IntPtr]($base + 0x2A6770))
if ($v6770 -ne 0) {
  Write-Output ("  0x2A6770 指向 0x{0:X8}，前 16 字节:" -f $v6770)
  try {
    $p = [IntPtr]$v6770
    $vals = @()
    for ($i = 0; $i -lt 64; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($p, $i)) }
    Write-Output ("    " + ($vals -join ' '))
  } catch { Write-Output "    读取失败" }
}