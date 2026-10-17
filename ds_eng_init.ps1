# EngLib_Init 正确参数 —— 首 DWORD 必须是 0x204
#
# ============================================================================
# EngLib_Init (RVA 0x3996E) 反汇编：
#   +010: 8B 45 08        mov eax,[ebp+0x08]     param_1
#   +013: 50              push eax
#   +014: E8 61 0C 00 00  call 0x3A5E7
#   +01A: 85 C0           test eax,eax
#   +01C: 0F 84 C0 00 00 00  jz +0xE2            ★ 返回 0 就跳过全部初始化
#
# 0x3A5E7 反汇编：
#   +000: 55 8B EC        push ebp; mov ebp,esp
#   +003: 56              push esi
#   +004: 8B 75 08        mov esi,[ebp+0x08]     param_1
#   +007: 85 F6           test esi,esi
#   +009: 0F 84 15 03 00 00  jz 返回0            ; NULL -> 0
#   +00F: 81 3E 04 02 00 00  cmp dword[esi],0x204  ; ★ 魔数 0x204
#   +015: 0F 85 09 03 00 00  jnz 返回0
#   +01B: E8 DE E3 FF FF  call ...               ; 继续
#   +020: 85 C0           test eax,eax
#   +022: 0F 84 FC 02 00 00  jz 返回0
#   +028: E8 F7 B1 FD FF  call ...
#   +02D: 8B C8           mov ecx,eax
#   +02F: E8 3C AE FD FF  call ...
#   +034: C7 46 04 42 99 03 10  mov [esi+0x04],0x10039942   ; 填函数表！
#   +03B: C7 46 08 73 9A 03 10  mov [esi+0x08],0x10039A73
#   +042: C7 46 0C 9B 9B 03 10  mov [esi+0x0C],0x10039B9B
#   +049: C7 46 10 2A A1 03 10  mov [esi+0x10],0x1003A12A
#   +050: C7 46 14 09 94 03 10  mov [esi+0x14],0x10039409
#   +057: C7 46 18 4C 94 03 10  mov [esi+0x18],0x1003944C
#   +05E: C7 46 1C 02 9B 03 10  mov [esi+0x1C],0x10039B02
#   +065: C7 46 20 DF 9E 03 10  mov [esi+0x20],0x10039EDF
#   +06C: C7 46 24 2B ...       mov [esi+0x24],...
#
# => param_1 是**输出结构**：
#      +0x00 DWORD  必须预置 0x204
#      +0x04...     函数被填入函数指针表
#
# 本脚本按此构造并调用，然后检查全局 0x2A67AC / 0x2A682C 是否被填充。
# 用法: -Root <产品目录> -Magic <十六进制> -Size <结构大小>
# ============================================================================

param([string]$Root, [string]$Magic, [int]$Size)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Magic) { $Magic = '0x204' }
if (-not $Size) { $Size = 0x204 }

$magicVal = [Convert]::ToInt32($Magic, 16)

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class EG {
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

[void][EG]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][EG]::LoadLibraryW($p) }
}
$h = [EG]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$base = $h.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]

function DumpG([string]$tag) {
  foreach ($rva in @(0x2A6770, 0x2A67AC, 0x2A682C, 0x2A6830)) {
    $v = $rd::ReadInt32([IntPtr]($base + $rva))
    Write-Output ("  [{0}] 0x{1:X} = 0x{2:X8}" -f $tag, $rva, $v)
  }
}

# BAPIInitialize
$hEng0 = [EG]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [EG]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [EG+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}

Write-Output "--- 调用前 ---"
DumpG "pre"

# 构造 param_1：首 DWORD = 0x204
$st = $rd::AllocHGlobal($Size)
for ($i = 0; $i -lt $Size; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, $magicVal)
Write-Output ("  构造 param_1 @ 0x{0:X}，首 DWORD = 0x{1:X}" -f $st.ToInt64(), $magicVal)

$pEng = [EG]::GetProcAddress($h, 'EngLib_Init')
$rcE = "EXC"
try {
  $ge = $rd::GetDelegateForFunctionPointer($pEng, [EG+F1])
  $rcE = $ge.Invoke($st)
} catch { $rcE = "EXC:" + $_.Exception.GetType().Name }
Write-Output ("  EngLib_Init(struct) rc=" + $rcE)

Write-Output "--- 调用后 ---"
DumpG "post"

# dump 结构被填入的内容
$vals = @()
for ($i = 0; $i -lt 64; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($st, $i)) }
Write-Output ("  结构内容: " + ($vals -join ' '))

# 检查被填入的函数指针是否指向 deepscan.dll
Write-Output "  填入的函数指针是否在 deepscan.dll 范围内:"
for ($i = 4; $i -lt 48; $i += 4) {
  $v = $rd::ReadInt32($st, $i)
  if ($v -gt 0x10000000 -and $v -lt 0x11000000) {
    $rva = $v - 0x10000000
    $inRange = ($rva -lt 0x2D0000)
    Write-Output ("    +0x{0:X2}: 0x{1:X8} -> RVA 0x{2:X} {3}" -f $i, $v, $rva, $(if($inRange){"(deepscan 内)"}else{"(范围外)"}))
  }
}