# ScanAveMemoryWithCode 魔数分支 —— param_5 必须非 0
#
# ============================================================================
# 精确反汇编 ScanAveMemoryWithCode (RVA 0x4001E) 的魔数分支：
#   +01C: 51                push ecx
#   +01D: 50                push eax
#   +01E: FF 75 14          push [ebp+0x14]   param_5
#   +021: FF 75 10          push [ebp+0x10]   param_4
#   +024: FF 75 0C          push [ebp+0x0C]   param_3
#   +027: FF 75 08          push [ebp+0x08]   param_2
#   +02A: E8 26 00 00 00    call 0x40073
#
# 0x40073 的校验（逐条机器码）：
#   +006: 8B 45 18          mov eax,[ebp+0x18]   param_6
#   +009: 85 C0             test eax,eax
#   +00B: 0F 84 21 02 00 00  jz 失败             param_6 必须非 0
#   +011: 83 7D 1C 00       cmp dword[ebp+0x1C],0
#   +015: 0F 84 17 02 00 00  jz 失败             param_7 必须非 0
#   +01B: 85 C9             test ecx,ecx
#   +01D: 0F 84 0B 02 00 00  jz 失败             ★ param_4 必须非 0
#   +023: 83 7D 14 00       cmp dword[ebp+0x14],0
#   +027: 0F 84 01 02 00 00  jz 失败             ★ param_5 必须非 0
#   +02D: 68 80 68 2A 10    push 0x102A6880      新全局
#
# 之前我一直传 param_5 = 0，所以永远走失败分支。
#
# 用法: -Target <文件> -Form N
# ============================================================================

param([string]$Root, [string]$Target, [int]$Form)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Form) { $Form = 1 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class P5 {
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

[void][P5]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][P5]::LoadLibraryW($p) }
}
$h = [P5]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$base = $h.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]

$hEng0 = [P5]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [P5]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [P5+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}

# 正确初始化
$st = $rd::AllocHGlobal(0x204)
for ($i = 0; $i -lt 0x204; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, 0x204)
$pEng = [P5]::GetProcAddress($h, 'EngLib_Init')
try {
  $ge = $rd::GetDelegateForFunctionPointer($pEng, [P5+F1])
  [void]$ge.Invoke($st)
} catch { }
if ($rd::ReadInt32([IntPtr]($base + 0x2A67AC)) -ne 1) { Write-Output "  init失败"; exit 0 }

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

# 结果缓冲与结构
$resBuf = $rd::AllocHGlobal(2048)
for ($i = 0; $i -lt 2048; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
$p6 = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($p6, $i, 0) }
$rd::WriteInt32($p6, 0, 0x18)
$rd::WriteInt32($p6, 8, 1)
$rd::WriteIntPtr($p6, 0x0C, $resBuf)

# ★ "lryy" 魔数结构 —— param_6
$magic = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($magic, $i, 0) }
$rd::WriteInt32($magic, 0, 0x7979726C)
$rd::WriteInt32($magic, 4, $size)
$rd::WriteIntPtr($magic, 8, $pathPtr)
$rd::WriteIntPtr($magic, 0x0C, $dataBuf)
$rd::WriteInt32($magic, 0x10, $size)

# param_5 非 0 的各种候选
$p5 = switch ($Form) {
  1 { $resBuf }        # 结果缓冲
  2 { $p6 }            # 结果结构
  3 { $pathPtr }       # 路径
  4 { $dataBuf }       # 数据
  5 { [IntPtr]1 }      # 常量 1
  6 { $magic }         # 魔数结构
  default { $resBuf }
}

$pWC = [P5]::GetProcAddress($h, 'ScanAveMemoryWithCode')
$rc = "EXC"
try {
  $g = $rd::GetDelegateForFunctionPointer($pWC, [P5+F6])
  # param_5 = $p5（必须非 0），param_6 = magic，param_7 = 长度(>4)
  $rc = $g.Invoke($dataBuf, [IntPtr]$size, $pathPtr, $p5, $magic, [IntPtr]32)
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

Write-Output ("P5" + [char]0x1f + "form=" + $Form + [char]0x1f + "size=" + $size + [char]0x1f + "rc=" + $rc)
$ch = 0
for ($i = 0; $i -lt 512; $i++) { if ($rd::ReadByte($resBuf, $i) -ne 0xCC) { $ch++ } }
Write-Output ("  res_changed=" + $ch)
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