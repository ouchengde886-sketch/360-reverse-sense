# 调用工厂函数拿引擎对象，dump 其虚表
#
# ============================================================================
# 关键发现：0x2A682C / 0x2A6830 存的是**函数指针**（首字节 55 8B EC = push ebp;mov ebp,esp），
# 不是对象指针。
#
# 0x40073 的用法：
#   +2A7: 8B 3D 2C 68 2A 10    mov edi,[0x102A682C]   ; 工厂函数
#   +2C2: FF D7                 call edi               ; ★ 调用工厂
#   +2C4: 8B F0                 mov esi,eax            ; ★ esi = 引擎对象
#   +2FC: 8B 06                 mov eax,[esi]          ; 对象虚表
#   +306: FF 50 18              call [eax+0x18]        ; 虚表+0x18（失败点）
#
# 本脚本：
#   1. 初始化 + 调一次 ScanAveMemoryWithCode 让工厂指针被填充
#   2. 自己 call [0x2A682C] 拿引擎对象
#   3. dump 对象虚表，反汇编 vtable+0x18
#
# 用法: -Target <文件>
# ============================================================================

param([string]$Root, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class VF {
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

[void][VF]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][VF]::LoadLibraryW($p) }
}
$h = [VF]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "no deepscan"; exit 0 }
$base = $h.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]

$hEng0 = [VF]::GetModuleHandleW('AVEngine.dll')
if ($hEng0 -ne [IntPtr]::Zero) {
  $pB = [VF]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pB -ne [IntPtr]::Zero) {
    try { $gb = $rd::GetDelegateForFunctionPointer($pB, [VF+BapiFn]); [void]$gb.Invoke($Root) } catch { }
  }
}

$st = $rd::AllocHGlobal(0x204)
for ($i = 0; $i -lt 0x204; $i++) { $rd::WriteByte($st, $i, 0) }
$rd::WriteInt32($st, 0, 0x204)
$pEng = [VF]::GetProcAddress($h, 'EngLib_Init')
try { $ge = $rd::GetDelegateForFunctionPointer($pEng, [VF+F1]); [void]$ge.Invoke($st) } catch { }

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
for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($resBuf, $i, 0xCC) }
$p6 = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($p6, $i, 0) }
$rd::WriteInt32($p6, 0, 0x18)
$rd::WriteInt32($p6, 8, 1)
$rd::WriteIntPtr($p6, 0x0C, $resBuf)
$magic = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($magic, $i, 0) }
$rd::WriteInt32($magic, 0, 0x7979726C)
$rd::WriteInt32($magic, 4, $size)

# 调一次触发工厂指针填充
$pWC = [VF]::GetProcAddress($h, 'ScanAveMemoryWithCode')
$g = $rd::GetDelegateForFunctionPointer($pWC, [VF+F6])
try { [void]$g.Invoke($dataBuf, [IntPtr]$size, $pathPtr, $resBuf, $magic, [IntPtr]32) } catch { }

$facA = $rd::ReadInt32([IntPtr]($base + 0x2A682C))
$facB = $rd::ReadInt32([IntPtr]($base + 0x2A6830))
Write-Output ("  工厂A 0x2A682C = 0x{0:X8}  (RVA 0x{1:X})" -f $facA, ($facA - $base))
Write-Output ("  工厂B 0x2A6830 = 0x{0:X8}  (RVA 0x{1:X})" -f $facB, ($facB - $base))

# 尝试调用工厂（用 P0 委托，无参数）
foreach ($fp in @($facA, $facB)) {
  if ($fp -eq 0) { continue }
  Write-Output ("  --- 尝试 call 0x{0:X8} ---" -f $fp)
  $obj = [IntPtr]::Zero
  try {
    $gf = $rd::GetDelegateForFunctionPointer([IntPtr]$fp, [VF+P0])
    $obj = $gf.Invoke()
  } catch { Write-Output ("    调用异常: " + $_.Exception.GetType().Name) }
  Write-Output ("    返回 = 0x{0:X8}" -f $obj.ToInt64())
  if ($obj -ne [IntPtr]::Zero) {
    $vtp = $rd::ReadInt32($obj)
    Write-Output ("    虚表 = 0x{0:X8}  (RVA 0x{1:X})" -f $vtp, ($vtp - $base))
    $vals = @()
    for ($i = 0; $i -lt 32; $i += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32($obj, $i)) }
    Write-Output ("    对象前 32 字节: " + ($vals -join ' '))
    if ($vtp -gt 0x10000 -and $vtp -lt 0x7FFFFFFF) {
      Write-Output "    虚表前 24 项:"
      for ($i = 0; $i -lt 24; $i++) {
        $fn = $rd::ReadInt32([IntPtr]($vtp + $i*4))
        $rva = $fn - $base
        $mk = ""
        if ($rva -gt 0 -and $rva -lt 0x2D0000) { $mk = " deepscan+0x{0:X}" -f $rva }
        Write-Output ("      [{0,2}] 0x{1:X8}{2}" -f $i, $fn, $mk)
      }
      # 反汇编 vtable+0x18
      $fn18 = $rd::ReadInt32([IntPtr]($vtp + 0x18))
      Write-Output ("    vtable+0x18 = 0x{0:X8} (RVA 0x{1:X})" -f $fn18, ($fn18 - $base))
      if ($fn18 -gt 0x10000 -and $fn18 -lt 0x7FFFFFFF) {
        Write-Output "    该函数前 80 字节:"
        for ($i = 0; $i -lt 80; $i += 16) {
          $bs = @()
          for ($j = 0; $j -lt 16; $j++) { $bs += ("{0:X2}" -f $rd::ReadByte([IntPtr]($fn18 + $i + $j))) }
          Write-Output ("      +{0:X3}: {1}" -f $i, ($bs -join ' '))
        }
      }
    }
  }
}