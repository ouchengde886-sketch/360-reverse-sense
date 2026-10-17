# avescan.dll!QueryFileInAVE —— 高层扫描 API（2 参数，路径直传）
#
# ============================================================================
# avescan.dll (deepscan\avescan.dll, 117248 字节, ImageBase=0x10000000)
#   导出: QueryFileInAVE RVA=0x2E1B / CreateADSAVEScanInstance RVA=0x3B83
#   字符串: CreateScannerEx / CloseScanner / ScanW / SetScannerConfig / CreateObject
#   => 这是 AVE 引擎的**官方薄封装**
#
# QueryFileInAVE 反汇编:
#   +000: FF 74 24 08    push [esp+8]     ; param_2
#   +004: FF 74 24 08    push [esp+8]     ; param_1
#   +008: E8 93 01 00 00 call 0x2FA0
#   +00D: 8B C8          mov ecx,eax
#   +00F: E8 35 06 00 00 call 0x3649
#   +014: C2 08 00       ret 8            ★ 2 参数
#
# 用法: -Target <文件>
# ============================================================================

param([string]$Root, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { $Target = 'D:\troyr2\tools\vendor\srdi-master.zip' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class AV {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi, EntryPoint="GetProcAddress")]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int S2(IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int S1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr P0();
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][AV]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\avescan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][AV]::LoadLibraryW($p) }
}
$ha = [AV]::GetModuleHandleW('avescan.dll')
if ($ha -eq [IntPtr]::Zero) { Write-Output "  no avescan.dll"; exit 0 }
$abase = $ha.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]
Write-Output ("  avescan base = 0x{0:X8}" -f $abase)

$pQ = [AV]::GetProcAddress($ha, 'QueryFileInAVE')
$pC = [AV]::GetProcAddress($ha, 'CreateADSAVEScanInstance')
Write-Output ("  QueryFileInAVE          = 0x{0:X8} (RVA 0x{1:X})" -f $pQ.ToInt64(), ($pQ.ToInt64() - $abase))
Write-Output ("  CreateADSAVEScanInstance= 0x{0:X8} (RVA 0x{1:X})" -f $pC.ToInt64(), ($pC.ToInt64() - $abase))

# 先建实例
$inst = [IntPtr]::Zero
try {
  $g0 = $rd::GetDelegateForFunctionPointer($pC, [AV+P0])
  $inst = $g0.Invoke()
} catch { Write-Output ("  CreateADSAVEScanInstance 异常: " + $_.Exception.GetType().Name) }
Write-Output ("  实例 = 0x{0:X8}" -f $inst.ToInt64())

$pathPtr = $rd::StringToHGlobalUni($Target)
$outBuf = $rd::AllocHGlobal(4096)
Write-Output ("  目标 = {0}" -f $Target)

# QueryFileInAVE 各种参数组合
$combos = @(
  @('path,out',   { param($g,$pp,$ob) $g.Invoke($pp, $ob) }),
  @('out,path',   { param($g,$pp,$ob) $g.Invoke($ob, $pp) }),
  @('path,0',     { param($g,$pp,$ob) $g.Invoke($pp, [IntPtr]::Zero) }),
  @('0,path',     { param($g,$pp,$ob) $g.Invoke([IntPtr]::Zero, $pp) })
)
$g = $rd::GetDelegateForFunctionPointer($pQ, [AV+S2])
foreach ($c in $combos) {
  $nm = $c[0]; $fn = $c[1]
  for ($i = 0; $i -lt 4096; $i++) { $rd::WriteByte($outBuf, $i, 0xCC) }
  Write-Output ("    TRY {0}" -f $nm)
  [Console]::Out.Flush()
  $r = "EXC"
  try { $r = & $fn $g $pathPtr $outBuf } catch { $r = "EXC:" + $_.Exception.GetType().Name }
  $ch = 0
  for ($i = 0; $i -lt 512; $i++) { if ($rd::ReadByte($outBuf, $i) -ne 0xCC) { $ch++ } }
  Write-Output ("      {0,-10} rc=0x{1:X8} ({1})  输出变化={2} 字节" -f $nm, $r, $ch)
  [Console]::Out.Flush()
  if ($ch -gt 0) {
    $rv = @()
    for ($i = 0; $i -lt 32; $i += 4) { $rv += ("{0:X8}" -f $rd::ReadInt32($outBuf, $i)) }
    Write-Output ("        前 32 字节: " + ($rv -join ' '))
    for ($off = 0; $off -lt 256; $off += 4) {
      try {
        $s = $rd::PtrToStringAnsi([IntPtr]($outBuf.ToInt64()+$off), 80)
        if ($s -and $s.Length -ge 3) {
          $ok = $true
          foreach ($ch2 in $s.ToCharArray()) { if ([int]$ch2 -lt 32 -or [int]$ch2 -gt 126) { $ok = $false; break } }
          if ($ok) { Write-Output ("        S@+{0:X2}: {1}" -f $off, $s) }
        }
      } catch { }
    }
    [Console]::Out.Flush()
  }
}