# PopSoftEng!Create360Object 正确签名测试 —— GUID 是第 3 参数
#
# ============================================================================
# 精确栈帧计算（pop_frame.py）：
#   +000 push -1        esp -= 4
#   +002 push SEH       esp -= 4
#   +00D push eax       esp -= 4
#   +00E push ebx       esp -= 4
#   +00F push esi       esp -= 4
#   +010 push edi       esp -= 4
#   +018 push eax       esp -= 4
#   累计 = 0x1C
#   +036: mov ebx,[esp+0x28] = [原esp - 0x1C + 0x28] = [原esp + 0xC] = param_3
#
# => Create360Object(param_1, param_2, REFGUID guid)
#    guid 是**第 3 个参数**，必须非 0。
#    我之前传 (guid, outBuf, flags) 完全反了。
#
# 用法: -Guid N -Out N
# ============================================================================

param([string]$Root, [int]$Guid, [int]$OutMode)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Guid) { $Guid = 0 }
if (-not $OutMode) { $OutMode = 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class PF {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi, EntryPoint="GetProcAddress")]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int HR3(IntPtr a, IntPtr b, IntPtr c);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][PF]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\ScChecker.dll', 'deepscan\PopSoftEng.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][PF]::LoadLibraryW($p) }
}
$hp = [PF]::GetModuleHandleW('PopSoftEng.dll')
if ($hp -eq [IntPtr]::Zero) { Write-Output "  no PopSoftEng"; exit 0 }
$pbase = $hp.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]
$pC = [PF]::GetProcAddress($hp, 'Create360Object')

$guids = @(
  @('22FA5512-0D00-4452-82BE-EBA5E33B9DB0', 0x85714),
  @('869330CB-E95B-4213-A224-917373C846A4', 0x85724),
  @('D665872C-8D3A-4F68-A5E7-5D39874B45CB', 0x85ED8),
  @('D665872C-8D3A-4F68-A5E7-5D39874B45CC', 0x85EE8),
  @('93E4B447-3C85-4F22-9D3E-CF8DF4E3AD40', 0x8626C)
)
$sel = $guids[$Guid]
$guidPtr = [IntPtr]($pbase + [int]$sel[1])

Write-Output ("  GUID[{0}] = {1} @ 0x{2:X8}" -f $Guid, $sel[0], $guidPtr.ToInt64())

$outBuf = $rd::AllocHGlobal(32)
$outBuf2 = $rd::AllocHGlobal(32)

# 正确签名: (param_1, param_2, guid)
$combos = @(
  @('null,null,guid',      { param($g,$o1,$o2,$gp) $g.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $gp) }),
  @('out,null,guid',       { param($g,$o1,$o2,$gp) $g.Invoke($o1, [IntPtr]::Zero, $gp) }),
  @('null,out,guid',       { param($g,$o1,$o2,$gp) $g.Invoke([IntPtr]::Zero, $o2, $gp) }),
  @('out,out,guid',        { param($g,$o1,$o2,$gp) $g.Invoke($o1, $o2, $gp) })
)
$g = $rd::GetDelegateForFunctionPointer($pC, [PF+HR3])
foreach ($c in $combos) {
  $nm = $c[0]; $fn = $c[1]
  for ($i = 0; $i -lt 32; $i++) { $rd::WriteByte($outBuf, $i, 0); $rd::WriteByte($outBuf2, $i, 0) }
  $hr = "EXC"
  try { Write-Output ("    TRY {0}" -f $nm); [Console]::Out.Flush(); $hr = & $fn $g $outBuf $outBuf2 $guidPtr } catch { $hr = "EXC:" + $_.Exception.GetType().Name }
  $o1 = $rd::ReadInt32($outBuf, 0)
  $o2 = $rd::ReadInt32($outBuf2, 0)
  Write-Output ("    {0,-16} hr=0x{1:X8} out1=0x{2:X8} out2=0x{3:X8}" -f $nm, $hr, $o1, $o2)
  foreach ($ov in @($o1, $o2)) {
    if ($ov -gt 0x10000 -and $ov -lt 0x7FFFFFFF) {
      $vtp = $rd::ReadInt32([IntPtr]$ov)
      Write-Output ("      ★ 对象 0x{0:X8} 虚表=0x{1:X8} (RVA 0x{2:X})" -f $ov, $vtp, ($vtp - $pbase))
      $vals = @()
      for ($k = 0; $k -lt 16; $k += 4) { $vals += ("{0:X8}" -f $rd::ReadInt32([IntPtr]$ov, $k)) }
      Write-Output ("        对象前 16 字节: " + ($vals -join ' '))
      if ($vtp -gt 0x10000 -and $vtp -lt 0x7FFFFFFF) {
        for ($k = 0; $k -lt 16; $k++) {
          $fn2 = $rd::ReadInt32([IntPtr]($vtp + $k*4))
          $rva = $fn2 - $pbase
          $tag = ""
          if ($rva -gt 0 -and $rva -lt 0x81388) { $tag = " .text" }
          Write-Output ("          [{0,2}] 0x{1:X8} RVA=0x{2:X}{3}" -f $k, $fn2, $rva, $tag)
        }
      }
    }
  }
}