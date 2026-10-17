param([string]$Root, [int]$Guid, [int]$OutMode)
if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
$sig = @"
using System;
using System.Runtime.InteropServices;
public static class PH {
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
[void][PH]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll','deepscan\BAPI.dll','deepscan\ave\AVEngine.dll','deepscan\ave\AVEI.dll','deepscan\ScChecker.dll','deepscan\PopSoftEng.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][PH]::LoadLibraryW($p) }
}
$hp = [PH]::GetModuleHandleW('PopSoftEng.dll')
$pbase = $hp.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]
$pC = [PH]::GetProcAddress($hp, 'Create360Object')
$guids = @(
  @(0x85714),@(0x85724),@(0x85ED8),@(0x85EE8),@(0x8626C)
)
$guidPtr = [IntPtr]($pbase + [int]$guids[$Guid][0])
$outBuf = $rd::AllocHGlobal(64)
$outBuf2 = $rd::AllocHGlobal(64)
for ($i=0;$i -lt 64;$i++){ $rd::WriteByte($outBuf,$i,0); $rd::WriteByte($outBuf2,$i,0) }
Write-Output ("  GUID[{0}] ptr=0x{1:X8} mode={2}" -f $Guid,$guidPtr.ToInt64(),$OutMode)
[Console]::Out.Flush()
$g = $rd::GetDelegateForFunctionPointer($pC, [PH+HR3])
$a = [IntPtr]::Zero; $b = [IntPtr]::Zero
if ($OutMode -eq 1) { $a = $outBuf }
if ($OutMode -eq 2) { $b = $outBuf }
if ($OutMode -eq 3) { $a = $outBuf; $b = $outBuf2 }
$hr = $g.Invoke($a, $b, $guidPtr)
Write-Output ("  hr=0x{0:X8}" -f $hr)
[Console]::Out.Flush()
foreach($ov in @($rd::ReadInt32($outBuf,0), $rd::ReadInt32($outBuf2,0))){
  if ($ov -gt 0x10000 -and $ov -lt 0x7FFFFFFF) {
    $vtp = $rd::ReadInt32([IntPtr]$ov)
    Write-Output ("  ★ 对象 0x{0:X8} 虚表=0x{1:X8} RVA=0x{2:X}" -f $ov,$vtp,($vtp-$pbase))
    [Console]::Out.Flush()
  }
}
