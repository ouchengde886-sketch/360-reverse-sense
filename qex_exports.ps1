param([string]$Root)
if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QE {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int InitFn(IntPtr buf);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop
[void][QE]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll','deepscan\BAPI.dll','deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QE]::LoadLibraryW($p) }
}
$h = [QE]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()
Write-Output ("  QEX base = 0x{0:X}" -f $base)
foreach ($nm in @('QexScanExportsInit','QexResourceExportsInit')) {
  $pf = [QE]::GetProcAddress($h,$nm)
  if ($pf -eq [IntPtr]::Zero) { Write-Output ("  {0}: 不存在" -f $nm); continue }
  Write-Output ("  === {0} (RVA 0x{1:X}) ===" -f $nm, ($pf.ToInt64()-$base))
  $ib = $rd::AllocHGlobal(512)
  for ($i=0;$i -lt 512;$i++){ $rd::WriteByte($ib,$i,0) }
  $rd::WriteInt32($ib,0,0x58)
  $fi = $rd::GetDelegateForFunctionPointer($pf,[QE+InitFn])
  $r = "EXC"
  try { $r = $fi.Invoke($ib) } catch { }
  Write-Output ("    返回 {0}" -f $r)
  Write-Output "    填充后的表内容:"
  for ($o=0;$o -lt 0x58;$o+=4){
    $v = $rd::ReadInt32($ib,$o)
    $mark = ''
    if ($v -ne 0) {
      $inMod = ($v -ge $base -and $v -lt ($base+0x240000))
      if ($inMod) { $mark = ("-> QEX RVA 0x{0:X}" -f ($v-$base)) } else { $mark = "-> 外部" }
    }
    Write-Output ("      +0x{0:X2} = 0x{1:X8} {2}" -f $o,$v,$mark)
  }
  $rd::FreeHGlobal($ib)
}
