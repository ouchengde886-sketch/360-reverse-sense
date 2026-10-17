param([string]$Target, [string]$Root)
if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QF {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int CreateFn(IntPtr a, IntPtr b, IntPtr c);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int ScanFn(IntPtr self, IntPtr path, IntPtr access, IntPtr disposition);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int InitFn(IntPtr buf);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop
[void][QF]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll','deepscan\BAPI.dll','deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QF]::LoadLibraryW($p) }
}
$h = [QF]::GetModuleHandleW('qex.dll')
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()
foreach ($nm in @('QexScanExportsInit','QexResourceExportsInit')) {
  $pf = [QF]::GetProcAddress($h,$nm)
  if ($pf -eq [IntPtr]::Zero) { continue }
  $ib = $rd::AllocHGlobal(512)
  for ($i=0;$i -lt 512;$i++){ $rd::WriteByte($ib,$i,0) }
  $rd::WriteInt32($ib,0,0x58)
  $fi = $rd::GetDelegateForFunctionPointer($pf,[QF+InitFn])
  try { [void]$fi.Invoke($ib) } catch { }
  $rd::FreeHGlobal($ib)
}
$out = $rd::AllocHGlobal(256)
for ($i=0;$i -lt 256;$i++){ $rd::WriteByte($out,$i,0) }
$fCreate = $rd::GetDelegateForFunctionPointer([QF]::GetProcAddress($h,'QEXCreateInstance'),[QF+CreateFn])
[void]$fCreate.Invoke([IntPtr]($base+0x1C2364),[IntPtr]($base+0x1C2354),$out)
$obj = $rd::ReadIntPtr($out,0)
$vt = $rd::ReadIntPtr($obj,0)
$pathPtr = $rd::StringToHGlobalUni($Target)
$fn = $rd::ReadIntPtr($vt,0x10)
$scan = $rd::GetDelegateForFunctionPointer($fn,[QF+ScanFn])
try { [void]$scan.Invoke($obj,$pathPtr,[IntPtr][int]0x80000000,[IntPtr]3) } catch { }

Write-Output ("TARGET " + $Target)
$buf = $rd::ReadIntPtr($obj,0x1C)
# 跟随 +0x34 指针
$p34 = $rd::ReadIntPtr($buf,0x34)
Write-Output ("  buf=0x{0:X}  buf+0x34=0x{1:X}" -f $buf.ToInt64(),$p34.ToInt64())
if ($p34 -ne [IntPtr]::Zero) {
  Write-Output "  --- [buf+0x34] 指向的内存 (0x00-0x60) ---"
  for ($o=0;$o -lt 0x60;$o+=16){
    $vals=@(); for($j=0;$j -lt 16;$j+=4){ $vals += ("{0:X8}" -f $rd::ReadInt32($p34,$o+$j)) }
    $asc=''
    for($j=0;$j -lt 16;$j++){ $c=$rd::ReadByte($p34,$o+$j); if($c -ge 32 -and $c -lt 127){ $asc += [char]$c } else { $asc += '.' } }
    Write-Output ("    +{0:X3}: {1}  |{2}|" -f $o,($vals -join ' '),$asc)
  }
  try { $s=$rd::PtrToStringUni($p34,80); if($s){ Write-Output ("    Uni: " + ($s -replace '[^\x20-\x7E]','.')) } } catch { }
}
# 也跟随 obj+0x2C 和 obj+0x34
foreach ($off in @(0x2C,0x34)) {
  $pp = $rd::ReadIntPtr($obj,$off)
  Write-Output ("  obj+0x{0:X2} = 0x{1:X}" -f $off,$pp.ToInt64())
  if ($pp -ne [IntPtr]::Zero) {
    for ($o=0;$o -lt 0x40;$o+=16){
      $vals=@(); for($j=0;$j -lt 16;$j+=4){ $vals += ("{0:X8}" -f $rd::ReadInt32($pp,$o+$j)) }
      $asc=''
      for($j=0;$j -lt 16;$j++){ $c=$rd::ReadByte($pp,$o+$j); if($c -ge 32 -and $c -lt 127){ $asc += [char]$c } else { $asc += '.' } }
      Write-Output ("      +{0:X3}: {1}  |{2}|" -f $o,($vals -join ' '),$asc)
    }
    try { $s=$rd::PtrToStringUni($pp,80); if($s){ Write-Output ("      Uni: " + ($s -replace '[^\x20-\x7E]','.')) } } catch { }
  }
}
$rd::FreeHGlobal($pathPtr); $rd::FreeHGlobal($out)
