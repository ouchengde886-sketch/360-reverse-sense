param([string]$Target, [string]$Root)
if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QB {
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
[void][QB]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll','deepscan\BAPI.dll','deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QB]::LoadLibraryW($p) }
}
$h = [QB]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()
foreach ($nm in @('QexScanExportsInit','QexResourceExportsInit')) {
  $pf = [QB]::GetProcAddress($h,$nm)
  if ($pf -eq [IntPtr]::Zero) { continue }
  $ib = $rd::AllocHGlobal(512)
  for ($i=0;$i -lt 512;$i++){ $rd::WriteByte($ib,$i,0) }
  $rd::WriteInt32($ib,0,0x58)
  $fi = $rd::GetDelegateForFunctionPointer($pf,[QB+InitFn])
  try { [void]$fi.Invoke($ib) } catch { }
  $rd::FreeHGlobal($ib)
}
$out = $rd::AllocHGlobal(256)
for ($i=0;$i -lt 256;$i++){ $rd::WriteByte($out,$i,0) }
$fCreate = $rd::GetDelegateForFunctionPointer([QB]::GetProcAddress($h,'QEXCreateInstance'),[QB+CreateFn])
[void]$fCreate.Invoke([IntPtr]($base+0x1C2364),[IntPtr]($base+0x1C2354),$out)
$obj = $rd::ReadIntPtr($out,0)
if ($obj -eq [IntPtr]::Zero) { Write-Output "null_obj"; exit 0 }
$vt = $rd::ReadIntPtr($obj,0)
$pathPtr = $rd::StringToHGlobalUni($Target)
$fn = $rd::ReadIntPtr($vt,0x10)
$scan = $rd::GetDelegateForFunctionPointer($fn,[QB+ScanFn])
try { [void]$scan.Invoke($obj,$pathPtr,[IntPtr][int]0x80000000,[IntPtr]3) } catch { }

Write-Output ("TARGET " + $Target)
# obj+0x1C 指向的缓冲 —— 每次扫描都不同，疑似结果区
$p1c = $rd::ReadIntPtr($obj,0x1C)
Write-Output ("  obj+0x1C = 0x{0:X}" -f $p1c.ToInt64())
if ($p1c -ne [IntPtr]::Zero) {
  Write-Output "  --- obj+0x1C 指向的内存 (0x00-0x80) ---"
  for ($o=0;$o -lt 0x80;$o+=16){
    $vals=@(); for($j=0;$j -lt 16;$j+=4){ $vals += ("{0:X8}" -f $rd::ReadInt32($p1c,$o+$j)) }
    $asc=''
    for($j=0;$j -lt 16;$j++){ $c=$rd::ReadByte($p1c,$o+$j); if($c -ge 32 -and $c -lt 127){ $asc += [char]$c } else { $asc += '.' } }
    Write-Output ("    +{0:X3}: {1}  |{2}|" -f $o,($vals -join ' '),$asc)
  }
  # 也按 Unicode 读一遍（威胁名可能是宽字符）
  Write-Output "  --- 同区域按 Unicode 读 ---"
  try {
    $s = $rd::PtrToStringUni($p1c, 64)
    if ($s) { Write-Output ("    Uni: " + ($s -replace '[^\x20-\x7E]','.')) }
  } catch { }
  # 按 ANSI 读
  try {
    $s2 = $rd::PtrToStringAnsi($p1c, 64)
    if ($s2) { Write-Output ("    Ansi: " + ($s2 -replace '[^\x20-\x7E]','.')) }
  } catch { }
}
# 也看 obj+0x2C..0x60 有没有别的指针
Write-Output "  --- obj 0x2C-0x60 ---"
for ($o=0x2C;$o -lt 0x60;$o+=4){
  $v=$rd::ReadInt32($obj,$o)
  Write-Output ("    obj+0x{0:X2} = 0x{1:X8} ({1})" -f $o,$v)
}
$rd::FreeHGlobal($pathPtr); $rd::FreeHGlobal($out)
