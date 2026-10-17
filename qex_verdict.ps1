param([string]$Target, [string]$Root)
if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QV {
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
  // 2 参数 thiscall getter
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int Get2(IntPtr self, IntPtr a, IntPtr b);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop
[void][QV]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll','deepscan\BAPI.dll','deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QV]::LoadLibraryW($p) }
}
$h = [QV]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()
foreach ($nm in @('QexScanExportsInit','QexResourceExportsInit')) {
  $pf = [QV]::GetProcAddress($h,$nm)
  if ($pf -eq [IntPtr]::Zero) { continue }
  $ib = $rd::AllocHGlobal(512)
  for ($i=0;$i -lt 512;$i++){ $rd::WriteByte($ib,$i,0) }
  $rd::WriteInt32($ib,0,0x58)
  $fi = $rd::GetDelegateForFunctionPointer($pf,[QV+InitFn])
  try { [void]$fi.Invoke($ib) } catch { }
  $rd::FreeHGlobal($ib)
}
$out = $rd::AllocHGlobal(256)
for ($i=0;$i -lt 256;$i++){ $rd::WriteByte($out,$i,0) }
$fCreate = $rd::GetDelegateForFunctionPointer([QV]::GetProcAddress($h,'QEXCreateInstance'),[QV+CreateFn])
[void]$fCreate.Invoke([IntPtr]($base+0x1C2364),[IntPtr]($base+0x1C2354),$out)
$obj = $rd::ReadIntPtr($out,0)
if ($obj -eq [IntPtr]::Zero) { Write-Output "null_obj"; exit 0 }
$vt = $rd::ReadIntPtr($obj,0)
$pathPtr = $rd::StringToHGlobalUni($Target)
$fn = $rd::ReadIntPtr($vt,0x10)
$scan = $rd::GetDelegateForFunctionPointer($fn,[QV+ScanFn])
try { [void]$scan.Invoke($obj,$pathPtr,[IntPtr][int]0x80000000,[IntPtr]3) } catch { }

$inner = $rd::ReadIntPtr($obj,4)
Write-Output ("TARGET " + $Target)
if ($inner -eq [IntPtr]::Zero) { Write-Output "  inner null"; exit 0 }
$ivt = $rd::ReadIntPtr($inner,0)
Write-Output ("  inner=0x{0:X} vt=0x{1:X}" -f $inner.ToInt64(),$ivt.ToInt64())

# inner 对象字段快照（扫描后）
Write-Output "  --- inner 字段 ---"
for ($o=0;$o -lt 0x60;$o+=4){
  $v=$rd::ReadInt32($inner,$o)
  Write-Output ("    +0x{0:X2} = {1} (0x{1:X8})" -f $o,$v)
}
# 调用各 getter 槽位
Write-Output "  --- 调用 getter 槽位 ---"
foreach ($slot in @(0x48,0x4C,0x50,0x54,0x58,0x5C,0x3C,0x40,0x44,0x2C,0x30,0x34,0x38)){
  $f = $rd::ReadIntPtr($ivt,$slot)
  if ($f -eq [IntPtr]::Zero) { Write-Output ("    [0x{0:X2}] 空" -f $slot); continue }
  $g = $rd::GetDelegateForFunctionPointer($f,[QV+Get2])
  $r1="EXC"; $r2="EXC"
  try { $r1 = $g.Invoke($inner,[IntPtr]0,[IntPtr]0) } catch { }
  try { $r2 = $g.Invoke($inner,[IntPtr]::Zero,[IntPtr]0) } catch { }
  Write-Output ("    [0x{0:X2}] (0,0)={1}  (null,0)={2}" -f $slot,$r1,$r2)
}
$rd::FreeHGlobal($pathPtr); $rd::FreeHGlobal($out)
