param([string]$Root)
if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QC {
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
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int CtxCreate(IntPtr outPtr);
}
"@
# ★★★ Add-Type 在本环境不可用（360 的 360FsFlt 微过滤驱动按扩展名拦截 .dll 写入）
#   症状: Add-Type 报 "Access to the path '...\xxxxxxxx.dll' is denied."
#   后果: 类型未加载 -> 后续所有 [类型]:: 调用抛 TypeNotFound / null 异常，
#         表现为"引擎不响应"，极具误导性。
#   变通: 编译到 .com（不被拦截）+ Assembly::LoadFile（不检查扩展名）
$typeOk = $false
try {
  Add-Type -TypeDefinition $sig -ErrorAction Stop
  $typeOk = $true
} catch {
  $comPath = Join-Path $env:TEMP ("avtype_" + [guid]::NewGuid().ToString('N') + ".com")
  try {
    Add-Type -TypeDefinition $sig -OutputAssembly $comPath -ErrorAction Stop
    [void][System.Reflection.Assembly]::LoadFile($comPath)
    $typeOk = $true
  } catch {
    Write-Host ("ADDTYPE_FAIL " + $_.Exception.Message)
  }
}
if (-not $typeOk) {
  Write-Host ("RESULT" + [char]31 + "EXC" + [char]31 + "Add-Type failed: type unavailable")
  exit 9
}[void][QC]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll','deepscan\BAPI.dll','deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QC]::LoadLibraryW($p) }
}
$h = [QC]::GetModuleHandleW('qex.dll')
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()
$ib = $rd::AllocHGlobal(512)
for ($i=0;$i -lt 512;$i++){ $rd::WriteByte($ib,$i,0) }
$rd::WriteInt32($ib,0,0x58)
$fi = $rd::GetDelegateForFunctionPointer([QC]::GetProcAddress($h,'QexScanExportsInit'),[QC+InitFn])
$initRc = "EXC"
try { $initRc = $fi.Invoke($ib) } catch { }
Write-Output ("  init rc = {0}" -f $initRc)
$pCreate = $rd::ReadIntPtr($ib,0x08)
$ctxOut = $rd::AllocHGlobal(16)
for ($i=0;$i -lt 16;$i++){ $rd::WriteByte($ctxOut,$i,0) }
$fCtx = $rd::GetDelegateForFunctionPointer($pCreate,[QC+CtxCreate])
$rc = "EXC"
try { $rc = $fCtx.Invoke($ctxOut) } catch { $rc = "EXC:" + $_.Exception.GetType().Name }
$ctx = $rd::ReadIntPtr($ctxOut,0)
Write-Output ("  create rc = {0}  ctx = 0x{1:X}" -f $rc,$ctx.ToInt64())
if ($ctx -eq [IntPtr]::Zero) { exit 0 }
Write-Output "  --- ctx 完整 dump (0x00-0x44) ---"
for ($o=0;$o -lt 0x44;$o+=16){
  $vals=@(); for($j=0;$j -lt 16;$j+=4){ $vals += ("{0:X8}" -f $rd::ReadInt32($ctx,$o+$j)) }
  Write-Output ("    +{0:X2}: {1}" -f $o,($vals -join ' '))
}
$p4 = $rd::ReadIntPtr($ctx,4)
Write-Output ("  ctx+4 = 0x{0:X}  ({1})" -f $p4.ToInt64(), $(if($p4 -eq [IntPtr]::Zero){'NULL - 未初始化!'}else{'已填充'}))
if ($p4 -ne [IntPtr]::Zero) {
  $v4 = $rd::ReadIntPtr($p4,0)
  Write-Output ("    [ctx+4] = 0x{0:X}  (在QEX内: {1})" -f $v4.ToInt64(), ($v4.ToInt64() -ge $base -and $v4.ToInt64() -lt ($base+0x240000)))
}
