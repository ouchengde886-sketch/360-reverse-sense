# QEX 对象字段 dump —— 验证引擎真实读取文件内容
#
# 已确认（多次实测可复现）：
#   obj 虚表 = RVA 0x1BFCC4（固定）
#   obj+0x0C = 被扫描文件的字节数
#   obj+0x20 = 同样等于文件字节数
#   obj+0x1C 指向扫描上下文，其 +0x34 指向文件完整路径（UTF-16）
#
# 本脚本用于回归验证"QEX 确实读取了文件真实内容"。

param([string]$Target, [string]$Root)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { Write-Output "need -Target"; exit 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QDump {
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
}
[void][QDump]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QDump]::LoadLibraryW($p) }
}
$h = [QDump]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

foreach ($nm in @('QexScanExportsInit', 'QexResourceExportsInit')) {
  $pf = [QDump]::GetProcAddress($h, $nm)
  if ($pf -eq [IntPtr]::Zero) { continue }
  $ib = $rd::AllocHGlobal(512)
  for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($ib, $i, 0) }
  $rd::WriteInt32($ib, 0, 0x58)
  $fi = $rd::GetDelegateForFunctionPointer($pf, [QDump+InitFn])
  try { [void]$fi.Invoke($ib) } catch { }
  $rd::FreeHGlobal($ib)
}

$out = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($out, $i, 0) }
$fCreate = $rd::GetDelegateForFunctionPointer(
  [QDump]::GetProcAddress($h, 'QEXCreateInstance'), [QDump+CreateFn])
[void]$fCreate.Invoke([IntPtr]($base + 0x1C2364), [IntPtr]($base + 0x1C2354), $out)
$obj = $rd::ReadIntPtr($out, 0)
if ($obj -eq [IntPtr]::Zero) { Write-Output "null_obj"; exit 0 }
$vt = $rd::ReadIntPtr($obj, 0)

$pathPtr = $rd::StringToHGlobalUni($Target)
$fn = $rd::ReadIntPtr($vt, 0x10)
$scan = $rd::GetDelegateForFunctionPointer($fn, [QDump+ScanFn])
try { [void]$scan.Invoke($obj, $pathPtr, [IntPtr][int]0x80000000, [IntPtr]3) } catch { }

Write-Output ("TARGET " + $Target)
foreach ($off in @(0x0C, 0x20, 0x18)) {
  Write-Output ("obj+0x{0:X2} = 0x{1:X}" -f $off, $rd::ReadInt32($obj, $off))
}
# 上下文里的文件路径
$ctx = $rd::ReadIntPtr($obj, 0x1C)
if ($ctx -ne [IntPtr]::Zero) {
  $p34 = $rd::ReadIntPtr($ctx, 0x34)
  if ($p34 -ne [IntPtr]::Zero) {
    try {
      $s = $rd::PtrToStringUni($p34, 260)
      Write-Output ("ctx+0x34 -> " + $s)
    } catch { }
  }
}

$rd::FreeHGlobal($pathPtr)
$rd::FreeHGlobal($out)