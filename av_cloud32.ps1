# 360 云安全引擎 —— jCloudScan.dll 实时云查询
#
# ============================================================================
# 逆向结论（参数个数全部由机器码 ret N 确认）
# ============================================================================
#
# jCloudScan.dll 提供完整的云查询 API：
#   CloudQueryCreate()                            __stdcall 0 参数 -> 查询句柄
#   CloudQueryCreateQueryItem()                   __stdcall 0 参数 -> 查询项
#   CloudQuerySetItemFileInfoFilePathAndSize()    __stdcall 4 参数
#   CloudQuerySetItemFileInfoScanType()           __stdcall 2 参数
#   CloudQueryNetQuery()                          __stdcall 0 参数 -> 执行
#   CloudQueryGetItemFileInfoTrojanName()         __stdcall 4 参数 -> 木马名
#   CloudQueryGetItemFileInfoCanDelete()          __stdcall 1 参数
#   CloudQueryDestroy()                           __stdcall 1 参数
#
# 这是 360 主力引擎（云安全）的实时查杀接口，不是签名/信誉查询。
# ============================================================================

param([string]$Target, [string]$Root)

$sep = [char]0x1f
if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { $Target = 'C:\Windows\Sysnative\notepad.exe' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class CloudQ {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr F0();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F2(IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][CloudQ]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\jcloudscan.dll',
                 'deepscan\cloudcom2.dll', 'deepscan\CloudEngine.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][CloudQ]::LoadLibraryW($p) }
}
$h = [CloudQ]::GetModuleHandleW('jcloudscan.dll')
if ($h -eq [IntPtr]::Zero) {
  Write-Output ("CLOUD" + $sep + "ok=0" + $sep + "err=load_failed"); exit 0
}
$rd = [System.Runtime.InteropServices.Marshal]

function Get-Fn($name, $type) {
  $p = [CloudQ]::GetProcAddress($h, $name)
  if ($p -eq [IntPtr]::Zero) { return $null }
  return $rd::GetDelegateForFunctionPointer($p, $type)
}

# 初始化网络基础库（1 参数，传 0）
$fInit = Get-Fn 'Init360NetBaseDll' ([CloudQ+F1])
$initRc = "skip"
if ($fInit) { try { $initRc = $fInit.Invoke([IntPtr]::Zero) } catch { $initRc = "EXC" } }

# 创建查询
$fCreate = Get-Fn 'CloudQueryCreate' ([CloudQ+F0])
if (-not $fCreate) { Write-Output ("CLOUD" + $sep + "ok=0" + $sep + "err=no_create"); exit 0 }
$query = [IntPtr]::Zero
try { $query = $fCreate.Invoke() } catch { }
if ($query -eq [IntPtr]::Zero) {
  Write-Output ("CLOUD" + $sep + "ok=0" + $sep + "err=null_query" + $sep + "init=" + $initRc)
  exit 0
}

# 创建查询项
$fItem = Get-Fn 'CloudQueryCreateQueryItem' ([CloudQ+F0])
$item = [IntPtr]::Zero
if ($fItem) { try { $item = $fItem.Invoke() } catch { } }

# 设置文件路径（4 参数：item, path, sizeLow, sizeHigh 或类似）
$fSetPath = Get-Fn 'CloudQuerySetItemFileInfoFilePathAndSize' ([CloudQ+F4])
$pathPtr = $rd::StringToHGlobalUni($Target)
$setRc = "skip"
if ($fSetPath -and $item -ne [IntPtr]::Zero) {
  try { $setRc = $fSetPath.Invoke($item, $pathPtr, [IntPtr]::Zero, [IntPtr]::Zero) } catch { $setRc = "EXC" }
}

# 设置扫描类型（2 参数）
$fSetType = Get-Fn 'CloudQuerySetItemFileInfoScanType' ([CloudQ+F2])
$typeRc = "skip"
if ($fSetType -and $item -ne [IntPtr]::Zero) {
  try { $typeRc = $fSetType.Invoke($item, [IntPtr]1) } catch { $typeRc = "EXC" }
}

# 创建查询项数组并加入（NetQuery 需要的是数组，不是裸 item）
$fArr = Get-Fn 'CloudQueryCreateItemArray' ([CloudQ+F0])
$arr = [IntPtr]::Zero
if ($fArr) { try { $arr = $fArr.Invoke() } catch { } }
$fApp = Get-Fn 'CloudQueryAppendItemArray' ([CloudQ+F2])
$appRc = "skip"
if ($fApp -and $arr -ne [IntPtr]::Zero -and $item -ne [IntPtr]::Zero) {
  try { $appRc = $fApp.Invoke($arr, $item) } catch { $appRc = "EXC" }
}

# 执行网络查询
# 汇编 C2 0C 00 确认 CloudQueryNetQuery 是 3 个栈参数（ret 0xC）
$fNet = Get-Fn 'CloudQueryNetQuery' ([CloudQ+F4])
$netRc = "skip"
if ($fNet) {
  $tgt = if ($arr -ne [IntPtr]::Zero) { $arr } else { $item }
  try { $netRc = $fNet.Invoke($query, $tgt, [IntPtr]::Zero, [IntPtr]::Zero) } catch { $netRc = "EXC" }
}

# 查询错误码
$fErr = Get-Fn 'CloudQueryGetQueryError' ([CloudQ+F1])
$errRc = "skip"
if ($fErr) { try { $errRc = $fErr.Invoke($query) } catch { $errRc = "EXC" } }

# 取木马名（4 参数：item, outBuf, bufLen, outLen?）
$fName = Get-Fn 'CloudQueryGetItemFileInfoTrojanName' ([CloudQ+F4])
$name = ""
if ($fName -and $item -ne [IntPtr]::Zero) {
  $nb = $rd::AllocHGlobal(1024)
  for ($i = 0; $i -lt 1024; $i++) { $rd::WriteByte($nb, $i, 0) }
  try {
    $r = $fName.Invoke($item, $nb, [IntPtr]512, [IntPtr]::Zero)
    $name = $rd::PtrToStringUni($nb)
    if (-not $name) { $name = $rd::PtrToStringAnsi($nb) }
  } catch { $name = "<EXC>" }
  $rd::FreeHGlobal($nb)
}

Write-Output ("CLOUD" + $sep + "file=" + (Split-Path $Target -Leaf) + $sep +
              "init=" + $initRc + $sep + "query=0x" + $query.ToInt64().ToString("X") + $sep +
              "item=0x" + $item.ToInt64().ToString("X") + $sep +
              "set=" + $setRc + $sep + "type=" + $typeRc + $sep + "append=" + $appRc + $sep +
              "net=" + $netRc + $sep + "err=" + $errRc + $sep + "name='" + $name + "'")

# 清理
$fDItem = Get-Fn 'CloudQueryDestroyQueryItem' ([CloudQ+F1])
if ($fDItem -and $item -ne [IntPtr]::Zero) { try { [void]$fDItem.Invoke($item) } catch { } }
$fDQ = Get-Fn 'CloudQueryDestroy' ([CloudQ+F1])
if ($fDQ) { try { [void]$fDQ.Invoke($query) } catch { } }
$rd::FreeHGlobal($pathPtr)