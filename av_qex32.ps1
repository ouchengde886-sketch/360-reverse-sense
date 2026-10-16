# QEX 脚本查杀引擎 —— 实例创建与状态探测
# 逆向结论（REA + Ghidra）：
#   QEXCreateInstance(&GUID_A, &GUID_B, &out)  __stdcall 3 参数，返回 S_OK
#     GUID_A = adbba672-ea79-4b82-b442-31fc68de50f8  (RVA 0x1C2364)
#     GUID_B = d60137d0-b2db-4587-beb9-b3d08c571912  (RVA 0x1C2354)
#     调用点参考 QEX.dll 内部 0x58B9 处的真实用法
#   成功后 out 指向对象，虚表 12 个方法，其中：
#     [0x10] RVA 0x38E90 = FUN_10038e90(this, wchar_t* path, a2, a3)
#            内部调用 FUN_10038b30(path, a2, 7, ...) 做实际解析
# 输出：QEX\x1fobj=0x...\x1fvt=0x...\x1fmethods=n\x1frc=0x...

$root = 'C:\Program Files (x86)\360\360Safe'
$sep = [char]0x1f

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QexProbe {
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
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][QexProbe]::SetDllDirectoryW((Join-Path $root 'deepscan\qex'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\qex\QEX.dll')) {
  $p = Join-Path $root $d
  if (Test-Path $p) { [void][QexProbe]::LoadLibraryW($p) }
}
$h = [QexProbe]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) {
  Write-Output ("QEX" + $sep + "ok=0" + $sep + "err=load_failed")
  exit 0
}
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

$out = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($out, $i, 0) }

$pCreate = [QexProbe]::GetProcAddress($h, 'QEXCreateInstance')
if ($pCreate -eq [IntPtr]::Zero) {
  Write-Output ("QEX" + $sep + "ok=0" + $sep + "err=no_export")
  exit 0
}
$f = $rd::GetDelegateForFunctionPointer($pCreate, [QexProbe+CreateFn])
$rc = -1
try {
  $rc = $f.Invoke([IntPtr]($base + 0x1C2364), [IntPtr]($base + 0x1C2354), $out)
} catch {
  Write-Output ("QEX" + $sep + "ok=0" + $sep + "err=exception")
  exit 0
}
$obj = $rd::ReadIntPtr($out, 0)

$methods = 0
$vtAddr = 0
$okFlag = 0
if ($obj -ne [IntPtr]::Zero) {
  $vt = $rd::ReadIntPtr($obj, 0)
  $vtAddr = $vt.ToInt64()
  for ($i = 0; $i -lt 12; $i++) {
    $fn = $rd::ReadIntPtr($vt, $i * 4)
    if ($fn -ne [IntPtr]::Zero) { $methods++ }
  }
  if ([int]$rc -eq 0) { $okFlag = 1 }
}

$parts = @(
  "QEX",
  "ok=$okFlag",
  ("rc=0x{0:X8}" -f ([int]$rc -band 0xFFFFFFFF)),
  ("obj=0x{0:X}" -f $obj.ToInt64()),
  ("vt=0x{0:X}" -f $vtAddr),
  "methods=$methods",
  ("base=0x{0:X}" -f $base)
)
Write-Output ($parts -join $sep)
$rd::FreeHGlobal($out)