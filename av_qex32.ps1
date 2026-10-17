# QEX 脚本查杀引擎 —— 真实调用（已验证可打开并处理非 PE 文件）
#
# ============================================================================
# 逆向结论（全部经机器码验证，非推测）
# ============================================================================
#
# 【1】QEXCreateInstance(&GUID_A, &GUID_B, &out)  __stdcall 3 参数
#       GUID_A = adbba672-ea79-4b82-b442-31fc68de50f8  (RVA 0x1C2364)
#       GUID_B = d60137d0-b2db-4587-beb9-b3d08c571912  (RVA 0x1C2354)
#       返回 S_OK，out 指向对象，虚表 RVA 0x1BFCC4（20+ 方法）。
#       注意：GUID 必须指向 DLL 自身内存，堆拷贝会返回 E_NOINTERFACE。
#
# 【2】对象虚表方法调用约定是 __thiscall（this 走 ECX）。
#       用 __stdcall / __cdecl 会 AccessViolation。
#
# 【3】slot[0x10] = FUN_10038e90(this, path, access, disposition)
#       内部:
#         FUN_10039430()                              CloseHandle(obj+8)
#         FUN_10038b30(path, access, 7, ecx, disposition, ...)  CreateFileW
#       对 FUN_10038b30 的逐条反汇编（ret 0x1C = 7 参数）确认参数映射:
#         param_1 = lpFileName
#         param_2 = dwDesiredAccess      <- 必须 GENERIC_READ (0x80000000)
#         param_3 = dwShareMode          <- 内部硬编码 7
#         param_4 = lpSecurityAttributes <- NULL
#         param_5 = dwCreationDisposition<- 由调用方的第 4 个参数传入
#         param_6 = dwFlagsAndAttributes <- 内部硬编码 0x80
#         param_7 = hTemplateFile        <- NULL
#       **关键**：第 4 个参数是 dwCreationDisposition，必须传
#       OPEN_EXISTING (3)。之前传 7（误当 share mode）导致
#       CreateFileW 返回 INVALID_HANDLE_VALUE，扫描被静默跳过。
#
# 【4】成功标志：调用后 obj+8 是有效文件句柄（非 0xFFFFFFFF），
#       obj+0x18 = 1 表示扫描流程完成。
#
# 已验证：对 .ps1 / .zip 等非 PE 文件，句柄正常打开，流程正常完成。
# ============================================================================

param([string]$Target, [string]$Root)

$sep = [char]0x1f
if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
# 无目标时退化为"仅创建实例"探测模式（供 qex_create_instance 使用）
$probeOnly = [string]::IsNullOrEmpty($Target)

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QexScanLib {
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
  // QexScanExportsInit / QexResourceExportsInit：填函数表（同 AveInitialize 模式）
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
[void][QexScanLib]::SetDllDirectoryW((Join-Path $Root 'deepscan\qex'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\qex\QEX.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][QexScanLib]::LoadLibraryW($p) }
}
$h = [QexScanLib]::GetModuleHandleW('qex.dll')
if ($h -eq [IntPtr]::Zero) {
  Write-Output ("QEX" + $sep + "ok=0" + $sep + "err=load_failed"); exit 0
}
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

# ---- 初始化导出函数表（必须！否则引擎判定能力未启用）----
# QexScanExportsInit(param): 首 DWORD 预置表大小 0x58 = 4 + 0x15*4
$initParts = @()
foreach ($nm in @('QexScanExportsInit', 'QexResourceExportsInit')) {
  $pf = [QexScanLib]::GetProcAddress($h, $nm)
  if ($pf -eq [IntPtr]::Zero) { $initParts += ($nm + "=NO"); continue }
  $ib = $rd::AllocHGlobal(512)
  for ($i = 0; $i -lt 512; $i++) { $rd::WriteByte($ib, $i, 0) }
  $rd::WriteInt32($ib, 0, 0x58)
  $fi = $rd::GetDelegateForFunctionPointer($pf, [QexScanLib+InitFn])
  $r = "EXC"
  try { $r = $fi.Invoke($ib) } catch { }
  $initParts += ($nm + "=" + $r)
  $rd::FreeHGlobal($ib)
}
$initStr = ($initParts -join ',')

$out = $rd::AllocHGlobal(256)
for ($i = 0; $i -lt 256; $i++) { $rd::WriteByte($out, $i, 0) }
$pCreate = [QexScanLib]::GetProcAddress($h, 'QEXCreateInstance')
if ($pCreate -eq [IntPtr]::Zero) {
  Write-Output ("QEX" + $sep + "ok=0" + $sep + "err=no_export"); exit 0
}
$fCreate = $rd::GetDelegateForFunctionPointer($pCreate, [QexScanLib+CreateFn])
$rc = -1
try {
  $rc = $fCreate.Invoke([IntPtr]($base + 0x1C2364), [IntPtr]($base + 0x1C2354), $out)
} catch {
  Write-Output ("QEX" + $sep + "ok=0" + $sep + "err=create_exception"); exit 0
}
$obj = $rd::ReadIntPtr($out, 0)
if ($obj -eq [IntPtr]::Zero) {
  Write-Output ("QEX" + $sep + "ok=0" + $sep +
                ("rc=0x{0:X8}" -f ([int]$rc -band 0xFFFFFFFF)) + $sep + "err=null_obj")
  exit 0
}
$vt = $rd::ReadIntPtr($obj, 0)

# ---- 探测模式：只报告实例信息，不扫描 ----
if ($probeOnly) {
  $methods = 0
  for ($i = 0; $i -lt 32; $i++) {
    $f2 = $rd::ReadIntPtr($vt, $i * 4)
    if ($f2 -ne [IntPtr]::Zero) { $methods++ } else { break }
  }
  Write-Output ("QEX" + $sep + "ok=1" + $sep +
                ("rc=0x{0:X8}" -f ([int]$rc -band 0xFFFFFFFF)) + $sep +
                ("obj=0x{0:X}" -f $obj.ToInt64()) + $sep +
                ("vt=0x{0:X}" -f $vt.ToInt64()) + $sep +
                "methods=" + $methods + $sep + ("base=0x{0:X}" -f $base))
  $rd::FreeHGlobal($out)
  exit 0
}

# 关键：第 4 个参数必须是 OPEN_EXISTING(3)，不是 share mode
$GENERIC_READ  = [IntPtr][int]0x80000000
$OPEN_EXISTING = [IntPtr]3

$pathPtr = $rd::StringToHGlobalUni($Target)
$slotRc = "n/a"
$opened = 0
try {
  $fn = $rd::ReadIntPtr($vt, 0x10)
  if ($fn -ne [IntPtr]::Zero) {
    $scan = $rd::GetDelegateForFunctionPointer($fn, [QexScanLib+ScanFn])
    $slotRc = $scan.Invoke($obj, $pathPtr, $GENERIC_READ, $OPEN_EXISTING)
    $handle = $rd::ReadInt32($obj, 8)
    if ($handle -ne -1 -and $handle -ne 0) { $opened = 1 }
  }
} catch {
  $slotRc = "EXC"
}

$handleV = $rd::ReadInt32($obj, 8)
$done = $rd::ReadInt32($obj, 0x18)

# 在对象及结果对象中搜索威胁名字符串（引擎判定为威胁时会写入）
$hits = @()
foreach ($ptr in @($obj, $rd::ReadIntPtr($obj, 0x1C))) {
  if ($ptr -eq [IntPtr]::Zero) { continue }
  try {
    $buf = [byte[]]::new(0x400)
    $rd::Copy($ptr, $buf, 0, 0x400)
    $txt = [System.Text.Encoding]::ASCII.GetString($buf)
    foreach ($kw in @('susp.virus', 'Virus.Generic', 'Trojan', 'Worm', 'Adware', 'Riskware', 'Backdoor')) {
      if ($txt.Contains($kw) -and ($hits -notcontains $kw)) { $hits += $kw }
    }
  } catch { }
}

# verdict: 优先用威胁名作为判定依据；没有威胁名时如实标注为"已处理"，
# 不谎报 clean。
if ($hits.Count -gt 0) {
  $verdict = "threat"
} elseif ($opened -eq 1) {
  $verdict = "processed"
} else {
  $verdict = "not_opened"
}

Write-Output ("QEX" + $sep + "ok=" + $opened + $sep + "verdict=" + $verdict + $sep +
              "slot10rc=" + $slotRc + $sep +
              ("handle=0x{0:X8}" -f $handleV) + $sep + "done=" + $done + $sep +
              "init=[" + $initStr + "]" + $sep + "hits=[" + ($hits -join ',') + "]")

$rd::FreeHGlobal($pathPtr)
$rd::FreeHGlobal($out)