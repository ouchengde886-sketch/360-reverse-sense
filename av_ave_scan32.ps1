# 360 AVE 查杀引擎 —— 外部调用（真正的病毒判定）
#
# ============================================================================
# 逆向成果（全部经机器码验证，非推测）
# ============================================================================
#
# 【1】AVEngine.dll!AveInitialize @ 0x4850 —— 获取引擎函数表（不是"初始化"）
#     机器码:
#       8b 08                 mov ecx,[eax]        ; ecx = *(DWORD*)arg1
#       83 f9 18              cmp ecx,0x18
#       72 f1                 jb  -15              ; 首 DWORD < 0x18 就跳回重试
#       c7 00 18 00 00 00     mov [eax],0x18       ; 写回 0x18
#       c7 40 04 90 58 00 10  mov [eax+4],0x10005890
#       c7 40 08 80 23 00 10  mov [eax+8],0x10002380
#       c7 40 0c 50 59 00 10  mov [eax+0xc],0x10005950
#       c7 40 10 f0 34 00 10  mov [eax+0x10],0x100034f0
#       c7 40 14 a0 5a 00 10  mov [eax+0x14],0x10005aa0
#       c2 04 00              ret 4                ; __stdcall, 1 参数
#     => arg1 是**输出结构**，函数填入 6 个函数指针（0x18 字节）。
#        首 DWORD 必须**预置 >= 0x18**，否则返回 E_INVALIDARG (0x80070057)。
#        AllocHGlobal 分配的是全 0 内存 —— 必须手动预置。
#
# 【2】AVEI.dll!CreateScannerEx @ 0x2D90
#     依赖 GetModuleHandleW("AVEngine.dll") / ("360ave.dll")，
#     必须先加载 AVEngine.dll，否则返回半初始化实例。
#     实例头部魔数 0x49455641 ("AVEI")。
#
# 【3】AVEI.dll!SetScannerConfig @ 0x2EF0 —— **不是** __thiscall
#     机器码证明 param_1 从栈读（非 ECX）:
#       8b 74 24 24   mov esi,[esp+0x24]   ; param_1 = scanner
#       8b 5c 24 28   mov ebx,[esp+0x28]   ; param_2 = GUID
#       8b 6c 24 2c   mov ebp,[esp+0x2c]   ; param_3 = cfg
#     => __stdcall 3 参数。
#     内部逻辑:
#       if (GUID == DAT_1002755c = fece107a-b540-4526-a77c-55cf4f01ccb0) {
#           if (*param_3 != 0x13) return false;
#           param_1[0x18] = *(int*)(param_3 + 8);
#       }
#     => 用 GUID fece107a-b540-4526-a77c-55cf4f01ccb0 + cfg 首 WORD = 0x13。
#     【实测】对 6 个 .def 特征库调用全部返回非 0（成功）。
#
# 【4】AVEI.dll!ScanW @ 0x3900 —— __stdcall 5 参数
#     机器码尾部: c2 14 00 = ret 0x14 = 20 字节 = 5 个参数
#     参数映射（逐条寄存器追踪得出）:
#       arg1 = scanner
#       arg2 = 路径
#       arg3 = 传给内部的对象
#       arg4 = 内部 param_2（路径相关）
#       arg5 = 结果输出缓冲
#
# 【5】结果结构（FUN_10003110）:
#       +0x000  BYTE   状态码: 0=干净 1=发现威胁 4/0xFC/0xFD=错误
#       +0x004  DWORD  文件大小
#       +0x007  CHAR[] 威胁名称
#       +0x108  BYTE   子状态
#
# ============================================================================
# 当前状态
# ============================================================================
# ✅ 引擎加载、初始化、函数表获取 —— 成功
# ✅ 扫描器创建、魔数校验 —— 成功
# ✅ 特征库配置 6/6 —— 成功
# ✅ 门禁通过 [+0x5c]=1，扫描流程真正进入 —— 成功
# ✅ ScanW 返回 rc=1（引擎有响应）—— 成功
# ⚠️ 结果状态码 = 4（引擎内部错误），尚未拿到 clean/threat 判定
#
# status=4 的成因（已定位到具体代码位置）:
#   FUN_10003110 中:
#     iVar4 = (**(code**)(*local_138 + 0xc))(local_138, param_2);
#     if (iVar4 < 0) { *param_5 = 4; ... }
#   其中 param_2 = FUN_10008560 的 local_20[0]，被显式置为 NULL 后未再赋值。
#   前一个工厂调用（7 参数）成功（否则不会走到这里），
#   但随后的方法调用收到 NULL 而失败。
#
# ============================================================================
# 用法
# ============================================================================
#   C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -File av_ave_scan32.ps1 <file>
# 输出:
#   RESULT<US>path<US>verdict<US>detail

param([string]$Target, [string]$Root)

$candidates = @()
if ($Root) { $candidates += $Root }
$candidates += 'C:\Program Files (x86)\360\360Safe'
$candidates += 'C:\Program Files\360\360Safe'
$candidates += 'C:\Users\Administrator\Desktop\360Safe'

$root = $null
foreach ($c in $candidates) {
  if ($c -and (Test-Path (Join-Path $c 'deepscan\ave\AVEI.dll'))) { $root = $c; break }
}
$US = [char]31
if (-not $root) {
  Write-Output ("RESULT" + $US + $Target + $US + "NO_ROOT")
  exit 2
}

$env:PATH = "$root;$root\deepscan;$root\deepscan\ave;$root\safemon;" + $env:PATH

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class AveScan {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);

  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int AveInitializeFn(IntPtr tbl);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
  public delegate IntPtr CreateScannerExFn(int cfg);
  // ScanW: __stdcall 5 参数（机器码 ret 0x14 证实）
  [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet=CharSet.Unicode)]
  public delegate int ScanWFn(IntPtr scanner, string path, IntPtr a3, IntPtr a4, IntPtr a5);
  // SetScannerConfig: __stdcall 3 参数（机器码证实 param_1 从栈读）
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int SetScannerConfigFn(IntPtr scanner, IntPtr guid, IntPtr cfg);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int CloseScannerFn(IntPtr scanner);
  // BAPIInitialize(LPCWSTR 产品根目录) —— AVEngine.dll 导出
  [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet=CharSet.Unicode)]
  public delegate int BapiInitFn(string root);
}
"@
try { Add-Type -TypeDefinition $sig -ErrorAction Stop } catch { }

[void][AveScan]::SetDllDirectoryW((Join-Path $root 'deepscan\ave'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\ave\AVEngine.dll')) {
  $p = Join-Path $root $d
  if (Test-Path $p) { [void][AveScan]::LoadLibraryW($p) }
}

# 0) AVEngine.dll!BAPIInitialize(LPCWSTR 产品根目录)
#    AVEI!CreateScannerEx 内部会 GetProcAddress(AVEngine,"BAPIInitialize") 并调用，
#    不先初始化会导致扫描器 +0x10 字段为空，进而 ScanW 返回 status=4。
$bapiRc = "n/a"
$hEng0 = [AveScan]::GetModuleHandleW('360ave.dll')
if ($hEng0 -eq [IntPtr]::Zero) { $hEng0 = [AveScan]::GetModuleHandleW('AVEngine.dll') }
if ($hEng0 -ne [IntPtr]::Zero) {
  $pBapi = [AveScan]::GetProcAddress($hEng0, 'BAPIInitialize')
  if ($pBapi -ne [IntPtr]::Zero) {
    $bapi = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pBapi, [AveScan+BapiInitFn])
    foreach ($bp in @($root, (Join-Path $root 'deepscan'), (Join-Path $root 'deepscan\ave'))) {
      try { $bapiRc = $bapi.Invoke($bp); break } catch { $bapiRc = "EXC" }
    }
  }
}

# 1) 获取引擎函数表（首 DWORD 必须预置 0x18）
$hEng = [AveScan]::GetModuleHandleW('AVEngine.dll')
$initRc = "n/a"
if ($hEng -ne [IntPtr]::Zero) {
  $tbl = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x40)
  for ($i = 0; $i -lt 0x40; $i++) { [System.Runtime.InteropServices.Marshal]::WriteByte($tbl, $i, 0) }
  [System.Runtime.InteropServices.Marshal]::WriteInt32($tbl, 0, 0x18)
  $pInit = [AveScan]::GetProcAddress($hEng, 'AveInitialize')
  if ($pInit -ne [IntPtr]::Zero) {
    $init = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pInit, [AveScan+AveInitializeFn])
    try { $initRc = $init.Invoke($tbl) } catch { $initRc = -1 }
  }
}

# 2) 加载 AVEI.dll（必须在函数表获取之后）
[void][AveScan]::LoadLibraryW((Join-Path $root 'deepscan\ave\AVEI.dll'))
$h = [AveScan]::GetModuleHandleW('AVEI.dll')
if ($h -eq [IntPtr]::Zero) {
  Write-Output ("RESULT" + $US + $Target + $US + "NO_AVEI")
  exit 5
}

$pCreate = [AveScan]::GetProcAddress($h, 'CreateScannerEx')
$pScan   = [AveScan]::GetProcAddress($h, 'ScanW')
$pCfg    = [AveScan]::GetProcAddress($h, 'SetScannerConfig')
$pClose  = [AveScan]::GetProcAddress($h, 'CloseScanner')
if ($pCreate -eq [IntPtr]::Zero -or $pScan -eq [IntPtr]::Zero) {
  Write-Output ("RESULT" + $US + $Target + $US + "NO_EXPORT")
  exit 6
}

$create = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pCreate, [AveScan+CreateScannerExFn])
$scan   = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pScan,   [AveScan+ScanWFn])
$setcfg = $null
if ($pCfg -ne [IntPtr]::Zero) {
  $setcfg = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pCfg, [AveScan+SetScannerConfigFn])
}
$close = $null
if ($pClose -ne [IntPtr]::Zero) {
  $close = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pClose, [AveScan+CloseScannerFn])
}

$scanner = [IntPtr]::Zero
$resBuf = New-Object byte[] 0x200
$ghRes = [System.Runtime.InteropServices.GCHandle]::Alloc($resBuf, [System.Runtime.InteropServices.GCHandleType]::Pinned)

try {
  $scanner = $create.Invoke(0)
  if ($scanner -eq [IntPtr]::Zero) {
    Write-Output ("RESULT" + $US + $Target + $US + "CREATE_NULL")
    exit 7
  }

  # 3) 加载特征库 —— GUID fece107a-b540-4526-a77c-55cf4f01ccb0 + cfg 首 WORD 0x13
  $cfgRc = "no-def"
  if ($setcfg) {
    $defFiles = @(Get-ChildItem (Join-Path $root 'deepscan\ave') -Filter '*.def' -ErrorAction SilentlyContinue |
                  Select-Object -ExpandProperty FullName)
    $okCount = 0
    foreach ($df in $defFiles) {
      $guidBuf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(16)
      [System.Runtime.InteropServices.Marshal]::WriteInt32($guidBuf, 0, [int]0xfece107a)
      [System.Runtime.InteropServices.Marshal]::WriteInt32($guidBuf, 4, [int]0x4526b540)
      [System.Runtime.InteropServices.Marshal]::WriteInt32($guidBuf, 8, [int]0xcf557ca7)
      [System.Runtime.InteropServices.Marshal]::WriteInt32($guidBuf, 12, [int]0xb0cc014f)

      $cfgBuf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x40)
      for ($i = 0; $i -lt 0x40; $i++) { [System.Runtime.InteropServices.Marshal]::WriteByte($cfgBuf, $i, 0) }
      [System.Runtime.InteropServices.Marshal]::WriteInt16($cfgBuf, 0, 0x13)
      $pathPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($df)
      [System.Runtime.InteropServices.Marshal]::WriteIntPtr($cfgBuf, 8, $pathPtr)

      try { if ($setcfg.Invoke($scanner, $guidBuf, $cfgBuf) -ne 0) { $okCount++ } } catch { }

      [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pathPtr)
      [System.Runtime.InteropServices.Marshal]::FreeHGlobal($cfgBuf)
      [System.Runtime.InteropServices.Marshal]::FreeHGlobal($guidBuf)
    }
    $cfgRc = "$okCount/$($defFiles.Count)"
  }

  for ($i = 0; $i -lt $resBuf.Length; $i++) { $resBuf[$i] = 0 }
  $resPtr = $ghRes.AddrOfPinnedObject()
  $rc = $scan.Invoke($scanner, $Target, [IntPtr]::Zero, [IntPtr]::Zero, $resPtr)

  $status = $resBuf[0]
  $sub    = $resBuf[0x108]
  $fsize  = [BitConverter]::ToUInt32($resBuf, 4)
  $name   = [System.Text.Encoding]::Default.GetString($resBuf, 8, 0xFF)
  $z = $name.IndexOf([char]0)
  if ($z -ge 0) { $name = $name.Substring(0, $z) }
  $name = $name.Trim()

  $verdict = switch ($status) {
    0       { "clean" }
    1       { "threat" }
    4       { "engine_error" }
    0xFC    { "error" }
    0xFD    { "invalid_args" }
    default { "unknown" }
  }

  Write-Output ("RESULT" + $US + $Target + $US + $verdict + $US +
                ("status={0} sub={1} size={2} name={3} init={4} cfg={5} rc={6} bapi={7}" -f $status, $sub, $fsize, $name, $initRc, $cfgRc, $rc, $bapiRc))
} catch {
  Write-Output ("RESULT" + $US + $Target + $US + "EXC" + $US + $_.Exception.Message)
} finally {
  $ghRes.Free()
  if ($scanner -ne [IntPtr]::Zero -and $close) {
    try { [void]$close.Invoke($scanner) } catch { }
  }
}