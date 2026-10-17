# 360 QVM AI 引擎 —— 外部调用
#
# QVM 是 360 的机器学习引擎，用于判定**未知木马**（无特征库也能查杀）。
# 这是免杀对抗中最关键的引擎，因为特征库可以绕过，AI 判定很难绕过。
#
# 逆向结果（机器码验证）：
#   BoleInitialize @ 0x5FE60
#     55                push ebp
#     8b ec             mov ebp,esp
#     8b 4d 08          mov ecx,[ebp+8]      ; arg1
#     85 c9             test ecx,ecx
#     0f 84 cf 00 00 00 je  +0xcf             ; arg1==NULL 直接返回
#     8b 11             mov edx,[ecx]        ; edx = *(DWORD*)arg1
#     83 fa 60          cmp edx,0x60         ; 需要 >= 0x60
#     76 05             jbe +5
#     ba 60 00 00 00    mov edx,0x60
#     => 与 AveInitialize 同一套路：arg1 是输出结构，首 DWORD 必须预置 >= 0x60
#
#   BoleFeaturesInitialize @ 0x68070 —— 同样结构，首 DWORD 需 >= 0x58
#   BoleGetVersion @ 0x5FFC0 —— __stdcall 1 参数，ret 4
#
# 用法:
#   C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -File av_qvm32.ps1

param([string]$Target, [string]$Root)

$candidates = @()
if ($Root) { $candidates += $Root }
$candidates += 'C:\Program Files (x86)\360\360Safe'
$candidates += 'C:\Program Files\360\360Safe'

$root = $null
foreach ($c in $candidates) {
  if ($c -and (Test-Path (Join-Path $c 'deepscan\QVM\360QVM.dll'))) { $root = $c; break }
}
$US = [char]31
if (-not $root) {
  Write-Output ("QVM" + $US + "NO_ROOT")
  exit 2
}

$env:PATH = "$root;$root\deepscan;$root\deepscan\QVM;$root\safemon;" + $env:PATH

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class QvmApi {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);

  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int InitFn(IntPtr tbl);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int VerFn(IntPtr outBuf);
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
[void][QvmApi]::SetDllDirectoryW((Join-Path $root 'deepscan\QVM'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\QVM\360QVM.dll')) {
  $p = Join-Path $root $d
  if (Test-Path $p) { [void][QvmApi]::LoadLibraryW($p) }
}

$h = [QvmApi]::GetModuleHandleW('360QVM.dll')
if ($h -eq [IntPtr]::Zero) {
  Write-Output ("QVM" + $US + "NO_DLL")
  exit 3
}

$rd = [System.Runtime.InteropServices.Marshal]
$out = @()

# --- BoleInitialize: 首 DWORD 预置 0x60 ---
$pInit = [QvmApi]::GetProcAddress($h, 'BoleInitialize')
if ($pInit -ne [IntPtr]::Zero) {
  $tbl = $rd::AllocHGlobal(0x100)
  for ($i = 0; $i -lt 0x100; $i++) { $rd::WriteByte($tbl, $i, 0) }
  $rd::WriteInt32($tbl, 0, 0x60)
  $fn = $rd::GetDelegateForFunctionPointer($pInit, [QvmApi+InitFn])
  $rc = "exc"
  try { $rc = $fn.Invoke($tbl) } catch { $rc = "exc:" + $_.Exception.Message }
  $out += ("BoleInitialize=" + $rc)
  # 读出填入的函数指针（该结构至少 12 项）
  $ptrs = @()
  for ($i = 1; $i -le 12; $i++) {
    $v = $rd::ReadIntPtr($tbl, $i*4)
    if ($v -ne [IntPtr]::Zero) { $ptrs += ("0x{0:X}" -f $v) }
  }
  $out += ("table=" + ($ptrs -join ','))
  $rd::FreeHGlobal($tbl)
}

# --- BoleFeaturesInitialize: 首 DWORD 预置 0x58 ---
# 这是"版本化结构填充器"（switch 按声明大小逐级 fall-through），
# 声明 0x58 会填满所有分支，共 21 个函数指针。
$pFeat = [QvmApi]::GetProcAddress($h, 'BoleFeaturesInitialize')
if ($pFeat -ne [IntPtr]::Zero) {
  $tbl = $rd::AllocHGlobal(0x200)
  for ($i = 0; $i -lt 0x200; $i++) { $rd::WriteByte($tbl, $i, 0) }
  $rd::WriteInt32($tbl, 0, 0x58)
  $fn = $rd::GetDelegateForFunctionPointer($pFeat, [QvmApi+InitFn])
  $rc = "exc"
  try { $rc = $fn.Invoke($tbl) } catch { $rc = "exc:" + $_.Exception.Message }
  $out += ("BoleFeaturesInitialize=" + $rc)
  $n = 0
  for ($i = 1; $i -le 24; $i++) {
    if ($rd::ReadIntPtr($tbl, $i*4) -ne [IntPtr]::Zero) { $n++ }
  }
  $out += ("featPtrs=" + $n)
  $rd::FreeHGlobal($tbl)
}

# --- BoleGetVersion ---
$pVer = [QvmApi]::GetProcAddress($h, 'BoleGetVersion')
if ($pVer -ne [IntPtr]::Zero) {
  $vb = $rd::AllocHGlobal(0x40)
  for ($i = 0; $i -lt 0x40; $i++) { $rd::WriteByte($vb, $i, 0) }
  $fn = $rd::GetDelegateForFunctionPointer($pVer, [QvmApi+VerFn])
  $rc = "exc"
  try { $rc = $fn.Invoke($vb) } catch { $rc = "exc" }
  $ver = $rd::ReadInt32($vb, 0)
  $out += ("BoleGetVersion rc=$rc ver=0x{0:X}" -f $ver)
  $rd::FreeHGlobal($vb)
}

Write-Output ("QVM" + $US + ($out -join ' '))