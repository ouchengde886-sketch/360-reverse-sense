# Create360Object 传 GUID —— 找到正确的对象创建方式
#
# ============================================================================
# Create360Object (RVA 0x38B46) 反汇编关键：
#   +030: mov esi,[ebp+0x0C]  ; param_2
#   +035: push 0x10 / pop edi
#   +037: push edi (0x10) / push esi / push 0x101C9160
#   +041: call 0x162AC1
#
# 0x101C9160 -> RVA 0x1C9160 处是一个 GUID：
#   E0CCA13B-E6A7-420E-8AA6-D5AC205B0191
#
# form=2 (0, out) 返回 0x80004002 E_NOINTERFACE —— 说明 param_1 被当 GUID 用。
# 本次：把该 GUID 作为 param_1 传入。
#
# 用法: -Form N
#   1: (guid, out)          GUID 在模块内（RVA 0x1C9160）
#   2: (guidCopy, out)      堆拷贝的 GUID
#   3: (guid2, out)         RVA 0x1C9170 的 GUID
#   4: (guid3, out)         RVA 0x1C9180 的 GUID
#   5: (guid4, out)         RVA 0x1C91D0 的 GUID
# ============================================================================

param([string]$Root, [int]$Form)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Form) { $Form = 1 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class DG {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F2(IntPtr a, IntPtr b);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][DG]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][DG]::LoadLibraryW($p) }
}
$h = [DG]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

# EngLib_Init(NULL) 先初始化
$pEng = [DG]::GetProcAddress($h, 'EngLib_Init')
try {
  $ge = $rd::GetDelegateForFunctionPointer($pEng, [DG+F1])
  [void]$ge.Invoke([IntPtr]::Zero)
} catch { }

# 选 GUID 源
$guidRva = switch ($Form) { 3 { 0x1C9170 } 4 { 0x1C9180 } 5 { 0x1C91D0 } default { 0x1C9160 } }
$guidInModule = [IntPtr]($base + $guidRva)

if ($Form -eq 2) {
  # 堆拷贝
  $g = $rd::AllocHGlobal(16)
  for ($i = 0; $i -lt 16; $i++) { $rd::WriteByte($g, $i, $rd::ReadByte($guidInModule, $i)) }
  $guidPtr = $g
} else {
  $guidPtr = $guidInModule
}

$pCreate = [DG]::GetProcAddress($h, 'Create360Object')
$out = $rd::AllocHGlobal(64)
for ($i = 0; $i -lt 64; $i++) { $rd::WriteByte($out, $i, 0) }

$rc = "EXC"
try {
  $f = $rd::GetDelegateForFunctionPointer($pCreate, [DG+F2])
  $rc = $f.Invoke($guidPtr, $out)
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

$v = $rd::ReadIntPtr($out, 0)
Write-Output ("CREATE" + [char]0x1f + "form=" + $Form + [char]0x1f + "rc=" + $rc + [char]0x1f + ("out=0x{0:X}" -f $v.ToInt64()))
if ($v -ne [IntPtr]::Zero) {
  $vt = $rd::ReadIntPtr($v, 0)
  Write-Output ("  obj=0x{0:X} vt=0x{1:X} (RVA 0x{2:X})" -f $v.ToInt64(), $vt.ToInt64(), ($vt.ToInt64() - $base))
  for ($k = 0; $k -lt 24; $k++) {
    $fp = $rd::ReadIntPtr($vt, $k * 4)
    if ($fp -ne [IntPtr]::Zero) {
      Write-Output ("  [{0:X2}] RVA 0x{1:X}" -f ($k * 4), ($fp.ToInt64() - $base))
    }
  }
}

$rd::FreeHGlobal($out)