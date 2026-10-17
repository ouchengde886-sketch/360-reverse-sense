# Create360Object 正确签名调用
#
# ============================================================================
# 反汇编确认参数使用点（RVA 0x38B46）：
#   +0x034: 8B 75 0C   mov esi,[ebp+0x0C]   -> param_3 被读
#   +0x07B: 8B 45 10   mov eax,[ebp+0x10]   -> param_4 被读
#   +0x1F9: 8B 4D 10   mov ecx,[ebp+0x10]   -> param_4
#   +0x3F5: 8B 45 08   mov eax,[ebp+0x08]   -> param_2
#
# 结构：这是一个**多分支对象工厂**，18 个分支各对应一个 GUID：
#   +0x03C GUID E0CCA13B-E6A7-420E-8AA6-D5AC205B0191 -> 分支 call 0xD94B8
#   +0x093 GUID CD9F10D7-067C-4CE7-93A6-7BEEC4424DAF -> 分支 call 0x3CA45
#   +0x0E5 GUID 2EC18DD8-F5F6-4734-853E-497C32154ADF -> 分支 call 0x3EB07
#   +0x120 GUID 7E288C33-F959-49B8-9324-5AE32A3B07BE -> 分支 call 0x8A104
#   ... 共 18 个
#
# 每个分支形如：
#   push GUID / push param_3 / push 0x10 / call 0x162AC1   ; 类型检查
#   test eax,eax / jnz 下一分支
#   push 0xC0 / call operator new
#   call <该分支的对象构造函数>
#   mov [param_4], eax                                      ; 写出对象
#
# 所以签名是：Create360Object(param_2, param_3, param_4)
# 但 param_3 在 +0x034 就被读为 esi，且作为数据传给 0x162AC1。
# 0x162AC1(guid, data, 0x10) 里的 0x10 是**类型选择器**。
#
# 用法: -Form N
#   1: (0, 0, out)      3 参数
#   2: (0, 0, 0, out)   4 参数
#   3: (out, 0, 0, 0)   4 参数，out 在前
#   4: (0, out, 0, 0)   4 参数
# ============================================================================

param([string]$Root, [int]$Form)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Form) { $Form = 2 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class DF {
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
  public delegate int F3(IntPtr a, IntPtr b, IntPtr c);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][DF]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][DF]::LoadLibraryW($p) }
}
$h = [DF]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

$pEng = [DF]::GetProcAddress($h, 'EngLib_Init')
try {
  $ge = $rd::GetDelegateForFunctionPointer($pEng, [DF+F1])
  [void]$ge.Invoke([IntPtr]::Zero)
} catch { }

$pCreate = [DF]::GetProcAddress($h, 'Create360Object')
$out = $rd::AllocHGlobal(64)
for ($i = 0; $i -lt 64; $i++) { $rd::WriteByte($out, $i, 0) }

$rc = "EXC"
try {
  if ($Form -eq 1) {
    $g = $rd::GetDelegateForFunctionPointer($pCreate, [DF+F3])
    $rc = $g.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $out)
  } elseif ($Form -eq 2) {
    $g = $rd::GetDelegateForFunctionPointer($pCreate, [DF+F4])
    $rc = $g.Invoke([IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, $out)
  } elseif ($Form -eq 3) {
    $g = $rd::GetDelegateForFunctionPointer($pCreate, [DF+F4])
    $rc = $g.Invoke($out, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
  } else {
    $g = $rd::GetDelegateForFunctionPointer($pCreate, [DF+F4])
    $rc = $g.Invoke([IntPtr]::Zero, $out, [IntPtr]::Zero, [IntPtr]::Zero)
  }
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