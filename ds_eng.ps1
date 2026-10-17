# EngLib_Init 单参数探测 —— 每个参数形式独立进程，隔离 AccessViolation
#
# EngLib_Init (RVA 0x3996E) 反汇编：
#   +00A: call 0x1619EE       ; __chkstk
#   +010: mov eax,[ebp+8]     ; param_1
#   +013: push eax
#   +014: call 0x3A5E7        ; 内部函数，接收 param_1
#   +019: test eax,eax / jz 失败
#   +020: cmp dword[0x102A67AC],0
#   ...
# 说明 EngLib_Init 接收 1 个参数并转发。
#
# 用法: -Form N   N=0 无参, 1 传 0, 2 传 1, 3 传 0x204, 4 传 0x100,
#                5 传指向 0x204 的指针, 6 传 deepscan 模块基址
# ============================================================================

param([string]$Root, [int]$Form)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class DE {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F0();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F1(IntPtr a);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][DE]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][DE]::LoadLibraryW($p) }
}
$h = [DE]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()
$pEng = [DE]::GetProcAddress($h, 'EngLib_Init')

$arg = switch ($Form) {
  0 { $null }
  1 { [IntPtr]::Zero }
  2 { [IntPtr]1 }
  3 { [IntPtr]0x204 }
  4 { [IntPtr]0x100 }
  5 { $script:buf = $rd::AllocHGlobal(8); $rd::WriteInt32($script:buf, 0, 0x204); $script:buf }
  6 { [IntPtr]$base }
  default { [IntPtr]::Zero }
}

$rc = "EXC"
try {
  if ($Form -eq 0) {
    $g = $rd::GetDelegateForFunctionPointer($pEng, [DE+F0])
    $rc = $g.Invoke()
  } else {
    $g = $rd::GetDelegateForFunctionPointer($pEng, [DE+F1])
    $rc = $g.Invoke($arg)
  }
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

Write-Output ("ENG" + [char]0x1f + "form=" + $Form + [char]0x1f + "rc=" + $rc)