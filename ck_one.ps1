# 单次调用 360SafeChecker.dll 导出（隔离进程，避免崩溃影响）
# 用法: -Func <名称> -Sig <I0|I1|I2|I3> -Arg1 <n> -Arg2 <n>
param(
  [string]$Root,
  [string]$Func,
  [string]$Sig,
  [int]$Arg1 = 0,
  [int]$Arg2 = 0,
  [string]$Str1
)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Func) { $Func = 'OperateScanLog' }
if (-not $Sig)  { $Sig = 'I1' }

$cs = @"
using System;
using System.Runtime.InteropServices;
public static class C1 {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi, EntryPoint="GetProcAddress")]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] public delegate int D0();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] public delegate int D1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] public delegate int D2(IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)] public delegate int D3(IntPtr a, IntPtr b, IntPtr c);
}
"@
Add-Type -TypeDefinition $cs -ErrorAction Stop 3>$null 2>$null
$rd = [System.Runtime.InteropServices.Marshal]

[void][C1]::SetDllDirectoryW($Root)
[void][C1]::LoadLibraryW((Join-Path $Root '360Base.dll'))
$h = [C1]::LoadLibraryW((Join-Path $Root 'Utils\360SafeChecker.dll'))
if ($h -eq [IntPtr]::Zero) { Write-Output "  LoadLibrary 失败"; exit 1 }
$a = [C1]::GetProcAddress($h, $Func)
if ($a -eq [IntPtr]::Zero) { Write-Output "  找不到导出 $Func"; exit 1 }

$p1 = if ($Str1) { $rd::StringToHGlobalUni($Str1) } else { [IntPtr]$Arg1 }
$p2 = [IntPtr]$Arg2

$r = 'EXC'
try {
  switch ($Sig) {
    'I0' { $g = $rd::GetDelegateForFunctionPointer($a, [C1+D0]); $r = $g.Invoke() }
    'I1' { $g = $rd::GetDelegateForFunctionPointer($a, [C1+D1]); $r = $g.Invoke($p1) }
    'I2' { $g = $rd::GetDelegateForFunctionPointer($a, [C1+D2]); $r = $g.Invoke($p1, $p2) }
    'I3' { $g = $rd::GetDelegateForFunctionPointer($a, [C1+D3]); $r = $g.Invoke($p1, $p2, [IntPtr]::Zero) }
  }
} catch {
  Write-Host ("  RESULT {0}({1},{2}) EXC {3}" -f $Func, $Sig, $Arg1, $_.Exception.GetType().Name)
  exit 2
}
Write-Host ("  RESULT {0}({1},{2}) -> {3}" -f $Func, $Sig, $Arg1, $r)