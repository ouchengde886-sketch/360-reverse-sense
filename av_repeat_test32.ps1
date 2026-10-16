# 验证 360 引擎的 GetFileTrustStateEx 能否被重复调用（同一进程内多次）。
# 目的：确认"外部批量查杀"是否可行 —— 若第二次调用导致进程退出，
# 则外部调用必须每次新建进程或改用其它接口。

param([string[]]$Targets)

$root = 'C:\Users\Administrator\Desktop\360Safe'
$dll  = Join-Path $root 'deepscan\cloudcom2.dll'
$env:PATH = "$root;$root\deepscan;$root\safemon;" + $env:PATH

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class AvR {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet=CharSet.Unicode)]
  public delegate void Fn(IntPtr p, IntPtr o);
  public static Fn Bind(IntPtr h, string n) {
    IntPtr p = GetProcAddress(h, n);
    if (p == IntPtr.Zero) return null;
    return (Fn)Marshal.GetDelegateForFunctionPointer(p, typeof(Fn));
  }
}
"@
Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue

[void][AvR]::SetDllDirectoryW((Join-Path $root 'deepscan'))
$h = [AvR]::LoadLibraryW($dll)
if ($h -eq [IntPtr]::Zero) { Write-Host '[!] load failed'; exit 1 }
$fn = [AvR]::Bind($h, 'GetFileTrustStateEx')
if ($null -eq $fn) { Write-Host '[!] bind failed'; exit 1 }
Write-Host '[+] engine ready'
Write-Host ''

$n = 0
foreach ($t in $Targets) {
  $n++
  Write-Host ("--- call #{0}: {1}" -f $n, $t)
  $gh = [System.Runtime.InteropServices.GCHandle]::Alloc($t, [System.Runtime.InteropServices.GCHandleType]::Pinned)
  $out = New-Object byte[] 4096
  $oh = [System.Runtime.InteropServices.GCHandle]::Alloc($out, [System.Runtime.InteropServices.GCHandleType]::Pinned)
  try {
    $fn.Invoke($gh.AddrOfPinnedObject(), $oh.AddrOfPinnedObject())
    $s = [System.Text.Encoding]::Unicode.GetString($out)
    $z = $s.IndexOf([char]0)
    if ($z -ge 0) { $s = $s.Substring(0, $z) }
    Write-Host ("    returned: '{0}'" -f $s)
  } catch {
    Write-Host ("    EXCEPTION: {0}" -f $_.Exception.Message)
  } finally {
    $gh.Free(); $oh.Free()
  }
}
Write-Host ''
Write-Host ("ALL DONE - {0} calls completed" -f $n)