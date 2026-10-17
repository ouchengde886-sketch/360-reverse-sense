# 360 引擎批量文件信誉查询（外部调用）。
#
# 关键约束（实测得出）：cloudcom2!GetFileTrustStateEx 在**同一进程内只能成功调用一次**，
# 第二次调用会使宿主进程静默退出（exit code 0，无异常）。因此批量查询必须
# **每个文件起一个独立进程**。本脚本是"单文件查询"的工作进程，由
# av_batch_scan32.ps1 逐文件调用。
#
# 用法:
#   C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -File av_trust_one32.ps1 <file>
# 输出（单行，便于父进程解析）:
#   RESULT|<path>|<publisher>|<firstDword>

param([string]$Target, [string]$Root)

# 引擎根目录探测顺序：
#   1) 显式传入的 -Root
#   2) 本机实际安装目录（优先 —— 这是"活"的引擎，特征库最新）
#   3) 桌面快照目录（离线/安全模式导出的副本，作为回退）
$candidates = @()
if ($Root) { $candidates += $Root }
$candidates += 'C:\Program Files (x86)\360\360Safe'
$candidates += 'C:\Program Files\360\360Safe'
$candidates += 'C:\Users\Administrator\Desktop\360Safe'

$root = $null
foreach ($c in $candidates) {
  if ($c -and (Test-Path (Join-Path $c 'deepscan\cloudcom2.dll'))) { $root = $c; break }
}
if (-not $root) {
  Write-Output ("RESULT" + [char]31 + $Target + [char]31 + [char]31 + [char]31)
  exit 2
}

$dll = Join-Path $root 'deepscan\cloudcom2.dll'
$env:PATH = "$root;$root\deepscan;$root\safemon;" + $env:PATH

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class AvOne {
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

[void][AvOne]::SetDllDirectoryW((Join-Path $root 'deepscan'))
$h = [AvOne]::LoadLibraryW($dll)
if ($h -eq [IntPtr]::Zero) {
  Write-Output ("RESULT|{0}|<load-failed>|0" -f $Target)
  exit 1
}
$fn = [AvOne]::Bind($h, 'GetFileTrustStateEx')
if ($null -eq $fn) {
  Write-Output ("RESULT|{0}|<bind-failed>|0" -f $Target)
  exit 1
}

$gh = [System.Runtime.InteropServices.GCHandle]::Alloc($Target, [System.Runtime.InteropServices.GCHandleType]::Pinned)
$out = New-Object byte[] 4096
$oh = [System.Runtime.InteropServices.GCHandle]::Alloc($out, [System.Runtime.InteropServices.GCHandleType]::Pinned)
try {
  $fn.Invoke($gh.AddrOfPinnedObject(), $oh.AddrOfPinnedObject())

  # 结构布局（由 FUN_1003d580 反编译 + 实测确定，总大小 0x318）：
  #   +0x0000  宽字符串  签名者/主体名称    (如 "Microsoft")
  #   +0x0100  宽字符串  签发者/发布者名称  (如 "Microsoft Windows")
  #   +0x0200  宽字符串  证书链/CA 名称     (如 "Microsoft Windows Production PCA 2011")
  #   +0x0300  若干 DWORD 时间戳等附加字段
  $f = @()
  foreach ($off in 0, 0x100, 0x200) {
    $s = [System.Text.Encoding]::Unicode.GetString($out, $off, 0x100)
    $z = $s.IndexOf([char]0)
    if ($z -ge 0) { $s = $s.Substring(0, $z) }
    $f += $s
  }
  # 用 \x1f (US) 作分隔符，避免发布者名中可能出现的 | 干扰解析
  $sep = [char]0x1f
  Write-Output ("RESULT{0}{1}{0}{2}{0}{3}{0}{4}" -f $sep, $Target, $f[0], $f[1], $f[2])
} catch {
  $sep = [char]0x1f
  Write-Output ("RESULT{0}{1}{0}<exception:{2}>{0}{0}" -f $sep, $Target, $_.Exception.Message)
} finally {
  $gh.Free(); $oh.Free()
}