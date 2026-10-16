# 解析 360 查杀引擎 GetFileTrustStateEx 的完整输出结构。
#
# 依据 REA 反编译 FUN_1003d580（cloudcom2.dll，GetFileTrustState* 的共同实现）：
#   - 结构总大小 0x318 字节（_memset(param_3, 0, 0x318)）
#   - 首字段写入 *param_3（DWORD）
#   - 偏移 +0x100 处：FUN_10008930((short*)(param_3 + 0x80), 0x80, ...)
#       param_3 是 undefined4*，param_3 + 0x80 == 字节偏移 0x200
#   - 偏移 +0x200 处：FUN_10008930((short*)(param_3 + 0x40), 0x80, ...)
#       param_3 + 0x40 == 字节偏移 0x100
#   两个字段都是 0x80 个宽字符（256 字节）的字符串缓冲。
#   实测该结构首部即 UTF-16LE 发布者名（如 "Microsoft"），
#   说明偏移 0 起就是一个宽字符串，而非数值状态。
#
# 本脚本 dump 结构全部非零字段，便于确定各字段语义。
#
# 用法:
#   C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -File av_dump_struct32.ps1 <file>

param([string]$Target)

$root = 'C:\Users\Administrator\Desktop\360Safe'
$dll  = Join-Path $root 'deepscan\cloudcom2.dll'
$env:PATH = "$root;$root\deepscan;$root\safemon;" + $env:PATH

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class AvDump {
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

[void][AvDump]::SetDllDirectoryW((Join-Path $root 'deepscan'))
$h = [AvDump]::LoadLibraryW($dll)
if ($h -eq [IntPtr]::Zero) { Write-Host '[!] load failed'; exit 1 }
$fn = [AvDump]::Bind($h, 'GetFileTrustStateEx')
if ($null -eq $fn) { Write-Host '[!] bind failed'; exit 1 }

# 结构 0x318 字节，多给一些余量
$size = 0x400
$gh = [System.Runtime.InteropServices.GCHandle]::Alloc($Target, [System.Runtime.InteropServices.GCHandleType]::Pinned)
$out = New-Object byte[] $size
$oh = [System.Runtime.InteropServices.GCHandle]::Alloc($out, [System.Runtime.InteropServices.GCHandleType]::Pinned)
try {
  $fn.Invoke($gh.AddrOfPinnedObject(), $oh.AddrOfPinnedObject())
} catch {
  Write-Host ("调用异常: {0}" -f $_.Exception.Message)
} finally {
  $gh.Free(); $oh.Free()
}

Write-Host ('=' * 74)
Write-Host ("目标: {0}" -f $Target)
Write-Host ('=' * 74)

# 1) 按 DWORD 列出非零字段
Write-Host ''
Write-Host '--- 非零 DWORD 字段 ---'
for ($off = 0; $off -lt $size; $off += 4) {
  $v = [BitConverter]::ToUInt32($out, $off)
  if ($v -ne 0) {
    Write-Host ("  +0x{0:X4} = 0x{1:X8} ({1})" -f $off, $v)
  }
}

# 2) 按已知的宽字符串字段解析
Write-Host ''
Write-Host '--- 宽字符串字段 ---'
foreach ($off in 0, 0x100, 0x200) {
  $len = [Math]::Min(0x100, $size - $off)
  $s = [System.Text.Encoding]::Unicode.GetString($out, $off, $len)
  $z = $s.IndexOf([char]0)
  if ($z -ge 0) { $s = $s.Substring(0, $z) }
  if ($s.Length -gt 0) {
    Write-Host ("  +0x{0:X4} = '{1}'" -f $off, $s)
  } else {
    Write-Host ("  +0x{0:X4} = (空)" -f $off)
  }
}

# 3) 原始 hex dump（前 0x120 字节）
Write-Host ''
Write-Host '--- 原始字节 (前 0x120) ---'
for ($i = 0; $i -lt 0x120; $i += 16) {
  $hex = ($out[$i..($i+15)] | ForEach-Object { $_.ToString('x2') }) -join ' '
  Write-Host ("  {0:X4}  {1}" -f $i, $hex)
}