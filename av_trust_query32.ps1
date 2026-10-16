# 在 32 位宿主中调用 360 查杀引擎，解析 GetFileTrustStateEx 的输出结构。
#
# 重要修正：先前把输出缓冲首 4 字节当作"信誉状态码"解读是错的。
# 实测 notepad.exe 的输出前 32 字节为
#   4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 ...
# 即 UTF-16LE 字符串 "Microsoft" —— 该结构承载的是**签名者/发布者名称**，
# 不是数值状态。本脚本按宽字符串解析，并同时导出原始字节供进一步分析。
#
# 用法:
#   C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -File av_trust_query32.ps1 <file>...

param([string[]]$Targets)

$ErrorActionPreference = 'Continue'
$root = 'C:\Users\Administrator\Desktop\360Safe'
$dll  = Join-Path $root 'deepscan\cloudcom2.dll'

Write-Host ('=' * 72)
Write-Host '360 引擎文件信誉查询（外部调用，解析输出结构）'
Write-Host ('=' * 72)
Write-Host ("宿主位数 : {0}" -f ([IntPtr]::Size * 8))
Write-Host ("引擎 DLL : {0}" -f $dll)
Write-Host ''

if (-not (Test-Path $dll)) { Write-Host '[!] DLL 不存在'; exit 1 }
$env:PATH = "$root;$root\deepscan;$root\safemon;" + $env:PATH

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class Av {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool FreeLibrary(IntPtr h);

  // cloudcom2!GetFileTrustStateEx(path, outState)
  // 反编译 0x1000BB800 -> FUN_1003d580(path, INVALID_HANDLE_VALUE, out, 0, 500000)
  [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet=CharSet.Unicode)]
  public delegate void TrustExFn(IntPtr path, IntPtr outState);

  public static TrustExFn Bind(IntPtr h, string name) {
    IntPtr p = GetProcAddress(h, name);
    if (p == IntPtr.Zero) return null;
    return (TrustExFn)Marshal.GetDelegateForFunctionPointer(p, typeof(TrustExFn));
  }
}
"@
Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue

[void][Av]::SetDllDirectoryW((Join-Path $root 'deepscan'))
$h = [Av]::LoadLibraryW($dll)
if ($h -eq [IntPtr]::Zero) {
  Write-Host ("[!] 加载失败, Win32Error={0}" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
  exit 1
}
$fn = [Av]::Bind($h, 'GetFileTrustStateEx')
if ($null -eq $fn) { Write-Host '[!] 绑定 GetFileTrustStateEx 失败'; exit 1 }
Write-Host '[+] 引擎加载并绑定成功'
Write-Host ''

if (-not $Targets -or $Targets.Count -eq 0) { $Targets = @($PSCommandPath) }

$n = 0
foreach ($t in $Targets) {
  $n++
  if (-not (Test-Path $t)) { Write-Host ("[!] 跳过（不存在）: {0}" -f $t); continue }
  $full = (Resolve-Path $t).Path

  $gh = [System.Runtime.InteropServices.GCHandle]::Alloc(
          $full, [System.Runtime.InteropServices.GCHandleType]::Pinned)
  $out = New-Object byte[] 4096
  $oh = [System.Runtime.InteropServices.GCHandle]::Alloc(
          $out, [System.Runtime.InteropServices.GCHandleType]::Pinned)
  try {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $fn.Invoke($gh.AddrOfPinnedObject(), $oh.AddrOfPinnedObject())
    $sw.Stop()

    Write-Host ("[{0}] {1}" -f $n, $full)
    Write-Host ("    调用成功，耗时 {0} ms" -f $sw.ElapsedMilliseconds)

    # 按 UTF-16LE 解析：结构里承载的是签名者/发布者等宽字符串
    $text = [System.Text.Encoding]::Unicode.GetString($out)
    $zero = $text.IndexOf([char]0)
    if ($zero -ge 0) { $text = $text.Substring(0, $zero) }
    if ($text.Length -gt 0) {
      Write-Host ("    发布者/签名字段 = {0}" -f $text)
    } else {
      Write-Host '    发布者/签名字段 = (空)'
    }
    # 逐字段列出前 8 个 DWORD，便于后续定位真正的数值状态位
    $dw = @()
    for ($k = 0; $k -lt 8; $k++) { $dw += ('0x{0:X8}' -f [BitConverter]::ToUInt32($out, $k * 4)) }
    Write-Host ("    前8个DWORD = {0}" -f ($dw -join ' '))
  } catch {
    Write-Host ("    调用异常: {0}" -f $_.Exception.Message)
  } finally {
    $gh.Free(); $oh.Free()
  }
}

[void][Av]::FreeLibrary($h)
Write-Host ''
Write-Host '说明：该结构承载签名者/发布者名称等字符串字段；'
Write-Host '      数值型"安全/可疑/未知"分级需结合 QueryFilesEx / SmartCacheQuery 等接口。'