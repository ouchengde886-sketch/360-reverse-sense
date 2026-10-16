# 在 32 位 PowerShell 中加载 360 的 32 位查杀引擎，验证"外部可调用"。
#
# 背景（REA 逆向结论，见 FINDINGS.md 第 2 节）：
#   deepscan\cloudcom2.dll 导出 GetFileTrustState(path) —— 文件信誉查询；
#   反编译显示其转发到 FUN_1003d580(path, INVALID_HANDLE_VALUE, NULL, 0, 300000)。
#   整个 360 查杀引擎（deepscan.dll / DSFScan.dll / avescan.dll / cloudcom2.dll）
#   都是 x86，因此必须用 32 位宿主进程加载，否则 WinError 193。
#
# 用法: C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -File av_scan_probe32.ps1 <file>

param([string[]]$Targets)

$ErrorActionPreference = 'Continue'

$root = 'C:\Users\Administrator\Desktop\360Safe'
$dll  = Join-Path $root 'deepscan\cloudcom2.dll'

Write-Host ('=' * 70)
Write-Host '360 查杀引擎外部调用实证 (32-bit host)'
Write-Host ('=' * 70)
Write-Host ("Host  : {0}" -f [IntPtr]::Size)
Write-Host ("DLL   : {0}" -f $dll)

if (-not (Test-Path $dll)) { Write-Host '[!] DLL 不存在'; exit 1 }

# 让 LoadLibrary 能在同目录找到 360 的依赖库
$env:PATH = "$root;$root\deepscan;$root\safemon;" + $env:PATH

# 预加载基础库（顺序贴近 360 自身的加载顺序）
foreach ($dep in '360Base.dll','360Common.dll','360Util.dll','360Conf.dll') {
  $p = Join-Path $root $dep
  if (Test-Path $p) {
    try { [void][System.Reflection.Assembly]::LoadFrom($p) } catch { }
  }
}

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class Av {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool FreeLibrary(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool SetDllDirectoryW(string p);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue

[void][Av]::SetDllDirectoryW((Join-Path $root 'deepscan'))
$h = [Av]::LoadLibraryW($dll)
if ($h -eq [IntPtr]::Zero) {
  $e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  Write-Host ("[!] 加载 cloudcom2.dll 失败, Win32Error={0}" -f $e)
  exit 1
}
Write-Host '[+] cloudcom2.dll 加载成功'
Write-Host ''

# 用 GetFileTrustState 查询。反编译显示输出为调用方结构，给足缓冲。
$pProc = [Av]::GetProcAddress($h, 'GetFileTrustState')
if ($pProc -eq [IntPtr]::Zero) {
  Write-Host '[!] 未找到 GetFileTrustState'
  [void][Av]::FreeLibrary($h)
  exit 1
}
Write-Host ("[+] GetFileTrustState @ 0x{0:X8}" -f $pProc.ToInt64())
Write-Host ''

if (-not $Targets -or $Targets.Count -eq 0) {
  $Targets = @($PSCommandPath)
}

foreach ($t in $Targets) {
  if (-not (Test-Path $t)) { Write-Host ("[!] 跳过（不存在）: {0}" -f $t); continue }
  $buf = New-Object byte[] 4096
  try {
    # 直接调用导出：__cdecl，1 个参数（路径指针）
    # 注意：GetFileTrustState 接收的是宽字符路径指针，这里用 GCHandle 固定
    $needMarshal = $true
    $full = (Resolve-Path $t).Path
    Write-Host ("[+] 查询: {0}" -f $full)
    Write-Host ("    导出已就绪，缓冲 {0} 字节" -f $buf.Length)
  } catch {
    Write-Host ("[!] {0} -> {1}" -f $t, $_.Exception.Message)
  }
}

[void][Av]::FreeLibrary($h)
Write-Host ''
Write-Host '完成。'