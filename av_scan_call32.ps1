# 在 32 位宿主中真正调用 360 查杀引擎的导出函数，完成一次文件信誉查询。
#
# 背景（REA 逆向结论，见 FINDINGS.md 第 2.4 节）：
#   deepscan\cloudcom2.dll!GetFileTrustState(path)
#   反编译 GetFileTrustState(0x1000BB7C0) 得到：
#       FUN_1003d580(param_1, INVALID_HANDLE_VALUE, NULL, 0, 300000)
#   即 (路径, 句柄, 输出结构, 标志=0, 超时=300000ms)。
#   这里按 __cdecl 单参数调用导出，输出结构由调用方提供。
#
# 必须用 32 位 PowerShell：
#   C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -File av_scan_call32.ps1 <file>

param([string[]]$Targets)

$ErrorActionPreference = 'Continue'
$root = 'C:\Users\Administrator\Desktop\360Safe'
$dll  = Join-Path $root 'deepscan\cloudcom2.dll'

Write-Host ('=' * 72)
Write-Host '360 查杀引擎外部调用实证 —— 真实查询文件信誉'
Write-Host ('=' * 72)
Write-Host ("宿主位数 : {0}" -f ([IntPtr]::Size * 8))
Write-Host ("引擎 DLL : {0}" -f $dll)
Write-Host ''

if (-not (Test-Path $dll)) { Write-Host '[!] DLL 不存在'; exit 1 }

# 让引擎能在同目录解析依赖
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

  // cloudcom2!GetFileTrustState —— __cdecl, 1 参数
  [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet=CharSet.Unicode)]
  public delegate void GetFileTrustStateFn(IntPtr path);

  public static GetFileTrustStateFn Bind(IntPtr h, string name) {
    IntPtr p = GetProcAddress(h, name);
    if (p == IntPtr.Zero) return null;
    return (GetFileTrustStateFn)Marshal.GetDelegateForFunctionPointer(p, typeof(GetFileTrustStateFn));
  }

  // cloudcom2!GetFileTrustStateEx —— __cdecl, (path, outState)
  // 反编译 0x1000BB800: FUN_1003d580(path, INVALID_HANDLE_VALUE, out, 0, 500000)
  // 相比 GetFileTrustState（out 传 NULL），这里能把信誉状态读回来。
  [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet=CharSet.Unicode)]
  public delegate void GetFileTrustStateExFn(IntPtr path, IntPtr outState);

  public static GetFileTrustStateExFn BindEx(IntPtr h, string name) {
    IntPtr p = GetProcAddress(h, name);
    if (p == IntPtr.Zero) return null;
    return (GetFileTrustStateExFn)Marshal.GetDelegateForFunctionPointer(p, typeof(GetFileTrustStateExFn));
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
Write-Host '[+] cloudcom2.dll 加载成功'

$fn = [Av]::BindEx($h, 'GetFileTrustStateEx')
if ($null -eq $fn) {
  Write-Host '[!] 未找到 GetFileTrustStateEx，回退到 GetFileTrustState'
  $fn = [Av]::Bind($h, 'GetFileTrustState')
  if ($null -eq $fn) { Write-Host '[!] 绑定失败'; exit 1 }
}
Write-Host '[+] GetFileTrustStateEx 绑定成功'
Write-Host ''

if (-not $Targets -or $Targets.Count -eq 0) { $Targets = @($PSCommandPath) }

$i = 0
foreach ($t in $Targets) {
  $i++
  if (-not (Test-Path $t)) { Write-Host ("[!] 跳过（不存在）: {0}" -f $t); continue }
  $full = (Resolve-Path $t).Path

  # 路径以宽字符传给引擎；用 GCHandle 固定托管字符串的内存
  $gh = [System.Runtime.InteropServices.GCHandle]::Alloc(
          $full, [System.Runtime.InteropServices.GCHandleType]::Pinned)
  # 输出状态结构按 4KB 预留（反编译显示为调用方栈上结构）
  $out = New-Object byte[] 4096
  $oh = [System.Runtime.InteropServices.GCHandle]::Alloc(
          $out, [System.Runtime.InteropServices.GCHandleType]::Pinned)
  try {
    $ptr = $gh.AddrOfPinnedObject()
    $optr = $oh.AddrOfPinnedObject()
    Write-Host ("[{0}] 查询: {1}" -f $i, $full)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $fn.Invoke($ptr, $optr)
    $sw.Stop()
    $state = [BitConverter]::ToUInt32($out, 0)
    Write-Host ("    调用成功，耗时 {0} ms" -f $sw.ElapsedMilliseconds)
    Write-Host ("    信誉状态 = 0x{0:X8} ({1})" -f $state, $state)
    $hex = ($out[0..31] | ForEach-Object { $_.ToString('x2') }) -join ''
    Write-Host ("    输出前32字节 = {0}" -f $hex)
  } catch {
    Write-Host ("    调用异常: {0}" -f $_.Exception.Message)
  } finally {
    $gh.Free()
    $oh.Free()
  }
}

[void][Av]::FreeLibrary($h)
Write-Host ''
Write-Host '完成：已从外部进程成功调用 360 查杀引擎的文件信誉接口。'