# 360 PC 端云安全引擎 —— Cloudsec3.dll (CloudsecNew.dll)
#
# ============================================================================
# 逆向结论
# ============================================================================
#
# Cloudsec3.dll 内部名是 CloudsecNew.dll，导出 15 个函数：
#   Create360Object      RVA 0x34180   创建引擎对象（与 deepscan.dll 同模式）
#   DSEngLib_Init        RVA 0x369A0   1 参数，引擎库初始化
#   EngCreateObject      RVA 0x7A2F0   创建引擎实例
#   SetDsSrvExePath      RVA 0xB2C50   1 参数（宽字符串），设置云服务程序路径
#   SetDsSrvName         RVA 0xB2C90   1 参数（宽字符串），设置云服务名
#   GetStartMds          RVA 0x74370   3 参数，读 [ebp+8]/[ebp+0xC]/[ebp+0x10]
#   GetStartMdsPlus      RVA 0x74A10   扫描入口
#   EngFrontFix          RVA 0x36C00
#
# SetDsSrvName / SetDsSrvExePath 汇编确认是 1 参数宽字符串 setter：
#   55 8B EC          push ebp; mov ebp,esp
#   8B 55 08          mov edx,[ebp+8]      ; 宽字符串
#   85 D2 74 2B       test edx,edx / jz
#   8B C2 56 8D 70 02 mov esi,edx; lea esi,[eax+2]   ; wcslen
#   66 8B 08 ...      wcslen 循环
#   50 52 E8 ...      push len; push str; call 写入
#
# 这正是之前缺的"告诉引擎用哪个云服务"的接口。
# ============================================================================

param([string]$Target, [string]$Mode)

$sep = [char]0x1f
$Root = 'C:\Program Files (x86)\360\360Safe'
if (-not $Target) { $Target = 'C:\Windows\Sysnative\notepad.exe' }
if (-not $Mode) { $Mode = 'probe' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class CSec {
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

[void][CSec]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\Cloudsec3.dll',
                 'deepscan\cloudcom2.dll', 'deepscan\CloudEngine.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][CSec]::LoadLibraryW($p) }
}
$h = [CSec]::GetModuleHandleW('Cloudsec3.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output ("CSEC" + $sep + "err=load"); exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
function Fn($n, $t) {
  $p = [CSec]::GetProcAddress($h, $n)
  if ($p -eq [IntPtr]::Zero) { return $null }
  return $rd::GetDelegateForFunctionPointer($p, $t)
}

# 1) 设置云服务程序路径与名称（1 参数宽字符串）
$srvExe = Join-Path $Root 'deepscan\360CloudSrv.exe'
if (-not (Test-Path $srvExe)) { $srvExe = Join-Path $Root '360Safe.exe' }
$pe = $rd::StringToHGlobalUni($srvExe)
$fPath = Fn 'SetDsSrvExePath' ([CSec+F1])
$pathRc = "skip"
if ($fPath) { try { $pathRc = $fPath.Invoke($pe) } catch { $pathRc = "EXC" } }

$pn = $rd::StringToHGlobalUni('360CloudSrv')
$fName = Fn 'SetDsSrvName' ([CSec+F1])
$nameRc = "skip"
if ($fName) { try { $nameRc = $fName.Invoke($pn) } catch { $nameRc = "EXC" } }

# 2) 引擎库初始化（1 参数）
$fInit = Fn 'DSEngLib_Init' ([CSec+F1])
$initRc = "skip"
if ($fInit) { try { $initRc = $fInit.Invoke([IntPtr]::Zero) } catch { $initRc = "EXC" } }

Write-Output ("CSEC" + $sep + "srvPath=" + $pathRc + $sep + "srvName=" + $nameRc + $sep + "init=" + $initRc)

if ($Mode -eq 'probe') {
  # 3) GetStartMds(target, ?, ?) —— 3 参数
  $fMds = Fn 'GetStartMds' ([CSec+F3])
  if ($fMds) {
    $tp = $rd::StringToHGlobalUni($Target)
    $r = "EXC"
    try { $r = $fMds.Invoke($tp, [IntPtr]::Zero, [IntPtr]::Zero) } catch { }
    Write-Output ("  GetStartMds(target,0,0) rc=" + $r)
    $rd::FreeHGlobal($tp)
  }
  # 4) GetStartMdsPlus() —— 0 参数
  $fPlus = Fn 'GetStartMdsPlus' ([CSec+F1])
  if ($fPlus) {
    $r2 = "EXC"
    try { $r2 = $fPlus.Invoke([IntPtr]::Zero) } catch { }
    Write-Output ("  GetStartMdsPlus(0) rc=" + $r2)
  }
}
$rd::FreeHGlobal($pe); $rd::FreeHGlobal($pn)