# 逐步隔离测试：360 AVE 引擎的哪一步会崩。
# 分步执行并打印，定位 AccessViolation 的确切位置。

param([string]$Root)

$candidates = @()
if ($Root) { $candidates += $Root }
$candidates += 'C:\Program Files (x86)\360\360Safe'
$candidates += 'C:\Users\Administrator\Desktop\360Safe'

$root = $null
foreach ($c in $candidates) {
  if ($c -and (Test-Path (Join-Path $c 'deepscan\ave\AVEI.dll'))) { $root = $c; break }
}
if (-not $root) { Write-Host "NO_ROOT"; exit 2 }

Write-Host "root = $root"
$aveDir = Join-Path $root 'deepscan\ave'
$env:PATH = "$root;$root\deepscan;$aveDir;$root\safemon;" + $env:PATH

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class Ave2 {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  // 必须显式 CharSet=Unicode + EntryPoint：只写 GetModuleHandleW(string)
  // 而不加 CharSet，.NET 会按 ANSI 传参导致查找失败返回 0（实测确认）。
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);

  [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
  public delegate IntPtr CreateScannerExFn(int cfg);
  // ScanW 是 __thiscall（从机器码确认：arg1 走 ECX，其余走栈）。
  // .NET 的 ThisCall 约定即"第一个参数放 ECX"，正是这里需要的。
  [UnmanagedFunctionPointer(CallingConvention.ThisCall, CharSet=CharSet.Unicode)]
  public delegate int ScanWFn(IntPtr scanner, string path, IntPtr ctx, int flags);
  [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
  public delegate int CloseScannerFn(IntPtr scanner);
}
"@
try { Add-Type -TypeDefinition $sig -ErrorAction Stop } catch { }

[void][Ave2]::SetDllDirectoryW($aveDir)

Write-Host "`n--- 步骤 1: 加载依赖 DLL ---"
foreach ($d in @('360Base.dll','deepscan\ave\AVEngine.dll','deepscan\ave\AVEI.dll')) {
  $p = Join-Path $root $d
  if (Test-Path $p) {
    $hh = [Ave2]::LoadLibraryW($p)
    Write-Host ("  {0,-32} handle=0x{1:X} err={2}" -f $d, $hh, [Runtime.InteropServices.Marshal]::GetLastWin32Error())
  } else {
    Write-Host ("  {0,-32} NOT FOUND" -f $d)
  }
}

Write-Host "`n--- 步骤 2: 确认 AVEngine.dll 已在内存 ---"
$m = [Ave2]::GetModuleHandleW('AVEngine.dll')
Write-Host ("  GetModuleHandleW('AVEngine.dll') = 0x{0:X}" -f $m)
$m2 = [Ave2]::GetModuleHandleW('360ave.dll')
Write-Host ("  GetModuleHandleW('360ave.dll')  = 0x{0:X}" -f $m2)

$h = [Ave2]::GetModuleHandleW('AVEI.dll')
Write-Host ("  GetModuleHandleW('AVEI.dll')    = 0x{0:X}" -f $h)
if ($h -eq [IntPtr]::Zero) { Write-Host "  AVEI.dll 未加载"; exit 3 }

Write-Host "`n--- 步骤 3: CreateScannerEx ---"
$pCreate = [Ave2]::GetProcAddress($h, 'CreateScannerEx')
Write-Host ("  proc = 0x{0:X}" -f $pCreate)
$create = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pCreate, [Ave2+CreateScannerExFn])

$scanner = [IntPtr]::Zero
foreach ($cfg in @(0, 1)) {
  try {
    $scanner = $create.Invoke($cfg)
    Write-Host ("  cfg={0} -> scanner=0x{1:X}" -f $cfg, $scanner)
    if ($scanner -ne [IntPtr]::Zero) { break }
  } catch {
    Write-Host ("  cfg={0} -> 异常: {1}" -f $cfg, $_.Exception.Message)
  }
}

if ($scanner -eq [IntPtr]::Zero) {
  Write-Host "  [!] CreateScannerEx 返回 NULL，无法继续"
  exit 4
}

Write-Host "`n--- 步骤 4: 检查 scanner 头部魔数（应为 0x49455641 'AVEI'） ---"
try {
  $magic = [System.Runtime.InteropServices.Marshal]::ReadInt32($scanner)
  Write-Host ("  *(int*)scanner = 0x{0:X8}  ({1})" -f $magic,
    [System.Text.Encoding]::ASCII.GetString([BitConverter]::GetBytes($magic)))
} catch {
  Write-Host ("  读取失败: {0}" -f $_.Exception.Message)
}

Write-Host "`n--- 步骤 5: ScanW ---"
$pScan = [Ave2]::GetProcAddress($h, 'ScanW')
Write-Host ("  proc = 0x{0:X}" -f $pScan)
$scan = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pScan, [Ave2+ScanWFn])
try {
  $rc = $scan.Invoke($scanner, "C:\Windows\System32\notepad.exe", [IntPtr]::Zero, 0)
  Write-Host ("  ScanW 返回 = 0x{0:X8}" -f $rc)
} catch {
  Write-Host ("  ScanW 异常: {0}" -f $_.Exception.Message)
}

Write-Host "`n--- 步骤 6: CloseScanner ---"
$pClose = [Ave2]::GetProcAddress($h, 'CloseScanner')
if ($pClose -ne [IntPtr]::Zero) {
  $close = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pClose, [Ave2+CloseScannerFn])
  try { Write-Host ("  close 返回 = {0}" -f $close.Invoke($scanner)) }
  catch { Write-Host ("  close 异常: {0}" -f $_.Exception.Message) }
}
Write-Host "`n完成。"