# 验证 'AVEI' 魔数假设 —— ScanW 的前置条件
#
# ============================================================================
# AVEI.dll!ScanW 真实实现 (RVA 0x8560) 反汇编确认:
#   +040: 81 3E 41 56 45 49  cmp dword[esi],'AVEI'   ★ 对象魔数
#   +046: 75 46             jnz +0x8E               ; 魔数不对直接返回
#   +03C: 85 C0             test eax,eax
#   +03E: 75 4E             jnz +0x8E               ; 前置校验失败
#
# 本轮实验:
#   1. 按 av_ave_scan32.ps1 创建扫描器（CreateScannerEx）
#   2. dump 扫描器对象前 32 字节，检查是否有 'AVEI' (41 56 45 49)
#   3. 对 PE 和非 PE 分别扫描，记录 status
#   4. 如果魔数缺失，尝试补写后再扫，对比结果
#
# 用法: -Target <文件>
# ============================================================================

param([string]$Root, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { $Target = 'D:\troyr2\tools\vendor\srdi-master.zip' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class AM {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi, EntryPoint="GetProcAddress")]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int I1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr P1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr P0();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int S5(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

$rd = [System.Runtime.InteropServices.Marshal]
$aveDir = Join-Path $Root 'deepscan\ave'

[void][AM]::SetDllDirectoryW($aveDir)
$hBase = [AM]::LoadLibraryW((Join-Path $Root '360Base.dll'))
$hBapi = [AM]::LoadLibraryW((Join-Path $Root 'deepscan\BAPI.dll'))
$hAv   = [AM]::LoadLibraryW((Join-Path $aveDir 'AVEngine.dll'))

# 初始化
$pBapi = [AM]::GetProcAddress($hAv, 'BAPIInitialize')
if ($pBapi -ne [IntPtr]::Zero) {
  $rp = $rd::StringToHGlobalUni($Root)
  $g = $rd::GetDelegateForFunctionPointer($pBapi, [AM+I1])
  $r = $g.Invoke($rp)
  Write-Output ("  BAPIInitialize -> {0}" -f $r)
}
$pAve = [AM]::GetProcAddress($hAv, 'AveInitialize')
if ($pAve -ne [IntPtr]::Zero) {
  $tbl = $rd::AllocHGlobal(0x40)
  for ($i = 0; $i -lt 0x40; $i++) { $rd::WriteByte($tbl, $i, 0) }
  $rd::WriteInt32($tbl, 0, 0x18)
  $g = $rd::GetDelegateForFunctionPointer($pAve, [AM+I1])
  $r = $g.Invoke($tbl)
  Write-Output ("  AveInitialize -> {0}" -f $r)
}

# 加载 AVEI.dll 并创建扫描器
$hI = [AM]::LoadLibraryW((Join-Path $aveDir 'AVEI.dll'))
Write-Output ("  AVEI.dll = 0x{0:X8}" -f $hI.ToInt64())
$pCreate = [AM]::GetProcAddress($hI, 'CreateScannerEx')
Write-Output ("  CreateScannerEx = 0x{0:X8}" -f $pCreate.ToInt64())

$scanner = [IntPtr]::Zero
try {
  $g = $rd::GetDelegateForFunctionPointer($pCreate, [AM+I1])
  $scanner = [IntPtr]$g.Invoke([IntPtr]::Zero)
} catch { Write-Output ("  CreateScannerEx 异常: " + $_.Exception.GetType().Name) }
Write-Output ("  扫描器 = 0x{0:X8}" -f $scanner.ToInt64())
if ($scanner -eq [IntPtr]::Zero) { exit 0 }

# ★ 关键：dump 扫描器对象头部，检查 'AVEI' 魔数
Write-Output "  --- 扫描器对象头部 dump ---"
for ($off = 0; $off -lt 64; $off += 16) {
  $hex = @()
  $asc = ""
  for ($i = 0; $i -lt 16; $i++) {
    $b = $rd::ReadByte($scanner, $off + $i)
    $hex += ("{0:X2}" -f $b)
    if ($b -ge 32 -and $b -lt 127) { $asc += [char]$b } else { $asc += "." }
  }
  Write-Output ("    +{0:X2}: {1}  {2}" -f $off, ($hex -join ' '), $asc)
}
$m0 = $rd::ReadInt32($scanner, 0)
Write-Output ("  对象首 DWORD = 0x{0:X8}" -f $m0)
$magic = [byte[]](0x41,0x56,0x45,0x49)
$isAvei = ($rd::ReadByte($scanner,0) -eq 0x41 -and $rd::ReadByte($scanner,1) -eq 0x56 -and
           $rd::ReadByte($scanner,2) -eq 0x45 -and $rd::ReadByte($scanner,3) -eq 0x49)
Write-Output ("  ★ 是否含 'AVEI' 魔数: {0}" -f $isAvei)

# 扫描测试
$pScan = [AM]::GetProcAddress($hI, 'ScanW')
Write-Output ("  ScanW = 0x{0:X8}" -f $pScan.ToInt64())
$pathPtr = $rd::StringToHGlobalUni($Target)
$resBuf = $rd::AllocHGlobal(0x300)
for ($i = 0; $i -lt 0x300; $i++) { $rd::WriteByte($resBuf, $i, 0) }
Write-Output ("  目标 = {0}" -f $Target)

$gS = $rd::GetDelegateForFunctionPointer($pScan, [AM+S5])
$r = "EXC"
try { $r = $gS.Invoke($scanner, $pathPtr, [IntPtr]::Zero, [IntPtr]::Zero, $resBuf) }
catch { $r = "EXC:" + $_.Exception.GetType().Name }
Write-Output ("  ScanW -> rc=0x{0:X8} ({0})" -f $r)
$st = $rd::ReadByte($resBuf, 0)
$sz = $rd::ReadInt32($resBuf, 4)
Write-Output ("    结果结构: status={0} size={1}" -f $st, $sz)
$nm = $rd::PtrToStringAnsi([IntPtr]($resBuf.ToInt64()+8), 128)
Write-Output ("    威胁名 = '{0}'" -f $nm)
$sub = $rd::ReadByte($resBuf, 0x108)
Write-Output ("    substatus = {0}" -f $sub)