# PopSoftEng!Create360Object 的 5 个 GUID 分支测试
#
# ============================================================================
# 反汇编确认 Create360Object (RVA 0xDFF0) 是 GUID 分发器：
#   +020: 83 3D 88 B6 09 10 00  cmp dword[0x1009B688],0   ; 单例
#   +032: 8B 5C 24 28     mov ebx,[esp+0x28]              ; param
#   +036: 85 DB           test ebx,ebx
#   +03A: B8 57 00 07 80  mov eax,0x80070057              ; E_INVALIDARG
#   +055: C2 0C 00        ret 0xC                         ; 3 参数
#   +05E: edx=0x10085714  {22FA5512-0D00-4452-82BE-EBA5E33B9DB0}
#   +0CA: edx=0x10085724  {869330CB-E95B-4213-A224-917373C846A4}
#   +12B: edx=0x10085ED8  {D665872C-8D3A-4F68-A5E7-5D39874B45CB}
#   +13B: edx=0x10085EE8  {D665872C-8D3A-4F68-A5E7-5D39874B45CC}
#   +14B: edx=0x1008626C  {93E4B447-3C85-4F22-9D3E-CF8DF4E3AD40}
#
# 签名推测: HRESULT Create360Object(REFGUID, void** ppv, int flags)
# 用法: -Guid N
# ============================================================================

param([string]$Root, [int]$Guid)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Guid) { $Guid = 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class PG {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi, EntryPoint="GetProcAddress")]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int HR3(IntPtr a, IntPtr b, int c);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int HR3b(IntPtr a, IntPtr b, IntPtr c);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][PG]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll',
                 'deepscan\ave\AVEngine.dll', 'deepscan\ave\AVEI.dll',
                 'deepscan\ScChecker.dll', 'deepscan\PopSoftEng.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][PG]::LoadLibraryW($p) }
}
$hp = [PG]::GetModuleHandleW('PopSoftEng.dll')
if ($hp -eq [IntPtr]::Zero) { Write-Output "  no PopSoftEng"; exit 0 }
$pbase = $hp.ToInt64()
$rd = [System.Runtime.InteropServices.Marshal]

$pC = [PG]::GetProcAddress($hp, 'Create360Object')

# 5 个 GUID（按内存布局写入：Data1(4) Data2(2) Data3(2) Data4(8)）
$guids = @(
  @('22FA5512-0D00-4452-82BE-EBA5E33B9DB0', 0x85714),
  @('869330CB-E95B-4213-A224-917373C846A4', 0x85724),
  @('D665872C-8D3A-4F68-A5E7-5D39874B45CB', 0x85ED8),
  @('D665872C-8D3A-4F68-A5E7-5D39874B45CC', 0x85EE8),
  @('93E4B447-3C85-4F22-9D3E-CF8DF4E3AD40', 0x8626C)
)

$sel = $guids[$Guid]
Write-Output ("  PopSoftEng base = 0x{0:X8}  Create360Object = 0x{1:X8}" -f $pbase, $pC.ToInt64())
Write-Output ("  测试 GUID[{0}] = {1}" -f $Guid, $sel[0])

# 用模块内的 GUID 指针（避免自建结构出错）
$guidPtr = [IntPtr]($pbase + [int]$sel[1])
Write-Output ("  GUID 指针 = 0x{0:X8}" -f $guidPtr.ToInt64())
$gb = @()
for ($i = 0; $i -lt 16; $i++) { $gb += ("{0:X2}" -f $rd::ReadByte($guidPtr, $i)) }
Write-Output ("  GUID 字节: " + ($gb -join ' '))

# 输出指针缓冲
$outBuf = $rd::AllocHGlobal(16)
foreach ($flags in 0, 1, 2) {
  for ($i = 0; $i -lt 16; $i++) { $rd::WriteByte($outBuf, $i, 0) }
  $hr = "EXC"
  try {
    $g = $rd::GetDelegateForFunctionPointer($pC, [PG+HR3])
    $hr = $g.Invoke($guidPtr, $outBuf, $flags)
  } catch { $hr = "EXC:" + $_.Exception.GetType().Name }
  $obj = $rd::ReadInt32($outBuf, 0)
  Write-Output ("    flags={0} -> hr=0x{1:X8} ({1})  obj=0x{2:X8}" -f $flags, $hr, $obj)
  if ($obj -gt 0x10000 -and $obj -lt 0x7FFFFFFF) {
    $vtp = $rd::ReadInt32([IntPtr]$obj)
    Write-Output ("      虚表 = 0x{0:X8} (RVA 0x{1:X})" -f $vtp, ($vtp - $pbase))
    for ($k = 0; $k -lt 20; $k++) {
      $fn = $rd::ReadInt32([IntPtr]($vtp + $k*4))
      $rva = $fn - $pbase
      $tag = ""
      if ($rva -gt 0 -and $rva -lt 0x81388) { $tag = " .text" }
      Write-Output ("        [{0,2}] 0x{1:X8} RVA=0x{2:X}{3}" -f $k, $fn, $rva, $tag)
    }
  }
}