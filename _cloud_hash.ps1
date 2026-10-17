# 云引擎哈希直查测试
#
# 目的：绕开"扫描整个文件"的复杂度，直接喂已知木马的哈希给云引擎，
#       验证判定通道本身是否通畅。
#
# 逆向得到的精确语义（汇编确认）：
#
# CloudQuerySetItemUseFileOrMem  (RVA 0x4E33, ret 0x10 = 4 参数)
#   8B 44 24 04       mov eax,[esp+4]     ; item
#   85 C0 74 18       test eax,eax / jz
#   8B 4C 24 08       mov ecx,[esp+8]
#   89 48 38          mov [eax+0x38],ecx  ; 写入 item+0x38
#   8B 4C 24 0C       mov ecx,[esp+0x0C]
#   89 48 3C          mov [eax+0x3C],ecx  ; item+0x3C
#   8B 4C 24 10       mov ecx,[esp+0x10]
#   89 48 40          mov [eax+0x40],ecx  ; item+0x40
#   33 C0 40          xor eax,eax; inc eax ; 返回 1
#   C2 10 00          ret 0x10
#
# CloudQuerySetItemCustomSha1AndCustomFingerPrint (RVA 0x4E6B, ret 0x10 = 4 参数)
#   同上，但写入 item+0x44 / +0x48 / +0x4C
#
# 这两个函数是纯本地 setter，不需要网络。可以用来验证：
#   1. 字段是否被正确写入（读回验证）
#   2. 写入后 GetTrojanName 是否有变化

param([string]$Hash, [string]$Mode)

$sep = [char]0x1f
$Root = 'C:\Program Files (x86)\360\360Safe'
if (-not $Hash) { $Hash = '945a972d2072aa26f9698ae7c888aa69' }  # MicrosoftEdgeUpdate.ps1
if (-not $Mode) { $Mode = 'set' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class CHash {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr F0();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F2(IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  [return: MarshalAs(UnmanagedType.I4)]
  public delegate int F4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate uint U4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][CHash]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\jcloudscan.dll',
                 'deepscan\cloudcom2.dll', 'deepscan\CloudEngine.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][CHash]::LoadLibraryW($p) }
}
$h = [CHash]::GetModuleHandleW('jcloudscan.dll')
$rd = [System.Runtime.InteropServices.Marshal]
function Fn($n, $t) {
  $p = [CHash]::GetProcAddress($h, $n)
  if ($p -eq [IntPtr]::Zero) { return $null }
  return $rd::GetDelegateForFunctionPointer($p, $t)
}

$fInit = Fn 'Init360NetBaseDll' ([CHash+F1])
if ($fInit) { try { [void]$fInit.Invoke([IntPtr]::Zero) } catch { } }

$fCreate = Fn 'CloudQueryCreate' ([CHash+F0])
$query = [IntPtr]::Zero
try { $query = $fCreate.Invoke() } catch { }
$fItem = Fn 'CloudQueryCreateQueryItem' ([CHash+F0])
$item = [IntPtr]::Zero
try { $item = $fItem.Invoke() } catch { }
if ($item -eq [IntPtr]::Zero) { Write-Output ("HASH" + $sep + "err=no_item"); exit 0 }

# 把 32 位十六进制哈希拆成 4 个 DWORD（小端）
$bytes = [byte[]]::new(16)
for ($i = 0; $i -lt 16; $i++) { $bytes[$i] = [Convert]::ToByte($Hash.Substring($i*2, 2), 16) }
$d0 = [BitConverter]::ToInt32($bytes, 0)
$d1 = [BitConverter]::ToInt32($bytes, 4)
$d2 = [BitConverter]::ToInt32($bytes, 8)
$d3 = [BitConverter]::ToInt32($bytes, 12)

# 调用 SetItemUseFileOrMem(item, d0, d1, d2) —— 4 参数
$fUse = Fn 'CloudQuerySetItemUseFileOrMem' ([CHash+U4])
$useRc = "skip"
if ($fUse) {
  try { $useRc = $fUse.Invoke($item, [IntPtr]$d0, [IntPtr]$d1, [IntPtr]$d2) } catch { $useRc = "EXC:" + $_.Exception.GetType().Name }
}

# 调用 SetItemCustomSha1AndCustomFingerPrint(item, d0, d1, d2) —— 4 参数
$fSha = Fn 'CloudQuerySetItemCustomSha1AndCustomFingerPrint' ([CHash+U4])
$shaRc = "skip"
if ($fSha) {
  try { $shaRc = $fSha.Invoke($item, [IntPtr]$d0, [IntPtr]$d1, [IntPtr]$d2) } catch { $shaRc = "EXC:" + $_.Exception.GetType().Name }
}

Write-Output ("HASH" + $sep + "hash=" + $Hash + $sep + "useRc=" + $useRc + $sep + "shaRc=" + $shaRc)

# 读回 item 对象，确认字段被写入
$fields = @()
for ($o = 0x30; $o -lt 0x60; $o += 4) {
  $v = $rd::ReadInt32($item, $o)
  if ($v -ne 0) { $fields += ("+{0:X}={1:X8}" -f $o, $v) }
}
Write-Output ("  item 字段: " + ($fields -join ' '))

if ($Mode -eq 'full') {
  # 完整流程：加入数组后查询
  $fArr = Fn 'CloudQueryCreateItemArray' ([CHash+F0])
  $arr = [IntPtr]::Zero
  if ($fArr) { try { $arr = $fArr.Invoke() } catch { } }
  $fApp = Fn 'CloudQueryAppendItemArray' ([CHash+F2])
  if ($fApp -and $arr -ne [IntPtr]::Zero) { try { [void]$fApp.Invoke($arr, $item) } catch { } }
  $fNet = Fn 'CloudQueryNetQuery' ([CHash+F4])
  $netRc = "skip"
  if ($fNet) { try { $netRc = $fNet.Invoke($query, $arr, [IntPtr]::Zero, [IntPtr]::Zero) } catch { $netRc = "EXC" } }
  Write-Output ("  NetQuery rc=" + $netRc)

  $fName = Fn 'CloudQueryGetItemFileInfoTrojanName' ([CHash+F4])
  if ($fName) {
    $nb = $rd::AllocHGlobal(1024)
    for ($i = 0; $i -lt 1024; $i++) { $rd::WriteByte($nb, $i, 0) }
    $nr = "EXC"
    try { $nr = $fName.Invoke($item, $nb, [IntPtr]512, [IntPtr]::Zero) } catch { }
    $nm = $rd::PtrToStringUni($nb)
    if (-not $nm) { $nm = $rd::PtrToStringAnsi($nb) }
    Write-Output ("  GetTrojanName rc=" + $nr + " name='" + $nm + "'")
    $rd::FreeHGlobal($nb)
  }
}