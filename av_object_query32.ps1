# 通过 cloudcom2!CreateObject + QueryFilesEx 获取数值型查杀判定。
#
# 依据 REA 反编译：
#   CreateObject(int* outObj, uint* param2)        —— 0x10048660
#   QueryFilesEx(void* obj, int* out, wchar_t* path) —— 0x100BBEA0
#       -> FUN_100b7800(obj, out, path)
#   SmartCacheQuery(void* obj, LPCWSTR path)       —— 0x100BAE50
#
# GetFileTrustState* 只返回签名/证书链（字符串），不含"安全/可疑/病毒"三态；
# 三态判定需要先建立引擎对象再查询。本脚本验证该路径是否可用。
#
# 用法:
#   C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -File av_object_query32.ps1 <file>

param([string]$Target)

$root = 'C:\Users\Administrator\Desktop\360Safe'
$dll  = Join-Path $root 'deepscan\cloudcom2.dll'
$env:PATH = "$root;$root\deepscan;$root\safemon;" + $env:PATH

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class AvObj {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);

  // CreateObject 内部走 COM（未初始化时返回 0x80004002 E_NOINTERFACE），
  // 调用前必须先 CoInitializeEx。
  [DllImport("ole32.dll")]
  public static extern int CoInitializeEx(IntPtr pvReserved, uint dwCoInit);
  [DllImport("ole32.dll")]
  public static extern void CoUninitialize();

  // uint CreateObject(int* outObj, uint* p2)
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
  public delegate uint CreateObjectFn(IntPtr outObj, IntPtr p2);

  // uint QueryFilesEx(void* obj, int* out, wchar_t* path)
  [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet=CharSet.Unicode)]
  public delegate uint QueryFilesExFn(IntPtr obj, IntPtr outBuf, IntPtr path);

  // void SigInit(void)  —— 0x100FD2A0，初始化签名库
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
  public delegate void SigInitFn();

  public static Delegate Bind<T>(IntPtr h, string n) {
    IntPtr p = GetProcAddress(h, n);
    if (p == IntPtr.Zero) return null;
    return Marshal.GetDelegateForFunctionPointer(p, typeof(T));
  }
}
"@
Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue

[void][AvObj]::SetDllDirectoryW((Join-Path $root 'deepscan'))
$h = [AvObj]::LoadLibraryW($dll)
if ($h -eq [IntPtr]::Zero) { Write-Host '[!] load failed'; exit 1 }
Write-Host '[+] cloudcom2.dll loaded'

$pCreate = [AvObj]::GetProcAddress($h, 'CreateObject')
$pQuery  = [AvObj]::GetProcAddress($h, 'QueryFilesEx')
Write-Host ("    CreateObject  @ 0x{0:X8}" -f $pCreate.ToInt64())
Write-Host ("    QueryFilesEx  @ 0x{0:X8}" -f $pQuery.ToInt64())

$create = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            $pCreate, [AvObj+CreateObjectFn])
$query  = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            $pQuery, [AvObj+QueryFilesExFn])

# CreateObject 依赖 COM，必须先初始化（0x2 = APARTMENTTHREADED）
$hrInit = [AvObj]::CoInitializeEx([IntPtr]::Zero, 0x2)
Write-Host ("    CoInitializeEx 返回 = 0x{0:X8}" -f $hrInit)

# 建立引擎对象
# ★ CreateObject 的第一个参数不是"输出对象指针"，而是**输入 CLSID**：
#   反编译显示它把 param_1 指向的内容与两个常量比较
#     DAT_10173b38 = {52E34769-C5AF-4C6F-913B-B9875F366F7C}
#     DAT_10173ad0 = {055045B8-832D-45B1-A4A3-AA88C26499A2}
#   匹配成功才走 FUN_10048aa0(param_2) 创建对象。
#   第二个参数 param_2 才是输出（传 NULL 返回 0x80070057 E_INVALIDARG）。
$CLSIDS = @(
  [byte[]](0x69,0x47,0xE3,0x52,0xAF,0xC5,0x6F,0x4C,0x91,0x3B,0xB9,0x87,0x5F,0x36,0x6F,0x7C),
  [byte[]](0xB8,0x45,0x50,0x05,0x2D,0x83,0xB1,0x45,0xA4,0xA3,0xAA,0x88,0xC2,0x64,0x99,0xA2)
)
$CLSID_NAMES = @(
  '{52E34769-C5AF-4C6F-913B-B9875F366F7C}',
  '{055045B8-832D-45B1-A4A3-AA88C26499A2}'
)

$objPtr = [IntPtr]::Zero
for ($ci = 0; $ci -lt $CLSIDS.Count; $ci++) {
  $ghClsid = [System.Runtime.InteropServices.GCHandle]::Alloc($CLSIDS[$ci], [System.Runtime.InteropServices.GCHandleType]::Pinned)
  $p2buf = New-Object byte[] 16
  $ghP2 = [System.Runtime.InteropServices.GCHandle]::Alloc($p2buf, [System.Runtime.InteropServices.GCHandleType]::Pinned)
  try {
    $rc = $create.Invoke($ghClsid.AddrOfPinnedObject(), $ghP2.AddrOfPinnedObject())
    Write-Host ("    CreateObject({0}) 返回 = 0x{1:X8}" -f $CLSID_NAMES[$ci], $rc)
    if ($rc -eq 0) {
      $objPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($ghP2.AddrOfPinnedObject())
      Write-Host ("      引擎对象指针 = 0x{0:X8}" -f $objPtr.ToInt64())
      if ($objPtr -ne [IntPtr]::Zero) { break }
    }
  } catch {
    Write-Host ("      异常: {0}" -f $_.Exception.Message)
  } finally {
    $ghClsid.Free(); $ghP2.Free()
  }
}

if ($objPtr -ne [IntPtr]::Zero) {
  # 引擎对象建好后，先尝试初始化签名库（SigInit）。
  # 反编译 SigInit(0x100FD2A0) -> FUN_100fa9c0()，无参数。
  $pSigInit = [AvObj]::GetProcAddress($h, 'SigInit')
  if ($pSigInit -ne [IntPtr]::Zero) {
    $sigInit = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
                 $pSigInit, [AvObj+SigInitFn])
    try {
      $sigInit.Invoke()
      Write-Host '    SigInit 已调用'
    } catch {
      Write-Host ("    SigInit 异常: {0}" -f $_.Exception.Message)
    }
  }

  $outBuf = New-Object byte[] 65536
  $ghOut = [System.Runtime.InteropServices.GCHandle]::Alloc($outBuf, [System.Runtime.InteropServices.GCHandleType]::Pinned)
  $ghPath = [System.Runtime.InteropServices.GCHandle]::Alloc($Target, [System.Runtime.InteropServices.GCHandleType]::Pinned)
  try {
    # 先把缓冲填成 0xCC，以便区分"引擎写入的 0"与"从未被写入"
    for ($k = 0; $k -lt $outBuf.Length; $k++) { $outBuf[$k] = 0xCC }
    $qr = $query.Invoke($objPtr, $ghOut.AddrOfPinnedObject(), $ghPath.AddrOfPinnedObject())
    Write-Host ("    QueryFilesEx 返回 = 0x{0:X8} ({0})" -f $qr)

    $firstTouched = -1; $lastTouched = -1; $touched = 0
    for ($k = 0; $k -lt $outBuf.Length; $k++) {
      if ($outBuf[$k] -ne 0xCC) {
        if ($firstTouched -lt 0) { $firstTouched = $k }
        $lastTouched = $k; $touched++
      }
    }
    Write-Host ''
    if ($touched -eq 0) {
      Write-Host '    [!] 输出缓冲完全未被写入（引擎未返回数据）'
    } else {
      Write-Host ("    被写入区间: +0x{0:X} .. +0x{1:X} (共 {2} 字节)" -f $firstTouched, $lastTouched, $touched)
      Write-Host '    非零 DWORD:'
      for ($o = 0; $o -lt [Math]::Min(512, $outBuf.Length); $o += 4) {
        $v = [BitConverter]::ToUInt32($outBuf, $o)
        if ($v -ne 0 -and $v -ne 0xCCCCCCCC) {
          Write-Host ("      +0x{0:X4} = 0x{1:X8} ({1})" -f $o, $v)
        }
      }
      $s = [System.Text.Encoding]::Unicode.GetString($outBuf, 0, 512)
      $z = $s.IndexOf([char]0)
      if ($z -ge 0) { $s = $s.Substring(0, $z) }
      if ($s.Length -gt 0) { Write-Host ("    首个宽字符串 = '{0}'" -f $s) }
    }
  } catch {
    Write-Host ("    QueryFilesEx 异常: {0}" -f $_.Exception.Message)
  } finally { $ghOut.Free(); $ghPath.Free() }
} else {
  Write-Host '    [!] 两个 CLSID 都未能创建引擎对象'
}