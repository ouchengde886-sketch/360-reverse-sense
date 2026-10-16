# 探测 360 的设备对象是否可被外部打开（外部调用可行性的直接证据）。
# 注意：PowerShell 会把 0xC0000000 解析为 Int32 负数，必须显式转 [uint32]，
# 否则参数绑定失败、返回 $null，会被误判成"打开成功"。

$sig = @'
using System;
using System.Runtime.InteropServices;
public class Dev {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateFileW(string n, uint acc, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr h);
}
'@
Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue

# 0xC0000000 does not survive PowerShell's Int32 literal parsing (it becomes
# -1073741824, and casting that to UInt32 throws). 3221225472 is the same value
# expressed as a positive decimal that fits UInt32 directly.
$GENERIC_READ_WRITE = [uint32]3221225472
$OPEN_EXISTING      = [uint32]3
$INVALID            = [IntPtr](-1)

$names = @(
  '\\.\360SelfProtection', '\\.\360SpShadow0', '\\.\360HookPort',
  '\\.\qutmipc', '\\.\qutmdrv', '\\.\BAPI', '\\.\360TdiFilter',
  '\\.\360qpesv', '\\.\DeepATS', '\\.\360AntiHijack', '\\.\360AntiHijackPacket'
)

"{0,-26} {1,-10} {2}" -f 'DEVICE', 'RESULT', 'Win32Error'
"-" * 60
foreach ($n in $names) {
  $h = [Dev]::CreateFileW($n, $GENERIC_READ_WRITE, [uint32]3, [IntPtr]::Zero, $OPEN_EXISTING, [uint32]0, [IntPtr]::Zero)
  $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if ($h -eq $INVALID -or $h -eq [IntPtr]::Zero) {
    "{0,-26} {1,-10} {2}" -f $n, 'CLOSED', $err
  } else {
    "{0,-26} {1,-10} {2}" -f $n, 'OPEN OK', $err
    [void][Dev]::CloseHandle($h)
  }
}