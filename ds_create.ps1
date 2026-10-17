# Create360Object 参数形式探测 —— 独立进程隔离崩溃
#
# Create360Object (RVA 0x38B46) 反汇编：
#   +010: lea eax,[ebp-0x210]
#   +01A: mov dword[ebp-0x210],0x204
#   +020: call 0x3996E        ; EngLib_Init(?)  <- 注意没有 push，说明用已有栈值
#   +026: test eax,eax / jnz 继续
#   +02A: mov eax,0x80004005  ; E_FAIL
#   +030: mov esi,[ebp+0x0C]  ; param_2
#   +035: push 0x10 / pop edi
#   +037: push edi / push esi / push 0x101C9160
#   +041: call 0x162AC1       ; 某函数(param_1=0x101C9160, param_2, 0x10)
#   +050: push 0xC0 / call 0x161AB9   ; operator new(0xC0)
#   +066: call 0xD94B8
#
# param_2 ([ebp+0x0C]) 被使用，说明 Create360Object 至少 2 个参数。
# 用法: -Form N
#   1: (out)            —— 1 参数
#   2: (0, out)         —— 2 参数
#   3: (out, GUID)      —— 2 参数反序
#   4: (0,0,out)        —— 3 参数
# ============================================================================

param([string]$Root, [int]$Form)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class DC {
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
  public delegate int F2(IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F3(IntPtr a, IntPtr b, IntPtr c);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

[void][DC]::SetDllDirectoryW((Join-Path $Root 'deepscan'))
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) { [void][DC]::LoadLibraryW($p) }
}
$h = [DC]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "load_failed"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()

# 先 EngLib_Init(NULL) 初始化引擎库
$pEng = [DC]::GetProcAddress($h, 'EngLib_Init')
try {
  $ge = $rd::GetDelegateForFunctionPointer($pEng, [DC+F1])
  [void]$ge.Invoke([IntPtr]::Zero)
} catch { }

$pCreate = [DC]::GetProcAddress($h, 'Create360Object')
$out = $rd::AllocHGlobal(64)
for ($i = 0; $i -lt 64; $i++) { $rd::WriteByte($out, $i, 0) }

$rc = "EXC"
try {
  if ($Form -eq 1) {
    $g = $rd::GetDelegateForFunctionPointer($pCreate, [DC+F1]); $rc = $g.Invoke($out)
  } elseif ($Form -eq 2) {
    $g = $rd::GetDelegateForFunctionPointer($pCreate, [DC+F2]); $rc = $g.Invoke([IntPtr]::Zero, $out)
  } elseif ($Form -eq 3) {
    $g = $rd::GetDelegateForFunctionPointer($pCreate, [DC+F2]); $rc = $g.Invoke($out, [IntPtr]::Zero)
  } else {
    $g = $rd::GetDelegateForFunctionPointer($pCreate, [DC+F3]); $rc = $g.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $out)
  }
} catch { $rc = "EXC:" + $_.Exception.GetType().Name }

$v = $rd::ReadIntPtr($out, 0)
$line = "CREATE" + [char]0x1f + "form=" + $Form + [char]0x1f + "rc=" + $rc + [char]0x1f + ("out=0x{0:X}" -f $v.ToInt64())
if ($v -ne [IntPtr]::Zero) {
  $vt = $rd::ReadIntPtr($v, 0)
  $line += [char]0x1f + ("vt=0x{0:X}(RVA 0x{1:X})" -f $vt.ToInt64(), ($vt.ToInt64() - $base))
}
Write-Output $line

if ($v -ne [IntPtr]::Zero) {
  $vt = $rd::ReadIntPtr($v, 0)
  for ($k = 0; $k -lt 20; $k++) {
    $fp = $rd::ReadIntPtr($vt, $k * 4)
    if ($fp -ne [IntPtr]::Zero) {
      Write-Output ("  [{0:X2}] 0x{1:X} (RVA 0x{2:X})" -f ($k * 4), $fp.ToInt64(), ($fp.ToInt64() - $base))
    }
  }
}

$rd::FreeHGlobal($out)