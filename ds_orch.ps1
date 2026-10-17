# deepscan.dll 编排层调用 —— Create360Object 对象工厂
#
# ============================================================================
# deepscan.dll 是 360 的**编排层**（不是底层引擎）：
#   Create360Object       RVA 0x38B46  —— 内部调用 EngLib_Init(0x3996E)
#   EngLib_Init           RVA 0x3996E
#   ScanAveMemory         RVA 0x3FEC8
#   ScanAveMemoryWithCode RVA 0x4001E
#   CreateQuarantObject   RVA 0x3913D
#   IsSupportFeature      RVA 0x3A246
#
# Create360Object 反汇编（RVA 0x38B46）：
#   +000: 68 04 02 00 00     push 0x204
#   +00A: call 0x1619BA       ; __chkstk
#   +010: lea eax,[ebp-0x210]
#   +01A: mov dword[ebp-0x210],0x204
#   +020: call 0x3996E        ; EngLib_Init  <- 先初始化引擎库
#   +026: test eax,eax / jnz 继续
#   +02A: mov eax,0x80004005  ; 失败返回 E_FAIL
#   +030: mov esi,[ebp+0x0C]  ; param_2
#   +035: push 0x10 / pop edi
#   +037: push edi / push esi / push 0x101C9160
#   +041: call 0x162AC1
#   +050: push 0xC0 / call 0x161AB9   ; operator new(0xC0)
#   ...
#   +066: call 0xD94B8
#
# 本脚本：加载 deepscan.dll，调 Create360Object，dump 返回对象与虚表。
# ============================================================================

param([string]$Root, [int]$Mode)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Mode) { $Mode = 0 }

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class DS {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="SetDllDirectoryW")]
  public static extern bool SetDllDirectoryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="LoadLibraryW")]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="GetModuleHandleW")]
  public static extern IntPtr GetModuleHandleW(string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern int GetLastError();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F0();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F1(IntPtr a);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F2(IntPtr a, IntPtr b);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F3(IntPtr a, IntPtr b, IntPtr c);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate int F4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction Stop

$dsDir = Join-Path $Root 'deepscan'
[void][DS]::SetDllDirectoryW($dsDir)
# 先加载依赖
foreach ($d in @('360Base.dll', 'deepscan\BAPI.dll', 'deepscan\AVEI.dll',
                 'deepscan\deepscan.dll')) {
  $p = Join-Path $Root $d
  if (Test-Path $p) {
    $r = [DS]::LoadLibraryW($p)
    Write-Output ("  load {0,-28} -> 0x{1:X} err={2}" -f (Split-Path $p -Leaf), $r.ToInt64(), [DS]::GetLastError())
  }
}
$h = [DS]::GetModuleHandleW('deepscan.dll')
if ($h -eq [IntPtr]::Zero) { Write-Output "  deepscan.dll 未加载"; exit 0 }
$rd = [System.Runtime.InteropServices.Marshal]
$base = $h.ToInt64()
Write-Output ("  deepscan.dll base = 0x{0:X}" -f $base)

# EngLib_Init 先单独试
$pEng = [DS]::GetProcAddress($h, 'EngLib_Init')
Write-Output ("  EngLib_Init = 0x{0:X}" -f $pEng.ToInt64())
if ($pEng -ne [IntPtr]::Zero) {
  foreach ($form in 0, 1) {
    $rc = "EXC"
    try {
      if ($form -eq 0) { $g = $rd::GetDelegateForFunctionPointer($pEng, [DS+F0]); $rc = $g.Invoke() }
      else { $g = $rd::GetDelegateForFunctionPointer($pEng, [DS+F1]); $rc = $g.Invoke([IntPtr]::Zero) }
    } catch { $rc = "EXC:" + $_.Exception.GetType().Name }
    Write-Output ("    EngLib_Init form={0} rc={1}" -f $form, $rc)
  }
}

# Create360Object
$pCreate = [DS]::GetProcAddress($h, 'Create360Object')
Write-Output ("  Create360Object = 0x{0:X}" -f $pCreate.ToInt64())
if ($pCreate -eq [IntPtr]::Zero) { exit 0 }

$out = $rd::AllocHGlobal(64)
for ($i = 0; $i -lt 64; $i++) { $rd::WriteByte($out, $i, 0) }

foreach ($form in 1, 2, 3) {
  for ($i = 0; $i -lt 64; $i++) { $rd::WriteByte($out, $i, 0) }
  $rc = "EXC"
  try {
    if ($form -eq 1) { $g = $rd::GetDelegateForFunctionPointer($pCreate, [DS+F1]); $rc = $g.Invoke($out) }
    elseif ($form -eq 2) { $g = $rd::GetDelegateForFunctionPointer($pCreate, [DS+F2]); $rc = $g.Invoke([IntPtr]::Zero, $out) }
    else { $g = $rd::GetDelegateForFunctionPointer($pCreate, [DS+F3]); $rc = $g.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $out) }
  } catch { $rc = "EXC:" + $_.Exception.GetType().Name }
  $v = $rd::ReadIntPtr($out, 0)
  Write-Output ("    Create360Object form={0} rc={1} out[0]=0x{2:X}" -f $form, $rc, $v.ToInt64())
  if ($v -ne [IntPtr]::Zero) {
    $vt = $rd::ReadIntPtr($v, 0)
    Write-Output ("      obj=0x{0:X} vtable=0x{1:X} (RVA 0x{2:X})" -f $v.ToInt64(), $vt.ToInt64(), ($vt.ToInt64() - $base))
    # dump 虚表前 24 项
    Write-Output "      虚表:"
    for ($k = 0; $k -lt 24; $k++) {
      $fp = $rd::ReadIntPtr($vt, $k * 4)
      if ($fp -ne [IntPtr]::Zero) {
        Write-Output ("        [{0:X2}] 0x{1:X} (RVA 0x{2:X})" -f ($k * 4), $fp.ToInt64(), ($fp.ToInt64() - $base))
      }
    }
    break
  }
}

$rd::FreeHGlobal($out)