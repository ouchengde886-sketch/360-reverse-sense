# 实测 DSMain.exe 命令行开关 —— 监控扫描互斥体 + 日志生成
#
# ============================================================================
# 第 90 轮发现：
#   DSMain.exe 真实开关: /infofastscan /frepscan /scanark /stdnsc /srv ...
#   扫描互斥体: Global\ScanInProgress_Q360DsMainMutex
#   日志目录: %APPDATA%\360Safe\360ScanLog\ScanLog_<时间>.txt
#
# 本轮：用不同开关组合启动 DSMain.exe，监控互斥体和日志文件生成。
# ============================================================================

param([string]$Root, [string]$Target)

if (-not $Root) { $Root = 'C:\Program Files (x86)\360\360Safe' }
if (-not $Target) { $Target = 'D:\troyr2' }

$exe = Join-Path $Root 'deepscan\DSMain.exe'
$logDir = "$env:APPDATA\360Safe\360ScanLog"

function LogSnap {
  $r = @{}
  if (Test-Path $logDir) {
    Get-ChildItem $logDir -File -ErrorAction SilentlyContinue | ForEach-Object {
      $r[$_.Name] = $_.Length
    }
  }
  return $r
}

function MutexHeld {
  # 尝试打开扫描互斥体；能打开说明没被占用（或已存在）
  try {
    $m = [System.Threading.Mutex]::OpenExisting('Global\ScanInProgress_Q360DsMainMutex')
    $m.Dispose()
    return $true
  } catch {
    return $false
  }
}

$before = LogSnap
Write-Host ("  日志目录现有 {0} 个文件" -f $before.Count)
Write-Host ("  目标: {0}" -f $Target)
Write-Host ("  DSMain.exe 存在: {0}" -f (Test-Path $exe))

# 现有 DSMain 进程
$existing = Get-Process -Name DSMain -ErrorAction SilentlyContinue
Write-Host ("  现有 DSMain 进程: {0}" -f (($existing | ForEach-Object { $_.Id }) -join ','))

# 测试不同开关组合
$combos = @(
  @{n='infofastscan';        a=@('/infofastscan')},
  @{n='infofastscan+target'; a=@('/infofastscan', $Target)},
  @{n='frepscan';            a=@('/frepscan')},
  @{n='frepscan+target';     a=@('/frepscan', $Target)},
  @{n='stdnsc';              a=@('/stdnsc')},
  @{n='scanark';             a=@('/scanark', $Target)},
  @{n='bootini+info';        a=@('/dbootini', '/infofastscan')},
  @{n='srv';                 a=@('/srv')}
)

foreach ($c in $combos) {
  Write-Host ("  --- 测试 {0}: {1} ---" -f $c.n, ($c.a -join ' '))
  $t0 = Get-Date
  try {
    $p = Start-Process -FilePath $exe -ArgumentList $c.a -WorkingDirectory (Split-Path $exe -Parent) -PassThru -ErrorAction Stop
    Write-Host ("      PID={0} 已启动" -f $p.Id)
  } catch {
    Write-Host ("      启动失败: {0}" -f $_.Exception.Message)
    continue
  }

  # 监控 25 秒
  $found = $null
  for ($i = 0; $i -lt 25; $i++) {
    Start-Sleep -Seconds 1
    $now = LogSnap
    foreach ($k in $now.Keys) {
      if (-not $before.ContainsKey($k)) {
        $found = $k
        Write-Host ("      [{0}s] ★ 新日志: {1} ({2} 字节)" -f ($i+1), $k, $now[$k])
        break
      }
    }
    if ($found) { break }
    if ($p.HasExited -and $i -gt 3) { break }
  }
  $el = [int]((Get-Date) - $t0).TotalSeconds
  Write-Host ("      退出={0}  耗时={1}s" -f $p.HasExited, $el)
  if (-not $found) { Write-Host "      无新日志" }
  $before = LogSnap
  Start-Sleep -Seconds 2
}

Write-Host ""
Write-Host "  --- 最终日志目录 ---"
Get-ChildItem $logDir -File -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 5 |
  ForEach-Object { Write-Host ("    {0,-40} {1,8}  {2}" -f $_.Name, $_.Length, $_.LastWriteTime) }