# 端到端验证：触发 360 扫描 -> 读本次结果（证明是本次触发的）
#
# ============================================================================
# 目标验证标准：
#   - 5 个已知恶意文件必须被报出来（威胁名）
#   - 结果必须能证明是"我这次触发的扫描"产生的，而非历史记录
#
# 证明手段：
#   1. 记录触发前日志的 MD5 和 ScanCache 状态
#   2. 触发扫描（右键菜单动词）
#   3. 等待 ScanCache 更新（时间戳 = 触发后）
#   4. 读结果
#
# 用法: -Target <目录>
# ============================================================================

param([string]$Target)

if (-not $Target) { $Target = 'D:\troyr2' }

$log = "$env:APPDATA\360Safe\360ScanLog\360safeScanLog.txt"
$cacheDir = 'C:\ProgramData\360Safe\ScanCache'

function Md5Of($p) {
  if (-not (Test-Path $p)) { return 'N/A' }
  $b = [System.IO.File]::ReadAllBytes($p)
  return (([System.Security.Cryptography.MD5]::Create().ComputeHash($b)) | ForEach-Object { '{0:x2}' -f $_ }) -join ''
}

function CacheSnap {
  $r = @{}
  Get-ChildItem $cacheDir -File -ErrorAction SilentlyContinue | ForEach-Object {
    $r[$_.Name] = @{ len = $_.Length; time = $_.LastWriteTime }
  }
  return $r
}

$logMd5Before = Md5Of $log
$cacheBefore = CacheSnap
$triggerTime = Get-Date

Write-Output "=============================================================="
Write-Output "端到端验证：触发 360 扫描"
Write-Output "=============================================================="
Write-Output ("  目标: {0}" -f $Target)
Write-Output ("  触发前日志 MD5: {0}" -f $logMd5Before)
Write-Output ("  触发时刻: {0}" -f $triggerTime.ToString('yyyy-MM-dd HH:mm:ss.fff'))
Write-Output ("  ScanCache 文件数: {0}" -f $cacheBefore.Count)

# 触发
$shell = New-Object -ComObject Shell.Application
$parent = Split-Path $Target -Parent
$leaf = Split-Path $Target -Leaf
if (-not $leaf) { $parent = $Target; $leaf = '' }
$folder = $shell.NameSpace($parent)
$item = if ($leaf -eq '') { $folder.Self } else { $folder.ParseName($leaf) }

Write-Output "  --- 触发 '使用 360进行木马云查杀' ---"
try {
  $item.InvokeVerb('使用 360进行木马云查杀')
  Write-Output "      InvokeVerb 成功"
} catch {
  Write-Output ("      异常: {0}" -f $_.Exception.Message)
}

# 等待 ScanCache 更新
Write-Output "  --- 等待扫描完成（监控 ScanCache 变化，最多 180 秒）---"
$updated = $false
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Seconds 3
  $now = CacheSnap
  foreach ($k in $now.Keys) {
    if ($cacheBefore.ContainsKey($k)) {
      if ($now[$k].len -ne $cacheBefore[$k].len -or $now[$k].time -gt $cacheBefore[$k].time) {
        Write-Output ("    [{0}s] ★ {1} 变化: {2} -> {3} 字节  时间={4}" -f (($i+1)*3), $k, $cacheBefore[$k].len, $now[$k].len, $now[$k].time)
        $updated = $true
      }
    } else {
      Write-Output ("    [{0}s] ★ 新文件 {1} ({2} 字节)" -f (($i+1)*3), $k, $now[$k].len)
      $updated = $true
    }
  }
  if ($updated) { break }
}

if (-not $updated) {
  Write-Output "  ★ 180 秒内 ScanCache 无变化"
} else {
  Write-Output ("  ★ 扫描确实执行了（ScanCache 在触发后 {0} 秒内更新）" -f '若干')
}

# 检查日志
$logMd5After = Md5Of $log
Write-Output ""
Write-Output ("  触发后日志 MD5: {0}" -f $logMd5After)
Write-Output ("  日志是否被重写: {0}" -f ($logMd5After -ne $logMd5Before))

# 读结果
Write-Output ""
Write-Output "=============================================================="
Write-Output "扫描结果（官方日志）"
Write-Output "=============================================================="
if (Test-Path $log) {
  $raw = [System.IO.File]::ReadAllText($log, [System.Text.Encoding]::Unicode)
  $lines = $raw -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 }
  foreach ($l in $lines) {
    $s = if ($l.Length -gt 165) { $l.Substring(0, 165) } else { $l }
    Write-Output ("  " + $s)
  }
}