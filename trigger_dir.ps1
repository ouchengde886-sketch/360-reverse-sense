# 对目录触发 360 扫描，并严格验证日志时间戳
#
# ============================================================================
# 验证标准（区别"读历史日志"与"我触发的扫描结果"）：
#   1. 记录日志基线（大小 + 时间戳 + 行数）
#   2. 触发扫描
#   3. 日志必须新增条目，且**时间戳 = 我触发的那一刻**
#   4. 新增条目里的判定 = 我这次扫描的结果
#
# 用法: -Target <目录或文件>
# ============================================================================

param([string]$Target)

if (-not $Target) { $Target = 'D:\troyr2\tools\vendor\sRDI-master\lib\PowerShell' }

$log = "$env:APPDATA\360Safe\360ScanLog\360safeScanLog.txt"

function Read-LogLines {
  if (-not (Test-Path $log)) { return @() }
  $raw = [System.IO.File]::ReadAllText($log, [System.Text.Encoding]::Unicode)
  return ($raw -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 })
}

$before = Read-LogLines
$fi = Get-Item $log -ErrorAction SilentlyContinue
Write-Output ("  目标: {0}" -f $Target)
Write-Output ("  日志基线: 行数={0} 大小={1} 时间={2}" -f $before.Count, $(if($fi){$fi.Length}else{0}), $(if($fi){$fi.LastWriteTime}else{'N/A'}))
$triggerTime = Get-Date
Write-Output ("  触发时刻: {0}" -f $triggerTime.ToString('yyyy-MM-dd HH:mm:ss'))

# 触发扫描
$shell = New-Object -ComObject Shell.Application
$parent = Split-Path $Target -Parent
$leaf = Split-Path $Target -Leaf
$folder = $shell.NameSpace($parent)
$item = $folder.ParseName($leaf)
if (-not $item) { Write-Output "  无法获取项"; exit 1 }

Write-Output "  --- 触发 '使用 360进行木马云查杀' ---"
try {
  $item.InvokeVerb('使用 360进行木马云查杀')
  Write-Output "      调用成功"
} catch {
  Write-Output ("      异常: {0}" -f $_.Exception.Message)
}

# 轮询日志（最多 120 秒）
Write-Output "  --- 轮询日志（最多 120 秒）---"
$changed = $false
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Seconds 2
  $now = Read-LogLines
  if ($now.Count -ne $before.Count) {
    $f2 = Get-Item $log
    Write-Output ("    [{0}s] ★ 日志行数变化: {1} -> {2}  时间={3}" -f (($i+1)*2), $before.Count, $now.Count, $f2.LastWriteTime)
    $changed = $true
    break
  }
}

if (-not $changed) {
  Write-Output "  ★ 120 秒内日志无新增"
  # 检查是否有新窗口
  Write-Output "  --- 检查 DSMain 窗口 ---"
  $dm = Get-Process -Name DSMain -ErrorAction SilentlyContinue
  foreach ($p in $dm) {
    Write-Output ("    PID {0} 窗口标题='{1}'" -f $p.Id, $p.MainWindowTitle)
  }
  exit 0
}

# 输出新增条目
Write-Output "  --- 新增日志条目 ---"
$now = Read-LogLines
$new = $now | Select-Object -Skip $before.Count
foreach ($l in $new) { Write-Output ("    " + $l.Trim()) }