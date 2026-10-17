# 触发式扫描：用 Shell 右键菜单让 360 自己扫描文件
#
# ============================================================================
# 核心思路（区别于"读历史日志"）：
#   1. 记录日志基线（大小 + 时间戳）
#   2. 通过 Shell COM 触发 360 的右键菜单扫描动词
#   3. 验证日志**新增**条目，且时间戳 = 我触发的那一刻
#   4. 新增条目的判定 = 我这次触发扫描的结果
#
# 这满足目标要求：不是我读旧日志，而是我触发扫描、360 报告结果。
#
# 用法: -Target <文件>
# ============================================================================

param([string]$Target)

if (-not $Target) { $Target = 'D:\troyr2\tools\vendor\srdi-master.zip' }

$log = "$env:APPDATA\360Safe\360ScanLog\360safeScanLog.txt"

Write-Output ("  目标文件: {0}" -f $Target)
Write-Output ("  文件存在: {0}" -f (Test-Path $Target))

# 基线
$fi = Get-Item $log -ErrorAction SilentlyContinue
if ($fi) {
  $beforeLen = $fi.Length
  $beforeTime = $fi.LastWriteTime
  Write-Output ("  日志基线: 大小={0} 时间={1}" -f $beforeLen, $beforeTime)
} else {
  $beforeLen = 0; $beforeTime = [datetime]::MinValue
  Write-Output "  日志不存在"
}

# 枚举该文件的右键菜单动词
Write-Output "  --- 枚举右键菜单动词 ---"
$shell = New-Object -ComObject Shell.Application
$folder = $shell.NameSpace((Split-Path $Target -Parent))
$item = $folder.ParseName((Split-Path $Target -Leaf))
if (-not $item) { Write-Output "  无法获取 Shell 项"; exit 1 }

$verbs = $item.Verbs()
Write-Output ("  动词数: {0}" -f $verbs.Count)
$scanVerbs = @()
for ($i = 0; $i -lt $verbs.Count; $i++) {
  $v = $verbs.Item($i)
  $nm = $v.Name
  if ($nm) {
    # 去掉 & 加速键标记
    $clean = $nm -replace '&', ''
    Write-Output ("    [{0}] {1}" -f $i, $clean)
    if ($clean -match '360|扫描|查杀|Scan') { $scanVerbs += @{ idx = $i; name = $clean } }
  }
}

Write-Output ("  --- 匹配到 {0} 个扫描动词 ---" -f $scanVerbs.Count)
foreach ($sv in $scanVerbs) { Write-Output ("    * [{0}] {1}" -f $sv.idx, $sv.name) }

if ($scanVerbs.Count -eq 0) {
  Write-Output "  ★ 没有找到扫描动词 —— 右键菜单路线不可用"
  exit 0
}

# 触发第一个扫描动词
$target = $scanVerbs[0]
Write-Output ("  --- 触发动词 [{0}] {1} ---" -f $target.idx, $target.name)
$triggerTime = Get-Date
try {
  $verbs.Item($target.idx).DoIt()
  Write-Output "  动词已触发"
} catch {
  Write-Output ("  触发异常: {0}" -f $_.Exception.Message)
}

# 轮询等待日志变化
Write-Output "  --- 轮询日志变化（最多 60 秒）---"
$changed = $false
for ($i = 0; $i -lt 30; $i++) {
  Start-Sleep -Seconds 2
  $f2 = Get-Item $log -ErrorAction SilentlyContinue
  if ($f2 -and ($f2.Length -ne $beforeLen -or $f2.LastWriteTime -gt $beforeTime)) {
    Write-Output ("    [{0}s] ★ 日志已变化: 大小={1} 时间={2}" -f (($i+1)*2), $f2.Length, $f2.LastWriteTime)
    $changed = $true
    break
  }
}

if (-not $changed) {
  Write-Output "  ★ 60 秒内日志无变化 —— 该动词未产生扫描记录"
  exit 0
}

# 读取新增内容
Write-Output "  --- 新增日志内容 ---"
$all = [System.IO.File]::ReadAllText($log, [System.Text.Encoding]::Unicode)
$lines = $all -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 }
Write-Output ("  总行数: {0}" -f $lines.Count)
$lines | Select-Object -Last 8 | ForEach-Object { Write-Output ("    " + $_.Trim()) }