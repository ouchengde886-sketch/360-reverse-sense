# 决定性实验：对 D:\troyr2 整个目录触发扫描，检查日志是否被重写
#
# ============================================================================
# 已知事实：
#   - 360safeScanLog.txt 里 5 条威胁记录来自"自定义扫描"（562 文件，27 秒）
#   - 扫描内容 = D:\troyr2\
#   - 该日志文件时间戳 2026/10/17 3:38:53，大小 2978
#
# 本轮实验：
#   1. 记录日志完整基线（大小 + 时间戳 + 内容哈希）
#   2. 对 D:\troyr2 目录触发 "使用 360进行木马云查杀"
#   3. 轮询等待日志变化（最多 300 秒，因为完整扫描约 27 秒+）
#   4. 如果日志变化 -> 读出新增/新内容，验证是否包含 5 条威胁
#
# 验证标准：日志内容哈希变化 + 时间戳 = 我触发之后
# ============================================================================

param([string]$Target)

if (-not $Target) { $Target = 'D:\troyr2' }

$log = "$env:APPDATA\360Safe\360ScanLog\360safeScanLog.txt"

function Get-LogInfo {
  if (-not (Test-Path $log)) { return $null }
  $fi = Get-Item $log
  $bytes = [System.IO.File]::ReadAllBytes($log)
  $md5 = [System.Security.Cryptography.MD5]::Create().ComputeHash($bytes)
  $hash = ($md5 | ForEach-Object { '{0:x2}' -f $_ }) -join ''
  $text = [System.Text.Encoding]::Unicode.GetString($bytes)
  $lines = ($text -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 })
  return @{ len = $fi.Length; time = $fi.LastWriteTime; hash = $hash; lines = $lines }
}

$b = Get-LogInfo
Write-Output ("  目标: {0}" -f $Target)
Write-Output ("  日志基线: 大小={0} 行数={1} MD5={2}" -f $b.len, $b.lines.Count, $b.hash)
Write-Output ("  日志时间: {0}" -f $b.time)
Write-Output ("  基线威胁数: {0}" -f (($b.lines | Where-Object { $_ -match '\[木马-|\[.*引擎\]' }).Count))

$triggerTime = Get-Date
Write-Output ("  触发时刻: {0}" -f $triggerTime.ToString('yyyy-MM-dd HH:mm:ss.fff'))

# 触发扫描
$shell = New-Object -ComObject Shell.Application
$parent = Split-Path $Target -Parent
$leaf = Split-Path $Target -Leaf
if (-not $leaf) { $parent = $Target; $leaf = '' }
$folder = $shell.NameSpace($parent)
$item = if ($leaf -eq '') { $folder.Self } else { $folder.ParseName($leaf) }
if (-not $item) { Write-Output "  无法获取 Shell 项"; exit 1 }

Write-Output "  --- 触发 '使用 360进行木马云查杀' ---"
try {
  $item.InvokeVerb('使用 360进行木马云查杀')
  Write-Output "      调用成功"
} catch {
  Write-Output ("      异常: {0}" -f $_.Exception.Message)
}

# 轮询（最多 300 秒）
Write-Output "  --- 轮询日志（最多 300 秒）---"
$changed = $false
for ($i = 0; $i -lt 100; $i++) {
  Start-Sleep -Seconds 3
  $n = Get-LogInfo
  if ($n -and $n.hash -ne $b.hash) {
    Write-Output ("    [{0}s] ★★★ 日志内容已变化！" -f (($i+1)*3))
    Write-Output ("        新大小={0} 新行数={1} 新MD5={2}" -f $n.len, $n.lines.Count, $n.hash)
    Write-Output ("        新时间={0}" -f $n.time)
    $changed = $true
    break
  }
  if (($i + 1) % 10 -eq 0) { Write-Output ("    [{0}s] 日志未变..." -f (($i+1)*3)) }
}

if (-not $changed) {
  Write-Output "  ★ 300 秒内日志内容无变化 —— 该动词不写这个日志"
  exit 0
}

# 输出新日志内容
$n = Get-LogInfo
Write-Output "  --- 新日志完整内容 ---"
$idx = 0
foreach ($l in $n.lines) {
  $idx++
  $s = if ($l.Length -gt 170) { $l.Substring(0, 170) } else { $l }
  Write-Output ("    [{0,2}] {1}" -f $idx, $s)
}