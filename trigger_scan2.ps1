# 触发式扫描 v2：直接触发"使用 360进行木马云查杀"动词
#
# ============================================================================
# v1 发现：右键菜单有 20 个动词，其中 [11] 是 "使用 360进行木马云查杀"
#         但 Verbs().Item(i).DoIt() 抛 "not implemented"（动词对象类型不同）
#
# v2 策略：用 InvokeVerb("...") 按动词名触发，这是 Shell 的标准做法。
#
# 用法: -Target <文件>
# ============================================================================

param([string]$Target)

if (-not $Target) { $Target = 'D:\troyr2\tools\vendor\srdi-master.zip' }

$log = "$env:APPDATA\360Safe\360ScanLog\360safeScanLog.txt"
Write-Output ("  目标: {0}" -f $Target)

$fi = Get-Item $log -ErrorAction SilentlyContinue
$beforeLen = if ($fi) { $fi.Length } else { 0 }
$beforeTime = if ($fi) { $fi.LastWriteTime } else { [datetime]::MinValue }
Write-Output ("  日志基线: 大小={0} 时间={1}" -f $beforeLen, $beforeTime)

$shell = New-Object -ComObject Shell.Application
$folder = $shell.NameSpace((Split-Path $Target -Parent))
$item = $folder.ParseName((Split-Path $Target -Leaf))
if (-not $item) { Write-Output "  无法获取 Shell 项"; exit 1 }

# 打印动词的规范名（InvokeVerb 需要规范名，不是显示名）
Write-Output "  --- 动词规范名 ---"
$verbs = $item.Verbs()
for ($i = 0; $i -lt $verbs.Count; $i++) {
  $v = $verbs.Item($i)
  Write-Output ("    [{0}] 显示名='{1}'" -f $i, ($v.Name -replace '&',''))
}

# 触发方式1: InvokeVerb 用显示名（去掉 &）
$triggerTime = Get-Date
$done = $false
foreach ($cand in @('使用 360进行木马云查杀', '使用360进行木马云查杀')) {
  Write-Output ("  --- 尝试 InvokeVerb('{0}') ---" -f $cand)
  try {
    $item.InvokeVerb($cand)
    Write-Output "      调用成功"
    $done = $true
    break
  } catch {
    Write-Output ("      异常: {0}" -f $_.Exception.Message)
  }
}

if (-not $done) {
  Write-Output "  --- 回退：用 Verbs().Item(11).DoIt() ---"
  try { $verbs.Item(11).DoIt(); Write-Output "      DoIt 成功"; $done = $true }
  catch { Write-Output ("      异常: {0}" -f $_.Exception.Message) }
}

# 轮询日志
Write-Output "  --- 轮询日志（最多 90 秒）---"
$changed = $false
for ($i = 0; $i -lt 45; $i++) {
  Start-Sleep -Seconds 2
  $f2 = Get-Item $log -ErrorAction SilentlyContinue
  if ($f2 -and ($f2.Length -ne $beforeLen -or $f2.LastWriteTime -gt $beforeTime)) {
    Write-Output ("    [{0}s] ★ 日志已变化: 大小={1} 时间={2}" -f (($i+1)*2), $f2.Length, $f2.LastWriteTime)
    $changed = $true
    break
  }
}

if (-not $changed) {
  Write-Output "  ★ 日志无变化"
  exit 0
}

Write-Output "  --- 新增日志内容 ---"
$all = [System.IO.File]::ReadAllText($log, [System.Text.Encoding]::Unicode)
$lines = $all -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 }
Write-Output ("  总行数: {0}" -f $lines.Count)
$lines | Select-Object -Last 6 | ForEach-Object { Write-Output ("    " + $_.Trim()) }