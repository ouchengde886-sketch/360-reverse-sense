# 枚举目录的右键菜单动词（找会写日志的扫描入口）
Add-Type -AssemblyName System.Drawing

$targets = @(
  'D:\troyr2',
  'D:\troyr2\tools\vendor',
  'D:\troyr2\tools\vendor\sRDI-master\lib\PowerShell'
)

$shell = New-Object -ComObject Shell.Application
foreach ($t in $targets) {
  if (-not (Test-Path $t)) { Write-Host ("  [跳过] {0} 不存在" -f $t); continue }
  $parent = Split-Path $t -Parent
  $leaf = Split-Path $t -Leaf
  if (-not $parent) { $parent = $t; $leaf = '' }
  Write-Host ("=== 目录: {0} ===" -f $t)
  try {
    $folder = $shell.NameSpace($parent)
    if ($leaf -eq '') { $item = $folder.Self } else { $item = $folder.ParseName($leaf) }
    if (-not $item) { Write-Host "  无法获取项"; continue }
    $verbs = $item.Verbs()
    Write-Host ("  动词数: {0}" -f $verbs.Count)
    for ($i = 0; $i -lt $verbs.Count; $i++) {
      $nm = $verbs.Item($i).Name
      if ($nm -and $nm.Trim().Length -gt 0) {
        Write-Host ("    [{0}] {1}" -f $i, ($nm -replace '&',''))
      }
    }
  } catch {
    Write-Host ("  异常: {0}" -f $_.Exception.Message)
  }
  Write-Host ""
}