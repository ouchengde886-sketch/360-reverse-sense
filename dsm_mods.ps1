# 检查 DSMain 进程加载的 360 引擎模块
$p = Get-Process -Id 18984 -ErrorAction SilentlyContinue
if (-not $p) { Write-Host "  进程 18984 不存在"; exit }
Write-Host ("  进程: {0}" -f $p.ProcessName)
try { Write-Host ("  路径: {0}" -f $p.Path) } catch { Write-Host "  路径: (拒绝访问)" }
try {
  $mods = $p.Modules | Where-Object { $_.FileName -match '360' }
  Write-Host ("  360 相关模块数: {0}" -f $mods.Count)
  foreach ($m in ($mods | Sort-Object ModuleName)) {
    Write-Host ("    {0,-34} {1}" -f $m.ModuleName, $m.FileName)
  }
} catch {
  Write-Host ("  读取模块失败: {0}" -f $_.Exception.Message)
}