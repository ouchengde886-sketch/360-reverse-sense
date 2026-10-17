# 检查所有 360 进程加载的引擎模块
$names = @('360Tray','360Safe','ZhuDongFangYu','DSMain','360Inst','360leakfixer')
foreach ($n in $names) {
  $ps = Get-Process -Name $n -ErrorAction SilentlyContinue
  foreach ($p in $ps) {
    Write-Host ("--- PID {0} {1} ---" -f $p.Id, $p.ProcessName)
    try {
      $mods = $p.Modules
      $eng = $mods | Where-Object { $_.ModuleName -match 'AVEI|QEX|ScChecker|deepscan|avescan|Cloudsec|PopSoft|AVEngine|jcloud|BAPI|360Base' }
      Write-Host ("    模块总数={0}  引擎相关={1}" -f $mods.Count, $eng.Count)
      foreach ($m in $eng) {
        Write-Host ("      {0,-30} {1}" -f $m.ModuleName, $m.FileName)
      }
    } catch {
      Write-Host ("    读取模块失败: {0}" -f $_.Exception.Message)
    }
  }
}