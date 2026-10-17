# 用 UI Automation 探索 360 主界面，找"自定义扫描"入口
Add-Type -AssemblyName UIAutomationClient -ErrorAction SilentlyContinue
Add-Type -AssemblyName UIAutomationTypes -ErrorAction SilentlyContinue

$proc = Get-Process -Name 360Safe -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $proc) { Write-Host "  360Safe 未运行"; exit 1 }
Write-Host ("  360Safe PID = {0}  窗口='{1}'" -f $proc.Id, $proc.MainWindowTitle)

$hwnd = $proc.MainWindowHandle
Write-Host ("  MainWindowHandle = 0x{0:X8}" -f $hwnd.ToInt64())
if ($hwnd -eq [IntPtr]::Zero) { Write-Host "  无主窗口句柄"; exit 1 }

try {
  $root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
  Write-Host ("  根元素: '{0}' class='{1}'" -f $root.Current.Name, $root.Current.ClassName)

  $all = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants,
                       [System.Windows.Automation.Condition]::TrueCondition)
  Write-Host ("  后代元素数: {0}" -f $all.Count)
  Write-Host "  --- 所有有名元素 ---"
  $n = 0
  foreach ($e in $all) {
    $nm = $e.Current.Name
    if ($nm -and $nm.Trim().Length -gt 0) {
      $ct = $e.Current.ControlType.ProgrammaticName -replace 'ControlType\.',''
      $en = if ($e.Current.IsEnabled) { 'Y' } else { 'N' }
      Write-Host ("    [{0}] en={1} '{2}'" -f $ct, $en, $nm.Trim())
      $n++
      if ($n -ge 60) { Write-Host "    ...(截断)"; break }
    }
  }
} catch {
  Write-Host ("  UIA 失败: {0}" -f $_.Exception.Message)
}