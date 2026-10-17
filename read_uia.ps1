# 用 UI Automation 读取 360 扫描结果对话框的文本
Add-Type -AssemblyName UIAutomationClient -ErrorAction SilentlyContinue
Add-Type -AssemblyName UIAutomationTypes -ErrorAction SilentlyContinue

$hwnd = [IntPtr]0x00D90732
try {
  $el = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
  if (-not $el) { Write-Host "  FromHandle 返回空"; exit 1 }
  Write-Host ("  元素名: '{0}'" -f $el.Current.Name)
  Write-Host ("  类名:   '{0}'" -f $el.Current.ClassName)
  Write-Host ("  控件类型: {0}" -f $el.Current.ControlType.ProgrammaticName)

  Write-Host "  --- 枚举所有后代元素 ---"
  $all = $el.FindAll([System.Windows.Automation.TreeScope]::Descendants,
                     [System.Windows.Automation.Condition]::TrueCondition)
  Write-Host ("  后代数: {0}" -f $all.Count)
  foreach ($c in $all) {
    $nm = $c.Current.Name
    $ct = $c.Current.ControlType.ProgrammaticName
    if ($nm -and $nm.Trim().Length -gt 0) {
      Write-Host ("    [{0}] '{1}'" -f $ct, $nm.Trim())
    }
  }
} catch {
  Write-Host ("  UIA 失败: {0}" -f $_.Exception.Message)
}