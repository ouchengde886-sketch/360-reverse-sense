# 360 引擎批量文件信誉查询（外部调用）—— 父进程驱动器。
#
# 设计依据（实测，见 FINDINGS.md 第 4.5 节）：
#   cloudcom2!GetFileTrustStateEx 在同一进程内只能成功调用一次；第二次调用
#   会让宿主进程静默退出。因此批量查询必须"每文件一个独立进程"。
#   本脚本用 32 位 PowerShell 逐文件启动 av_trust_one32.ps1 并汇总结果。
#
# 用法:
#   C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -File av_batch_scan32.ps1 -Path <file-or-dir> [-Recurse] [-Limit N]

param(
  [Parameter(Mandatory=$true)][string]$Path,
  [switch]$Recurse,
  [int]$Limit = 0,
  [string]$Csv
)

$ErrorActionPreference = 'Continue'
$ps32 = 'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
$one  = Join-Path $PSScriptRoot 'av_trust_one32.ps1'

if (-not (Test-Path $one)) { Write-Host "[!] 缺少 $one"; exit 1 }

# 收集目标文件
$files = @()
if (Test-Path $Path -PathType Container) {
  $files = Get-ChildItem -LiteralPath $Path -File -Recurse:$Recurse -ErrorAction SilentlyContinue |
           Select-Object -ExpandProperty FullName
} else {
  $files = @((Resolve-Path -LiteralPath $Path).Path)
}
if ($Limit -gt 0 -and $files.Count -gt $Limit) { $files = $files[0..($Limit-1)] }

Write-Host ('=' * 78)
Write-Host '360 查杀引擎 —— 批量文件信誉查询（外部调用，每文件独立进程）'
Write-Host ('=' * 78)
Write-Host ("目标数量 : {0}" -f $files.Count)
Write-Host ("工作脚本 : {0}" -f $one)
Write-Host ''

$rows = New-Object System.Collections.ArrayList
$i = 0
foreach ($f in $files) {
  $i++
  $pct = if ($files.Count -gt 0) { [int](100 * $i / $files.Count) } else { 100 }
  Write-Progress -Activity '查询文件信誉' -Status $f -PercentComplete $pct

  $raw = & $ps32 -ExecutionPolicy Bypass -NoProfile -File $one $f 2>$null
  $sep = [char]0x1f
  $line = $raw | Where-Object { $_ -like "RESULT$sep*" } | Select-Object -First 1

  $subject = ''; $issuer = ''; $ca = ''
  if ($line) {
    $parts = $line -split $sep
    # RESULT <sep> path <sep> subject <sep> issuer <sep> ca
    if ($parts.Count -ge 5) {
      $subject = $parts[2]; $issuer = $parts[3]; $ca = $parts[4]
    }
  }
  $signed = -not [string]::IsNullOrWhiteSpace($subject)
  $verdict = if ($signed) { "已签名: $subject" } else { '无签名信息' }
  [void]$rows.Add([PSCustomObject]@{
    File    = $f
    Subject = $subject
    Issuer  = $issuer
    CA      = $ca
    Signed  = $signed
  })
  Write-Host ("[{0}/{1}] {2}" -f $i, $files.Count, (Split-Path $f -Leaf))
  Write-Host ("        -> {0}" -f $verdict)
  if ($issuer) { Write-Host ("           签发者: {0}" -f $issuer) }
  if ($ca)     { Write-Host ("           证书链: {0}" -f $ca) }
}
Write-Progress -Activity '查询文件信誉' -Completed

Write-Host ''
Write-Host ('=' * 78)
Write-Host '汇总'
Write-Host ('=' * 78)
$rows | Format-Table -AutoSize -Wrap

if ($Csv) {
  $rows | Export-Csv -LiteralPath $Csv -NoTypeInformation -Encoding UTF8
  Write-Host ("已导出 CSV: {0}" -f $Csv)
}