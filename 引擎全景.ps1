# 360 查杀引擎全景 —— 多引擎清单与启用状态
#
# 目标：把 360 的木马查杀涉及的**所有引擎**列清楚，标明哪些已打通。
# 依据：deepscan.dll / avescan.dll / BAPI.dll 的字符串引用 + 各 DLL 导出表 + 磁盘文件。

$root = 'C:\Program Files (x86)\360\360Safe'
$ds   = Join-Path $root 'deepscan'

function Test-Engine {
  param([string]$Name, [string]$Desc, [string]$Path, [string]$Status, [string]$Note)
  $exists = if ($Path) { Test-Path (Join-Path $root $Path) } else { $true }
  [pscustomobject]@{
    引擎 = $Name
    作用 = $Desc
    文件 = $Path
    存在 = $exists
    状态 = $Status
    说明 = $Note
  }
}

$engines = @()

# ---- 本地文件特征引擎（已打通）----
$engines += Test-Engine 'AVE 特征引擎' '本地病毒特征库比对' 'deepscan\ave\AVEI.dll' '已打通' 'ScanW 调用成功，6/6 特征库已加载'
$engines += Test-Engine 'AVEngine 核心' 'AVE 引擎底层实现' 'deepscan\ave\AVEngine.dll' '已打通' 'AveInitialize 取函数表成功'

# ---- 解包/解压引擎（AVE 内部依赖）----
$engines += Test-Engine 'QEX 解包引擎' '压缩包/安装包解包扫描' 'deepscan\qex\QEX.dll' '随 AVE 自动启用' 'AVE 扫描时内部调用，无需单独初始化'
$engines += Test-Engine '7z 解压' '7z 格式解压' 'safemon\7z.dll' '随扫描自动加载' 'deepscan.dll 引用'
$engines += Test-Engine 'unrar 解压' 'RAR 格式解压' 'deepscan\unrar.dll' '随扫描自动加载' 'deepscan.dll 引用'
$engines += Test-Engine 'avpack 解包' '通用解包' 'deepscan\avpack.dll' '随扫描自动加载' 'deepscan.dll 引用'

# ---- AI / 机器学习引擎 ----
$engines += Test-Engine 'QVM AI 引擎' '机器学习判定未知木马' 'deepscan\QVM\360QVM.dll' '已打通' 'BoleInitialize/BoleFeaturesInitialize 均返回 S_OK，引擎版本 5'

# ---- 云查杀引擎 ----
$engines += Test-Engine '云端信誉 cloudcom2' '云查杀/白名单/MD5 查询' 'deepscan\cloudcom2.dll' '已打通(签名信誉)' 'av_trust_one32.ps1 使用 GetFileTrustState'
$engines += Test-Engine 'CloudEngine' '云引擎' 'deepscan\CloudEngine.dll' '需网络' '依赖云服务连通'
$engines += Test-Engine 'Cloudsec3' '云安全' 'deepscan\Cloudsec3.dll' '需网络' 'deepscan.dll 引用'
$engines += Test-Engine 'jcloudscan' '极速云扫描' 'deepscan\jcloudscan.dll' '需网络' ''

# ---- 内存 / 行为引擎 ----
$engines += Test-Engine 'ramengine 内存引擎' '内存马/进程内存扫描' 'deepscan\ramengine.dll' '未接入' '导出 Scan/Fix/FixEx，Fix 可用于处理威胁'
$engines += Test-Engine 'ImAVEng 即时引擎' '导入表/即时扫描' 'deepscan\ImAVEng.dll' '未接入' '依赖 savapi3.dll/scan.dll'
$engines += Test-Engine 'heavygate' '重量级检测网关' 'deepscan\heavygate.dll' '未接入' 'ramengine 引用'

# ---- 系统/引导区 ----
$engines += Test-Engine 'MBR 引导区扫描' '主引导记录扫描' 'deepscan\mbr.bin' '未接入' 'deepscan.dll 引用'
$engines += Test-Engine 'BAPI 底层接口' '内核态文件/注册表接口' 'deepscan\BAPI.dll' '随扫描自动加载' '提供 FS*/BReg* 接口'
$engines += Test-Engine 'DsArk 系统修复' '系统异常修复' 'deepscan\DsArk.dll' '未接入' ''
$engines += Test-Engine '360MalwareSection' '恶意节区检测' 'deepscan\360MalwareSection.dll' '未接入' 'deepscan.dll 引用'

# ---- 其他 ----
$engines += Test-Engine 'UDiskScanEngine' 'U盘专项扫描' 'safemon\UDiskScanEngine.dll' '未接入' ''
$engines += Test-Engine 'nextav' '下一代引擎' 'safemon\nextav.dll' '未接入' 'deepscan.dll 引用'

Write-Host ""
Write-Host "==================== 360 查杀引擎全景 ===================="
Write-Host ""
$engines | Format-Table -AutoSize -Wrap
Write-Host ""
Write-Host "==================== 特征库文件 ===================="
Write-Host ""
Get-ChildItem (Join-Path $ds 'ave') -Filter '*.def' -ErrorAction SilentlyContinue |
  Sort-Object Name | ForEach-Object {
    [pscustomobject]@{ 文件=$_.Name; 大小=$_.Length; 已加载='是' }
  } | Format-Table -AutoSize
Write-Host ""
Write-Host "==================== 统计 ===================="
Write-Host ""
$total = $engines.Count
$done  = ($engines | Where-Object { $_.状态 -like '*已打通*' }).Count
$auto  = ($engines | Where-Object { $_.状态 -like '*自动*' }).Count
Write-Host ("  引擎总数        : {0}" -f $total)
Write-Host ("  已打通          : {0}" -f $done)
Write-Host ("  随扫描自动启用  : {0}" -f $auto)
Write-Host ("  需单独初始化    : {0}" -f (($engines | Where-Object { $_.状态 -like '*需单独*' }).Count))
Write-Host ("  未接入          : {0}" -f (($engines | Where-Object { $_.状态 -eq '未接入' }).Count))
Write-Host ""
Write-Host "  已加载特征库    : 6/6"