# 360 安全卫士逆向 —— 查杀引擎调用与感知层

对 360 安全卫士（v13）做逆向，目标是给**免杀自动化**提供感知与控制能力：
主动调用查杀、感知主动防御弹窗与杀毒通知、获取拦截状态、处理威胁。

> 核心动机：自动化生成样本后，需要知道**哪里被拦截、被什么拦截**。
> 这个仓库就是那层"眼睛"。

---

## 能做什么

| 能力 | 接口 | 状态 |
|---|---|---|
| 主动查杀（AVE 特征引擎，任意 PE）| `AV360Sense.scan_ave(path)` | ✅ 实测可用 |
| 多引擎联合查杀 | `AV360Sense.scan_all_engines(path)` | ✅ 5/5 检出 |
| 读取官方扫描结果（含引擎归属）| `AV360Sense.scan_log_latest()` | ✅ 实测可用 |
| 处理威胁（隔离/删除/改名）| `AV360Sense.handle_threat()` / `handle_scan_log()` | ✅ 实测可用 |
| 感知主动防御弹窗 | `AV360Sense.poll_popups()` | ✅ 实测可用 |
| 感知杀毒通知 | `AV360Sense.poll_scan_log()` | ✅ 实测可用 |
| 感知防护进程启停 | `AV360Sense.poll_processes()` | ✅ 实测可用 |
| 查询拦截状态 | `AV360Sense.state()` | ✅ 实测可用 |
| 实时统一监听 | `AV360Sense.watch()` | ✅ 实测可用 |
| QVM AI 引擎 | `AV360Sense.qvm_state()` | ⚠️ 初始化通，扫描入口未接 |
| QEX 脚本引擎实例 | `AV360Sense.qex_create_instance()` | ⚠️ 实例创建通，判定方法未定 |

---

## 快速开始

```bash
# 拦截状态
python av360_sense.py state

# 主动查杀（真实引擎）
python av360_sense.py scan-all C:\samples\payload.exe

# 读取 360 官方扫描结果（含每条威胁由哪个引擎判定）
python av360_sense.py scan-log

# 处理威胁（先试运行）
python av360_sense.py handle --dry-run
python av360_sense.py handle --copy-only --action quarantine   # 测试：只复制

# 实时感知
python av360_sense.py watch --seconds 60
```

作为库使用：

```python
from av360_sense import AV360Sense

s = AV360Sense()
print(s.state())                       # 拦截状态
print(s.scan_ave(r"C:\samples\a.exe")) # AVE 特征引擎
print(s.scan_all_engines(r"C:\a.ps1")) # 多引擎
for ev in s.watch(seconds=30):         # 实时感知
    print(ev)
```

---

## 关键发现

### 1. 360 的查杀引擎是编排式的，不是一个引擎

官方扫描日志明确记录：

```
扫描引擎:360云查杀引擎（本地木马库）  360启发式引擎  QEX脚本查杀引擎
```

运行时实测（`EnumProcessModules` 扫描前后对比）证明 **AVE 引擎不驱动其他引擎** ——
它扫描时只加载 `360Base.dll` + `AVEI.dll` + `AVEngine.dll`。

各引擎分工（来自官方日志归因，实测数据）：

| 文件类型 | 负责引擎 |
|---|---|
| PE 可执行文件 | AVE 特征引擎（本地木马库）|
| `.ps1` / `.vbs` / `.js` / `.bat` 脚本 | QEX 脚本引擎 |
| 压缩包、信誉查询 | 云安全引擎 |
| 未知样本 | 启发式 / QVM |

**AVE 引擎只处理 PE**，对脚本/压缩包一律返回 `status=4`。
判定脚本类样本必须用 `scan_all_engines()`。

### 2. 引擎调用链的关键细节

- `AveInitialize` 是**取函数表**而非初始化，首 DWORD 必须预置 `0x18`
- `ScanW` 是 `__stdcall` 5 参数（机器码 `ret 0x14` 证实）
- `SetScannerConfig` 是 `__stdcall` 而非 `__thiscall` —— 用错会**静默失败**，特征库不加载
- 目标引擎是 **x86**，必须用 `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`

详见 [查杀引擎调用现状.md](查杀引擎调用现状.md)。

### 3. 感知通道

- HIPS 弹窗窗口类：`Q360HIPSClass`（`360hipsPopWnd.dll` 注册）
- 主监控窗口类：`Q360SafeMonClass`
- 扫描日志：`%APPDATA%\360Safe\360ScanLog\360safeScanLog.txt`（**UTF-16LE**）
- 拦截开关：`HKLM\SOFTWARE\WOW6432Node\360Safe\safemon\*Access`
- 自我保护设备：`\\.\360SelfProtection`，IOCTL `0x22204C`

---

## 文件说明

### 核心交付

| 文件 | 说明 |
|---|---|
| `av360_sense.py` | 感知层 SDK（查杀/处理/感知/状态）|
| `av_ave_scan32.ps1` | AVE 特征引擎调用器（32 位宿主）|
| `av_qvm32.ps1` | QVM AI 引擎初始化 |
| `av_qex32.ps1` | QEX 脚本引擎实例创建（GUID 工厂）|
| `av_trust_one32.ps1` | 云端信誉查询 |
| `引擎全景.ps1` | 20 个引擎组件清单与状态 |

### 逆向辅助工具

| 文件 | 说明 |
|---|---|
| `exports.py` | PE 导出表解析（含 forwarder 识别）|
| `imports.py` | PE 导入表解析 |
| `guidtable.py` | 从 PE 指定 RVA 读取 GUID 表 |
| `strings.py` | UTF-16 / ASCII 字符串提取 |

### 文档

| 文件 | 说明 |
|---|---|
| `查杀引擎调用现状.md` | 引擎接入现状、调用序列、逆向细节、踩坑记录 |
| `感知层集成指南.md` | SDK 集成指南 |
| `360逆向分析报告.md` | 整体逆向报告 |
| `FINDINGS.md` | 逆向发现汇总 |
| `troyr2扫描报告.md` | 实测扫描报告 |

### 测试

| 文件 | 说明 |
|---|---|
| `test_av360_sense.py` | SDK 回归测试 |
| `test_perception.py` | 感知通道实测 |

### 逆向工具

`rea_q.py` / `rea.cmd`（REA CLI 封装）、`eat.py`（导出表）、`guid.py`、
`vftable.py` / `rtti_vftable.py`（虚表与 RTTI）、`decode_ioctl.py`、
`pe_scan.py` / `static_deep.py`（静态分析）、`selfprotect_probe.py`、
`query_intercept_state.py`、`probe_devices.ps1`

---

## 实测证据

### 多引擎检出（5/5，与 360 GUI 结果一致）

```
[命中] QEX引擎    MicrosoftEdgeUpdate.ps1    木马-ex_virus.powershell.agent.bw
[命中] 云安全引擎  srdi-master.zip            木马-ex_virus.powershell.inject.b
[命中] 云安全引擎  Get-LibSymbols.ps1         木马-Generic/Trojan.Generic.HscASRMA
[命中] 云安全引擎  Get-PEHeader.ps1           木马-Script/Worm.PowerSploit.Hp4ASREA
[命中] 云安全引擎  Invoke-Shellcode.ps1       木马-ex_virus.powershell.inject.b
```

### 威胁处理

| 模式 | 原文件 | 隔离副本 |
|---|---|---|
| `copy_only=True`（测试）| **保留** | MD5 一致 |
| `copy_only=False`（生产）| 移除 | MD5 一致 |

360 自我保护**不拦截**对普通文件的删除/改名，只保护自身安装目录。

---

## 已知限制

1. **QVM 扫描入口未接通**。`BoleInitialize` / `BoleFeaturesInitialize` 成功
   （拿到 12 + 21 个函数指针，版本 5），但 `CreateEnviroment` 在内部
   `FUN_10019d10` 处 AccessViolation，穷举 25 种参数组合均失败。
2. **QEX 只接通了实例创建，没接通判定**。已用正确的 GUID 工厂调用
   `QEXCreateInstance` 拿到实例（`rc=0`，虚表 12 个方法），并定位到
   `[0x10] FUN_10038e90(this, wchar_t* path, a2, a3)` 是带路径参数的
   扫描方法。但该方法对任意输入（含不存在的文件）都返回 0，且对象内
   存变化与判定结果无对应关系 —— 判定结果很可能通过 `a2`/`a3` 指向的
   结构体返回，其语义尚未确定。**因此脚本文件的即时查杀仍然依赖
   `official` 通道（先触发 360 扫描再读日志）。**
3. **`official` 通道读的是最近一次官方扫描日志**，不是即时查询。
   要判定新文件需先触发一次 360 扫描。AVE 通道才是即时调用（仅限 PE）。
4. **威胁处理是自己实现的**，非调用 `360Quarant.dll`。效果等价，
   但恢复依赖 `_manifest.txt` 而非 360 GUI 的隔离区。
5. 云引擎依赖网络连通。

### 关于 `DSFScan.dll!DSFStartScan`

本项目的目标是接通 `DSFStartScan` 来驱动 360 自身扫描器，但逆向发现
**它是个空壳**：

```asm
DSFStartScan:  33 c0 c2 04 00    xor eax,eax; ret 4   ; 恒返回 0，忽略参数
DSFStopScan:   33 c0 c2 04 00    xor eax,eax; ret 4
DSFCreate:     33 c0 c3          xor eax,eax; ret     ; 恒返回 0
DSFRedirect:   33 c0 40 c3       xor eax,eax; inc eax; ret  ; 恒返回 1
```

`DSFScan.dll` 只导入系统 DLL（无 `AVEI.dll`/`QEX.dll`/`cloudsec3.dll`），
真正的引擎编排在 `deepscan.dll`（`EngLib_Init`/`ScanAveMemory`/
`Create360Object`）和 `Cloudsec3.dll`（`DSEngLib_Init`/`EngCreateObject`/
`IsSupportFeature`）里。这两者已实测可调用（`DSEngLib_Init(0)=0`、
`EngLib_Init(0)=0`），但它们的扫描对象创建仍需构造 COM 环境，
成本高于直接调用 AVE 引擎。

**结论：`DSFStartScan` 不是有效的接入点。**

---

## 环境要求

- Windows，已安装 360 安全卫士（默认路径 `C:\Program Files (x86)\360\360Safe`）
- Python 3.8+
- 32 位 PowerShell：`C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`

---

## 免责声明

本项目仅**调用** 360 的引擎与读取其日志，不修改其任何文件。
所有逆向结论均基于运行时实测与静态分析，未使用 360 源码。