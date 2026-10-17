# 360 安全卫士逆向 —— 查杀引擎调用与感知层

对 360 安全卫士（v13）做逆向，目标是给**免杀自动化**提供感知与控制能力：
主动调用查杀、感知主动防御弹窗与杀毒通知、获取拦截状态、处理威胁。

> 核心动机：自动化生成样本后，需要知道**哪里被拦截、被什么拦截**。
> 这个仓库就是那层"眼睛"。

---

## 能做什么

| 能力 | 接口 | 状态 |
|---|---|---|
| 主动查杀（AVE 特征引擎，任意 PE）| `AV360Sense.scan_ave(path)` | ✅ 12/12 验证通过 |
| **非 PE 查杀（QEX 脚本引擎）** | `AV360Sense.scan_qex(path)` | ✅ 11/11 验证通过 |
| 多引擎联合查杀（仅即时引擎参与判定）| `AV360Sense.scan_all_engines(path)` | ✅ 即时引擎可用 |
| 处理威胁（隔离/删除/改名）| `AV360Sense.handle_threat()` / `handle_scan_log()` | ✅ 实测可用 |
| 感知主动防御弹窗 | `AV360Sense.poll_popups()` | ✅ 实测可用 |
| 感知杀毒通知 | `AV360Sense.poll_scan_log()` | ✅ 实测可用 |
| 感知防护进程启停 | `AV360Sense.poll_processes()` | ✅ 实测可用 |
| 查询拦截状态 | `AV360Sense.state()` | ✅ 实测可用 |
| 实时统一监听 | `AV360Sense.watch()` | ✅ 实测可用 |
| 读取官方扫描结果（含引擎归属）| `AV360Sense.scan_log_latest()` | ⚠️ 历史记录，**不参与判定** |
| **聚合全部历史扫描日志的威胁** | `AV360Sense.scan_log_history()` / `scan_log_threats_all()` | ✅ **实测恢复 9 条威胁记录** |
| **★ 双通道判定（防误报干净）** | `AV360Sense.scan_verdict()` / `scan_and_verdict()` | ✅ **三态判定实测通过** |
| **触发 360 自己的扫描（右键菜单）** | `AV360Sense.trigger_scan(path)` | ✅ **实测触发成功** |
| **触发 360 扫描（DSMain.exe）** | `AV360Sense.trigger_scan_dsmain()` | ✅ **实测触发成功** |
| QVM AI 引擎 | `AV360Sense.qvm_state()` | ⚠️ 初始化通，扫描入口未接 |
| QEX 引擎实例 | `AV360Sense.qex_create_instance()` | ✅ 实例创建通 |

> **重要：判定结论只来自即时引擎调用。** 360 官方扫描日志是历史记录，
> 对新文件会给出误导性的 clean，因此它被隔离在 `reference` 字段中，
> **绝不参与 `verdict` 计算**。详见「关于扫描日志」一节。

> **关于 `scan_qex` 的 `verdict='processed'`**：这表示引擎**确实读取并
> 处理了该文件**（文件句柄有效、扫描流程完成），这是相比日志方案的关键
> 进步。威胁判定的具体字段仍在定位中，因此该方法**不会把未确认的状态
> 谎报成 `clean`**。

### ★★★ 触发扫描后必须用 `scan_verdict()` 判定，不能看 `executed`

**实测发现（2026-10-18）**：360 的右键扫描有**两条内部路径**：

| 路径 | 表现 | 结果可读性 |
|---|---|---|
| A | 写完整格式 A 日志（扫描类型/引擎/文件数/威胁名） | ✅ **可读** |
| B | 只更新 `ScanCache`（加密） | ❌ **不可读** |

**走哪条由 360 内部决定，调用方无法控制。**

**因此这条纪律是硬性的**：

> **`trigger_scan()` 返回 `executed=True` 只证明"扫描执行了"，
> 不证明"结果是干净的"。**

**错误写法**（会误报干净）：
```python
r = s.trigger_scan(path)
if r["executed"] and not new_threats:
    print("干净")        # ← 错！可能只是日志没写出来
```

**正确写法**：
```python
v = s.scan_and_verdict(path)
if v["clean_known"]:                 # 仅"有日志且威胁数为 0"时为 True
    print("确定干净")
elif v["verdict_source"] == "cache_only":
    print("扫描跑了，但结果不可读 —— 不能声称干净")
else:
    print("扫描未执行")
```

**`clean_known` 字段在证据不足时强制为 `False`** —— 这是把
"不要报告 processed 为 clean" 这条纪律固化成了代码约束。

---

## 验证

四条独立测试，全部可复现：

```bash
python test_ave_engine.py            # AVE 引擎真实调用验证（12 项）
python test_nonpe_engine.py          # 非 PE 文件查杀验证（11 项）
python test_no_log_hallucination.py  # 证明判定不来自日志（8 项）
python test_av360_sense.py           # 感知层回归（弹窗/查杀通知）
```

`test_ave_engine.py` 用「同一份字节、不同路径」和「存在/不存在」构造对照，
证明引擎确实在判定文件内容，而不是恒返回某个值。

`test_nonpe_engine.py` 验证 QEX 脚本引擎对 `.ps1`/`.zip` 等非 PE 文件的
处理能力，用文件句柄和流程完成标志作为证据。

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

### 2. 引擎调用链的关键细节

- `AveInitialize` 是**取函数表**而非初始化，首 DWORD 必须预置 `0x18`
- `ScanW` 是 `__stdcall` 5 参数（机器码 `ret 0x14` 证实）
- `SetScannerConfig` 是 `__stdcall` 而非 `__thiscall` —— 用错会**静默失败**，特征库不加载
- **`AVEngine.dll!BAPIInitialize(LPCWSTR 产品根目录)` 必须先调用** ——
  `AVEI!CreateScannerEx` 内部会 `GetProcAddress` 并调用它；
  不调用则扫描器上下文为空，`ScanW` 返回 `status=4`
- 结果结构：`+0x000` 状态码（0=干净 1=威胁 4=非PE 251=文件不可见）、
  `+0x004` 文件大小、`+0x008` 威胁名、`+0x108` 子状态
- 目标引擎是 **x86**，必须用 `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`
- **WOW64 重定向**：32 位宿主访问 `C:\Windows\System32` 会被重定向到
  `SysWOW64`，文件"消失"导致 `status=251`。SDK 会自动改写为 `Sysnative`

### 2b. QEX 脚本引擎（非 PE 覆盖）

QEX 负责 `.ps1`/`.vbs`/`.js`/`.zip` 等 AVE 覆盖不到的文件。调用链已打通：

- `QEXCreateInstance(&GUID_A, &GUID_B, &out)` 是 `__stdcall` 3 参数，
  GUID 必须指向 **DLL 自身内存**（RVA `0x1C2364`/`0x1C2354`），
  堆拷贝会返回 `E_NOINTERFACE`
- 对象虚表 RVA `0x1BFCC4`，方法调用约定是 **`__thiscall`** ——
  用 `__stdcall`/`__cdecl` 会 `AccessViolation`
- `slot[0x10]` 内部调用 `CreateFileW(path, access, 7, NULL, disposition, 0x80, NULL)`。
  对 `FUN_10038b30` 逐条反汇编（`ret 0x1C` = 7 参数）确认了参数映射：
  **第 4 个参数是 `dwCreationDisposition`，必须传 `OPEN_EXISTING(3)`**。
  之前误传 `7`（当成 share mode）导致 `CreateFileW` 返回
  `INVALID_HANDLE_VALUE`，扫描被静默跳过 —— 这是长期卡住的根因
- 成功标志：`obj+8` 是有效文件句柄，`obj+0x18 = 1` 表示流程完成
- **必须先调用 `QexScanExportsInit` / `QexResourceExportsInit`**（同
  `AveInitialize` 的函数表模式：首 DWORD 预置表大小 `0x58`），
  它们分别填入 21 / 15 个函数指针。不调用则引擎的判定能力未启用

**已知限制（如实标注，不谎报）**：`slot[0x10]` 经反汇编确认只做
「打开文件 + 取大小」（内部调用 `CreateFileW` 与 `GetFileSizeEx`），
**不做内容判定**。真正的检测函数 `FUN_10023b50`（内含
`susp.virus.generic.a` / `Virus.Generic.A` 等威胁名模板）尚未被触发，
因此 `scan_qex` 目前返回 `verdict='processed'` 而非 `clean`——
它表示「引擎确实读取并处理了该文件」，这是相对日志方案的真实进步，
但还不是最终判定。

### 2c. QEX 真实扫描 API（`qex1` 上下文 + selector 接口）

后续逆向**打通了 QEX 的完整 API 层**，这是比 `slot[0x10]` 更底层的通道：

- `QexScanExportsInit`（RVA `0xD48D0`）填入 **21 个函数指针**
  （RVA `0xD1230`..`0xD20F0`），`QexResourceExportsInit` 另填 15 个
- 表中 `+0x08`（RVA `0xD1330`）是**上下文创建函数**：
  `int Create(void** out)`，成功返回 `0` 并写出上下文指针。
  上下文首 DWORD 是魔数 **`0x31786571`**（ASCII `"qex1"`）
- 创建过程内部按 GUID 对创建对象并存入 `ctx+4`，
  实测 `ctx+4` 指向真实 QEX 内部对象（虚表 RVA `0x1C0C1C`）
- 表中 `+0x14`（RVA `0xD1640`）是**查询入口**：
  `int Query(void* ctx, int selector, int mode)`，`mode` 只接受 `0`/`1`，
  内部 dispatch 到 `ctx+4` 对象的 `vtable[0x48]`（RVA `0xDF9D0`）
- `vtable[0x48]` 是 **0x56 路跳转表**，`selector` 取值 `1..0x56`（1..86）

**实测结果**（`test_qex_api.py`，13/13 通过）：

| 验证项 | 结果 |
|---|---|
| `QexScanExportsInit` 返回 0 | ✅ |
| 上下文创建返回 `rc=0` | ✅ |
| 魔数 `0x31786571` 校验通过 | ✅ |
| `ctx+4` 指向 QEX 内部对象 | ✅ |
| 86 个 selector 全部可调用、无崩溃 | ✅ |
| 有区分性响应（61 个 S_OK / 23 个 E_FAIL）| ✅ |
| `obj+0x0C` 等于被扫描文件字节数 | ✅ |

**仍未拿到最终判定**：86 个 selector 中没有任何一个通过**返回值**
给出「是否恶意」。`sel=65`/`67` 返回 `1`，但对干净与恶意文件
**结果完全相同**，确认是特性标志而非判定。
判定结果通过 `vtable[0x48]` 的**输出结构**（`[ebp+0x0C]`）返回，
该结构的字段布局尚未完全解出。

**结论**：QEX 引擎的**调用通道已完整打通并验证**（上下文、魔数、
selector 接口、真实文件读取全部有硬证据），
但**判定值的输出结构**是当前已知的最后一层未解细节。

详见 [查杀引擎调用现状.md](查杀引擎调用现状.md)。

### 3. 关于扫描日志（为什么它不参与判定）

`%APPDATA%\360Safe\360ScanLog\360safeScanLog.txt` 是 **360 GUI 扫描的历史记录**，
不是查询接口。它的致命问题是：**对新文件会返回误导性的结论**。

实测证据：造一个 360 从未扫描过的 `brand_new.ps1`，日志通道报 `clean`
—— 它根本没看过这个文件，只是"不在上次的威胁列表里"。

因此本 SDK 的规则是：

- `verdict` **只由即时引擎调用决定**（`scan_ave` / `scan` / `qex`）
- 日志内容放在 `reference` 字段，标注"历史记录，不参与判定"
- 需要日志请显式调用 `scan_log_latest()`

`test_no_log_hallucination.py` 专门验证这条规则不被破坏。

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