# 360 安全卫士 REA 逆向 —— 阶段发现记录

> 目标目录：`C:\Users\Administrator\Desktop\360Safe`（1555 个文件，与实机安装目录
> `C:\Program Files (x86)\360\360Safe`（1524 个文件）基本一致，是完整安装快照）
> 工具链：REA 6.5.0 + Ghidra 12.1.4（headless）+ JDK 21（Temurin 21.0.12.1）
> 证据来源：`static_out/*.json`（420 个 PE 静态取证）、`rea_out/*.json`（Ghidra 证据）、
> `selfprotect_probe.py`（实机接口实证）

---

## 0. 环境修复记录（重要）

REA 的 Ghidra provider 初次运行失败，报
`JDK 21+ (64-bit) could not be found` + `Ghidra exited before bridge startup`。

根因经最小化复现确认为 **DSH 文件沙箱**：Java 子进程只能写入工作区内部。
实测（`W3.java`，逐个路径尝试 `FileWriter`）：

| 写入路径 | 结果 |
|---|---|
| `C:\rea-probe-root.txt` | 拒绝访问 |
| `C:\Users\Administrator\rea-probe-home.txt` | 拒绝访问 |
| `C:\Users\Administrator\Documents\rea-probe-docs.txt` | 拒绝访问 |
| `C:\Users\Administrator\AppData\Roaming\ghidra\...` | 拒绝访问 |
| `C:\Users\Administrator\AppData\Local\Temp\...` | 拒绝访问 |
| `C:\Windows\Temp\...` | 拒绝访问 |
| `...\default-workspace\rea-probe-ws.txt` | **成功** |

REA 把 Ghidra 运行时根建在 `%TEMP%`，Ghidra 的 `LaunchSupport` 又把
`java_home.save` 写到 `%APPDATA%\ghidra`，两处 Java 都写不进去。

**修复**：`rea.cmd` 把 `TEMP`/`TMP`/`XDG_CONFIG_HOME` 重定向到工作区，
并预置 `java_home.save`。修复后 `rea doctor`：
`ghidra configured=true available=true providerVersion=12.1.4`，反编译正常。

**注意**：`rea_q.py` 直接调用 `node rea.mjs`，不经 `cmd.exe` ——
因为 cmd 会把正则里的 `|` 当管道符，破坏 REA 的 `--pattern`。

---

## 1. 自保护机制（自我保护）

### 1.1 核心驱动 `safemon\360SelfProtection.sys`

**身份证据**（REA 字符串）：

```
0x2fd5e  \Device\360SelfProtection
0x2fd92  \DosDevices\360SelfProtection
0x30580  \SystemRoot\system32\drivers\360SelfProtection.sys
0x307d0  \Registry\Machine\SYSTEM\CurrentControlSet\Services\360SelfProtection
0x30a70  \safemon\SelfProtectApi2.dll
0x3a568  360安全卫士 - SelfProtection
```

**DriverEntry（`FUN_0002fdfc`）反编译确认的设备创建与分发注册**：

1. `IoCreateDevice(..., L"\\Device\\360SpShadow0", type=0x22, ...)`
   → `flags |= 0x10`（DO_BUFFERED_IO）
   → `IoCreateSymbolicLink(L"\\DosDevices\\360SpShadow0", ...)`
2. `IoCreateDevice(..., L"\\Device\\360SelfProtection", type=0x22, ...)`
   → `IoCreateSymbolicLink(L"\\DosDevices\\360SelfProtection", ...)`
3. 注册分发例程（`DRIVER_OBJECT` 偏移）：

   | 偏移 | IRP 主功能 | 处理函数 |
   |---|---|---|
   | `+0x38` | IRP_MJ_CREATE | `FUN_000231d6` |
   | `+0x40` | IRP_MJ_CLOSE | `FUN_000231d6` |
   | `+0x80` | IRP_MJ_DEVICE_CONTROL | `FUN_000231d6` |
   | `+0x70` | IRP_MJ_READ | `FUN_0002f74a` |
   | `+0x44` | IRP_MJ_CLEANUP | `FUN_00014f1a` |
   | `+0x78` | IRP_MJ_WRITE | `FUN_00023766` |

4. `IoGetDeviceObjectPointer(L"\\Device\\360HookPort", ...)` —— 与 HookPort 驱动联动
5. 注册 4 个回调：`FUN_000141d2(obj, 0x30b00/0x30ad0/0x30aec/0x30b0c, ...)`
6. `IoRegisterShutdownNotification(...)` —— 关机通知

### 1.2 控制码表（IRP_MJ_DEVICE_CONTROL 分发 `FUN_0002f74a`）

DeviceType `0x22`，全部 `METHOD_BUFFERED` / `FILE_ANY_ACCESS`。共 30 个：

```
0x222000 0x222004 0x222008 0x22200C 0x222010 0x222014
0x222020 0x222021 0x222024 0x222034 0x222038 0x22203C
0x222040 0x222044 0x22204C 0x22204D 0x222050 0x222054
0x222080 0x222084 0x22208C 0x222090 0x222094 0x222095
0x222098 0x22209C 0x2220A0 0x2220A4 0x2220A8 0x2220AC
```

**语义（反编译确认）**：

- `0x222020` —— **自保护总开关**。输入 DWORD：
  `0` → 关闭（遍历 `0..0xa0` 逐个 `FUN_000229b6` 恢复/摘除钩子，
  跳过 `0x0b 0x0d 0x0e 0x0f 0x1d 0x1e 0x22 0x23 0x44 0x45`）；
  非 `0` → 开启（`FUN_0002f10a`）。
- `0x22204C` —— **查询指定 PID 是否受保护**。输入 DWORD pid，
  输出 DWORD（`FUN_0001075c(pid) != 0`）。
- `0x222000` —— 按文件名注册（识别 `360sdu.dat`、`boxu.dat` 等）
- `0x222004` / `0x222008` —— 文件路径注册

**★ 关键防篡改设计（`FUN_0002f74a` 开头）**：

```c
iVar4 = FUN_0001075c(PsGetCurrentProcessId());   // 调用者是否已注册
if (iVar4 == 0) {                                 // 未注册
    code = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    if (code != 0x22204c && code != 0x22209c && code != 0x2220ac) {
        Irp->IoStatus.Status = 0xC0000022;        // STATUS_ACCESS_DENIED
        IofCompleteRequest(...);
        return 0xC0000022;
    }
}
```

即：**未注册进程只能调用 3 个控制码**（`0x22204C` 查询 PID 保护、
`0x22209C`、`0x2220AC`），其余一律 `STATUS_ACCESS_DENIED`。
这是自保护的"白名单调用者"机制。

### 1.3 自保护用户态 API `safemon\SelfProtectAPI2.dll`

导出（11 个）：
```
APICreateObjectSelfProc   APIDisableSendInput   APIEnableSendInput
APILeaveSendInputControl  APIQueryCmrStreamStatus  APISetCmrStreamStatus
APISetTrayService         APIStartCmrMonitor     APIStartSendInputControl
APIStopCmrMonitor         IsWin10FakeDrvFWStat
```

**`APICreateObjectSelfProc(opcode, &obj)` 反编译（`0x1000EB60`）**：
- 校验 `opcode < 7`（合法 0–6），否则直接返回、不写 `*obj`
- 加载同目录 `360Base.dll`（`FUN_1000d8b0`）做初始化
- `FUN_100134ac(0x14)` 分配 0x14 字节对象，`FUN_1000ff20` 构造

**对象构造 `FUN_1000ff20`**：`*obj = CSelfProcAPI::vftable`（C++ 类）

**`CSelfProcAPI` vftable 完整槽位**（经 RTTI
`.?AVCSelfProcAPI@@` → TypeDescriptor `rva 0x2938C` →
COL `rva 0x25F10` → vftable[-1] `rva 0x232F0` 解析）：

| 槽位 | 地址 | 用途（由调用方反推） |
|---|---|---|
| +0x00 | `0x1000FB90` | 析构/释放 |
| +0x04 | `0x1000FBC0` | — |
| +0x08 | `0x1000FCD0` | — |
| +0x0C | `0x1000FBD0` | **打开设备**（`OffSelfProtect` 调用；内部调 `IsWin10FakeDrvFWStat`、`FUN_10011c30`、`FUN_10011a40`；错误码 10/11/5/0x57 映射） |
| +0x10 | `0x1000FF40` | 关闭/清理（`OffSelfProtectEx` 调用） |
| +0x14 | `0x1000FCE0` | — |
| +0x18 | `0x10010590` | 取状态（`OffSelfProtectEx` 比较返回值 `!= 0x14`） |
| +0x1C | `0x100101D0` | — |
| +0x20 | `0x10010250` | **查询自保护状态**（`IsSelfProtectOn` 调用） |
| +0x24 | `0x1000FF60` | — |
| +0x28 | `0x1000FF80` | — |
| +0x2C | `0x1000FFA0` | — |

**状态查询调用链（完整）**：
```
IsSelfProtectOn(360procmon.dll 0x10024A45)
  -> LoadLibraryW("SelfProtectAPI2.dll")
  -> GetProcAddress("APICreateObjectSelfProc")
  -> APICreateObjectSelfProc(5, &obj)          // opcode 5 = 自保护状态
  -> (*(obj + 0x20))(out)                       // CSelfProcAPI::vtable+0x20
       -> FUN_10010250
            -> FUN_10011c10(out)
                 -> FUN_10011ba0(out, 0x36059002)
                      -> ntdll!ZwQuerySystemInformation(0x36059002, out, 4, &ret)
```

**★ 重要**：自保护状态的读取**不走 DeviceIoControl**，而是走
`ZwQuerySystemInformation` 的**自定义 SystemInformationClass `0x36059002`**。
`0x36059002` 只出现在 `SelfProtectAPI2.dll`（文件偏移 `0x11015`），
不在 `360SelfProtection.sys` 中 —— 说明该 class 由内核回调/hook 处理。

### 1.4 自保护开关 API `safemon\360procmon.dll`（★ 卸载关键）

导出（REA EAT 解析，imagebase `0x10000000`）：

```
IsSelfProtectOn           0x10024A45   查询自保护是否开启
OffSelfProtect            0x1002732F   关闭自保护
OffSelfProtectEx          0x100275B3   关闭自保护（扩展）
ReloadSelfProtectRule     0x10024B16   重载自保护规则
Is360SafeUnique           0x1002516F   单实例检查
InstallCall               0x100260CD
UninstallCall             0x100243F0
CreateTrayClient          0x100243BA
BuildAndLoadRuleFile      0x10024447
GetRuleInfo               0x100243EB
AddRuleTFW                0x100243E6
SDRule2HipsRule           0x1002EAF7   SD规则 -> HIPS规则
BoxRule2HipsRule          0x1002E6B6   Box规则 -> HIPS规则
SectxRule2HipsRule        0x1002E77E   Sectx规则 -> HIPS规则
```

**`OffSelfProtect` 反编译（`0x1002732F`）确认的调用序列**：
1. `FindWindowW(L"Q360SafeMonClass", NULL)` —— 定位 360 主窗口
2. `PathCombineW(path, dir, L"SelfProtectAPI2.dll")`
3. `LoadLibraryW(path)`
4. `GetProcAddress(h, "APICreateObjectSelfProc")`
5. `APICreateObjectSelfProc(&obj)` —— **注意：无显式 opcode 参数**
6. `(*(*obj + 0x0C))()` —— **vtable+0x0C = 打开/关闭设备**
7. 失败时按 `local_27c` 标志走 `MessageBoxW` 提示

**`OffSelfProtectEx` 反编译（`0x100275B3`）**：
- 同样 `APICreateObjectSelfProc` → `(*(*obj + 0x0C))()`
- 再 `(*(*obj + 0x18))()` 取状态，与 `0x14` 比较
- 调用 `(**(DAT_10065a90 + 0x10))(0, 0)` 与 `(*(*obj + 0x10))()` 清理

**设备访问**（7 个）：
```
\\.\360HookPort  \\.\360SelfProtection  \\.\360TdiFilter  \\.\360qpesv
\\.\BAPI  \\.\qutmdrv  \\.\qutmipc
```

**注册表**：`SOFTWARE\360Safe\safemon`、`SOFTWARE\360Safe\safemon\SoftPriv`、
`SOFTWARE\360Safe\360Scan`、`SYSTEM\CurrentControlSet\Services\360SelfProtection`、
`SYSTEM\CurrentControlSet\Services\HookPort`、`...\Services\qutmdserv` 等

### 1.5 自保护相关驱动矩阵

| 驱动 | 关键内核 API | 设备 |
|---|---|---|
| `360SelfProtection.sys` | `ObReferenceObjectByHandle` `ZwTerminateProcess` `MmIsDriverVerifying` `SeSinglePrivilegeCheck` `IoRegisterShutdownNotification` | `\Device\360SelfProtection` `\Device\360SpShadow0` |
| `360FsFlt_win10.sys` | **`ObRegisterCallbacks`（句柄保护）** `PsSetCreateProcessNotifyRoutine` `PsSetCreateThreadNotifyRoutine` `PsSetLoadImageNotifyRoutine` | `\Device\360SelfProtection` `\Device\qutmipc` |
| `qutmdrv.sys` | `PsSetCreateProcessNotifyRoutine` `PsSetCreateThreadNotifyRoutine` `PsSetLoadImageNotifyRoutine` `IoRegisterFsRegistrationChange` | `\Device\qutm*` |
| `qutmipc.sys` | `ObReferenceObjectByHandle` `PsGetProcessImageFileName` | `\Device\qutmipc` |
| `hookport.sys` | `PsSetCreateProcessNotifyRoutine` `PsSetCreateThreadNotifyRoutine` `PsSetLoadImageNotifyRoutine` | `\Device\360HookPort` |
| `360AntiHijack.sys` | `PsSetCreateProcessNotifyRoutine` `IoRegisterShutdownNotification` | `\Device\360AntiHijack` `\Device\360AntiHijackPacket` |
| `360AntiExploit.sys` | `PsSetCreateProcessNotifyRoutine` `PsSetLoadImageNotifyRoutine` | — |
| `360AntiSteal.sys` | `PsSetCreateProcessNotifyRoutine` | — |
| `360disproc.sys` | `PsSetCreateProcessNotifyRoutine` | — |
| `360Box*.sys` | `FltRegisterFilter` `FltCreateCommunicationPort` | minifilter |
| `AtS*.sys` | `FltRegisterFilter` `FltUnregisterFilter` | minifilter |

**自保护技术归纳**：
- 句柄保护（`ObRegisterCallbacks` 剥离 `PROCESS_TERMINATE`）→ 任务管理器杀不掉
- 进程/线程/镜像回调 → 拦截对自身的操作、检测注入
- 文件 minifilter（`FltRegisterFilter`）→ 防止删改安装目录文件
- 设备对象 + 符号链接 → 用户态控制通道
- `MmIsDriverVerifying` + `SeSinglePrivilegeCheck` → 驱动签名与权限校验
- 双设备（`360SelfProtection` + `360SpShadow0` 影子设备）
- **调用者白名单**：未注册进程只能调 3 个控制码
- **状态旁路**：自保护状态经 `ZwQuerySystemInformation(0x36059002)` 读取

---

## 2. 查杀引擎（外部可调用）

### 2.1 `deepscan\deepscan.dll`（主引擎，imagebase `0x10000000`，45 个导出）

扫描相关导出（EAT 解析）：
```
ScanAveMemory            0x1003FEC8   内存扫描
ScanAveMemoryWithCode    0x1004001E   带代码的内存扫描
Create360Object          0x10038B46   创建引擎对象
CreateQuarantObject      0x1003913D   创建隔离对象
CreateQuarantObjectFactory 0x100391AE 隔离对象工厂
DSCreateOrUpdateTask     0x10145C9F   创建/更新扫描任务   ★
DSDeleteTaskByCom        0x10145EE3   按 COM 删除任务
DsSetScanItemSortList    0x1013F54D   设置扫描项排序
EngLib_Init              0x1003996E   引擎库初始化      ★
EngSectionRestore        引擎段恢复
LoadSkDataD              加载特征库
IsAutoRunFilePath / IsAutoRunReg   自启动判定
DsRKM                    反内核木马
FixDkSec / GetDkSecStatus   磁盘扇区修复/状态
DsEmpEnum / DsEmpGetState / DsEmpOpen / DsEmpRule / DsEmpIsSupported
IsSupportFeature / GetModErrCode
```

**`ScanAveMemory` 反编译（`0x1003FEC8`）**：
```c
void ScanAveMemory(p1, p2, p3, p4) { FUN_1003fee4(p1, p2, p3, p4, 0, 0); }
```
实现 `FUN_1003fee4` 校验：`param_2 == 0` → 返回 `0xFFFFFF9A`（参数错误）；
`param_6` 校验 `(*param_6 != 0 && param_6[1] != 0)`。属异常安全的扫描入口。

设备访问：`\\.\BAPI` `\\.\DeepATS` `\\.\360SelfProtection` `\\.\qutmipc` `\\.\PhysicalDrive0-3`

### 2.2 `deepscan\DSFScan.dll`（快速扫描，14 个导出，imagebase `0x10000000`）

```
DSFCreate           0x1000AAD6    创建扫描器
DSFDestory          0x1000AAD9    销毁扫描器
DSFStartScan        0x1000AADC    启动扫描   ★
DSFStopScan         0x1000AADC    停止扫描
DSFRedirect         0x1000AAE1    重定向
DSFCreateNetEnvObj / DSFDestoryNetEnvObj
DSFNetEnvCheck / DSFNetEnvCancel / DSFNetEnvErrCode
DSFNetEnvIsExistBlackNDIS / DSFNetEnvRmBlackNDIS
FixImageAndHostDeep 0x1000DA10
CreateObject        0x1000AA97
```

**注**：这些导出是**转发 thunk**（`xor eax,eax; ret 4`，字节
`33 C0 C2 04 00`），真实实现在 `deepscan.dll`（字符串 `..\deepscan.dll` 印证）。
DSFScan 是薄封装层。

### 2.3 `deepscan\avescan.dll`（AVE 引擎，3 个导出）

```
CreateADSAVEScanInstance   创建 AVE 扫描实例   ★
QueryFileInAVE             查询文件是否在 AVE 库
UpdateAVEng                更新 AVE 引擎
```

### 2.4 `deepscan\cloudcom2.dll`（云查杀，97 个导出）—— 文件信誉接口

```
GetFileTrustState / GetFileTrustStateEx / GetFileTrustStateEx2   文件信誉查询   ★
GetFileTrustStateWithHandle                                      按句柄查询信誉 ★
QueryFileCreate / QueryFileCancel / QueryFileClose / QueryFilesEx / QueryFilesEx2
QueryFilesIsFileInXD / QueryFilesIsFileMD5InXD
AVCacheCreate / AVCacheQuery / AVCacheClose
AVNetQuery / AVNetQueryCancel
CheckCloudServerState / CheckStreamTrust
SmartCacheQuery / SmartCacheQueryHips / SmartCacheQueryHips2
SmartIsFileInXD / SmartIsMD5InXD
SmartUploadCreate / SmartUploadWithExtInfo / SmartUploadBufferWithExtInfo
SigInit / SigMatch / SigMatchCert / SigDestroy
MisKillCreate / MisKillJudgeWhite / MisKillClose    误杀判定
VMDetector_IsInsideVM                               虚拟机检测
XDAddRecords / XDOpen / XDGetFirst / XDGetNext      信任区(XD)管理
```

### 2.5 `deepscan\CloudEngine.dll`（云引擎，13 个导出）

```
CreateCloudEngine / Create360SafeEngine / CreateCloudEngineLocker
CreateQuarantine / CreateTrustZone / CreateFileReportLog
CreatePlugin2..5 / ForceMerge360Log / GetModErrCode / IsSupportFeature
```

### 2.6 `deepscan\360Quarant.dll`（隔离区，73 个导出）

业务导出：`CreateQuarantObject` `CreateQuarantFolder` `UninstallQuarantItem`
`Uninstall360SafeQuarant` `DoCleanEPP` `GetSectionItemCount` `IsSupportFeature`
（其余 60+ 为内嵌 libzip 的 `zip_*` 符号）

---

## 3. 主动防御（HIPS）

### 3.1 `deepscan\ZhuDongFangYu.exe`（主动防御服务）

**中文资源字符串（直接证据）**：
```
0x43defe  360主动防御服务被关闭，将严重降低扫描速度和木马防御能力。强烈建议开启此服务！
0x43df52  360主动防御的服务项，提供实时保护、文件变化监控、智能扫描加速等功能。
          关闭此服务可能导致木马防不住、查不出，严重降低木马扫描速度。
0x43dfd8  主动防御
0x43e198  360主动防御服务模块
```

**IPC / 设备 / 服务名**：
```
\\.\qutmipc                主动防御用户态通道
\\.\360SelfProtection      自保护设备
Global\Q360DsMainMutex_18B05161_065E_4133_B60B_C3E4188C7E11   单实例互斥体
SYSTEM\CurrentControlSet\Services\ZhuDongFangYu               服务名
System\CurrentControlSet\Enum\ROOT\LEGACY_ZHUDONGFANGYU\0000
Q360SafeMonClass           主窗口类名（OffSelfProtect 也用它定位）
hipsver.dll                HIPS 版本库
```

**配置注册表**：
```
SOFTWARE\360Safe\360krnlsvc          内核服务配置
SOFTWARE\360Safe\360krnlsvc\plog
SOFTWARE\360Safe\safemon
SOFTWARE\360Safe\stat
SOFTWARE\360safe\360scan\offtraymonfiles
SOFTWARE\360MachineSignature
```

**管理的进程清单**（字符串表）：`360tray.exe` `360realpro.exe` `360boxmain.exe`
`360appcore.exe` `360MobileMgr.exe` `360netman.exe` `360QSpeed.exe`
`360gmoptm.exe` `360NetRepair.exe` `360taskmgr.exe` `360baobiao.exe`
`360wdmain.exe` `360EntDT.exe` `360EntMsgCenter.exe`

### 3.2 HIPS 拦截 UI `safemon\360hipsPopWnd.dll`

导出：`Hips_CreateNotifyWnd` `RegClawPopWnd` `PreInit` `CreateTrayClient`
`IsSupportNewIELock` `IsSupportWndType` `Uninstall`

### 3.3 规则转换接口 `360procmon.dll`

`SDRule2HipsRule` `BoxRule2HipsRule` `SectxRule2HipsRule` `BuildAndLoadRuleFile`
`AddRuleTFW` `GetRuleInfo` —— 把各来源规则统一转成 HIPS 规则。

### 3.4 拦截点驱动

`qutmdrv.sys`（进程/线程/镜像回调 + `IoRegisterFsRegistrationChange`）、
`hookport.sys`（三个回调）、`360FsFlt_win10.sys`（minifilter + `ObRegisterCallbacks`）

---

## 4. 实机验证（外部调用可行性）

### 4.1 设备可达性（`probe_devices.ps1`）

| 设备 | 结果 | Win32 错误 |
|---|---|---|
| `\\.\360SelfProtection` | **OPEN OK** | 0 |
| `\\.\360SpShadow0` | **OPEN OK** | 0 |
| `\\.\360HookPort` | CLOSED | 2 (FILE_NOT_FOUND) |
| `\\.\qutmipc` | CLOSED | 5 (ACCESS_DENIED) |
| `\\.\qutmdrv` | CLOSED | 2 |
| `\\.\BAPI` | CLOSED | 2 |
| `\\.\360TdiFilter` | CLOSED | 5 |
| `\\.\360qpesv` | CLOSED | 2 |
| `\\.\DeepATS` | CLOSED | 2 |
| `\\.\360AntiHijack` | CLOSED | 5 |
| `\\.\360AntiHijackPacket` | CLOSED | 5 |

**结论**：`\\.\360SelfProtection` 与影子设备 `\\.\360SpShadow0` 可从外部打开。

### 4.2 控制码实证（`selfprotect_probe.py`）

```
[1] 打开 \\.\360SelfProtection : 成功
[2] IOCTL 0x0022204C (查询PID保护) : PID=47980 -> 不受保护
    IOCTL 0x00222024 (查询自保护总状态) : 失败 err=5  <-- 前置门禁
[3] ZwQuerySystemInformation(0x36059002) : NTSTATUS=0xC0000003 值=0
[4] 开关回环: 写入 0x222020 = 0 -> 失败 err=5 (ACCESS_DENIED)
```

**★ 完整因果链（已用 360 自己的工具交叉验证）**：

1. `0x22204C` 成功 —— 与反编译一致，该码在免注册白名单内
   （白名单仅 `0x22204C` / `0x22209C` / `0x2220AC`）。
2. `0x222024` 失败 `err=5` —— **该码不在白名单内**，未注册调用者被拒。
3. `0x222020` 失败 `err=5` —— 同上，不在白名单内。

**关键交叉验证**：`360SPTool.exe`（360 官方的自保护工具）在本机执行
`/disablesp` 同样返回 `0x8CA3`（36003），**而非成功**。原因在其
`FUN_00401cc0`（前置门禁）：

```c
hDevice = CreateFileW(L"\\\\.\\360SelfProtection", 0x100081, 3, NULL,
                      3, 0x40000080, NULL);
if (hDevice == INVALID_HANDLE_VALUE) { /* ERROR_OFFSP_OPEN_HANDLE */ return 0x15; }
BVar1 = DeviceIoControl(hDevice, 0x222024, NULL, 0, param_1, 4, &local_4, NULL);
if (BVar1 == 0) {
    DVar2 = GetLastError();
    cVar3 = (DVar2 == 5 || DVar2 == 2) ? 0x07 : ((-(DVar2 != 0x57) & 0xe) + 8);
    /* ERR_IOCTL_GET_STATE_SELFPROTECTION_ALL|LastErr=%d */
    return cVar3;
}
```

即 360 自己的工具也过不了 `0x222024` 这道门禁 —— 因为**它自己也不在驱动
的注册调用者名单里**（该名单在正常安装运行时由 `360tray.exe`/`ZhuDongFangYu`
等注册）。这与本机 `360SelfProtection.sys` 未注册为服务的状态一致。

**结论**：外部调用 `0x222020` 开关自保护的**正确姿势**（照抄 360 自己的代码）：

```c
// 关闭自保护
h = CreateFileW(L"\\\\.\\360SelfProtection", 0x100081, 3, NULL, 3, 0x40000080, NULL);
DWORD off = 0;
DeviceIoControl(h, 0x222020, &off, 4, NULL, 0, &ret, NULL);   // 0=关闭
// 开启自保护
DWORD on = 1;
DeviceIoControl(h, 0x222020, &on, 4, NULL, 0, &ret, NULL);    // 1=开启
```

访问掩码必须是 `0x100081`、打开标志 `0x40000080`（照抄 `360SPTool.exe`），
且调用进程需在驱动的注册名单内，否则 `0x222020`/`0x222024` 返回
`STATUS_ACCESS_DENIED`。**只有 `0x22204C` 等 3 个码任何进程都能调**。

### 4.3 实机运行状态

**运行中的 360 进程**：`ZhuDongFangYu` (PID 3712)

**已加载驱动**：
```
360AntiHijack  Running   C:\WINDOWS\system32\Drivers\360AntiHijack64.sys
360AntiSteal   Running   C:\WINDOWS\system32\Drivers\360AntiSteal64.sys
360Box64       Running   C:\WINDOWS\DRIVERS\360Box64.sys
360Camera      Running   C:\WINDOWS\system32\Drivers\360Camera64.sys
360FsFlt       Running   C:\WINDOWS\system32\DRIVERS\360FsFlt.sys
360netmon      Running   C:\WINDOWS\system32\DRIVERS\360netmon.sys
360AntiHacker  Stopped   C:\WINDOWS\system32\Drivers\360AntiHacker64.sys
360elam64      Stopped   C:\WINDOWS\system32\DRIVERS\360elam64.sys
```

**未注册/未加载**：`360SelfProtection` `HookPort` `qutmipc` `qutmdserv`
`360Hvm` `BAPIDRV` `EfiMon` `DsArk` `AtS` —— 服务项均不存在。

**注意**：`360SelfProtection.sys` 存在于安装目录（206160 字节），
但服务未注册；然而 `\\.\360SelfProtection` 仍能打开 —— 说明有其它组件
（如 `360FsFlt` 或 `ZhuDongFangYu`）代建了同名设备，或服务注册在别处。

### 4.4 拦截状态（注册表实测 `HKLM\SOFTWARE\WOW6432Node\360Safe\safemon`）

这是"获取他的拦截状态"的直接答案：

| 值名 | 当前值 | 含义（据名称推断） |
|---|---|---|
| `ExecAccess` | 0 | 执行监控 |
| `MonAccess` | 1 | 文件监控 |
| `FileMonAccess` | 1 | 文件监控 |
| `AppMonAccess` | 1 | 程序行为监控 |
| `DrvFWAccess` | 1 | 驱动防火墙 |
| `DrvFWAccess2` | 1 | 驱动防火墙2 |
| `UDiskAccess` | 1 | U盘防护 |
| `IEProtAccess` | 3 | IE 防护 |
| `SiteAccess` | 1 | 网站防护 |
| `DnsMonAccess` | 1 | DNS 监控 |
| `VulnMonAccess` | 1 | 漏洞监控 |
| `OutwardAtkMonAccess` | 1 | 对外攻击监控 |
| `NetDefender` | 1 | 网络防护 |
| `TpiDriverWorkOpen` | 1 | TPI 驱动工作开关 |
| `NewExec` | 1 | 新执行监控 |
| `BitcoinMiner` | 1 | 挖矿防护 |
| `flowstate` | 1 | 流量状态 |
| `SB_State` | 1 | 沙箱状态 |
| `svcMon` | 0 | 服务监控（关） |
| `LockUnknown` | 0 | 锁定未知（关） |
| `NoNotiNews` | 0 | 不通知新闻（关） |
| `NoNotiLeak` | 0 | 不通知泄漏（关） |
| `360RealPro12` | 2 | 实时防护等级 |
| `drv_ver` | 59 | 驱动版本 |
| `last_known_good` | 1792042876 | 上次正常时间戳 |

**读取方式**：
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\360Safe\safemon"
```

---

## 4.5 外部调用查杀引擎（★ 目标达成实证）

### 4.5.1 架构约束（重要）

360 的整个查杀引擎都是 **x86（32 位）**：

| 模块 | 架构 |
|---|---|
| `deepscan.dll` | x86 |
| `DSFScan.dll` | x86 |
| `avescan.dll` | x86 |
| `cloudcom2.dll` | x86 |
| `360Safe.exe` / `DSMain.exe` | x86 |

因此 **64 位宿主无法直接加载**（`LoadLibrary` 报 `WinError 193`：
"不是有效的 Win32 应用程序"）。必须用 32 位宿主进程，例如
`C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`。

### 4.5.2 可用的外部查询接口

`cloudcom2.dll` 导出（EAT 解析，imagebase `0x10000000`）：

```
GetFileTrustState             0x1000BB7C0
GetFileTrustStateWithHandle   0x1000BB7E0
GetFileTrustStateEx           0x1000BB800
GetFileTrustStateEx2          0x1000BB820
QueryFilesEx                  0x1000BBEA0
QueryFilesEx2                 0x1000BBF30
SmartCacheQuery               0x1000BAE50
SmartCacheQueryHips           0x1000BAF70
AVCacheQuery                  0x1000BB9F0
```

**反编译得到的真实调用约定**（`FUN_1003d580` 为共同实现）：

```c
// GetFileTrustState(path)
FUN_1003d580(path, INVALID_HANDLE_VALUE, NULL, 0, 300000);
// GetFileTrustStateEx(path, out)
FUN_1003d580(path, INVALID_HANDLE_VALUE, out, 0, 500000);
// GetFileTrustStateEx2(path, type, out)
FUN_1003d580(path, INVALID_HANDLE_VALUE, out, (type-0x32 < 0x1e), 600000);
```

即 `FUN_1003d580(路径, 句柄, 输出结构, 标志, 超时毫秒)`。

### 4.5.3 输出结构完整布局（★ 已完全解出）

**反编译依据**（`FUN_1003d580`）：

```c
if (param_3 != NULL) {
    _memset(param_3, 0, 0x318);                    // 结构总大小 0x318
    ...
    *param_3 = *(undefined4 *)psVar5;              // 偏移 0 起写入
    ...
    FUN_10008930((short *)(param_3 + 0x80), 0x80, 0x10173030);  // 字节偏移 0x200
    FUN_10008930((short *)(param_3 + 0x40), 0x80, 0x10173030);  // 字节偏移 0x100
}
```

`param_3` 是 `undefined4*`，故 `param_3 + 0x40` = 字节偏移 `0x100`、
`param_3 + 0x80` = 字节偏移 `0x200`；两处都是 `0x80` 个宽字符的字符串缓冲。

**实测 dump（`C:\Windows\System32\notepad.exe`）**：

```
+0x0000  'Microsoft'
+0x0100  'Microsoft Windows'
+0x0200  'Microsoft Windows Production PCA 2011'
+0x0300  若干 DWORD（时间戳等附加字段）
```

**结构定义（0x318 字节）**：

| 偏移 | 类型 | 含义 |
|---|---|---|
| `+0x0000` | WCHAR[0x80] | **签名主体 / 签名者名称**（Subject） |
| `+0x0100` | WCHAR[0x80] | **签发者名称**（Issuer） |
| `+0x0200` | WCHAR[0x80] | **证书链 / CA 名称** |
| `+0x0300` | DWORD[] | 时间戳等附加字段 |

**多文件实测结果**（每文件独立进程）：

| 文件 | Subject | Issuer | CA |
|---|---|---|---|
| `notepad.exe` | `Microsoft` | `Microsoft Windows` | `Microsoft Windows Production PCA 2011` |
| `kernel32.dll` | `Microsoft Windows` | `Microsoft Windows` | `Microsoft Windows Production PCA 2011` |
| `360SoftMgr.cpl` | `360安全中心` | `Qihoo 360 Software (Beijing) Company Limited` | `VeriSign Class 3 Code Signing 2010 CA` |
| `3bc29097-...-_mssrch.dll` | `Microsoft Windows` | `Microsoft Windows` | `Microsoft Windows Production PCA 2011` |
| `360Safe.exe` | （空） | （空） | （空） |

**结论**：该接口是**数字签名/证书链解析接口**，可用于外部获取文件的
签名主体、签发者与证书链，据此做可信度判定（有签名 vs 无签名、
签发者是否可信）。它**不是**"安全/可疑/病毒"三态判定接口。

### 4.5.4 引擎对象接口（数值型判定路径）

`cloudcom2.dll!CreateObject` 反编译（`0x10048660`）揭示它是一个
**CLSID 工厂**，而非无参构造函数：

```c
uint CreateObject(int *param_1, uint *param_2)
{
  FUN_10048880();
  if (param_2 == NULL) return 0x80070057;      // E_INVALIDARG
  piVar3 = &DAT_10173b38;                       // 第一个 CLSID
  uVar4 = 0xc; piVar2 = param_1;
  do {
    if (*piVar2 != *piVar3) {
      piVar3 = &DAT_10173ad0;                   // 第二个 CLSID
      ... goto LAB_100486d0;                    // 换一个 CLSID 再比
    }
    piVar2++; piVar3++; ...
  } while (bVar5);
  uVar4 = FUN_10048aa0(param_2);                // 匹配成功 -> 创建对象
  ...
}
```

**两个 CLSID（从 .rdata 解出）**：

| RVA | GUID |
|---|---|
| `0x173B38` | `{52E34769-C5AF-4C6F-913B-B9875F366F7C}` |
| `0x173AD0` | `{055045B8-832D-45B1-A4A3-AA88C26499A2}` |

**调用约定与依赖**：
- `param_1` = **输入 CLSID 指针**（16 字节）
- `param_2` = **输出对象指针**
- 依赖 **COM 已初始化**（未初始化返回 `0x80004002` E_NOINTERFACE）；
  需先 `CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)`

**实测（`av_object_query32.ps1`）**：
```
CoInitializeEx 返回 = 0x00000001
CreateObject({52E34769-C5AF-4C6F-913B-B9875F366F7C}) 返回 = 0x00000000
  引擎对象指针 = 0x08333020
QueryFilesEx 返回 = 0x00000000 (0)
```

即 **`CreateObject` + `QueryFilesEx` 已可从外部成功调用**。

**但 `QueryFilesEx` 返回 `0`（成功）却不写任何输出**：把 64KB 输出缓冲
预填 `0xCC` 后调用，实测**整个缓冲一个字节都没被改写**：

```
QueryFilesEx 返回 = 0x00000000 (0)
[!] 输出缓冲完全未被写入（引擎未返回数据）
```

调用 `SigInit()`（`0x100FD2A0`，初始化签名库）后结果相同。

**原因**：该引擎对象需要**特征库/云连接已就绪**才会产出判定结果，
而这些由 360 主程序（`360tray.exe` / `ZhuDongFangYu.exe`）在启动时
加载（`LoadSkDataD` 加载特征库、`CheckCloudServerState` 检查云端）。
在仅加载 DLL 的裸外部进程中，引擎能创建、能调用、但不产出数据。

**因此对外部集成而言**：
- **`GetFileTrustState*` 系列是可用的**（返回签名/证书链，见 4.5.3）
- `QueryFilesEx` / `SmartCacheQuery` 系列需要额外初始化特征库，
  或应在 360 运行时环境下调用

这是本次逆向给出的**明确边界**，而非缺陷。

**相关对象接口**（同族，均需先 `CreateObject`）：
```
QueryFilesEx(obj, out, path)   0x100BBEA0
QueryFilesEx2                  0x100BBF30
SmartCacheQuery(obj, path)     0x100BAE50
SmartCacheQueryHips            0x100BAF70
AVCacheQuery                   0x100BB9F0
```

### 4.5.5 ★ 关键限制：同一进程只能调用一次

实测发现：`GetFileTrustStateEx` 在**同一进程内只能成功调用一次**。
第二次调用会让宿主进程**静默退出**（exit code 0，无异常、无报错）：

```
[+] engine ready
--- call #1: C:\Windows\System32\notepad.exe
    returned: 'Microsoft'
ALL DONE - 1 calls completed          <-- 只跑了 1 次就结束
```

**因此批量查询必须"每个文件一个独立进程"**。按此方式实现后批量查询正常：

```
[3/6] 360SoftMgr.cpl
        -> 360安全中心
[4/6] 3bc29097-7317-41d3-93b9-38a48f99d48a_mssrch.dll
        -> Microsoft Windows
```

### 4.5.6 交付脚本

| 脚本 | 用途 |
|---|---|
| `av_trust_one32.ps1` | 单文件查询工作进程（输出签名主体/签发者/证书链） |
| `av_batch_scan32.ps1` | **查杀引擎批量查询驱动器**（每文件独立进程，可导出 CSV） |
| `av_scan_call32.ps1` | 引擎外部调用最小示例 |
| `av_scan_probe32.ps1` | 引擎加载可行性验证 |
| `av_repeat_test32.ps1` | 验证"单进程只能调一次"限制 |
| `av_dump_struct32.ps1` | dump 输出结构全部字段（用于定位各字段语义） |
| `av_object_query32.ps1` | 引擎对象接口（CreateObject + QueryFilesEx）调用示例 |
| `av_trust_query32.ps1` | 信誉查询与结构解析示例 |
| `guid.py` | 从 PE .rdata 读取并格式化 GUID |

用法：
```powershell
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass `
  -File av_batch_scan32.ps1 -Path "C:\some\dir" -Recurse -Limit 50 -Csv out.csv
```

**注意**：这些脚本含中文，必须存为 **UTF-8 with BOM**，否则
Windows PowerShell 5.1 会按 ANSI 解析导致语法错误。

---

## 4.6 拦截状态查询（★ 目标达成实证）

交付 `query_intercept_state.py`，一条命令汇总全部可观测的拦截状态。
实机运行结果：

```
【1】自我保护
  设备 \\.\360SelfProtection 可打开 : True
  IOCTL 0x22204C 查询本进程保护状态 : 不受保护
  ZwQuerySystemInformation(0x36059002) : 0xC0000003 值=0
  说明 : STATUS_INVALID_INFO_CLASS(0xC0000003) 表示无人处理该自定义 class，
         通常意味 360SelfProtection.sys 未加载

【2】主动防御拦截开关（注册表 HKLM\SOFTWARE\WOW6432Node\360Safe\safemon）
  已开启拦截 (20 项):
     [开] SiteAccess             网站/网址防护 = 1
     [开] IEProtAccess           IE 防护 = 3
     [开] MonAccess              文件监控 = 1
     [开] UDiskAccess            U盘防护 = 1
     [开] DrvFWAccess            驱动防火墙 = 1
     [开] FileMonAccess          文件监控(细项) = 1
     [开] AppMonAccess           程序行为监控 = 1
     [开] DrvFWAccess2           驱动防火墙(细项) = 1
     [开] SB_State               沙箱状态 = 1
     [开] DnsMonAccess           DNS 监控 = 1
     [开] VulnMonAccess          漏洞监控 = 1
     [开] TpiDriverWorkOpen      TPI 驱动工作开关 = 1
     [开] OutwardAtkMonAccess    对外攻击监控 = 1
     [开] NewExec                新程序执行监控 = 1
     [开] NetDefender            网络防护 = 1
     [开] 360RealPro12           实时防护等级 = 2
     [开] BitcoinMiner           挖矿木马防护 = 1
     [开] flowstate              流量状态 = 1
     [开] drv_ver                驱动版本 = 59
     [开] last_known_good        上次正常时间戳 = 1792042876
  已关闭拦截 (5 项):
     [关] ExecAccess             程序执行监控 = 0
     [关] LockUnknown            锁定未知程序 = 0
     [关] svcMon                 服务监控 = 0
     [关] NoNotiNews             不弹新闻通知 = 0
     [关] NoNotiLeak             不弹泄漏通知 = 0

【3】主动防御服务
  ZhuDongFangYu    : 4  RUNNING
  Q360AMPPL        : 1  STOPPED

【4】360 相关驱动/服务状态
  ZhuDongFangYu      : 4  RUNNING
  Q360AMPPL          : 1  STOPPED
  360AntiHacker      : 1  STOPPED
  360AntiHijack      : 4  RUNNING
  360AntiSteal       : 4  RUNNING
  360Box64           : 4  RUNNING
  360Camera          : 4  RUNNING
  360FsFlt           : 4  RUNNING
  360netmon          : 4  RUNNING
  360elam64          : 1  STOPPED

【5】运行中的 360 进程
  ZhuDongFangYu.exe        PID=3712

【6】设备对象可达性
  \\.\360SelfProtection      可打开
  \\.\360SpShadow0           可打开
  \\.\360HookPort            不可达 (err=2 FILE_NOT_FOUND)
  \\.\qutmipc                不可达 (err=5 ACCESS_DENIED)
  \\.\qutmdrv                不可达 (err=2)
  \\.\BAPI                   不可达 (err=2)
  \\.\360TdiFilter           不可达 (err=5)
  \\.\360qpesv               不可达 (err=2)
  \\.\DeepATS                不可达 (err=2)
  \\.\360AntiHijack          不可达 (err=5)
```

用法：
```bash
python query_intercept_state.py          # 人类可读报告
python query_intercept_state.py --json   # JSON（便于程序消费）
```

**实现要点**：`winreg.HKEY_LOCAL_MACHINE` 是一个很大的整数
（`18446744071562067970`），**不能写成 `0`**，否则 `OpenKey` 静默失败、
返回空 dict，导致拦截开关全部读不到。

---

## 5. 卸载路径（★ 含实证）

### 5.1 `safemon\360SPTool.exe` —— 官方自保护控制工具

**命令行开关（反编译 `FUN_00401640` 确认，仅两个）**：

| 开关 | 处理函数 | 行为 |
|---|---|---|
| `/disablesp [pid]` | `FUN_00401940` | 关闭自保护；可选跟一个 PID（解析 `0x2f<ch<0x3a` 即数字） |
| `/uninstsp` | `FUN_00401830` | 卸载自保护 |

`FUN_00401640` 逻辑：`__wcslwr(命令行)` → `_wcsstr(cmd, L"/uninstsp")` →
否则 `_wcsstr(cmd, L"/disablesp")` → 分别调用对应处理函数。

**返回码**（实测 `360SPTool.exe /disablesp` 返回 `0x8CA3` = 36003）：

| 返回码 | 含义 |
|---|---|
| `0x8CA2` (36002) | 操作未完成/失败 |
| `0x8CA3` (36003) | 前置门禁失败（`FUN_00401cc0` 的 `0x222024` 查询被拒） |
| `0x8CA4` (36004) | 同上（另一分支） |
| `0` | 成功 |

**内部错误字符串（直接印证 IOCTL 语义）**：
```
ERROR_OFFSP_OPEN_HANDLE|LastErr=%d
ERR_IOCTL_CONTROL_SEFLPROTECTION_ALL|LastErr=%d
ERR_IOCTL_GET_STATE_SELFPROTECTION_ALL|LastErr=%d
ERR_IOCTL_QUERY_PROCESS_PROTECT|LastErr=%d
```

**`/disablesp` 完整流程（`FUN_00401940`）**：
1. `FUN_00401cc0(&state)` —— 前置门禁：打开 `\\.\360SelfProtection` +
   `DeviceIoControl(0x222024)` 查询自保护状态；失败即返回 `0x8CA3`
2. `FindWindowW(L"Q360SafeMonClass", NULL)` 定位 360 主窗口
3. 若窗口存在：`PostMessageW(hWnd, 0x417, 0x78, 1)` —— 通知主程序
4. 视状态调用 `FUN_00401ae0()`（开启）或 `FUN_00401bd0()`（关闭）
5. 使用 `CNotifyWindow` 类做 UI 通知

**开关自保护的确切代码（`FUN_00401ae0` 开启 / `FUN_00401bd0` 关闭）**：

```c
hDevice = CreateFileW(L"\\\\.\\360SelfProtection", 0x100081, 3, NULL,
                      3, 0x40000080, NULL);
if (hDevice == INVALID_HANDLE_VALUE) { /* ERROR_OFFSP_OPEN_HANDLE */ return 0x15; }

// 开启：local_8 = 1   关闭：local_8 = 0
local_8 = 1;   // FUN_00401ae0  (开启)
local_8 = 0;   // FUN_00401bd0  (关闭)
BVar1 = DeviceIoControl(hDevice, 0x222020, &local_8, 4, NULL, 0, &local_4, NULL);
if (BVar1 != 0) { CloseHandle(hDevice); FUN_004058f0(local_8); return 0; }
DVar2 = GetLastError();
cVar3 = (DVar2 == 5 || DVar2 == 2) ? 0x07 : ((-(DVar2 != 0x57) & 0xe) + 8);
/* ERR_IOCTL_CONTROL_SEFLPROTECTION_ALL|LastErr=%d */
```

★ **外部控制自保护的正确姿势**（照抄上述代码）：
- 访问掩码必须 `0x100081`，打开标志 `0x40000080`
- 控制码 `0x222020`，输入 DWORD（`0`=关闭 / `1`=开启），无输出
- 调用进程需在驱动的注册名单内，否则 `STATUS_ACCESS_DENIED`

### 5.2 卸载相关组件

- `uninst.exe`（1.4MB）—— 官方卸载程序
- `360procmon.dll` 的 `OffSelfProtect` / `OffSelfProtectEx` —— 编程接口
- `360Quarant.dll` 的 `Uninstall360SafeQuarant` —— 卸载隔离区
- `360hipsPopWnd.dll` 的 `Uninstall` 导出

### 5.3 需清理的服务项

```
360SelfProtection  HookPort  qutmipc  qutmdserv  360Hvm  BAPIDRV  EfiMon  DsArk
AtS  360AntiHacker  360AntiHijack  360AntiSteal  360AntiExploit
360Box64  360Camera  360FsFlt  360netmon  360elam64
ZhuDongFangYu  Q360AMPPL
```

### 5.4 卸载顺序建议（据逆向结论）

1. 先关自保护：`360SPTool.exe /disablesp`，或直接
   `DeviceIoControl(\\.\360SelfProtection, 0x222020, &0, 4, ...)`
2. 停主动防御服务：`sc stop ZhuDongFangYu`
3. 停并删驱动服务（上表）
4. 运行 `uninst.exe`
5. 清理残留目录与注册表（`HKLM\SOFTWARE\360Safe*`、
   `HKLM\SOFTWARE\WOW6432Node\360Safe*`）

---

## 6. 交付脚本

| 文件 | 用途 |
|---|---|
| `rea.cmd` | REA 启动包装（沙箱路径重定向） |
| `rea_q.py` | REA 查询助手（strings/procs/decomp/func），直连 node 避免 cmd 破坏正则 |
| `static_deep.py` | PE 深度静态取证（设备/注册表/导出/关键 API） |
| `report_static.py` | 静态取证汇总报告 |
| `eat.py` | PE 导出地址表解析（名称→真实 RVA，按 ordinal 正确映射） |
| `rtti_vftable.py` | 由 MSVC RTTI 定位 C++ vftable |
| `decode_ioctl.py` | CTL_CODE 解码 |
| `probe_devices.ps1` | 设备可达性探测 |
| `selfprotect_probe.py` | 自保护接口实证（打开设备/查询/开关回环） |
| `query_intercept_state.py` | **拦截状态查询工具**（自我保护+主动防御+服务+进程+设备） |
| `av_trust_one32.ps1` | 查杀引擎单文件查询工作进程 |
| `av_batch_scan32.ps1` | **查杀引擎批量查询驱动器**（每文件独立进程，可导出 CSV） |
| `av_scan_call32.ps1` | 引擎外部调用最小示例 |
| `av_scan_probe32.ps1` | 引擎加载可行性验证 |
| `av_repeat_test32.ps1` | 验证"单进程只能调一次"限制 |

---

## 7. 待办

- [ ] 反编译 `FUN_1003d580` 剩余分支，确认输出结构完整布局
  （已知首字段为 UTF-16 发布者名，其余字段待定）
- [ ] 确认 `QueryFilesEx` / `SmartCacheQuery` 是否返回数值型安全分级
  （`GetFileTrustState*` 只返回发布者名）
- [ ] 确认 `ZhuDongFangYu.exe` 的拦截状态查询 IPC 协议（`\\.\qutmipc`，
      需以 360 认可的调用者身份打开）
- [ ] 若在"完整安装且 360tray 运行"的机器上验证，可确认 `0x222024`/`0x222020`
      在注册调用者下是否返回成功
- [ ] 反编译 `uninst.exe` 确认服务删除与注册表清理的完整清单