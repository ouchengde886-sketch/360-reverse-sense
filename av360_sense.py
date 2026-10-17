#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
360 感知层 SDK —— 免杀自动化测试的"眼睛"。

设计目标（对应免杀自动化需求）：
  1. 主动调用查杀   —— scan()        把样本交给 360 引擎判定
  2. 感知主动防御弹窗 —— watch()       实时捕获 HIPS 拦截弹窗
  3. 感知杀毒通知    —— watch()       实时捕获查杀命中/处理通知
  4. 知道哪里被拦截  —— events()      结构化事件流（谁、什么、在哪、被怎么处理）

逆向依据（详见 FINDINGS.md / 360逆向分析报告.md）：
  * HIPS 弹窗窗口类 = Q360HIPSClass
      - 360hipsPopWnd.dll 中 GetClassInfoW/RegisterClass 注册（RVA 0x2544）
      - 同 DLL 还引用 Q360SafeMonClass（主窗口）
  * 弹窗定义文件：%s\\360hipspopwnd\\popwnds\\*.xml
  * 通知分发：Utils\\360MsgCenter.exe /NOTIFY=%d
  * 查杀引擎：cloudcom2.dll!GetFileTrustState*（32 位宿主，单进程只能调一次）
  * 扫描日志：%APPDATA%\\360Safe\\360ScanLog\\360safeScanLog.txt（明文）
  * 拦截开关：HKLM\\SOFTWARE\\WOW6432Node\\360Safe\\safemon\\*Access
  * 自保护设备：\\\\.\\360SelfProtection，IOCTL 0x22204C 查询 PID 保护

用法（作为库）：
    from av360_sense import AV360Sense
    s = AV360Sense()
    print(s.state())            # 当前拦截状态
    print(s.scan(r"C:\\test.exe"))   # 主动查杀
    for ev in s.watch(seconds=30):   # 实时感知
        print(ev)

用法（命令行）：
    python av360_sense.py state                 # 打印拦截状态
    python av360_sense.py scan <file>           # 主动查杀
    python av360_sense.py watch --seconds 60    # 实时感知弹窗与通知
    python av360_sense.py events --json         # 导出历史事件
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Iterator

sys.stdout.reconfigure(encoding="utf-8")

# ---------------------------------------------------------------- 常量

SAFE_ROOT = r"C:\Program Files (x86)\360\360Safe"
SNAP_ROOT = r"C:\Users\Administrator\Desktop\360Safe"

# 引擎根目录候选（按优先级）：本机安装 > 快照副本
ENGINE_ROOTS = [
    r"C:\Program Files (x86)\360\360Safe",
    r"C:\Program Files\360\360Safe",
    r"C:\Users\Administrator\Desktop\360Safe",
]


def find_engine_root() -> str | None:
    """定位可用的 360 引擎根目录。

    优先使用**本机实际安装**的引擎（特征库最新、与运行中的
    主动防御一致）；找不到时回退到离线快照副本。
    """
    for r in ENGINE_ROOTS:
        if os.path.exists(os.path.join(r, "deepscan", "cloudcom2.dll")):
            return r
    return None


APPDATA_360 = os.path.join(os.environ.get("APPDATA", ""), "360Safe")
SCAN_LOG = os.path.join(APPDATA_360, "360ScanLog", "360safeScanLog.txt")
LOGINFO_DIR = os.path.join(APPDATA_360, "LogInfo")
PROGRAMDATA_360 = r"C:\ProgramData\360safe"

# 逆向确认的窗口类名
HIPS_POPUP_CLASS = "Q360HIPSClass"      # 主动防御拦截弹窗
MAIN_WINDOW_CLASS = "Q360SafeMonClass"  # 360 主窗口
NETMON_WINDOW_CLASS = "Q360NetmonMainWndClass"

# ★ 实测枚举到的全部 360 弹窗/通知窗口类（2026-10-18 本机 EnumWindows 快照）
# 主动防御与实时防护的提示窗口不止 Q360HIPSClass 一个 —— 只盯一个类会漏报。
POPUP_CLASSES = {
    "Q360HIPSClass",              # 主动防御拦截弹窗
    "Q360SafeMainClass",          # 360 主界面（扫描结果在此显示）
    "Q360SafeMonClass",           # 实时防护监控窗口
    "Qh360ExpClient",             # 体验/通知客户端（Qh360ExpClient_safe）
    "Qh360UCenterWnd",            # 用户中心通知
    "Qh360TraySafeId",            # 托盘身份提示
    "Q360NetmonMainWndClass",     # 网络监控
    "Q360NetmonClass",            # 网络监控（托盘）
    "360NetmonWindowClass{364B9", # 网络监控（截断类名，前缀匹配）
    "Q360AdPopBlocker",           # 广告弹窗拦截器
    "AdvToolUpdateTip",           # 工具更新提示
    "CAdvToolExecutorAdaptWnd",   # 工具执行器（360AdvTool）
    "SitesUI",                    # 网站提示
    "360LeakFixer",               # 漏洞修复
    "LiveUpd360C",                # 升级提示
    "SoftMgrSingleUpgradeMain",   # 软件管家升级
    "SMLSingleUpgrade_HelpWndCl", # 软件管家升级帮助
    "WebSoket_MiniAppHelperClas", # 小程序助手
    "ADShutdownListenerHiddenWi", # 关机监听
    "360InstallMain",             # 360 安装/组件安装窗口
    "#360IDSMultiUserWnd",        # 入侵检测
    "#360NetDefenderMultiUserWn", # 网络防御
    "#32770",                     # 标准 Win32 对话框（360 也会用）
}

# 标题里出现这些词 → 判定为"需要用户注意的提示"
POPUP_TITLE_HINTS = (
    "木马", "病毒", "拦截", "阻止", "发现", "处理", "威胁",
    "提醒", "警告", "风险", "安全", "防护", "隔离", "清除",
)


def is_popup_class(cls: str) -> bool:
    """判断窗口类名是否属于 360 的弹窗/通知窗口（含前缀匹配）。"""
    if not cls:
        return False
    if cls in POPUP_CLASSES:
        return True
    # 类名可能被 EnumWindows 截断，做前缀匹配
    for c in POPUP_CLASSES:
        if len(c) >= 12 and cls.startswith(c[:12]):
            return True
    return False


def is_popup_title(title: str) -> bool:
    """判断窗口标题是否像"拦截/查杀提示"。"""
    if not title:
        return False
    return any(h in title for h in POPUP_TITLE_HINTS)

SAFEMON_KEY = r"SOFTWARE\WOW6432Node\360Safe\safemon"

# 拦截开关 -> 中文含义
ACCESS_FLAGS = {
    "ExecAccess": "程序执行监控",
    "MonAccess": "文件监控",
    "FileMonAccess": "文件监控(细项)",
    "AppMonAccess": "程序行为监控",
    "DrvFWAccess": "驱动防火墙",
    "DrvFWAccess2": "驱动防火墙(细项)",
    "UDiskAccess": "U盘防护",
    "IEProtAccess": "IE 防护",
    "SiteAccess": "网站/网址防护",
    "DnsMonAccess": "DNS 监控",
    "VulnMonAccess": "漏洞监控",
    "OutwardAtkMonAccess": "对外攻击监控",
    "NetDefender": "网络防护",
    "TpiDriverWorkOpen": "TPI 驱动工作开关",
    "NewExec": "新程序执行监控",
    "BitcoinMiner": "挖矿木马防护",
    "flowstate": "流量状态",
    "SB_State": "沙箱状态",
    "svcMon": "服务监控",
    "LockUnknown": "锁定未知程序",
}

IOCTL_IS_PID_PROTECTED = 0x22204C
DEV_SELF_PROTECTION = r"\\.\360SelfProtection"

# 引擎脚本（32 位宿主）
PS32 = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
HERE = os.path.dirname(os.path.abspath(__file__))
ONE_SHOT = os.path.join(HERE, "av_trust_one32.ps1")
# 真正的病毒查杀引擎（AVEI.dll / AVEngine.dll）调用脚本
AVE_SCAN = os.path.join(HERE, "av_ave_scan32.ps1")
# QVM AI 引擎（机器学习判定未知木马）
QVM_INIT = os.path.join(HERE, "av_qvm32.ps1")
# QEX 脚本查杀引擎（.ps1/.vbs/.js 等非 PE 脚本）
QEX_PROBE = os.path.join(HERE, "av_qex32.ps1")
QEX_SCAN = QEX_PROBE

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)


def _to_sysnative(path: str) -> str:
    """32 位进程访问 C:\\Windows\\System32 会被 WOW64 重定向到 SysWOW64。

    引擎返回 status=251（文件不可见）多半就是这个原因。
    用 Sysnative 别名可以穿透重定向拿到真实的 64 位 System32。
    """
    low = path.lower()
    if low.startswith("c:\\windows\\system32\\"):
        return "C:\\Windows\\Sysnative\\" + path[len("C:\\Windows\\System32\\"):]
    return path


def _from_sysnative(path: str) -> str:
    """Sysnative 是 32 位进程专用别名，64 位 Python 读不到，需还原。"""
    low = path.lower()
    if low.startswith("c:\\windows\\sysnative\\"):
        return "C:\\Windows\\System32\\" + path[len("C:\\Windows\\Sysnative\\"):]
    return path

k32.CreateFileW.restype = wt.HANDLE
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, wt.HANDLE]
k32.DeviceIoControl.restype = wt.BOOL
k32.DeviceIoControl.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD,
                                ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD),
                                ctypes.c_void_p]
k32.CloseHandle.argtypes = [wt.HANDLE]


# ---------------------------------------------------------------- 事件模型

@dataclass
class Event:
    """感知到的单个事件。"""
    ts: float                       # unix 时间戳
    kind: str                       # popup / scan_hit / state_change / process
    source: str                     # 来源模块
    title: str = ""                 # 弹窗标题 / 事件摘要
    body: str = ""                  # 弹窗正文
    path: str = ""                  # 涉及的文件路径
    action: str = ""                # 处理动作（拦截/清除/放行/询问）
    verdict: str = ""               # 判定（病毒/可疑/安全/未知）
    rule: str = ""                  # 规则 ID
    hwnd: int = 0                   # 窗口句柄（弹窗类事件）
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------- 引擎调用

def _run_ps32(script: str, *args, timeout=120):
    """在 32 位 PowerShell 里跑辅助脚本并返回 stdout。

    ★ 注意：PowerShell 在首次启动时可能把版权横幅写进 stdout
    （实测在 `-File` 模式下也会出现），污染 JSON 解析。
    这里统一剥掉横幅，只返回真正的输出。
    """
    cmd = [PS32, "-ExecutionPolicy", "Bypass", "-NoProfile", "-File", script, *args]
    p = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    return _strip_ps_banner(p.stdout or "")


# PowerShell 启动横幅的特征行（出现即丢弃该行及其之前的空行）
_PS_BANNER_MARKS = (
    "Windows PowerShell",
    "Copyright (C) Microsoft Corporation",
    "Install the latest PowerShell",
    "Try the new cross-platform",
    "https://aka.ms/pscore6",
)


def _strip_ps_banner(out: str) -> str:
    """剥掉 PowerShell 启动横幅，返回真正的脚本输出。

    实测：即使带 `-NoProfile -File`，PowerShell 仍可能输出
    `Windows PowerShell` / `Copyright (C) Microsoft Corporation` 横幅，
    导致调用方把横幅当成脚本返回值（例如把 "Windows PowerShell"
    当成 rc 解析而失败）。
    """
    if not out:
        return out
    lines = out.splitlines()
    # 找到最后一条横幅行的位置，丢弃它及其之前的内容
    cut = -1
    for i, ln in enumerate(lines):
        s = ln.strip()
        if any(s.startswith(m) or m in s for m in _PS_BANNER_MARKS):
            cut = i
    if cut >= 0:
        lines = lines[cut + 1:]
    # 丢弃开头的空行
    while lines and not lines[0].strip():
        lines.pop(0)
    return "\n".join(lines)


def _read_scan_log(log: str) -> str:
    """读取 360 扫描日志。日志为 UTF-16LE（带 BOM），需显式解码。"""
    try:
        with open(log, "rb") as f:
            raw = f.read()
    except OSError:
        return ""
    for enc in ("utf-16", "utf-8-sig", "gbk"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


class AV360Sense:
    """360 感知层。"""

    def __init__(self, safe_root: str | None = None):
        # 默认自动探测本机安装的引擎；探测不到再用快照
        self.safe_root = safe_root or find_engine_root() or SNAP_ROOT
        self._seen_log_size = 0
        self._seen_hwnds: set[int] = set()
        self._popup_bodies: dict[int, str] = {}
        self._events: list[Event] = []

    # -------------------------------------------------- 状态感知

    def state(self) -> dict:
        """获取当前拦截/防护状态（对应"知道哪里被拦截"的静态部分）。"""
        import winreg
        flags = {}
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SAFEMON_KEY) as k:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    if name in ACCESS_FLAGS:
                        flags[name] = {
                            "meaning": ACCESS_FLAGS[name],
                            "value": val,
                            "on": bool(val) if isinstance(val, int) else None,
                        }
                    i += 1
        except OSError:
            pass

        # 自保护设备
        sp = {"device_openable": False, "self_pid_protected": None}
        h = k32.CreateFileW(DEV_SELF_PROTECTION, 0x100081, 3, None, 3, 0x40000080, None)
        if h != ctypes.c_void_p(-1).value:
            sp["device_openable"] = True
            try:
                buf = ctypes.c_uint32(os.getpid())
                out = ctypes.create_string_buffer(4)
                ret = wt.DWORD(0)
                ok = k32.DeviceIoControl(h, IOCTL_IS_PID_PROTECTED,
                                         ctypes.byref(buf), 4, out, 4,
                                         ctypes.byref(ret), None)
                if ok:
                    sp["self_pid_protected"] = bool(int.from_bytes(out.raw[:4], "little"))
            finally:
                k32.CloseHandle(h)

        # 服务状态
        svcs = {}
        for s in ("ZhuDongFangYu", "360SelfProtection", "360FsFlt", "360AntiHijack"):
            try:
                p = subprocess.run(["sc", "query", s], capture_output=True,
                                   text=True, timeout=10)
                if "1060" in p.stdout:
                    svcs[s] = "NOT_INSTALLED"
                else:
                    for line in p.stdout.splitlines():
                        if "STATE" in line and ":" in line:
                            svcs[s] = line.split(":", 1)[1].strip()
            except Exception:  # noqa: BLE001
                svcs[s] = "ERR"

        return {
            "intercept_flags": flags,
            "enabled_count": sum(1 for v in flags.values() if v["on"]),
            "disabled_count": sum(1 for v in flags.values() if v["on"] is False),
            "self_protection": sp,
            "services": svcs,
        }

    # -------------------------------------------------- 主动查杀

    def scan(self, path: str, timeout=180) -> dict:
        """主动调用 360 引擎查杀单个文件。

        返回签名/证书链信息。注意引擎限制：
          - 必须 32 位宿主
          - 同一进程只能调用一次 -> 每次起独立进程
        """
        # 去掉可能的 BOM / 首尾空白（从文件列表读入时常见）
        path = path.lstrip("\ufeff").strip().strip('"')
        path = os.path.abspath(path)
        if not os.path.exists(path):
            return {"path": path, "ok": False, "error": "file not found"}
        if not os.path.exists(ONE_SHOT):
            return {"path": path, "ok": False, "error": "missing %s" % ONE_SHOT}

        out = _run_ps32(ONE_SHOT, path, self.safe_root, timeout=timeout)
        sep = "\x1f"
        for line in out.splitlines():
            if line.startswith("RESULT" + sep):
                parts = line.split(sep)
                if len(parts) >= 5:
                    subject, issuer, ca = parts[2], parts[3], parts[4]
                    return {
                        "path": path,
                        "ok": True,
                        "signed": bool(subject.strip()),
                        "subject": subject,
                        "issuer": issuer,
                        "ca": ca,
                        "verdict": ("已签名: " + subject) if subject.strip() else "无签名",
                    }
        return {"path": path, "ok": False, "error": "no result", "raw": out[:400]}

    def scan_many(self, paths, on_result=None) -> list[dict]:
        """批量查杀（每文件独立进程）。"""
        res = []
        for i, p in enumerate(paths):
            r = self.scan(p)
            res.append(r)
            if on_result:
                on_result(i, len(paths), r)
        return res

    # -------------------------------------------------- 真实病毒查杀引擎

    def scan_ave(self, path: str, timeout=180) -> dict:
        """调用 360 真正的病毒查杀引擎（AVEI.dll）扫描单个文件。

        与 scan() 的区别：
          scan()      -> 只查签名/证书链信誉（cloudcom2）
          scan_ave()  -> 真正加载特征库、解析 PE、做病毒比对

        引擎限制（逆向得出，已在 av_ave_scan32.ps1 中处理）：
          - 引擎是 x86，必须用 32 位 PowerShell 宿主
          - 必须先 AveInitialize 取函数表，再加载 AVEI.dll
          - 必须 BAPIInitialize 初始化（否则扫描器上下文为空）
          - 必须 SetScannerConfig 加载特征库，否则扫描被静默跳过
          - 只接受合法 PE 文件；非 PE 返回 status=4

        WOW64 注意：32 位宿主访问 C:\\Windows\\System32 会被重定向到
        SysWOW64，导致文件"不存在"（引擎返回 status=251）。
        本方法自动把 System32 路径改写为 Sysnative。

        返回 dict:
          ok       bool
          verdict  'clean' | 'threat' | 'engine_error' | 'error' | 'invalid_args'
          status   引擎原始状态码（0=干净 1=威胁 4=非PE 251=文件不可见）
          name     威胁名称（threat 时有值）
          detail   原始明细
        """
        path = path.lstrip("\ufeff").strip().strip('"')
        # 调用方可能直接给了 Sysnative 路径（32 位视角），
        # 64 位 Python 看不到该别名，先还原再检查存在性。
        real_path = _from_sysnative(path)
        real_path = os.path.abspath(real_path)
        if not os.path.exists(real_path):
            return {"path": real_path, "ok": False, "error": "file not found"}
        if not os.path.exists(AVE_SCAN):
            return {"path": real_path, "ok": False, "error": "missing %s" % AVE_SCAN}

        # 32 位宿主看不到 System32（WOW64 重定向），改写为 Sysnative
        scan_path = _to_sysnative(real_path)
        out = _run_ps32(AVE_SCAN, scan_path, self.safe_root, timeout=timeout)
        sep = "\x1f"
        for line in out.splitlines():
            if line.startswith("RESULT" + sep):
                parts = line.split(sep)
                if len(parts) >= 4:
                    verdict = parts[2]
                    detail = parts[3] if len(parts) > 3 else ""
                    r = {
                        "path": path,
                        "ok": verdict not in ("NO_ROOT", "NO_AVEI", "NO_EXPORT",
                                              "CREATE_NULL", "EXC"),
                        "verdict": verdict,
                        "detail": detail,
                    }
                    m = re.search(r"status=(\d+)", detail)
                    if m:
                        r["status"] = int(m.group(1))
                    m = re.search(r"name=(\S*)", detail)
                    if m:
                        r["name"] = m.group(1)
                    m = re.search(r"size=(\d+)", detail)
                    if m:
                        r["size"] = int(m.group(1))
                    m = re.search(r"cfg=([\d/]+)", detail)
                    if m:
                        r["cfg"] = m.group(1)
                    return r
        return {"path": path, "ok": False, "error": "no result", "raw": out[:400]}

    def scan_ave_many(self, paths, on_result=None) -> list[dict]:
        """用真实引擎批量查杀（每文件独立进程）。"""
        res = []
        for i, p in enumerate(paths):
            r = self.scan_ave(p)
            res.append(r)
            if on_result:
                on_result(i, len(paths), r)
        return res

    def qvm_state(self, timeout=120) -> dict:
        """查询 QVM AI 引擎状态（机器学习引擎，判定未知木马）。

        QVM 是 360 的机器学习引擎，特征库可绕过但 AI 判定很难绕过，
        对免杀自动化对抗最有价值。
        """
        if not os.path.exists(QVM_INIT):
            return {"ok": False, "error": "missing %s" % QVM_INIT}
        out = _run_ps32(QVM_INIT, timeout=timeout)
        sep = "\x1f"
        for line in out.splitlines():
            if line.startswith("QVM" + sep):
                body = line.split(sep, 1)[1]
                r = {"ok": True, "raw": body}
                m = re.search(r"BoleInitialize=(\S+)", body)
                if m:
                    r["bole_init"] = m.group(1)
                m = re.search(r"BoleFeaturesInitialize=(\S+)", body)
                if m:
                    r["features_init"] = m.group(1)
                m = re.search(r"featPtrs=(\d+)", body)
                if m:
                    r["feature_ptrs"] = int(m.group(1))
                m = re.search(r"table=([0-9a-fx,]+)", body)
                if m:
                    r["bole_table"] = [t for t in m.group(1).split(",") if t]
                m = re.search(r"ver=0x([0-9A-Fa-f]+)", body)
                if m:
                    r["version"] = int(m.group(1), 16)
                return r
        return {"ok": False, "error": "no result", "raw": out[:400]}

    def qex_create_instance(self, timeout=120) -> dict:
        """创建 QEX 脚本查杀引擎实例。

        QEX 是 360 的脚本查杀引擎，负责 .ps1/.vbs/.js 等非 PE 文件 ——
        这正是 AVE 特征引擎覆盖不到的部分。

        逆向得到的调用方式（QEX.dll）：
            QEXCreateInstance(&GUID_A, &GUID_B, &out)   __stdcall 3 参数
              GUID_A = adbba672-ea79-4b82-b442-31fc68de50f8  (RVA 0x1C2364)
              GUID_B = d60137d0-b2db-4587-beb9-b3d08c571912  (RVA 0x1C2354)
            参考 QEX.dll 内部 0x58B9 处的真实调用点。
            GUID 必须指向 DLL 自身内存，堆拷贝会返回 E_NOINTERFACE。
            成功后 out 指向对象，虚表 RVA 0x1BFCC4（20+ 方法）。

        返回实例状态。要真正扫描文件请用 scan_qex()。
        """
        if not os.path.exists(QEX_PROBE):
            return {"ok": False, "error": "missing %s" % QEX_PROBE}
        out = _run_ps32(QEX_PROBE, timeout=timeout)
        sep = "\x1f"
        for line in out.splitlines():
            if line.startswith("QEX" + sep):
                body = line.split(sep, 1)[1]
                r = {"ok": False, "raw": body}
                for kv in body.split(sep):
                    if "=" not in kv:
                        continue
                    k, v = kv.split("=", 1)
                    if k == "ok":
                        r["ok"] = v == "1"
                    elif k in ("obj", "vt", "base"):
                        try:
                            r[k] = int(v, 16)
                        except ValueError:
                            r[k] = v
                    elif k == "methods":
                        try:
                            r[k] = int(v)
                        except ValueError:
                            r[k] = v
                    else:
                        r[k] = v
                return r
        return {"ok": False, "error": "no result", "raw": out[:400]}

    def scan_qex(self, path: str, timeout=120) -> dict:
        """用 QEX 脚本查杀引擎处理单个文件（支持非 PE）。

        这是 AVE 覆盖不到的部分：.ps1 / .vbs / .js / .zip 等。

        逆向确认的调用链（机器码验证）：
            slot[0x10] = FUN_10038e90(this, path, access, disposition)
            内部 CreateFileW(path, access, 7, NULL, disposition, 0x80, NULL)
            第 4 个参数是 dwCreationDisposition，必须传 OPEN_EXISTING(3)。
            传错会导致 CreateFileW 返回 INVALID_HANDLE_VALUE，扫描被静默跳过。

        返回 dict:
          ok       引擎是否成功打开并处理了该文件
          verdict  'processed'（引擎已处理）| 'not_opened'（未能打开）
          handle   文件句柄
          done     扫描流程完成标志
          detail   原始明细

        注意：verdict='processed' 表示**引擎确实读取并处理了这个文件**，
        这是相比日志方案的关键进步。威胁判定的具体字段仍在定位中，
        因此本方法不会把未确认的状态谎报成 'clean'。
        """
        path = path.lstrip("\ufeff").strip().strip('"')
        real_path = _from_sysnative(path)
        real_path = os.path.abspath(real_path)
        if not os.path.exists(real_path):
            return {"path": real_path, "ok": False, "error": "file not found"}
        if not os.path.exists(QEX_SCAN):
            return {"path": real_path, "ok": False, "error": "missing %s" % QEX_SCAN}

        out = _run_ps32(QEX_SCAN, _to_sysnative(real_path), self.safe_root, timeout=timeout)
        sep = "\x1f"
        for line in out.splitlines():
            if line.startswith("QEX" + sep):
                body = line.split(sep, 1)[1]
                r = {"path": real_path, "ok": False, "detail": body}
                for kv in body.split(sep):
                    if "=" not in kv:
                        continue
                    k, v = kv.split("=", 1)
                    if k == "ok":
                        r["ok"] = v == "1"
                    elif k in ("handle",):
                        try:
                            r[k] = int(v, 16)
                        except ValueError:
                            r[k] = v
                    elif k == "done":
                        try:
                            r[k] = int(v)
                        except ValueError:
                            r[k] = v
                    else:
                        r[k] = v
                return r
        return {"path": real_path, "ok": False, "error": "no result", "raw": out[:400]}

    def scan_all_engines(self, path: str, timeout=180) -> dict:
        """多引擎联合查杀 —— 全部为即时引擎调用。

        覆盖的引擎通道：
          ave       —— AVE 特征引擎（本地木马库），直接调用 DLL，支持任意 PE
          cloud     —— 云端信誉（GetFileTrustState 签名/信誉查询）
          qex       —— QEX 脚本引擎实例状态（脚本类文件）

        **判定结论只来自上述即时调用。** 360 官方扫描日志单独放在
        `reference` 字段，仅供对照，绝不参与 verdict 计算 ——
        因为日志是历史记录，对新文件会给出误导性的 clean。
        需要日志内容请显式调用 scan_log_latest()。

        返回 dict:
          path       目标文件
          verdict    'threat' | 'clean' | 'unknown'（仅由即时引擎决定）
          engines    各引擎的原始返回
          reference  360 官方扫描日志中的相关记录（不参与判定）
        """
        out = {"path": os.path.abspath(path), "engines": {}}
        try:
            out["engines"]["ave"] = self.scan_ave(path, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            out["engines"]["ave"] = {"ok": False, "error": str(e)}
        try:
            out["engines"]["cloud"] = self.scan(path, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            out["engines"]["cloud"] = {"ok": False, "error": str(e)}
        try:
            q = self.scan_qex(path, timeout=timeout)
            out["engines"]["qex"] = q
        except Exception as e:  # noqa: BLE001
            out["engines"]["qex"] = {"ok": False, "error": str(e)}

        # 判定：只看即时引擎，且必须 ok 才算数
        verdicts = [v.get("verdict") for v in out["engines"].values()
                    if v.get("verdict") and v.get("ok")]
        if "threat" in verdicts:
            out["verdict"] = "threat"
        elif "clean" in verdicts:
            out["verdict"] = "clean"
        elif "processed" in verdicts:
            # QEX 确认处理了文件，但威胁判定字段尚未完全确认。
            # 不谎报 clean —— 如实标注为"已处理"。
            out["verdict"] = "processed"
        else:
            out["verdict"] = "unknown"
        out["ok"] = any(v.get("ok") for v in out["engines"].values())

        # 参考信息：官方扫描日志（明确标注不参与判定）
        try:
            ap = os.path.abspath(path).lower()
            hits = [t for t in self.scan_log_threats() if t["path"].lower() == ap]
            if hits:
                h = hits[0]
                out["reference"] = {
                    "source": "360 官方扫描日志（历史记录，不参与判定）",
                    "found": True,
                    "engine": h["engine"], "name": h["verdict"],
                    "action": h["action"], "handled": h["handled"],
                }
            else:
                out["reference"] = {
                    "source": "360 官方扫描日志（历史记录，不参与判定）",
                    "found": False,
                    "note": "不在最近一次官方扫描的威胁列表中",
                }
        except Exception as e:  # noqa: BLE001
            out["reference"] = {"source": "360 官方扫描日志", "error": str(e)}
        return out

    # -------------------------------------------------- 处理威胁

    def handle_threat(self, path: str, action: str = "quarantine",
                      quarantine_dir: str | None = None,
                      copy_only: bool = False) -> dict:
        """处理查杀发现的威胁文件。

        action:
          'quarantine' 移入隔离目录（默认，可恢复，带 manifest）
          'delete'     直接删除
          'rename'     原地改名加 .vir 后缀（最保守）
          'none'       只记录，不动文件

        copy_only:
          **测试专用**。True 时用"复制"代替"移动/删除"，
          原文件保持不动。适合反复测试同一批样本，
          避免第一次处理后就再也扫不到东西。

        说明：360 的自我保护只拦截**对自身文件的写入**，
        对普通被感染文件的删除/改名不受影响（已实测验证）。
        360Quarant.dll 提供 CreateQuarantObject 做正规隔离，
        但需要构造 COM 对象；此处用文件操作实现等价且可控的效果。
        """
        path = os.path.abspath(path.lstrip("\ufeff").strip().strip('"'))
        if not os.path.exists(path):
            return {"path": path, "ok": False, "error": "file not found"}

        if action == "none":
            return {"path": path, "ok": True, "action": "none"}

        if quarantine_dir is None:
            quarantine_dir = os.path.join(HERE, "_quarantine")

        try:
            if action == "delete":
                if copy_only:
                    # 测试模式：不真删，只记录
                    return {"path": path, "ok": True, "action": "delete",
                            "skipped": "copy_only"}
                os.remove(path)
                return {"path": path, "ok": True, "action": "delete"}

            if action == "rename":
                new = path + ".vir"
                if os.path.exists(new):
                    os.remove(new)
                if copy_only:
                    shutil.copy2(path, new)
                    return {"path": path, "ok": True, "action": "rename",
                            "to": new, "copied": True}
                os.rename(path, new)
                return {"path": path, "ok": True, "action": "rename", "to": new}

            # quarantine
            os.makedirs(quarantine_dir, exist_ok=True)
            base = os.path.basename(path)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            new = os.path.join(quarantine_dir, "%s.%s.vir" % (base, stamp))
            n = 1
            while os.path.exists(new):
                new = os.path.join(quarantine_dir, "%s.%s.%d.vir" % (base, stamp, n))
                n += 1
            if copy_only:
                shutil.copy2(path, new)
            else:
                os.rename(path, new)
            with open(os.path.join(quarantine_dir, "_manifest.txt"), "a",
                      encoding="utf-8") as fh:
                fh.write("%s\t%s\t%s\t%s\n"
                         % (stamp, path, new, "copied" if copy_only else "moved"))
            return {"path": path, "ok": True, "action": "quarantine",
                    "to": new, "copied": copy_only}
        except Exception as e:  # noqa: BLE001
            return {"path": path, "ok": False, "error": str(e)}

    def handle_scan_log(self, action: str = "quarantine",
                        quarantine_dir: str | None = None,
                        copy_only: bool = False,
                        dry_run: bool = False) -> dict:
        """处理最近一次 360 官方扫描发现的所有威胁。

        这是 `scan-log` 之后"怎么处理病毒"的答案：
        读取官方扫描日志里的威胁列表，逐个按 action 处理。

        action / copy_only 含义同 handle_threat。
        dry_run=True 只列出将要处理的文件，不动手。

        返回 {"total":n, "handled":[...], "failed":[...], "skipped":[...]}
        """
        threats = self.scan_log_threats()
        res = {"total": len(threats), "handled": [], "failed": [],
               "skipped": [], "dry_run": dry_run}
        for t in threats:
            p = t["path"]
            if dry_run:
                res["skipped"].append({"path": p, "reason": "dry_run",
                                       "engine": t["engine"],
                                       "verdict": t["verdict"]})
                continue
            if not os.path.exists(p):
                res["skipped"].append({"path": p, "reason": "not found"})
                continue
            h = self.handle_threat(p, action=action,
                                   quarantine_dir=quarantine_dir,
                                   copy_only=copy_only)
            h["engine"] = t["engine"]
            h["verdict"] = t["verdict"]
            (res["handled"] if h.get("ok") else res["failed"]).append(h)
        return res

    def scan_and_handle(self, path: str, action: str = "quarantine",
                        timeout=180, copy_only: bool = False) -> dict:
        """查杀 + 按结果自动处理威胁（多引擎）。

        copy_only=True 时只复制不移动，便于反复测试。
        """
        r = self.scan_all_engines(path, timeout=timeout)
        if r.get("verdict") == "threat":
            r["handled"] = self.handle_threat(path, action=action,
                                              copy_only=copy_only)
        return r

    # -------------------------------------------------- 弹窗感知

    def _enum_windows(self):
        """枚举当前所有顶层窗口，返回 (hwnd, class, title)。"""
        out = []

        @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
        def cb(hwnd, _):
            cls = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, cls, 256)
            title = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(hwnd, title, 512)
            out.append((hwnd, cls.value, title.value))
            return True

        user32.EnumWindows(cb, 0)
        return out

    def _window_text(self, hwnd) -> str:
        """递归收集窗口内所有子控件文本（弹窗正文在里面）。"""
        texts = []

        @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
        def cb(child, _):
            buf = ctypes.create_unicode_buffer(1024)
            user32.GetWindowTextW(child, buf, 1024)
            if buf.value.strip():
                texts.append(buf.value.strip())
            return True

        user32.EnumChildWindows(hwnd, cb, 0)
        return "\n".join(texts)

    def poll_popups(self, include_all_360: bool = False) -> list[Event]:
        """扫描当前存在的 360 弹窗，返回新出现的弹窗事件。

        弹窗的正文往往在窗口出现后若干毫秒才由 360 填入子控件，
        因此这里对"已见但正文为空"的窗口做一次补读（enrich），
        补读成功时产出补充事件，避免漏掉正文/路径/动作信息。

        ★ 2026-10-18 扩展：不再只匹配 Q360HIPSClass。
        实测枚举到 360 有 20+ 个弹窗/通知窗口类（见 POPUP_CLASSES），
        只盯一个类会漏报实时防护与主界面提示。
        判定规则：类名在 POPUP_CLASSES 中（含前缀匹配），
        或标题命中 POPUP_TITLE_HINTS（木马/病毒/拦截/...）。
        include_all_360=True 时，额外把标题含 "360" 的窗口也纳入。

        首次调用只建立基线，不产出事件。
        """
        events = []
        alive = set()
        for hwnd, cls, title in self._enum_windows():
            hit = is_popup_class(cls) or is_popup_title(title)
            if not hit and include_all_360 and "360" in (title or ""):
                hit = True
            if not hit:
                continue
            alive.add(hwnd)

            if hwnd not in self._seen_hwnds:
                self._seen_hwnds.add(hwnd)
                body = self._window_text(hwnd)
                self._popup_bodies[hwnd] = body
                events.append(Event(
                    ts=time.time(),
                    kind="popup",
                    source="360hipsPopWnd.dll",
                    title=title or "360 主动防御拦截",
                    body=body,
                    hwnd=hwnd,
                    action=self._guess_action(body),
                    verdict=self._guess_verdict(body),
                    path=self._guess_path(body),
                ))
                continue

            # 已见窗口：若此前正文为空，尝试补读
            prev = self._popup_bodies.get(hwnd, "")
            if not prev:
                body = self._window_text(hwnd)
                if body:
                    self._popup_bodies[hwnd] = body
                    events.append(Event(
                        ts=time.time(),
                        kind="popup_detail",
                        source="360hipsPopWnd.dll",
                        title=title or "360 主动防御拦截",
                        body=body,
                        hwnd=hwnd,
                        action=self._guess_action(body),
                        verdict=self._guess_verdict(body),
                        path=self._guess_path(body),
                    ))

        # 已关闭的窗口从"已见"集合移除，这样同一句柄被复用时仍能再次触发
        self._seen_hwnds &= alive
        for h in list(self._popup_bodies):
            if h not in alive:
                del self._popup_bodies[h]
        return events

    def prime_popups(self) -> int:
        """建立弹窗基线：把当前已存在的 HIPS 弹窗标记为已见，返回数量。"""
        cur = {h for h, c, _ in self._enum_windows() if c == HIPS_POPUP_CLASS}
        self._seen_hwnds |= cur
        for h in cur:
            self._popup_bodies.setdefault(h, self._window_text(h))
        return len(cur)

    @staticmethod
    def _guess_action(text: str) -> str:
        for kw, act in (("拦截", "blocked"), ("阻止", "blocked"),
                        ("允许", "allowed"), ("放行", "allowed"),
                        ("清除", "cleaned"), ("删除", "deleted"),
                        ("隔离", "quarantined"), ("信任", "trusted"),
                        ("询问", "ask")):
            if kw in text:
                return act
        return ""

    @staticmethod
    def _guess_verdict(text: str) -> str:
        for kw, v in (("木马", "trojan"), ("病毒", "virus"),
                      ("可疑", "suspicious"), ("风险", "risk"),
                      ("广告", "adware"), ("蠕虫", "worm"),
                      ("后门", "backdoor"), ("勒索", "ransomware")):
            if kw in text:
                return v
        return ""

    @staticmethod
    def _guess_path(text: str) -> str:
        m = re.search(r"[A-Za-z]:\\[^\r\n<>\"|?*]+", text)
        return m.group(0).strip() if m else ""

    # -------------------------------------------------- 查杀通知感知

    def poll_scan_log(self) -> list[Event]:
        """监控 360 扫描日志，捕捉查杀命中（含判定引擎）。"""
        events = []
        if not os.path.exists(SCAN_LOG):
            return events
        try:
            size = os.path.getsize(SCAN_LOG)
        except OSError:
            return events
        if size == self._seen_log_size:
            return events
        content = _read_scan_log(SCAN_LOG)
        if not content:
            return events
        self._seen_log_size = size

        # 真实日志行格式（实测，UTF-16LE）：
        #   <路径> <md5> <数字串> ERT=... [引擎][病毒名][动作][处理状态]
        for t in self.scan_log_threats():
            events.append(Event(
                ts=time.time(),
                kind="scan_hit",
                source="360ScanLog",
                title=t["verdict"],
                body="%s  [%s] %s" % (t["path"], t["engine"], t["verdict"]),
                path=t["path"],
                action=t["action"],
                verdict=self._guess_verdict(t["verdict"]) or "risk",
                rule="",
                extra={"engine": t["engine"], "md5": t["md5"],
                       "handled": t["handled"]},
            ))
        return events

    def scan_log_summary(self) -> dict:
        """解析扫描日志头部的统计信息与本次启用的引擎。"""
        if not os.path.exists(SCAN_LOG):
            return {}
        txt = _read_scan_log(SCAN_LOG)
        if not txt:
            return {}
        out = {}
        m = re.search(r"发现安全威胁:\s*(\d+)", txt)
        if m:
            out["threats_found"] = int(m.group(1))
        m = re.search(r"已处理安全威胁:\s*(\d+)", txt)
        if m:
            out["threats_handled"] = int(m.group(1))
        m = re.search(r"扫描引擎[:：]\s*(.+)", txt)
        if m:
            out["engines"] = [e.strip() for e in m.group(1).split() if e.strip()]
        m = re.search(r"扫描文件数:\s*(\d+)", txt)
        if m:
            out["files_scanned"] = int(m.group(1))
        m = re.search(r"安全的文件数:\s*(\d+)", txt)
        if m:
            out["files_clean"] = int(m.group(1))
        m = re.search(r"扫描模式:\s*(.+)", txt)
        if m:
            out["mode"] = m.group(1).strip()
        return out

    def scan_log_threats(self, path=None) -> list[dict]:
        """解析 360 扫描日志中的逐条威胁记录，含**判定引擎**归属。

        这是"多引擎"的真实证据来源：360 自己的日志会写明每条威胁
        由哪个引擎判定（[QEX引擎] / [云安全引擎] / [启发式引擎] ...）。

        返回每项：
          path    被判定文件
          md5     360 记录的 MD5
          engine  判定引擎（QEX引擎 / 云安全引擎 / ...）
          verdict 病毒名（如 木马-ex_virus.powershell.agent.bw）
          action  建议动作（隔离文件 / 删除文件 ...）
          handled 是否已处理
        """
        log = path or SCAN_LOG
        if not os.path.exists(log):
            return []
        txt = _read_scan_log(log)
        if not txt:
            return []
        out = []
        # 形如: <路径> <md5> <数字串> ERT=... [引擎][病毒名][动作][处理状态]
        pat = re.compile(
            r"^(?P<path>[A-Za-z]:\\[^\s]+)\s+"
            r"(?P<md5>[0-9a-fA-F]{32})\s+"
            r"(?P<stats>[\d,]+)\s+"
            r"(?P<ert>ERT=\S+)?\s*"
            r"\[(?P<engine>[^\]]+)\]\s*"
            r"\[(?P<verdict>[^\]]+)\]\s*"
            r"\[(?P<action>[^\]]+)\]\s*"
            r"\[(?P<handled>[^\]]+)\]",
            re.MULTILINE)
        for m in pat.finditer(txt):
            d = m.groupdict()
            out.append({
                "path": d["path"],
                "md5": d["md5"],
                "engine": d["engine"],
                "verdict": d["verdict"],
                "action": d["action"],
                "handled": d["handled"],
            })
        return out

    def scan_log_latest(self) -> dict:
        """返回最近一次扫描的完整结果（含逐条威胁与引擎归属）。"""
        r = self.scan_log_summary()
        r["threats"] = self.scan_log_threats()
        return r

    def scan_log_history(self, limit: int = 100) -> list[dict]:
        """聚合**全部历史**扫描日志（不只是最近一条）。

        360 每次扫描都会在 360ScanLog 目录下留一份带时间戳的日志，
        但 `360safeScanLog.txt` 只保留最近一次。若只读后者，
        一旦发生新扫描，上一次的结果就被覆盖 —— 免杀自动化里
        "我刚扫的那次查到了什么" 会丢失。

        本方法遍历目录下所有 ScanLog_*.txt，按时间倒序解析，
        返回每次扫描的 {log, time, files, safe, threats, threat_list}。

        参数 limit 限制返回的日志条数（按时间倒序取前 N 条）。
        """
        d = os.path.dirname(SCAN_LOG)
        if not os.path.isdir(d):
            return []
        try:
            names = [n for n in os.listdir(d)
                     if n.startswith("ScanLog_") and n.endswith(".txt")]
        except OSError:
            return []
        # 文件名形如 ScanLog_2026-10-18_02_41_52.txt，可直接按名排序
        names.sort(reverse=True)
        out = []
        for n in names[:limit]:
            full = os.path.join(d, n)
            txt = _read_scan_log(full)
            if not txt:
                continue
            rec = {"log": n, "path": full}
            m = re.search(r"开始时间:\s*([\d\-: ]+)", txt)
            if m:
                rec["time"] = m.group(1).strip()
            for key, pat in (
                ("files", r"扫描文件数:\s*(\d+)"),
                ("safe", r"安全的文件数:\s*(\d+)"),
                ("threats", r"发现安全威胁:\s*(\d+)"),
                ("handled", r"已处理安全威胁:\s*(\d+)"),
            ):
                m = re.search(pat, txt)
                rec[key] = int(m.group(1)) if m else None
            m = re.search(r"扫描类型:\s*(.+)", txt)
            if m:
                rec["scan_type"] = m.group(1).strip()
            m = re.search(r"扫描引擎:\s*(.+)", txt)
            if m:
                rec["engines"] = m.group(1).strip()
            m = re.search(r"扫描内容\s*-+\s*\r?\n(.+)", txt)
            if m:
                rec["target"] = m.group(1).strip()
            rec["threat_list"] = self.scan_log_threats(full)
            out.append(rec)
        return out

    def scan_log_threats_all(self) -> list[dict]:
        """汇总全部历史日志中的威胁记录，按 (path, md5) 去重。

        每条附加 `first_seen` / `last_seen`（来自日志文件名时间戳），
        便于判断某个文件是"这次新查到的"还是"历史上就被标记过"。
        """
        seen: dict[tuple, dict] = {}
        for rec in self.scan_log_history():
            ts = rec.get("time") or rec.get("log", "")
            for t in rec.get("threat_list", []):
                key = (t["path"].lower(), t["md5"].lower())
                if key in seen:
                    seen[key]["last_seen"] = max(seen[key]["last_seen"], ts)
                    seen[key]["first_seen"] = min(seen[key]["first_seen"], ts)
                    seen[key]["hits"] += 1
                else:
                    d = dict(t)
                    d["first_seen"] = ts
                    d["last_seen"] = ts
                    d["hits"] = 1
                    seen[key] = d
        return sorted(seen.values(), key=lambda x: x["last_seen"], reverse=True)

    def scan_log_files(self) -> list[str]:
        """列出全部历史扫描日志（按时间倒序）。"""
        d = os.path.join(APPDATA_360, "360ScanLog")
        if not os.path.isdir(d):
            return []
        fs = [os.path.join(d, n) for n in os.listdir(d)
              if n.lower().endswith(".txt")]
        fs.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return fs

    # -------------------------------------------------- 双通道判定

    def scan_verdict(self, target: str | None = None,
                     since: float | None = None) -> dict:
        """★ 双通道判定：区分"扫描执行了"与"结果可读"。

        **为什么需要这个**：实测发现 360 的右键扫描有两条内部路径 ——
        一条写完整格式 A 日志（可读出威胁名与引擎归属），
        另一条只更新 ScanCache（**只能证明扫描跑过，不能证明结果是干净的**）。

        因此"ScanCache 变了但没有日志" **不等于** "没有威胁"。
        本方法把这个区分显式化，避免自动化脚本把"无日志"误判为"干净"。

        参数：
          target  只统计扫描目标包含该字符串的日志（None = 不筛选）
          since   只统计 mtime 晚于该时间戳的日志（None = 不筛选）

        返回：
          verdict_source  "log"       有日志，结果可读（最强证据）
                          "cache_only" 只有 ScanCache 变化，结果不可读
                          "none"       两者都无变化，扫描未执行
          log_available   布尔，是否有可读日志
          clean_known     布尔，**是否可确定地判定为干净**
                          （只有 verdict_source=="log" 且 threats==0 时才为 True）
          threats         本次日志中的威胁列表
          scans           匹配到的扫描记录
          cache_changed   ScanCache 是否在 since 之后变化
          note            人类可读的结论说明
        """
        out = {
            "target": target,
            "verdict_source": "none",
            "log_available": False,
            "clean_known": False,
            "threats": [],
            "scans": [],
            "cache_changed": False,
            "note": "",
        }

        # --- 通道 1：日志 ---
        scans = []
        for rec in self.scan_log_history():
            if since is not None:
                try:
                    if os.path.getmtime(rec["path"]) < since:
                        continue
                except OSError:
                    continue
            if target:
                tgt = (rec.get("target") or "").replace("/", "\\").lower()
                if target.replace("/", "\\").lower().rstrip("\\") not in tgt:
                    continue
            scans.append(rec)
        out["scans"] = scans

        if scans:
            out["log_available"] = True
            out["verdict_source"] = "log"
            ths = []
            for rec in scans:
                ths.extend(rec.get("threat_list") or [])
            out["threats"] = ths
            # 只有"有日志"且"日志里威胁为 0"才能确定干净
            total = sum((r.get("threats") or 0) for r in scans)
            if total == 0:
                out["clean_known"] = True
                out["note"] = ("有扫描日志且威胁数为 0 —— 可判定为干净"
                               "（证据充分）")
            else:
                out["note"] = ("有扫描日志，发现 %d 个威胁 —— 结果可读"
                               "（含威胁名与引擎归属）" % total)
            return out

        # --- 通道 2：ScanCache（只证明执行，不证明结论）---
        if since is not None:
            try:
                now = _snap()
                for _k, (sz, mt) in now.items():
                    if mt > since:
                        out["cache_changed"] = True
                        break
            except Exception:  # noqa: BLE001
                pass

        if out["cache_changed"]:
            out["verdict_source"] = "cache_only"
            out["note"] = ("ScanCache 有变化 —— 扫描确实执行了，"
                           "但**没有日志**，因此**不能判定为干净**。"
                           "需改用主 UI 扫描或其它手段获取判定。")
        else:
            out["note"] = "日志与 ScanCache 均无变化 —— 扫描未执行。"
        return out

    def scan_and_verdict(self, target: str, wait: int = 180,
                         poll: int = 3) -> dict:
        """触发扫描并返回双通道判定结果（一步到位）。

        这是给自动化脚本用的高层接口：**它不会把"无日志"误报为"干净"**。
        """
        t0 = time.time()
        r = self.trigger_scan(target, wait=wait, poll=poll)
        v = self.scan_verdict(target=target, since=t0)
        v["trigger"] = {
            "triggered": r.get("triggered"),
            "executed": r.get("executed"),
            "elapsed": r.get("elapsed"),
        }
        return v

    # -------------------------------------------------- 触发 360 自己的扫描

    def trigger_scan(self, path: str, wait=180, poll=3) -> dict:
        """触发 360 自己的查杀（右键菜单动词），并等待扫描真正执行。

        这是**唯一能激活 360 完整引擎状态**的路径：外部 LoadLibrary 加载
        360 的 DLL 时，引擎内部状态不完整（AVE 返回 status=4、ScChecker
        是空壳、SendMainCommand 的全局对象为空），只有让 360 自己扫，
        才会加载并配置全部引擎（含云端）。

        判据不是"函数返回成功"，而是**扫描副作用**：360 会把扫描进度写入
        `C:\\ProgramData\\360Safe\\ScanCache\\`，该目录文件的大小/时间戳
        变化即为"扫描确实执行了"的硬证据。

        ⚠️ 该动词走弹窗路径，**不写** `360safeScanLog.txt`，
        结果落在加密的 ScanCache 里（格式未公开）。

        返回 dict: ok / triggered / executed / elapsed / cache_delta
        """
        import glob as _glob
        target = os.path.abspath(path)
        out = {"path": target, "triggered": False, "executed": False,
               "elapsed": None, "cache_delta": []}

        cache_dir = r"C:\ProgramData\360Safe\ScanCache"

        def _snap():
            s = {}
            try:
                for f in _glob.glob(os.path.join(cache_dir, "*")):
                    try:
                        st = os.stat(f)
                        s[os.path.basename(f)] = (st.st_size, st.st_mtime)
                    except OSError:
                        pass
            except OSError:
                pass
            return s

        before = _snap()
        t0 = time.time()

        # 通过 Shell.Application 调用右键菜单动词
        ps = (
            "$ErrorActionPreference='Stop';"
            "$s=New-Object -ComObject Shell.Application;"
            "$p=Split-Path -Path '{0}' -Parent;"
            "$l=Split-Path -Path '{0}' -Leaf;"
            "$f=$s.NameSpace($p);"
            "if(-not $f){{Write-Output 'ERR:NameSpace';exit 2}};"
            "$i=if($l){{$f.ParseName($l)}}else{{$f.Self}};"
            "if(-not $i){{Write-Output 'ERR:ParseName';exit 3}};"
            "$v=$i.Verbs()|Where-Object {{$_.Name -like '*木马*'}};"
            "if(-not $v){{Write-Output 'ERR:NoVerb';exit 4}};"
            "$v.DoIt();"
            "Write-Output ('OK:'+$v.Name)"
        ).format(target.replace("'", "''"))

        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-Command", ps],
                capture_output=True, text=True, timeout=60,
                encoding="utf-8", errors="replace")
            sout = (r.stdout or "").strip()
            out["verb_result"] = sout[:200]
            out["triggered"] = sout.startswith("OK")
            if not out["triggered"]:
                out["error"] = (sout or r.stderr or "").strip()[:300]
        except Exception as e:  # noqa: BLE001
            out["error"] = str(e)
            return out

        # 等待扫描副作用
        deadline = t0 + wait
        while time.time() < deadline:
            time.sleep(poll)
            now = _snap()
            for k, v in now.items():
                old = before.get(k)
                if old is None:
                    out["cache_delta"].append(
                        {"file": k, "change": "new", "size": v[0]})
                elif v[0] != old[0] or v[1] > old[1]:
                    out["cache_delta"].append(
                        {"file": k, "change": "grew",
                         "from": old[0], "to": v[0]})
            if out["cache_delta"]:
                out["executed"] = True
                out["elapsed"] = round(time.time() - t0, 1)
                break

        if not out["executed"]:
            out["elapsed"] = round(time.time() - t0, 1)
            out["note"] = ("未观察到 ScanCache 变化；扫描可能未执行或"
                           "结果被缓存复用")
        return out

    def trigger_scan_dsmain(self, wait=90, poll=3) -> dict:
        """用 `DSMain.exe /infofastscan` 触发 360 扫描。

        ⚠️ 必须用 `cmd /c start` 启动：360 自我保护会拦截 .NET
        `Start-Process` 的进程创建（报 `Access is denied.`），
        而 `cmd` 的 `start` 可以绕过。

        同样以 ScanCache 变化作为"扫描确实执行"的判据。
        """
        import glob as _glob
        root = self.safe_root or find_engine_root()
        exe = os.path.join(root, "deepscan", "DSMain.exe")
        out = {"exe": exe, "triggered": False, "executed": False,
               "elapsed": None, "cache_delta": []}
        if not os.path.isfile(exe):
            out["error"] = "DSMain.exe 不存在"
            return out

        cache_dir = r"C:\ProgramData\360Safe\ScanCache"

        def _snap():
            s = {}
            for f in _glob.glob(os.path.join(cache_dir, "*")):
                try:
                    st = os.stat(f)
                    s[os.path.basename(f)] = (st.st_size, st.st_mtime)
                except OSError:
                    pass
            return s

        before = _snap()
        t0 = time.time()
        try:
            subprocess.run(
                ["cmd", "/c", "start", "", exe, "/infofastscan"],
                capture_output=True, text=True, timeout=30,
                encoding="utf-8", errors="replace")
            out["triggered"] = True
        except Exception as e:  # noqa: BLE001
            out["error"] = str(e)
            return out

        deadline = t0 + wait
        while time.time() < deadline:
            time.sleep(poll)
            now = _snap()
            for k, v in now.items():
                old = before.get(k)
                if old is None:
                    out["cache_delta"].append(
                        {"file": k, "change": "new", "size": v[0]})
                elif v[0] != old[0] or v[1] > old[1]:
                    out["cache_delta"].append(
                        {"file": k, "change": "grew",
                         "from": old[0], "to": v[0]})
            if out["cache_delta"]:
                out["executed"] = True
                out["elapsed"] = round(time.time() - t0, 1)
                break
        if not out["executed"]:
            out["elapsed"] = round(time.time() - t0, 1)
        return out

    # -------------------------------------------------- 进程感知

    def poll_processes(self) -> list[Event]:
        """感知 360 关键进程的启停（用于判断防护是否生效）。"""
        events = []
        try:
            p = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                               capture_output=True, text=True, timeout=20)
        except Exception:  # noqa: BLE001
            return events
        cur = set()
        for line in p.stdout.splitlines():
            parts = [x.strip('"') for x in line.split('","')]
            if parts and any(k in parts[0].lower()
                             for k in ("360", "zhudong", "q360")):
                cur.add(parts[0].lower())
        if not hasattr(self, "_proc_snapshot"):
            self._proc_snapshot = cur
            return events
        for name in cur - self._proc_snapshot:
            events.append(Event(ts=time.time(), kind="process",
                                source="tasklist", title="进程启动",
                                body=name, path=name, action="started"))
        for name in self._proc_snapshot - cur:
            events.append(Event(ts=time.time(), kind="process",
                                source="tasklist", title="进程退出",
                                body=name, path=name, action="stopped"))
        self._proc_snapshot = cur
        return events

    # -------------------------------------------------- 统一监听

    def watch(self, seconds=60, interval=0.5,
              kinds=("popup", "scan_hit", "process")) -> Iterator[Event]:
        """实时感知循环，逐条产出事件。

        这是免杀自动化的核心：样本一跑，就能立刻知道
        是否弹窗、是否被查杀、被谁拦、拦了什么。
        """
        end = time.time() + seconds
        # 建立基线，避免把历史日志/历史弹窗当成新事件
        self._seen_log_size = os.path.getsize(SCAN_LOG) if os.path.exists(SCAN_LOG) else 0
        self.prime_popups()
        self.poll_processes()

        while time.time() < end:
            got = []
            if "popup" in kinds:
                got += self.poll_popups()
            if "scan_hit" in kinds:
                got += self.poll_scan_log()
            if "process" in kinds:
                got += self.poll_processes()
            for ev in got:
                self._events.append(ev)
                yield ev
            time.sleep(interval)

    def events(self) -> list[dict]:
        return [e.to_dict() for e in self._events]


# ---------------------------------------------------------------- CLI

def main():
    ap = argparse.ArgumentParser(description="360 感知层 SDK")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("state", help="打印当前拦截/防护状态")
    sp = sub.add_parser("scan", help="主动查杀文件")
    sp.add_argument("files", nargs="+")
    sa = sub.add_parser("scan-all", help="多引擎联合查杀（AVE+云+官方引擎）")
    sa.add_argument("files", nargs="+")
    sl = sub.add_parser("scan-log", help="读取 360 官方扫描结果（含引擎归属）")
    sl.add_argument("--json", action="store_true")
    shist = sub.add_parser(
        "scan-history",
        help="聚合全部历史扫描日志中的威胁（不止最近一次）")
    shist.add_argument("--json", action="store_true")
    shist.add_argument("--limit", type=int, default=100,
                       help="最多读取的日志条数（按时间倒序）")
    sverd = sub.add_parser(
        "verdict",
        help="★ 双通道判定：区分'扫描执行了'与'结果可读'（避免误报干净）")
    sverd.add_argument("path", nargs="?", default=None,
                       help="扫描目标（用于筛选日志）；省略则只看最近")
    sverd.add_argument("--json", action="store_true")
    sverd.add_argument("--trigger", action="store_true",
                       help="先触发一次扫描再判定")
    sverd.add_argument("--wait", type=int, default=180)
    sh = sub.add_parser("handle", help="处理最近一次扫描发现的威胁")
    sh.add_argument("--action", default="quarantine",
                    choices=["quarantine", "delete", "rename", "none"])
    sh.add_argument("--copy-only", action="store_true",
                    help="测试用：只复制不移动，原文件保留")
    sh.add_argument("--dry-run", action="store_true",
                    help="只列出将处理的文件，不动手")
    sh.add_argument("--dir", default=None, help="隔离目录")
    sw = sub.add_parser("watch", help="实时感知弹窗与查杀通知")
    sw.add_argument("--seconds", type=int, default=60)
    sw.add_argument("--interval", type=float, default=0.5)
    sw.add_argument("--json", action="store_true")
    ts = sub.add_parser("trigger", help="触发 360 自己的扫描（右键菜单动词）")
    ts.add_argument("path")
    ts.add_argument("--wait", type=int, default=180)
    td = sub.add_parser("trigger-dsmain",
                        help="用 DSMain.exe /infofastscan 触发扫描")
    td.add_argument("--wait", type=int, default=90)

    args = ap.parse_args()
    s = AV360Sense()

    if args.cmd == "state":
        st = s.state()
        print("=" * 70)
        print("360 拦截状态")
        print("=" * 70)
        print("\n[拦截开关] 已开启 %d 项 / 已关闭 %d 项"
              % (st["enabled_count"], st["disabled_count"]))
        for k, v in st["intercept_flags"].items():
            mark = "开" if v["on"] else "关"
            print("  [%s] %-22s %s = %s" % (mark, k, v["meaning"], v["value"]))
        print("\n[自我保护] %s" % json.dumps(st["self_protection"], ensure_ascii=False))
        print("\n[服务状态]")
        for k, v in st["services"].items():
            print("  %-20s %s" % (k, v))
        summ = s.scan_log_summary()
        if summ:
            print("\n[上次扫描] %s" % json.dumps(summ, ensure_ascii=False))

    elif args.cmd == "scan":
        for f in args.files:
            r = s.scan(f)
            print(json.dumps(r, ensure_ascii=False, indent=2))

    elif args.cmd == "scan-all":
        for f in args.files:
            r = s.scan_all_engines(f)
            print("=" * 70)
            print("文件: %s" % r["path"])
            print("聚合判定: %s" % r["verdict"])
            for k, v in r["engines"].items():
                detail = v.get("engine") or v.get("name") or v.get("error") or ""
                print("  [%-8s] %-12s %s" % (k, v.get("verdict", "-"), detail))

    elif args.cmd == "scan-log":
        r = s.scan_log_latest()
        if args.json:
            print(json.dumps(r, ensure_ascii=False, indent=2))
        else:
            print("=" * 70)
            print("360 官方扫描结果")
            print("=" * 70)
            print("启用引擎: %s" % "  ".join(r.get("engines") or []))
            print("扫描文件: %s  安全: %s  威胁: %s"
                  % (r.get("files_scanned"), r.get("files_clean"),
                     r.get("threats_found")))
            th = r.get("threats") or []
            if th:
                print("\n逐条威胁（含判定引擎）:")
                for t in th:
                    print("  [%s] %s" % (t["engine"], t["verdict"]))
                    print("        %s" % t["path"])

    elif args.cmd == "scan-history":
        hist = s.scan_log_history(limit=args.limit)
        ths = s.scan_log_threats_all()
        if args.json:
            print(json.dumps({"scans": hist, "threats": ths},
                             ensure_ascii=False, indent=2))
        else:
            print("=" * 70)
            print("360 历史扫描记录聚合")
            print("=" * 70)
            print("扫描记录: %d 条   唯一威胁: %d 个" % (len(hist), len(ths)))
            real = [h for h in hist if h.get("time")]
            print("其中含完整信息的: %d 条" % len(real))
            print()
            print("--- 有检出的扫描 ---")
            for h in hist:
                if h.get("threats"):
                    print("  %s  [%s]  目标=%s"
                          % (h.get("time"), h.get("scan_type"), h.get("target")))
                    print("        文件=%s 安全=%s 威胁=%s"
                          % (h.get("files"), h.get("safe"), h.get("threats")))
            print()
            print("--- 唯一威胁汇总（含首次/末次出现）---")
            for t in ths:
                print("  [%s] %s" % (t.get("engine"), t.get("verdict")))
                print("        %s" % t.get("path"))
                print("        md5=%s  命中=%d 次  首次=%s  末次=%s"
                      % (t.get("md5"), t.get("hits"),
                         t.get("first_seen"), t.get("last_seen")))

    elif args.cmd == "verdict":
        if args.trigger:
            if not args.path:
                print("--trigger 需要指定 path")
                return
            v = s.scan_and_verdict(args.path, wait=args.wait)
        else:
            v = s.scan_verdict(target=args.path)
        if args.json:
            print(json.dumps(v, ensure_ascii=False, indent=2))
        else:
            print("=" * 70)
            print("★ 双通道判定（区分'扫描执行了'与'结果可读'）")
            print("=" * 70)
            print("判定来源: %s" % v["verdict_source"])
            print("结果可读: %s" % v["log_available"])
            print("可判定干净: %s" % v["clean_known"])
            print("威胁数: %d" % len(v["threats"]))
            print()
            print("结论: %s" % v["note"])
            if v.get("trigger"):
                print()
                print("触发信息: 已触发=%s 已执行=%s 耗时=%.1fs"
                      % (v["trigger"]["triggered"], v["trigger"]["executed"],
                         v["trigger"]["elapsed"] or 0))
            if v["threats"]:
                print()
                print("--- 威胁明细 ---")
                for t in v["threats"]:
                    print("  [%s] %s" % (t.get("engine"), t.get("verdict")))
                    print("        %s" % t.get("path"))

    elif args.cmd == "handle":
        r = s.handle_scan_log(action=args.action, quarantine_dir=args.dir,
                              copy_only=args.copy_only, dry_run=args.dry_run)
        print("=" * 70)
        print("处理扫描发现的威胁")
        print("=" * 70)
        print("发现威胁: %d 个" % r["total"])
        if r["dry_run"]:
            print("\n[试运行] 将处理以下文件（未动手）:")
            for x in r["skipped"]:
                print("  [%s] %s" % (x.get("engine", "-"), x["path"]))
        else:
            if r["handled"]:
                print("\n[已处理] %d 个:" % len(r["handled"]))
                for h in r["handled"]:
                    print("  [%s] %s" % (h.get("engine", "-"), h["path"]))
                    if h.get("to"):
                        print("        -> %s%s" % (h["to"],
                              "  (原文件已保留)" if h.get("copied") else ""))
            if r["failed"]:
                print("\n[失败] %d 个:" % len(r["failed"]))
                for h in r["failed"]:
                    print("  %s  %s" % (h["path"], h.get("error")))
            if r["skipped"]:
                print("\n[跳过] %d 个:" % len(r["skipped"]))
                for x in r["skipped"]:
                    print("  %s  (%s)" % (x["path"], x.get("reason")))

    elif args.cmd == "watch":
        print("=" * 70)
        print("360 感知层 —— 实时监听（%d 秒）" % args.seconds)
        print("监听：主动防御弹窗 / 查杀通知 / 防护进程")
        print("=" * 70)
        n = 0
        for ev in s.watch(seconds=args.seconds, interval=args.interval):
            n += 1
            if args.json:
                print(json.dumps(ev.to_dict(), ensure_ascii=False))
            else:
                print("\n[%s] %s  (%s)"
                      % (time.strftime("%H:%M:%S", time.localtime(ev.ts)),
                         ev.kind, ev.source))
                if ev.title:
                    print("   标题: %s" % ev.title)
                if ev.path:
                    print("   路径: %s" % ev.path)
                if ev.action:
                    print("   动作: %s" % ev.action)
                if ev.verdict:
                    print("   判定: %s" % ev.verdict)
                if ev.body:
                    print("   正文: %s" % ev.body.replace("\n", " | ")[:300])
        print("\n共捕获 %d 个事件。" % n)

    elif args.cmd == "trigger":
        print("=" * 70)
        print("触发 360 自己的扫描（右键菜单动词）")
        print("=" * 70)
        r = s.trigger_scan(args.path, wait=args.wait)
        print("  目标: %s" % r["path"])
        print("  已触发: %s" % r["triggered"])
        print("  已执行: %s" % r["executed"])
        if r.get("elapsed") is not None:
            print("  耗时: %ss" % r["elapsed"])
        if r.get("cache_delta"):
            print("  ★ 扫描副作用（ScanCache 变化，证明扫描确实执行）:")
            for d in r["cache_delta"]:
                if d["change"] == "new":
                    print("      [新增] %s (%s 字节)" % (d["file"], d["size"]))
                else:
                    print("      [增长] %s %s -> %s 字节"
                          % (d["file"], d["from"], d["to"]))
        if r.get("note"):
            print("  说明: %s" % r["note"])
        if r.get("error"):
            print("  错误: %s" % r["error"])
        print("\n  注：该动词走弹窗路径，结果落在加密 ScanCache，"
              "不写 360safeScanLog.txt。")

    elif args.cmd == "trigger-dsmain":
        print("=" * 70)
        print("触发 360 扫描（DSMain.exe /infofastscan）")
        print("=" * 70)
        r = s.trigger_scan_dsmain(wait=args.wait)
        print("  可执行文件: %s" % r["exe"])
        print("  已触发: %s" % r["triggered"])
        print("  已执行: %s" % r["executed"])
        if r.get("elapsed") is not None:
            print("  耗时: %ss" % r["elapsed"])
        if r.get("cache_delta"):
            print("  ★ 扫描副作用（ScanCache 变化，证明扫描确实执行）:")
            for d in r["cache_delta"]:
                if d["change"] == "new":
                    print("      [新增] %s (%s 字节)" % (d["file"], d["size"]))
                else:
                    print("      [增长] %s %s -> %s 字节"
                          % (d["file"], d["from"], d["to"]))
        if r.get("error"):
            print("  错误: %s" % r["error"])
        print("\n  注：用 cmd /c start 启动（绕过 360 自我保护对 "
              "Start-Process 的拦截）。")


if __name__ == "__main__":
    main()