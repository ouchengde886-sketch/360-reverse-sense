#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
360 深度静态取证：从 PE 原始字节中提取"外部可调用接口"与"自保护机制"证据。

与 pe_scan.py 的浅层扫描不同，本脚本专门提取：
  1. 设备名 / 符号链接（\Device\Xxx、\DosDevices\Xxx、\\.\Xxx）—— 外部调用入口
  2. 设备接口 GUID（DEVICE_INTERFACE_*）—— 用户态定位设备的另一条路径
  3. IOCTL 常量（CTL_CODE 形态：0x0022xxxx 等）—— 控制码
  4. 注册表路径（\Registry\Machine\...）—— 自保护/配置持久化
  5. 内嵌驱动/模块文件名（*.sys）—— 自保护链
  6. 互斥体 / 事件名（\BaseNamedObjects\...）—— 单实例与 IPC
  7. 导出表 —— 外部调用 API
  8. 导入表中与"句柄保护/进程回调/注册表回调"相关的 API

输出 out/static/<name>.json 与一份汇总。
"""
import os
import re
import sys
import json
import struct

WS = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
OUT = os.path.join(WS, "static_out")

# ---------- 字符串提取 ----------
ASCII_RE = re.compile(rb"[\x20-\x7e]{4,260}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,260}")


def strings_of(data):
    """返回 (ascii_set, utf16_set)。"""
    a = {m.group().decode("latin1") for m in ASCII_RE.finditer(data)}
    u = set()
    for m in UTF16_RE.finditer(data):
        try:
            u.add(m.group().decode("utf-16-le"))
        except UnicodeDecodeError:
            pass
    return a, u


# ---------- 分类模式 ----------
PATTERNS = {
    "device": re.compile(r"^\\Device\\[A-Za-z0-9_{}.\-]+$"),
    "dosdevice": re.compile(r"^\\DosDevices\\[A-Za-z0-9_{}.\-]+$"),
    "dosdev_short": re.compile(r"^\\\\\.\\[A-Za-z0-9_{}.\-]+$"),
    "basedobj": re.compile(r"^\\BaseNamedObjects\\[A-Za-z0-9_{}.\-]+$"),
    "regpath": re.compile(r"^\\Registry\\[A-Za-z0-9_\\{}.\-]+$"),
    "regpath2": re.compile(r"^(?:SOFTWARE|SYSTEM|HARDWARE)\\[A-Za-z0-9_\\{}.\-]+$"),
    "sysfile": re.compile(r"^[A-Za-z0-9_\-]+\.(?:sys|dll|exe|dat)$", re.I),
    "guid": re.compile(r"^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$"),
    "kernelobj": re.compile(r"^(?:\\KernelObjects\\|\\Callback\\|\\FileSystem\\|\\Driver\\|\\ObjectTypes\\)[A-Za-z0-9_\\{}.\-]+$"),
}

# 自保护 / 主动防御 关键内核 API
KEY_APIS = {
    # 进程/线程/镜像回调 —— 自保护核心
    "PsSetCreateProcessNotifyRoutine": "进程创建回调（可拦截进程启动）",
    "PsSetCreateProcessNotifyRoutineEx": "进程创建回调Ex（可拒绝创建）",
    "PsSetCreateThreadNotifyRoutine": "线程创建回调",
    "PsSetLoadImageNotifyRoutine": "模块加载回调（DLL注入检测）",
    # 对象回调 —— 句柄保护（杀不掉进程的关键）
    "ObRegisterCallbacks": "对象回调（句柄剥离，自保护核心）",
    "ObUnRegisterCallbacks": "反注册对象回调",
    "ObGetObjectType": "取对象类型",
    "ObOpenObjectByPointer": "按指针打开对象",
    "ObReferenceObjectByHandle": "按句柄引用对象",
    # 注册表回调 —— 防止改配置
    "CmRegisterCallback": "注册表回调（防改配置）",
    "CmRegisterCallbackEx": "注册表回调Ex",
    "CmUnRegisterCallback": "反注册注册表回调",
    # 文件过滤 —— 查杀/防删
    "FltRegisterFilter": "minifilter注册",
    "FltStartFiltering": "启动文件过滤",
    "FltCreateCommunicationPort": "创建通信端口（用户态交互接口）",
    "FltSendMessage": "向用户态发消息",
    "FltUnregisterFilter": "反注册过滤",
    "IoRegisterFsRegistrationChange": "文件系统注册变更通知",
    # 设备/IOCTL —— 外部调用入口
    "IoCreateDevice": "创建设备对象",
    "IoCreateSymbolicLink": "创建符号链接（外部可打开）",
    "IoCreateDeviceSecure": "创建设备对象（带安全描述符）",
    "IoDeleteDevice": "删除设备",
    "IoDeleteSymbolicLink": "删除符号链接",
    # 进程/内存操作 —— 查杀与主动防御
    "ZwOpenProcess": "打开进程",
    "ZwTerminateProcess": "结束进程",
    "ZwProtectVirtualMemory": "改内存保护",
    "ZwAllocateVirtualMemory": "分配内存",
    "ZwWriteVirtualMemory": "写内存",
    "ZwReadVirtualMemory": "读内存",
    "PsLookupProcessByProcessId": "按PID查进程",
    "PsGetProcessImageFileName": "取进程名",
    "KeStackAttachProcess": "附加进程",
    "MmIsAddressValid": "内存校验",
    # 驱动完整性
    "MmIsDriverVerifying": "驱动签名校验",
    "SeSinglePrivilegeCheck": "权限检查",
    "ZwQuerySystemInformation": "查询系统信息（枚举进程/驱动）",
    # 关机/卸载
    "IoRegisterShutdownNotification": "注册关机通知",
}

# 用户态关键 API
KEY_USER_APIS = {
    "DeviceIoControl": "设备IO控制（外部调用主通道）",
    "CreateFileW": "打开设备/文件",
    "CreateFileA": "打开设备/文件",
    "OpenProcess": "打开进程",
    "TerminateProcess": "结束进程",
    "Process32First": "枚举进程",
    "Process32Next": "枚举进程",
    "CreateToolhelp32Snapshot": "进程/模块快照",
    "RegOpenKeyEx": "打开注册表",
    "RegSetValueEx": "写注册表",
    "OpenSCManager": "打开服务管理器",
    "ControlService": "控制服务（停止服务）",
    "ChangeServiceConfig": "改服务配置",
    "AdjustTokenPrivileges": "调整权限（SeDebugPrivilege）",
    "WinVerifyTrust": "验证数字签名",
    "CryptVerifySignature": "验签",
    "CreateMutex": "创建互斥体（单实例）",
    "SetWindowsHookEx": "装钩子",
    "LoadLibrary": "加载DLL",
    "GetProcAddress": "取函数地址",
    "ShellExecute": "启动外部程序",
    "CreateProcess": "创建进程",
    "WaitForSingleObject": "等待对象",
}


def parse_pe(data):
    """最小 PE 解析：返回节表、导入表、导出表。"""
    info = {"sections": [], "imports": {}, "exports": [], "errors": []}
    if len(data) < 0x40 or data[:2] != b"MZ":
        info["errors"].append("not MZ")
        return info
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        info["errors"].append("not PE")
        return info

    machine = struct.unpack_from("<H", data, pe + 4)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    info["machine"] = {0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64"}.get(machine, hex(machine))
    info["timestamp"] = struct.unpack_from("<I", data, pe + 8)[0]

    opt_off = pe + 24
    magic = struct.unpack_from("<H", data, opt_off)[0] if opt_size >= 2 else 0
    is64 = magic == 0x20B
    info["pe_magic"] = hex(magic)

    sec_off = pe + 24 + opt_size
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        if o + 40 > len(data):
            break
        name = data[o:o + 8].rstrip(b"\0").decode("latin1", "replace")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, o + 8)
        chars = struct.unpack_from("<I", data, o + 36)[0]
        secs.append({"name": name, "vsize": vsize, "vaddr": vaddr,
                     "rawsize": rsize, "rawaddr": raddr,
                     "exec": bool(chars & 0x20000000), "write": bool(chars & 0x80000000)})
    info["sections"] = secs

    def rva2off(rva):
        # Section raw data is the authority for file offsets. Use the raw size
        # for the span so a virtual size larger than the raw size (common when
        # the tail is zero-filled) cannot push an offset past the section.
        for s in secs:
            if s["rawsize"] and s["vaddr"] <= rva < s["vaddr"] + s["rawsize"]:
                return s["rawaddr"] + (rva - s["vaddr"])
        return None

    # 导入表 / 导出表
    try:
        if opt_size >= 0x80:
            # DataDirectory[0] sits at the end of the fixed optional header:
            # PE32 = 0x60, PE32+ = 0x70. Entry N is at that base + N*8.
            dd_off = opt_off + (0x70 if is64 else 0x60)
            imp_rva, imp_size = struct.unpack_from("<II", data, dd_off + 1 * 8)
            exp_rva, exp_size = struct.unpack_from("<II", data, dd_off + 0 * 8)
            if imp_rva:
                off = rva2off(imp_rva)
                idx = 0
                while off and idx < 500:
                    e = off + idx * 20
                    if e + 20 > len(data):
                        break
                    oft, ts, fwd, namerva, first = struct.unpack_from("<IIIII", data, e)
                    if namerva == 0 and first == 0:
                        break
                    no = rva2off(namerva)
                    if no:
                        end = data.find(b"\0", no)
                        dll = data[no:end].decode("latin1", "replace")
                        funcs = []
                        fo = rva2off(first if first else oft)
                        if fo:
                            step = 8 if is64 else 4
                            fi = 0
                            while fi < 2000:
                                p = fo + fi * step
                                if p + step > len(data):
                                    break
                                val = struct.unpack_from("<Q" if is64 else "<I", data, p)[0]
                                if val == 0:
                                    break
                                if not (val & (1 << (63 if is64 else 31))):
                                    n2 = rva2off(val & 0x7FFFFFFF)
                                    if n2:
                                        e2 = data.find(b"\0", n2)
                                        if e2 > n2 + 2:
                                            funcs.append(data[n2 + 2:e2].decode("latin1", "replace"))
                                fi += 1
                        info["imports"][dll] = funcs
                    idx += 1
            # 导出表
            # IMAGE_EXPORT_DIRECTORY layout. MajorVersion/MinorVersion are WORDs,
            # so the header is IIHH + 7 DWORDs (40 bytes total) -- unpacking it as
            # 11 DWORDs shifts every later field by two bytes.
            if exp_rva:
                off = rva2off(exp_rva)
                if off and off + 40 <= len(data):
                    chars, tds, major, minor, name_rva, base, nfunc, nname, \
                        afunc, aname, aord = struct.unpack_from("<IIHHIIIIIII", data, off)
                    no = rva2off(name_rva)
                    if no:
                        e = data.find(b"\0", no)
                        info["dll_name"] = data[no:e].decode("latin1", "replace")
                    ao = rva2off(aname)
                    if ao:
                        for i in range(min(nname, 500)):
                            p = ao + i * 4
                            if p + 4 > len(data):
                                break
                            nr = struct.unpack_from("<I", data, p)[0]
                            n2 = rva2off(nr)
                            if n2:
                                e2 = data.find(b"\0", n2)
                                if e2 > n2:
                                    info["exports"].append(data[n2:e2].decode("latin1", "replace"))
    except Exception as ex:
        info["errors"].append("parse: %s" % ex)

    return info


def classify(strs):
    """把字符串集合按模式分类。"""
    out = {}
    for s in strs:
        s = s.strip()
        if not s:
            continue
        for label, pat in PATTERNS.items():
            if pat.match(s):
                out.setdefault(label, set()).add(s)
    return {k: sorted(v) for k, v in out.items()}


def find_ioctls(data):
    """
    在 .text/.rdata 中寻找 CTL_CODE 常量。
    CTL_CODE(DeviceType, Function, Method, Access) =
      (DeviceType<<16) | (Access<<14) | (Function<<2) | Method
    常见 DeviceType: 0x8000+ (自定义), 0x0001..0x0022 (系统)
    这里收集 0x0002_0000..0xFFFF_FFFF 中形如 xxxx0000 的 4 字节小端值，
    且 Method/Access 位组合合法。
    """
    found = {}
    for m in re.finditer(rb"[\x00-\xff]{4}", data):
        pass  # 占位，下面用 struct 扫描更精确
    # 扫描所有 4 字节对齐窗口
    for i in range(0, len(data) - 4):
        v = struct.unpack_from("<I", data, i)[0]
        if v < 0x00020000 or v > 0xFFFFFFFF:
            continue
        dev = (v >> 16) & 0xFFFF
        acc = (v >> 14) & 0x3
        fn = (v >> 2) & 0xFFF
        meth = v & 0x3
        # 自定义设备类型 0x8000-0xFFFF，或常见系统类型
        if 0x8000 <= dev <= 0xFFFF and fn != 0:
            found[v] = (dev, fn, meth, acc)
    return {hex(k): {"device_type": hex(v[0]), "function": v[1],
                     "method": v[2], "access": v[3]} for k, v in sorted(found.items())}


def main():
    targets = sys.argv[1:]
    if not targets:
        print("usage: static_deep.py <binary> ...")
        return
    os.makedirs(OUT, exist_ok=True)
    for path in targets:
        if not os.path.isfile(path):
            print("[!] missing %s" % path)
            continue
        with open(path, "rb") as f:
            data = f.read()
        name = os.path.basename(path)
        pe = parse_pe(data)
        a, u = strings_of(data)

        allfuncs = set()
        for dll, fs in pe.get("imports", {}).items():
            allfuncs.update(fs)

        rec = {
            "file": name,
            "path": path,
            "size": len(data),
            "machine": pe.get("machine"),
            "pe_magic": pe.get("pe_magic"),
            "dll_name": pe.get("dll_name"),
            "sections": pe.get("sections"),
            "errors": pe.get("errors"),
            "exports": sorted(set(pe.get("exports", []))),
            "import_dlls": sorted(pe.get("imports", {}).keys()),
            "key_apis": {k: v for k, v in KEY_APIS.items()
                         if any(k.lower() in f.lower() for f in allfuncs)},
            "key_user_apis": {k: v for k, v in KEY_USER_APIS.items()
                              if any(k.lower() in f.lower() for f in allfuncs)},
            "classified_ascii": classify(a),
            "classified_utf16": classify(u),
        }
        dst = os.path.join(OUT, name + ".json")
        with open(dst, "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, indent=1)
        print("[+] %-32s dev=%-3d reg=%-3d sys=%-3d guid=%-3d exp=%-3d keyapi=%d" % (
            name,
            len(rec["classified_ascii"].get("device", [])) + len(rec["classified_utf16"].get("device", [])),
            len(rec["classified_ascii"].get("regpath", [])) + len(rec["classified_utf16"].get("regpath", [])),
            len(rec["classified_ascii"].get("sysfile", [])) + len(rec["classified_utf16"].get("sysfile", [])),
            len(rec["classified_ascii"].get("guid", [])) + len(rec["classified_utf16"].get("guid", [])),
            len(rec["exports"]),
            len(rec["key_apis"]),
        ))


if __name__ == "__main__":
    main()