#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
360 样本 PE 静态分析（不依赖反编译器）
- 节表 / 熵值（壳检测）
- 导入表（推断自保护手法）
- 字符串扫描（设备名、回调、驱动名）
"""
import os, sys, struct, math, re, json
from collections import Counter

SAMPLES = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\360-samples"

# 自保护 / 内核相关 API 特征
KERNEL_APIS = {
    # 进程/线程回调 —— 自保护核心
    "PsSetCreateProcessNotifyRoutine": "进程创建回调(自保护)",
    "PsSetCreateProcessNotifyRoutineEx": "进程创建回调Ex(可拦截)",
    "PsSetCreateThreadNotifyRoutine": "线程创建回调",
    "PsSetLoadImageNotifyRoutine": "模块加载回调",
    "ObRegisterCallbacks": "对象回调(句柄保护)★",
    "ObUnRegisterCallbacks": "反注册对象回调",
    "CmRegisterCallback": "注册表回调★",
    "CmRegisterCallbackEx": "注册表回调Ex",
    # 文件过滤 —— minifilter
    "FltRegisterFilter": "minifilter注册★",
    "FltStartFiltering": "启动过滤",
    "FltCreateCommunicationPort": "创建通信端口(外部调用接口)★",
    "FltSendMessage": "向用户态发消息",
    "FltUnregisterFilter": "反注册过滤",
    "IoCreateDevice": "创建设备对象",
    "IoCreateSymbolicLink": "创建符号链接",
    # 进程/内存
    "ZwOpenProcess": "打开进程",
    "ZwTerminateProcess": "结束进程",
    "PsLookupProcessByProcessId": "查进程",
    "KeStackAttachProcess": "附加进程",
    "MmIsAddressValid": "内存校验",
    "ZwProtectVirtualMemory": "改内存保护",
    # 驱动卸载控制
    "IoDeleteDevice": "删除设备",
    "IoDeleteSymbolicLink": "删除符号链接",
    "RtlUnicodeStringToAnsiString": "字符串转换",
    # 签名/镜像
    "ZwQuerySystemInformation": "查询系统信息",
    "SeAccessCheck": "访问检查",
    "PsGetProcessImageFileName": "取进程名",
    "PsGetProcessId": "取PID",
}

USER_APIS = {
    "OpenProcess": "打开进程",
    "TerminateProcess": "结束进程",
    "CreateToolhelp32Snapshot": "进程快照",
    "Process32First": "枚举进程",
    "DeviceIoControl": "设备IO控制★",
    "CreateFileW": "打开文件/设备",
    "ReadFile": "读",
    "WriteFile": "写",
    "RegOpenKeyExW": "打开注册表",
    "RegSetValueExW": "写注册表",
    "AdjustTokenPrivileges": "调整权限",
    "GetTokenInformation": "取令牌",
    "OpenProcessToken": "打开令牌",
    "CreateMutexW": "创建互斥体",
    "CreateEventW": "创建事件",
    "WaitForSingleObject": "等待对象",
    "SetWindowsHookExW": "装钩子",
    "LoadLibraryW": "加载DLL",
    "GetProcAddress": "取函数地址",
    "WSAStartup": "网络初始化",
    "WinHttpOpen": "HTTP",
    "CryptVerifySignature": "验签",
    "WinVerifyTrust": "验证信任★",
}

INTERESTING_STRINGS = [
    r"\\Device\\[A-Za-z0-9_]+",
    r"\\DosDevices\\[A-Za-z0-9_]+",
    r"\\BaseNamedObjects\\[A-Za-z0-9_]+",
    r"\\Registry\\Machine\\[A-Za-z0-9_\\]+",
    r"\\SystemRoot\\[A-Za-z0-9_.\\]+",
    r"[A-Za-z0-9_]+\.sys",
    r"\\\\\.\\[A-Za-z0-9_]+",
    r"Flt[A-Za-z]+",
    r"360[A-Za-z0-9_]+",
    r"Qutm[A-Za-z0-9_]*",
    r"QHSafe[A-Za-z0-9_]*",
    r"ZhuDong[A-Za-z0-9_]*",
]


def entropy(data):
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def parse_pe(path):
    with open(path, "rb") as f:
        b = f.read()
    info = {"file": os.path.basename(path), "size": len(b)}

    if b[:2] != b"MZ":
        info["error"] = "not MZ"
        return info, b

    pe = struct.unpack_from("<I", b, 0x3C)[0]
    if b[pe:pe + 4] != b"PE\0\0":
        info["error"] = "not PE"
        return info, b

    machine = struct.unpack_from("<H", b, pe + 4)[0]
    nsec = struct.unpack_from("<H", b, pe + 6)[0]
    tstamp = struct.unpack_from("<I", b, pe + 8)[0]
    opt_size = struct.unpack_from("<H", b, pe + 20)[0]
    chars = struct.unpack_from("<H", b, pe + 22)[0]

    info["machine"] = {0x14c: "x86", 0x8664: "x64", 0xaa64: "ARM64"}.get(machine, hex(machine))
    info["timestamp"] = tstamp
    info["is_dll"] = bool(chars & 0x2000)
    info["is_driver"] = bool(chars & 0x1000) or info["file"].lower().endswith(".sys")
    info["sections"] = []
    info["subsystem"] = None

    opt_off = pe + 24
    if opt_size >= 0x44:
        magic = struct.unpack_from("<H", b, opt_off)[0]
        info["pe_magic"] = hex(magic)
        # Subsystem 偏移: PE32=0x5C, PE32+=0x5C 相对 optional header
        if opt_size > 0x5C:
            info["subsystem"] = struct.unpack_from("<H", b, opt_off + 0x5C)[0]

    sec_off = pe + 24 + opt_size
    for i in range(nsec):
        o = sec_off + i * 40
        if o + 40 > len(b):
            break
        name = b[o:o + 8].rstrip(b"\0").decode("latin1", "replace")
        vsize = struct.unpack_from("<I", b, o + 8)[0]
        vaddr = struct.unpack_from("<I", b, o + 12)[0]
        rsize = struct.unpack_from("<I", b, o + 16)[0]
        raddr = struct.unpack_from("<I", b, o + 20)[0]
        schar = struct.unpack_from("<I", b, o + 36)[0]
        raw = b[raddr:raddr + rsize] if rsize else b""
        info["sections"].append({
            "name": name, "vsize": vsize, "vaddr": vaddr,
            "rawsize": rsize, "entropy": round(entropy(raw), 3),
            "exec": bool(schar & 0x20000000),
            "write": bool(schar & 0x80000000),
        })

    # 导入表
    info["imports"] = {}
    info["dll_count"] = 0
    try:
        if opt_size >= 0x80:
            is64 = info.get("pe_magic") == "0x20b"
            dd_off = opt_off + (0x70 if is64 else 0x60)
            imp_rva = struct.unpack_from("<I", b, dd_off + 8)[0]
            if imp_rva:
                # RVA -> file offset
                def rva2off(rva):
                    for s in info["sections"]:
                        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
                            return s["vaddr"], s["rawsize"], None
                    return None
                # 简化：直接按节表映射
                def r2o(rva):
                    for s in info["sections"]:
                        if s["vaddr"] <= rva < s["vaddr"] + s["rawsize"]:
                            return rva - s["vaddr"] + (sec_off + info["sections"].index(s) * 40)
                    return None
                # 更稳妥：重建节表 raddr
                secs = []
                for i in range(nsec):
                    o = sec_off + i * 40
                    secs.append((struct.unpack_from("<I", b, o + 12)[0],
                                 struct.unpack_from("<I", b, o + 16)[0],
                                 struct.unpack_from("<I", b, o + 20)[0],
                                 struct.unpack_from("<I", b, o + 8)[0]))

                def rva_to_off(rva):
                    for va, rs, ra, vs in secs:
                        if va <= rva < va + max(rs, vs):
                            return ra + (rva - va)
                    return None

                off = rva_to_off(imp_rva)
                if off:
                    idx = 0
                    while idx < 200:
                        e = off + idx * 20
                        if e + 20 > len(b):
                            break
                        oft, tstamp2, fwd, namerva, first = struct.unpack_from("<IIIII", b, e)
                        if namerva == 0 and first == 0:
                            break
                        no = rva_to_off(namerva)
                        if no:
                            end = b.find(b"\0", no)
                            dll = b[no:end].decode("latin1", "replace")
                            funcs = []
                            fo = rva_to_off(first if first else oft)
                            if fo:
                                is64 = info.get("pe_magic") == "0x20b"
                                step = 8 if is64 else 4
                                fi = 0
                                while fi < 500:
                                    p = fo + fi * step
                                    if p + step > len(b):
                                        break
                                    val = struct.unpack_from("<Q" if is64 else "<I", b, p)[0]
                                    if val == 0:
                                        break
                                    if not (val & (1 << (63 if is64 else 31))):
                                        no2 = rva_to_off(val & 0x7FFFFFFF)
                                        if no2:
                                            e2 = b.find(b"\0", no2)
                                            if e2 > no2:
                                                funcs.append(b[no2 + 2:e2].decode("latin1", "replace"))
                                    fi += 1
                            info["imports"][dll] = funcs
                            info["dll_count"] += 1
                        idx += 1
    except Exception as ex:
        info["import_error"] = str(ex)

    return info, b


def scan_strings(b, info):
    found = {}
    try:
        txt = b.decode("latin1")
    except Exception:
        return found
    for pat in INTERESTING_STRINGS:
        ms = set(re.findall(pat, txt))
        ms = {m for m in ms if 3 < len(m) < 120}
        if ms:
            found[pat] = sorted(ms)[:25]
    return found


def main():
    files = sorted(os.listdir(SAMPLES))
    report = []
    for fn in files:
        p = os.path.join(SAMPLES, fn)
        if not os.path.isfile(p):
            continue
        info, b = parse_pe(p)
        info["strings"] = scan_strings(b, info)

        # 命中的关键 API
        allfuncs = set()
        for dll, fs in info.get("imports", {}).items():
            allfuncs.update(fs)
        hits_k = {k: v for k, v in KERNEL_APIS.items() if any(k.lower() in f.lower() for f in allfuncs)}
        hits_u = {k: v for k, v in USER_APIS.items() if any(k.lower() in f.lower() for f in allfuncs)}
        info["selfprotect_hits"] = hits_k
        info["user_hits"] = hits_u
        report.append(info)

    out = os.path.join(os.path.dirname(SAMPLES), "pe_report.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    print("报告已写入:", out)
    print("样本数:", len(report))

    # 摘要打印
    for r in report:
        print("\n" + "=" * 78)
        print(f"{r['file']}  [{r.get('machine')}]  {r['size']/1024:.0f}KB  "
              f"{'DRIVER' if r.get('is_driver') else ('DLL' if r.get('is_dll') else 'EXE')}")
        if r.get("error"):
            print("  ERROR:", r["error"]); continue
        ents = [s["entropy"] for s in r.get("sections", [])]
        print(f"  节数={len(r.get('sections',[]))}  最高熵={max(ents) if ents else 0}  "
              f"导入DLL={r.get('dll_count',0)}")
        hs = r.get("selfprotect_hits", {})
        if hs:
            print("  ★ 自保护/内核 API:")
            for k, v in list(hs.items())[:14]:
                print(f"      {k:<38} {v}")
        us = r.get("user_hits", {})
        if us:
            print("  · 用户态 API:")
            for k, v in list(us.items())[:10]:
                print(f"      {k:<38} {v}")


if __name__ == "__main__":
    main()