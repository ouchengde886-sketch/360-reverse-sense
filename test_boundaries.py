"""★ 边界复验测试：确认"后缀不拦截、占用才失败"这一结论。

这个测试的存在意义：第 45 轮发现此前把"文件被独占占用"误判为
"360 拦截可执行后缀"。本测试用对照实验固定正确结论，
防止将来再次误判。
"""
import os
import sys
import time
import ctypes
from ctypes import wintypes

sys.stdout.reconfigure(encoding="utf-8")

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok))
    print("  [%s] %-50s %s" % ("通过" if ok else "失败", name, detail))


def main():
    print("=" * 78)
    print("  边界复验：后缀 vs 占用（第 45 轮更正结论的固化测试）")
    print("=" * 78)
    print()

    src = r"C:\Windows\System32\notepad.exe"
    if not os.path.exists(src):
        print("  找不到 %s，跳过" % src)
        return
    data = open(src, "rb").read()
    d = os.path.join(os.environ.get("TEMP", "."), "bnd_%d" % (int(time.time()) % 100000))
    os.makedirs(d, exist_ok=True)

    # ---------------------------------------------------------------- A
    print("[A] 未被占用时，所有后缀都应写入成功")
    exts = ["exe", "EXE", "dll", "DLL", "sys", "ocx", "vbs", "scr",
            "cpl", "com", "bin", "dat", "tmp", "txt", "ps1", "log"]
    failed = []
    for e in exts:
        p = os.path.join(d, "a." + e)
        try:
            with open(p, "wb") as f:
                f.write(data)
            if os.path.getsize(p) != len(data):
                failed.append(e + "(size)")
        except Exception as ex:  # noqa: BLE001
            failed.append("%s(%s)" % (e, type(ex).__name__))
    check("16 种后缀全部写入成功", not failed, "失败=%s" % (failed or "无"))
    check("内容完整（字节数一致）", not failed,
          "写入 %d 字节" % len(data))
    print()

    # ---------------------------------------------------------------- B
    print("[B] 被独占占用时，所有后缀都应写入失败")
    print("    （若只有 .exe 失败而 .com 成功 => 后缀论成立）")
    print("    （若所有后缀都失败 => 占用论成立）")
    import subprocess
    ps = ("$ErrorActionPreference='Stop';"
          "$r=@();"
          "foreach($e in @('exe','com','dll','txt')){"
          "  $p=Join-Path $env:TEMP ('lk_'+[guid]::NewGuid().ToString('N')+'.'+$e);"
          "  Copy-Item 'C:\\Windows\\System32\\notepad.exe' $p;"
          "  $fs=[System.IO.File]::Open($p,'Open','Read','None');"
          "  try{ $f2=[System.IO.File]::Open($p,'Open','Write','None'); $f2.Close(); $r+=\"$e=OK\" }"
          "  catch{ $r+=\"$e=DENIED\" };"
          "  $fs.Close(); Remove-Item $p -Force };"
          "$r -join ','")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                         capture_output=True, text=True, timeout=90).stdout.strip()
    print("      实测: %s" % out)
    parts = dict(x.split("=") for x in out.split(",") if "=" in x)
    all_denied = parts and all(v == "DENIED" for v in parts.values())
    check("被独占时所有后缀都失败（占用论成立）", bool(all_denied),
          "结果=%s" % parts)
    check("不存在'只有 .exe 失败'的现象",
          not (parts.get("exe") == "DENIED" and parts.get("com") == "OK"),
          "exe=%s com=%s" % (parts.get("exe"), parts.get("com")))
    print()

    # ---------------------------------------------------------------- C
    print("[C] 边界 1 仍成立：ZhuDongFangYu 句柄不可获取")
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    nt = ctypes.WinDLL("ntdll", use_last_error=True)
    out2 = subprocess.run(["tasklist", "/fo", "csv", "/nh"],
                          capture_output=True, text=True).stdout
    pid = None
    for ln in out2.splitlines():
        p = [x.strip('"') for x in ln.split('","')]
        if p and p[0].lower().startswith("zhudongfangyu"):
            pid = int(p[1])
            break
    if pid is None:
        check("ZhuDongFangYu 在运行", False, "进程未找到")
    else:
        k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.OpenProcess.restype = wintypes.HANDLE
        h = k.OpenProcess(0x1F0FFF, False, pid)
        check("OpenProcess(ALL_ACCESS) 被拒", not h,
              "handle=0x%X" % (h or 0))
        h0 = k.OpenProcess(0, False, pid)
        check("OpenProcess(mask=0) 也被拒", not h0,
              "handle=0x%X" % (h0 or 0))

        class CLIENT_ID(ctypes.Structure):
            _fields_ = [("UniqueProcess", ctypes.c_void_p),
                        ("UniqueThread", ctypes.c_void_p)]

        class OBJA(ctypes.Structure):
            _fields_ = [("Length", wintypes.ULONG),
                        ("RootDirectory", ctypes.c_void_p),
                        ("ObjectName", ctypes.c_void_p),
                        ("Attributes", wintypes.ULONG),
                        ("SecurityDescriptor", ctypes.c_void_p),
                        ("SecurityQualityOfService", ctypes.c_void_p)]

        nt.NtOpenProcess.argtypes = [ctypes.POINTER(wintypes.HANDLE),
                                     wintypes.DWORD,
                                     ctypes.POINTER(OBJA),
                                     ctypes.POINTER(CLIENT_ID)]
        nt.NtOpenProcess.restype = ctypes.c_long
        hh = wintypes.HANDLE()
        cid = CLIENT_ID()
        cid.UniqueProcess = ctypes.c_void_p(pid)
        oa = OBJA()
        oa.Length = ctypes.sizeof(OBJA)
        st = nt.NtOpenProcess(ctypes.byref(hh), 0x1F0FFF,
                              ctypes.byref(oa), ctypes.byref(cid))
        st &= 0xFFFFFFFF
        check("NtOpenProcess -> STATUS_ACCESS_DENIED", st == 0xC0000022,
              "NTSTATUS=0x%08X" % st)
    print()

    # 清理
    try:
        for f in os.listdir(d):
            os.remove(os.path.join(d, f))
        os.rmdir(d)
    except OSError:
        pass

    passed = sum(1 for _, ok in RESULTS if ok)
    print("=" * 78)
    print("  总计: %d/%d 通过" % (passed, len(RESULTS)))
    print("=" * 78)
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
