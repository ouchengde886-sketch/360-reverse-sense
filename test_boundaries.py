"""★ 边界复验测试：PE 映像后缀的写入确实被 360 拦截。

★★★ 重要更正历史（第 51 轮）★★★
  第 45 轮曾得出结论："可执行后缀写入被拦截"是误判，真实原因是
  "文件被独占占用"。该结论**只对了一半**：
    - 独占占用确实会让所有后缀写入失败（这部分成立，见测试 B）；
    - 但**未被占用时，PE 映像后缀依然被拒绝**（err=5 ACCESS_DENIED），
      第 45 轮的 A 段之所以"全部通过"，是因为当时写的是**小文件**，
      且 360 的拦截与文件大小/内容无关、只与**最终扩展名**有关。
  第 51 轮用对照实验重新固定了正确结论：
    - 空内容写 .exe  -> 被拒
    - 1 字节写 .exe  -> 被拒
    - 360KB 真实 PE 写 .txt -> 成功
    - 360KB 真实 PE 写 .exe -> 被拒
  即：**拦截是纯文件名驱动的**，与内容无关。
  拦截者是 360 的文件系统微过滤驱动 360FsFlt / 360Box64
  （driverquery 显示为 "File System" 类型，Altitude 382300/382310）。

这个测试的存在意义：把"PE 后缀被拦、.com 可绕过"这一可利用面
用可复现的对照实验固定下来，防止再次误判。
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
    print("[A] ★ 未被占用时，PE 映像后缀仍应被拒绝（第 51 轮更正）")
    print("    拦截与内容无关：空文件、1 字节、真实 PE 都一样被拒")
    print("    可用后缀（非 PE 映像）应全部成功")
    # PE 映像后缀：360FsFlt 微过滤驱动按扩展名拒绝
    pe_exts = ["exe", "dll", "sys", "ocx", "scr", "cpl", "vbs"]
    # 非 PE 映像后缀：应全部成功
    ok_exts = ["com", "bin", "dat", "tmp", "txt", "ps1", "log", "zip", "json"]
    pe_denied, pe_allowed = [], []
    for e in pe_exts:
        p = os.path.join(d, "a." + e)
        try:
            with open(p, "wb") as f:
                f.write(data)
            pe_allowed.append(e)
        except PermissionError:
            pe_denied.append(e)
        except Exception as ex:  # noqa: BLE001
            pe_denied.append("%s(%s)" % (e, type(ex).__name__))
    check("PE 映像后缀全部被拒（%d 种）" % len(pe_exts),
          not pe_allowed, "被放行=%s" % (pe_allowed or "无"))

    ok_failed = []
    for e in ok_exts:
        p = os.path.join(d, "a." + e)
        try:
            with open(p, "wb") as f:
                f.write(data)
            if os.path.getsize(p) != len(data):
                ok_failed.append(e + "(size)")
        except Exception as ex:  # noqa: BLE001
            ok_failed.append("%s(%s)" % (e, type(ex).__name__))
    check("非 PE 后缀全部写入成功（%d 种）" % len(ok_exts),
          not ok_failed, "失败=%s" % (ok_failed or "无"))
    print()

    # ---------------------------------------------------------------- A2
    print("[A2] ★ 拦截是文件名驱动，与内容无关（关键对照）")
    cases = [
        ("空内容 -> .exe", b"", "exe", True),
        ("1 字节 -> .exe", b"A", "exe", True),
        ("真实 PE -> .txt", data, "txt", False),
        ("真实 PE -> .exe", data, "exe", True),
    ]
    mismatch = []
    for label, blob, ext, expect_denied in cases:
        p = os.path.join(d, "c_%s.%s" % (abs(hash(label)) % 10000, ext))
        denied = False
        try:
            with open(p, "wb") as f:
                f.write(blob)
        except PermissionError:
            denied = True
        except Exception:  # noqa: BLE001
            denied = True
        if denied != expect_denied:
            mismatch.append("%s(实际%s)" % (label, "被拒" if denied else "成功"))
        print("      %-18s -> %s" % (label, "被拒" if denied else "成功"))
    check("4 组内容/后缀对照全部符合预期", not mismatch,
          "不符=%s" % (mismatch or "无"))
    print()

    # ---------------------------------------------------------------- B
    print("[B] 被独占占用时，非 PE 后缀也应写入失败（占用论仍成立）")
    print("    注意：这里只能用非 PE 后缀，因为 PE 后缀在 A 段已被无条件拒绝，")
    print("    无法用来区分'占用'与'后缀'两种原因。")
    import subprocess
    ps = ("$ErrorActionPreference='Stop';"
          "$r=@();"
          "foreach($e in @('com','txt','dat','bin')){"
          "  $p=Join-Path $env:TEMP ('lk_'+[guid]::NewGuid().ToString('N')+'.'+$e);"
          "  [System.IO.File]::WriteAllText($p,'hello');"
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
    check("被独占时非 PE 后缀也全部失败（占用论成立）", bool(all_denied),
          "结果=%s" % parts)
    check("占用是独立于后缀的第二种失败原因",
          bool(all_denied) and len(parts) == 4,
          "覆盖 %d 种后缀" % len(parts))
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
