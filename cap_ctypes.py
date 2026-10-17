import ctypes, sys, os
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
u=ctypes.windll.user32; g=ctypes.windll.gdi32
# 找 DSMain 窗口
EnumWindows=u.EnumWindows
CB=ctypes.WINFUNCTYPE(ctypes.c_bool,wintypes.HWND,wintypes.LPARAM)
found=[]
def cb(h,l):
    n=u.GetWindowTextLengthW(h)
    if n:
        b=ctypes.create_unicode_buffer(n+1)
        u.GetWindowTextW(h,b,n+1)
        if '360' in b.value or '木马' in b.value:
            found.append((h,b.value))
    return True
EnumWindows(CB(cb),0)
print("=== 找到的 360 窗口 ===")
for h,t in found:
    pid=wintypes.DWORD()
    u.GetWindowThreadProcessId(h,ctypes.byref(pid))
    print("    HWND 0x%X  PID %d  '%s'"%(h,pid.value,t))
print()
# 对 DSMain 窗口截图
target=None
for h,t in found:
    pid=wintypes.DWORD()
    u.GetWindowThreadProcessId(h,ctypes.byref(pid))
    if '木马' in t: target=(h,t,pid.value); break
if not target:
    print("未找到木马查杀窗口"); sys.exit()
h,title,pid=target
print("=== 截图目标: HWND 0x%X '%s' (PID %d) ==="%(h,title,pid))
class RECT(ctypes.Structure):
    _fields_=[('L',ctypes.c_long),('T',ctypes.c_long),('R',ctypes.c_long),('B',ctypes.c_long)]
r=RECT()
ok=u.GetWindowRect(h,ctypes.byref(r))
print("    GetWindowRect: %s  (%d,%d)-(%d,%d)"%(bool(ok),r.L,r.T,r.R,r.B))
w,hgt=r.R-r.L,r.B-r.T
print("    尺寸: %dx%d"%(w,hgt))
if w<=0 or hgt<=0:
    print("    尺寸无效，退出"); sys.exit()
# BitBlt 到 DIB
hdc=u.GetWindowDC(h)
print("    GetWindowDC: 0x%X"%(hdc or 0))
mdc=g.CreateCompatibleDC(hdc)
bmp=g.CreateCompatibleBitmap(hdc,w,hgt)
g.SelectObject(mdc,bmp)
R2=0x00CC0020
res=g.BitBlt(mdc,0,0,w,hgt,hdc,0,0,R2)
print("    BitBlt: %s"%bool(res))
# 取像素
class BITMAPINFOHEADER(ctypes.Structure):
    _fields_=[('biSize',wintypes.DWORD),('biWidth',ctypes.c_long),('biHeight',ctypes.c_long),
              ('biPlanes',wintypes.WORD),('biBitCount',wintypes.WORD),('biCompression',wintypes.DWORD),
              ('biSizeImage',wintypes.DWORD),('biXPelsPerMeter',ctypes.c_long),('biYPelsPerMeter',ctypes.c_long),
              ('biClrUsed',wintypes.DWORD),('biClrImportant',wintypes.DWORD)]
bi=BITMAPINFOHEADER()
bi.biSize=ctypes.sizeof(BITMAPINFOHEADER); bi.biWidth=w; bi.biHeight=-hgt
bi.biPlanes=1; bi.biBitCount=32; bi.biCompression=0
buf=ctypes.create_string_buffer(w*hgt*4)
lines=g.GetDIBits(mdc,bmp,0,hgt,buf,ctypes.byref(bi),0)
print("    GetDIBits 行数: %d"%lines)
# 统计颜色（判断是否纯色）
data=buf.raw
uniq=set()
for i in range(0,min(len(data),w*hgt*4),4*97):
    uniq.add(data[i:i+4])
print("    采样到的不同颜色数: %d"%len(uniq))
print("    前 5 种: %s"%[c.hex() for c in list(uniq)[:5]])
# 存为 BMP
import struct
def save_bmp(path,w,h,data):
    row=w*4
    hdr=struct.pack('<2sIHHI',b'BM',14+40+len(data),0,0,14+40)
    ih=struct.pack('<IiiHHIIiiII',40,w,-h,1,32,0,len(data),0,0,0,0)
    open(path,'wb').write(hdr+ih+data)
out=r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\dsm_popup.bmp"
save_bmp(out,w,hgt,data)
print("    已保存: %s (%d 字节)"%(out,os.path.getsize(out)))
g.DeleteObject(bmp); g.DeleteDC(mdc); u.ReleaseDC(h,hdc)
