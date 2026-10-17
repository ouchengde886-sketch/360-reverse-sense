import struct,sys,zlib,os
sys.stdout.reconfigure(encoding='utf-8')
src=r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\dsm_popup.bmp"
d=open(src,'rb').read()
# 解析 BMP
off=struct.unpack_from('<I',d,10)[0]
w=struct.unpack_from('<i',d,18)[0]
h=struct.unpack_from('<i',d,22)[0]
bpp=struct.unpack_from('<H',d,28)[0]
print("BMP: %dx%d %dbpp dataoff=%d"%(w,h,bpp,off))
h=abs(h)
px=d[off:off+w*h*4]
# 转成 RGB（BGRA -> RGB），并做 PNG 编码
rows=[]
for y in range(h):
    row=bytearray()
    row.append(0)
    for x in range(w):
        i=(y*w+x)*4
        b,g,r,a=px[i],px[i+1],px[i+2],px[i+3]
        row+=bytes((r,g,b))
    rows.append(bytes(row))
raw=b''.join(rows)
def chunk(t,data):
    c=t+data
    return struct.pack('>I',len(data))+c+struct.pack('>I',zlib.crc32(c)&0xffffffff)
png=b'\x89PNG\r\n\x1a\n'
png+=chunk(b'IHDR',struct.pack('>IIBBBBB',w,h,8,2,0,0,0))
png+=chunk(b'IDAT',zlib.compress(raw,6))
png+=chunk(b'IEND',b'')
out=r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\dsm_popup.png"
open(out,'wb').write(png)
print("PNG 已保存: %s (%d 字节)"%(out,os.path.getsize(out)))
# 顺便统计主要颜色分布，判断是否有文字区域
from collections import Counter
c=Counter()
for y in range(0,h,2):
    for x in range(0,w,2):
        i=(y*w+x)*4
        c[(px[i+2],px[i+1],px[i])]+=1
print()
print("主要颜色 top8:")
for col,n in c.most_common(8):
    print("    RGB%s  %d 次 (%.1f%%)"%(col,n,100*n/((h//2)*(w//2))))
