import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
seg=a[offs[1]:offs[2]]
# 原字节 99.8% 高位置1 => b = 0x80 | v, v 是 7 位值
# >>1 后 = 0x40 | (v>>1)，即 6 位值 v>>1 加上 0x40
# 所以有效数据是 (b-0x80) 的 7 位，或 (b>>1)-0x40 的 6 位
print("=== 有效值分布 ===")
v7=[b-0x80 for b in seg]
v6=[(b>>1)-0x40 for b in seg]
print("  7位值范围: %d-%d  不同值 %d"%(min(v7),max(v7),len(set(v7))))
print("  6位值范围: %d-%d  不同值 %d"%(min(v6),max(v6),len(set(v6))))
print()
# 6位值映射到标准 base64 字母表 -> 得到 base64 文本 -> 解码
B64='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
s=''.join(B64[v&0x3F] for v in v6)
print("=== 6位值按 base64 字母表映射 ===")
print("  %s"%s[:100])
import base64
for pad in range(4):
    try:
        dec=base64.b64decode(s[:600]+'='*pad)
        pr=sum(1 for c in dec if 32<=c<127)
        print("  pad=%d 解码 %d 字节 可打印 %d (%.0f%%) %r"%(pad,len(dec),pr,100*pr/max(1,len(dec)),dec[:60]))
    except Exception as e:
        print("  pad=%d 失败 %s"%(pad,str(e)[:40]))
print()
# 7位值直接当 ASCII
s7=''.join(chr(v) if 32<=v<127 else '.' for v in v7)
print("=== 7位值直接当 ASCII ===")
print("  %s"%s7[:120])
