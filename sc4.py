import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
b=open(os.path.join(d,'MIndex.dat'),'rb').read()
print("=== MIndex.dat 56 字节记录结构（前 12 条）===")
print("  字段: [+0 ptr][+4 ptr][+8 1][+12 size][+16 size2][+20 0][+24 float][+28 const][+32 hash][+36..55 零]")
for i in range(12):
    o=56+i*56
    if o+56>len(b): break
    v=struct.unpack_from('<14I',b,o)
    f=struct.unpack_from('<f',b,o+24)[0]
    print("  #%-3d +0=0x%08X +4=0x%08X +8=%d +12=%-6d +16=%-6d +24=%.4f +28=0x%08X +32=0x%08X"
          %(i,v[0],v[1],v[2],v[3],v[4],f,v[7],v[8]))
print()
print("=== 记录总数 ===")
print("  (len-56)/56 = %.1f"%((len(b)-56)/56))
print()
# CIndex 与 MIndex 的关系：CIndex 里的指针 0x10015fa5 等
ci=open(os.path.join(d,'CIndex_2026_10_15.dat'),'rb').read()
civ=struct.unpack_from('<%dI'%(len(ci)//4),ci,0)
print("=== CIndex_2026_10_15 的指针值分布 ===")
from collections import Counter
c=Counter(civ)
print("  唯一值数: %d / 总数 %d"%(len(c),len(civ)))
for v,n in c.most_common(8):
    print("    0x%08X 出现 %d 次"%(v,n))
