import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\sweeper\CleanSoftEng.dll'
d=open(p,'rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+optsz
secs=[]
for i in range(nsec):
    nm=d[so+i*40:so+i*40+8].rstrip(b'\x00').decode('latin1')
    vs,va,rs,ra=struct.unpack_from('<IIII',d,so+i*40+8)
    secs.append((nm,va,vs,ra,rs))
def r2o(r):
    for nm,va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
def o2r(o):
    for nm,va,vs,ra,rs in secs:
        if ra<=o<ra+rs: return va+(o-ra)
    return None
# ★ 检查重定位表：字符串 RVA 是否被重定位引用
rel=[x for x in secs if x[0]=='.reloc']
print("  节: %s"%[x[0] for x in secs])
nm,va,vs,ra,rs=rel[0]
rb=d[ra:ra+rs]
print("  .reloc 大小 %d"%len(rb))
# 解析重定位块
targets=set()
i=0
while i<len(rb)-8:
    page=struct.unpack_from('<I',rb,i)[0]
    size=struct.unpack_from('<I',rb,i+4)[0]
    if size==0: break
    n=(size-8)//2
    for k in range(n):
        ent=struct.unpack_from('<H',rb,i+8+k*2)[0]
        typ=ent>>12; off=ent&0xFFF
        if typ==3:  # HIGHLOW
            targets.add(page+off)
    i+=size
print("  重定位目标数: %d"%len(targets))
# 字符串 RVA
for name,rva in [('MIndex',0x120DA0),('Data_',0x120DC0),('CIndex',0x120D8A)]:
    print("  %s RVA 0x%X 在重定位表中: %s"%(name,rva,rva in targets))
print()
# ★ 若字符串被重定位引用，说明有代码/数据**直接持有该地址**
# 找持有该地址的位置：搜索 0x120DA0 附近的所有 4 字节
# 但前面搜过 0 次... 说明是 **lea reg,[ebx+offset]** 形式
# 检查 .text 里是否有指令引用 0x120000 附近作为基址
print("=== 搜索 .text 中引用 0x12xxxx 的立即数 ===")
txt=[x for x in secs if x[0]=='.text'][0]
nm,va,vs,ra,rs=txt
b=d[ra:ra+vs]
for name,rva in [('MIndex',0x120DA0),('Data_',0x120DC0)]:
    found=[]
    for j in range(len(b)-4):
        v=struct.unpack_from('<I',b,j)[0]
        if v==rva: found.append((va+j,hex(b[j-1]) if j>0 else ''))
    print("  %s (0x%X): %d 处 %s"%(name,rva,len(found),found[:5]))
