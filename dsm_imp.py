import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
import os
p=r'C:\Program Files (x86)\360\360Safe\deepscan\DSMain.exe'
d=open(p,'rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+optsz
secs=[]
for i in range(nsec):
    vs,va,rs,ra=struct.unpack_from('<IIII',d,so+i*40+8)
    secs.append((va,vs,ra,rs))
def o2r(o):
    for va,vs,ra,rs in secs:
        if ra<=o<ra+rs: return va+(o-ra)
    return None
# 导入表
dd_off = pe+24+96 if optsz>=96 else None
imp_rva,imp_sz = struct.unpack_from('<II',d,pe+24+96+8)
print("  导入表 RVA=0x%X size=%d" % (imp_rva,imp_sz))
def r2o(r):
    for va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
o=r2o(imp_rva)
print("  DSMain.exe 导入的 DLL:")
i=0
while True:
    ent=d[o+i*20:o+i*20+20]
    if len(ent)<20: break
    oft,ts,fc,nm,ft=struct.unpack('<IIIII',ent)
    if nm==0: break
    no=r2o(nm)
    s=d[no:d.find(b'\0',no)].decode('ascii','ignore')
    print("    %s" % s)
    i+=1
    if i>40: break
print()
print("  DSMain.exe 是否导入 deepscan.dll 的符号？")
# 看 deepscan 导入项
i=0
found=False
while True:
    ent=d[o+i*20:o+i*20+20]
    if len(ent)<20: break
    oft,ts,fc,nm,ft=struct.unpack('<IIIII',ent)
    if nm==0: break
    no=r2o(nm)
    s=d[no:d.find(b'\0',no)].decode('ascii','ignore')
    if 'deepscan' in s.lower():
        found=True
        print("    -> %s" % s)
        # 列函数
        oo=r2o(oft) if oft else r2o(ft)
        j=0
        while j<60:
            if oft:
                v=struct.unpack_from('<I',d,oo+j*4)[0]
                if v==0: break
                if v & 0x80000000:
                    print("       ord#%d" % (v & 0xFFFF))
                else:
                    fo=r2o(v)
                    fn=d[fo+2:d.find(b'\0',fo+2)].decode('ascii','ignore')
                    print("       %s" % fn)
            j+=1
    i+=1
if not found: print("    (未导入 deepscan.dll)")
