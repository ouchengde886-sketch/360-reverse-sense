import sys,struct,re
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\ScChecker.dll'
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
    print("  %-8s VA=0x%08X VS=0x%08X RAW=0x%08X RS=0x%08X  范围 0x%X-0x%X"%(nm,va,vs,ra,rs,va,va+vs))
def o2r(o):
    for nm,va,vs,ra,rs in secs:
        if ra<=o<ra+rs: return va+(o-ra)
    return None
def r2o(r):
    for nm,va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
i=d.find(b'.?AVCScChecker@@')
print()
print("  .?AVCScChecker@@ 文件偏移=0x%X -> RVA=0x%X"%(i,o2r(i)))
print()
print("  该 RVA 附近 64 字节:")
o=i-16
for k in range(0,80,16):
    print("    +%03X: %s"%(k,' '.join('%02X'%c for c in d[o+k:o+k+16])))
print()
# 名字前的结构
print("  往前找 type_info（vftable 应指向 0x1012F9CC）:")
pat=struct.pack('<I',0x1012F9CC)
for m in re.finditer(re.escape(pat),d):
    rr=o2r(m.start())
    if rr and abs(rr-o2r(i))<0x100:
        print("    候选 type_info RVA=0x%X (距名字 %d 字节)"%(rr, o2r(i)-rr))
        oo=m.start()
        vt,np_=struct.unpack_from('<II',d,oo)
        print("      vftable=0x%08X name_ptr=0x%08X"%(vt,np_))
        if np_==0x10100000+o2r(i):
            print("      ✓ name_ptr 正确！type_info RVA=0x%X"%rr)
