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
def r2o(r):
    for nm,va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
def o2r(o):
    for nm,va,vs,ra,rs in secs:
        if ra<=o<ra+rs: return va+(o-ra)
    return None
# type_info 结构: vftable_ptr(4) spare(4) name_ptr(4) name[]
# 所以名字在 type_info+8，不是 +0x10
for name in [b'.?AVCScChecker@@', b'.?AVIScChecker2@@', b'.?AVIScChecker@@']:
    i=d.find(name)
    r=o2r(i)
    ti=r-8
    print("  %s 名字RVA=0x%X  type_info RVA=0x%X"%(name.decode('latin1'),r,ti))
    # 检查 type_info+8 是否指向名字
    o=r2o(ti)
    vt,sp,np_=struct.unpack_from('<III',d,o)
    print("    type_info: vftable=0x%08X spare=0x%08X name_ptr=0x%08X"%(vt,sp,np_))
    if np_==0x10100000+r:
        print("    ✓ name_ptr 正确指向名字")
    print()
# 找 RTTI Complete Object Locator: signature=1
print("  搜索 COL（signature=1, pTypeDescriptor 指向上述 type_info）:")
for name in [b'.?AVCScChecker@@', b'.?AVIScChecker2@@', b'.?AVIScChecker@@']:
    i=d.find(name)
    r=o2r(i); ti=r-8
    pat=struct.pack('<I',0x10100000+ti)
    for m in re.finditer(re.escape(pat),d):
        rr=o2r(m.start())
        if rr is None: continue
        col=rr-12
        o=r2o(col)
        if o is None or o<0: continue
        try:
            sig,off,cd=struct.unpack_from('<III',d,o)
        except: continue
        if sig==1:
            print("    %s COL RVA=0x%X (sig=1, offset=%d)"%(name.decode('latin1'),col,off))
            # vftable 在 COL 之前，搜索引用 COL 的重定位
            pat2=struct.pack('<I',0x10100000+col)
            for m2 in re.finditer(re.escape(pat2),d):
                r2=o2r(m2.start())
                if r2: print("      vftable 候选 RVA=0x%X"%r2)
