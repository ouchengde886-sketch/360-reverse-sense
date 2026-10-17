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
# type_info: vftable(4) + name_ptr(4) + name[]  => name 在 +4
for name in [b'.?AVCScChecker@@', b'.?AVIScChecker2@@', b'.?AVIScChecker@@']:
    i=d.find(name)
    r=o2r(i)
    ti=r-4
    o=r2o(ti)
    vt,np_=struct.unpack_from('<II',d,o)
    ok = (np_==0x10100000+r)
    print("  %s type_info RVA=0x%X vftable=0x%08X name_ptr=0x%08X %s"%(
        name.decode('latin1'),ti,vt,np_,'OK' if ok else 'BAD'))
    # 找 COL: pTypeDescriptor 指向 ti
    pat=struct.pack('<I',0x10100000+ti)
    for m in re.finditer(re.escape(pat),d):
        rr=o2r(m.start())
        if rr is None: continue
        col=rr-12
        oo=r2o(col)
        if oo is None or oo<0 or oo+20>len(d): continue
        sig,off,cd,ptd,pcd=struct.unpack_from('<IIIII',d,oo)
        if sig==1 and ptd==0x10100000+ti:
            print("    ★ COL RVA=0x%X"%col)
            pat2=struct.pack('<I',0x10100000+col)
            for m2 in re.finditer(re.escape(pat2),d):
                r2=o2r(m2.start())
                if r2:
                    print("      vftable 候选 RVA=0x%X"%r2)
                    o3=r2o(r2)
                    vs=struct.unpack_from('<IIIIIIII',d,o3)
                    print("        前 8 项: "+' '.join('%08X'%v for v in vs))
    print()
