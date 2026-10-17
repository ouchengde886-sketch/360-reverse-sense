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
# 布局: [vftable 0x1012F9CC][name_ptr 0x101xxxxx][name]
# 从 dump 看: CC F9 12 10 | 00 00 00 00 | 2E 3F 41 56 ...
# 0x1012F9CC 是 vftable，接着 4 字节 0，然后是名字。
# 所以 type_info 是 {vftable, name_ptr}，name_ptr 应在名字前 4 字节处。
i=d.find(b'.?AVCScChecker@@')
name_rva=o2r(i)
o=i-8
vt,np_=struct.unpack_from('<II',d,o)
print("  名字 RVA=0x%X"%name_rva)
print("  名字前 8 字节: vftable=0x%08X  name_ptr=0x%08X"%(vt,np_))
print("  期望 name_ptr = 0x%08X"%(0x10100000+name_rva))
print()
# name_ptr 实际是 0，说明这是"名字内联"布局：
# type_info = {vftable(4), name_ptr(4), name[]}，name_ptr 指向自身名字
# 但这里是 0，所以可能是 {vftable(4), spare(4), name_ptr(4), name[]}
o2=i-12
a,b,c=struct.unpack_from('<III',d,o2)
print("  名字前 12 字节: %08X %08X %08X"%(a,b,c))
if c==0x10100000+name_rva:
    print("  ✓ type_info RVA=0x%X (name_ptr 在 +8)"%o2r(o2))
    ti=o2r(o2)
    # 找 COL
    pat=struct.pack('<I',0x10100000+ti)
    print("  搜索引用 type_info 的 COL:")
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
                    o3=r2o(r2)
                    vs2=struct.unpack_from('<IIIIIIII',d,o3)
                    print("      vftable RVA=0x%X: %s"%(r2,' '.join('%08X'%v for v in vs2)))
