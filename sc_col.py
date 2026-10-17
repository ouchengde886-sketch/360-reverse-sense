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
# 用重定位表找所有引用 type_info RVA=0x15F504 的位置
ddoff=pe+24+96
rel_rva,rel_sz=struct.unpack_from('<II',d,ddoff+40)
refs={}
o=r2o(rel_rva); end=o+rel_sz
while o<end:
    page,bsz=struct.unpack_from('<II',d,o)
    if bsz==0: break
    n=(bsz-8)//2
    for k in range(n):
        ent=struct.unpack_from('<H',d,o+8+k*2)[0]
        if (ent>>12)==3:
            refs.setdefault(page+(ent&0xFFF),[]).append(page)
    o+=bsz
ti=0x15F504
print("  引用 type_info RVA=0x%X 的位置:"%ti)
for u in refs.get(ti,[]):
    print("    页 RVA=0x%X"%u)
    oo=r2o(u)
    # 该页内搜索值 0x1015F504
    pat=struct.pack('<I',0x10100000+ti)
    for m in re.finditer(re.escape(pat),d[oo:oo+0x1000]):
        col_rva=u+m.start()-12
        co=r2o(col_rva)
        if co is None or co<0: continue
        try: sig,off,cd,ptd,pcd=struct.unpack_from('<IIIII',d,co)
        except: continue
        if sig==1:
            print("      ★ COL RVA=0x%X"%col_rva)
            pat2=struct.pack('<I',0x10100000+col_rva)
            for m2 in re.finditer(re.escape(pat2),d):
                r2=o2r(m2.start())
                if r2:
                    o3=r2o(r2)
                    vs2=struct.unpack_from('<IIIIIIIIIIIIIIIIIIII',d,o3)
                    print("        vftable RVA=0x%X"%r2)
                    for j,v in enumerate(vs2):
                        rv=v-0x10100000
                        tag=""
                        if 0x1000<=rv<0x119B5A: tag=" .text"
                        print("          [%2d] 0x%08X%s"%(j,v,tag))
