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
# 解析重定位表，建立 RVA -> 被引用位置 的映射
ddoff=pe+24+96
rel_rva,rel_sz=struct.unpack_from('<II',d,ddoff+40)
print("  重定位表 RVA=0x%X size=%d"%(rel_rva,rel_sz))
refs={}
if rel_rva:
    o=r2o(rel_rva); end=o+rel_sz
    while o<end:
        page,bsz=struct.unpack_from('<II',d,o)
        if bsz==0: break
        n=(bsz-8)//2
        for k in range(n):
            ent=struct.unpack_from('<H',d,o+8+k*2)[0]
            if (ent>>12)==3:  # HIGHLOW
                tgt=page+(ent&0xFFF)
                refs.setdefault(tgt,[]).append(page)
        o+=bsz
print("  重定位项数:",len(refs))
print()
for name in [b'.?AVCScChecker@@', b'.?AVIScChecker2@@', b'.?AVIScChecker@@']:
    i=d.find(name)
    if i<0: continue
    r=o2r(i)
    ti=r-0x10
    print("  %s type_info RVA=0x%X"%(name.decode('latin1'),ti))
    users=refs.get(ti,[])
    print("    被引用的页 RVA:", ', '.join('0x%X'%u for u in users[:20]))
    # 每个引用页里找 COL（Complete Object Locator）
    for pg in users[:5]:
        o=r2o(pg)
        # COL 结构: sig(4) offset(4) cdOffset(4) pTypeDescriptor(4) pClassDescriptor(4)
        # 搜索该页内 pTypeDescriptor == 0x10100000+ti 的位置
        pat=struct.pack('<I',0x10100000+ti)
        for m in re.finditer(re.escape(pat),d[o:o+0x1000]):
            col_rva=pg+m.start()
            col_off=col_rva-16  # pTypeDescriptor 在 COL+12
            print("      找到 COL 候选 RVA=0x%X (pTypeDescriptor 在 +12)"%col_off)
            # vftable 指向 COL，搜索引用 col_off 的重定位
            for u2 in refs.get(col_off,[]):
                print("        COL 被引用于页 RVA=0x%X -> vftable 附近"%u2)
    print()
