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
# 找 RTTI 名字
for name in [b'.?AVCScChecker@@', b'.?AVIScChecker2@@', b'.?AVIScChecker@@']:
    i=d.find(name)
    if i<0: continue
    r=o2r(i)
    print("  %s RVA=0x%X"%(name.decode('latin1'),r))
    # RTTI 完整结构在名字前 0x10 字节
    # type_info: vftable(4) + spare(4) + name_ptr(4)
    # 找引用这个 type_info 的 RTTI Complete Object Locator
    ti_rva=r-0x10  # 假设 type_info 从名字前 0x10 开始
    print("    推测 type_info RVA=0x%X"%ti_rva)
    # 搜索谁引用了 ti_rva（作为绝对地址 0x10100000+ti_rva）
    abs_addr=0x10100000+ti_rva
    pat=struct.pack('<I',abs_addr)
    hits=[]
    for m in re.finditer(re.escape(pat),d):
        rr=o2r(m.start())
        if rr: hits.append(rr)
    print("    被引用处 RVA:", ', '.join('0x%X'%h for h in hits[:20]))
    print()
