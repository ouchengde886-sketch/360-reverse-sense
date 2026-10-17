import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
p=root+r'\sweeper\CleanSoftEng.dll'
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
def o2r(o):
    for nm,va,vs,ra,rs in secs:
        if ra<=o<ra+rs: return va+(o-ra)
    return None
print("=== CleanSoftEng.dll 节表 ===")
for nm,va,vs,ra,rs in secs: print("  %-10s VA=0x%08X VS=0x%08X RA=0x%08X"% (nm,va,vs,ra))
print()
# 找 'Data_%04d_%02d_%02d.dat' 的 RVA 及引用
for kw in ['%s\\MIndex.dat','Data_%04d_%02d_%02d.dat']:
    w=kw.encode('utf-16-le')
    i=d.find(w)
    rva=o2r(i)
    print("  %r @0x%X RVA=0x%X"%(kw,i,rva))
    pat=struct.pack('<I',rva)
    refs=[]
    st=0
    while True:
        j=d.find(pat,st)
        if j<0: break
        refs.append((j,o2r(j)))
        st=j+1
    print("     被引用 %d 次: %s"%(len(refs),[(hex(x),hex(r) if r else None) for x,r in refs[:6]]))
