import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\Utils\360SafeChecker.dll'
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
def dump(rva,n,label):
    o=r2o(rva)
    if o is None: print("  %s RVA=0x%X 不在节内"%(label,rva)); return
    print("  === %s RVA=0x%X ==="%(label,rva))
    b=d[o:o+n]
    for i in range(0,n,16):
        print("    +%03X (0x%X): %s"%(i,rva+i,' '.join('%02X'%c for c in b[i:i+16])))
    print()
# 0x6CE3E 附近（命令码 2080 = 0x820）
dump(0x6CE00,0x60,"SendMainCommand 调用点 0x6CE3E")
# 搜索所有 0x820 立即数出现处
print("  搜索 imm32 = 0x820 (2080) 出现位置:")
nm,va,vs,ra,rs=[s for s in secs if s[0]=='.text'][0]
b=d[ra:ra+vs]
pat=struct.pack('<I',0x820)
st=0;cnt=0
while True:
    i=b.find(pat,st)
    if i<0: break
    if i>0 and b[i-1]==0x68:
        print("    push 0x820 @RVA=0x%X"%(va+i-1))
        cnt+=1
    st=i+1
print("  共 %d 处"%cnt)
