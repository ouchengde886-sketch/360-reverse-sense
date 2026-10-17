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
# 找所有 call SendMainCommand (0xA69A2) 的地方，看第一个参数
target=0xA69A2
print("  所有调用 SendMainCommand(0xA69A2) 的位置:")
nm,va,vs,ra,rs=[s for s in secs if s[0]=='.text'][0]
b=d[ra:ra+vs]
st=0
cnt=0
while True:
    i=b.find(b'\xE8',st)
    if i<0: break
    if i+5<=len(b):
        rel=struct.unpack_from('<i',b,i+1)[0]
        tgt=va+i+5+rel
        if tgt==target:
            # 往前找 push 立即数（最多 40 字节）
            ctx=b[max(0,i-40):i]
            pushes=[]
            j=len(ctx)-1
            # 从后往前扫 push imm32 (0x68) 和 push imm8 (0x6A)
            k=0
            while k < len(ctx)-4:
                if ctx[k]==0x68:
                    pushes.append(('imm32',struct.unpack_from('<I',ctx,k+1)[0]))
                    k+=5
                elif ctx[k]==0x6A:
                    pushes.append(('imm8',ctx[k+1]))
                    k+=2
                else:
                    k+=1
            print("    call @RVA=0x%X  前面push: %s"%(va+i, pushes[-4:]))
            cnt+=1
    st=i+1
print("  共 %d 处"%cnt)
