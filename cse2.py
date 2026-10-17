import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
p=root+r'\sweeper\CleanSoftEng.dll'
d=open(p,'rb').read()
# 直接搜 RVA 0x120DA0 和 0x120DC0 的 4 字节小端
for name,rva in [('MIndex',0x120DA0),('Data_',0x120DC0)]:
    pat=struct.pack('<I',rva)
    n=d.count(pat)
    print("  RVA 0x%X (%s) 出现 %d 次"%(rva,name,n))
    st=0
    while True:
        j=d.find(pat,st)
        if j<0: break
        print("     文件偏移 0x%X"%j)
        st=j+1
print()
# ★ 也许字符串是通过 **lea reg,[rip+disp]** 引用的（x64）或 push（x86）
# 先确认架构
pe=struct.unpack_from('<I',d,0x3c)[0]
mach=struct.unpack_from('<H',d,pe+4)[0]
print("  机器码: 0x%04X (%s)"%(mach,'x86' if mach==0x14c else 'x64' if mach==0x8664 else '?'))
print()
# 若是 x64，用 RIP 相对寻址找引用
if mach==0x8664:
    nsec=struct.unpack_from('<H',d,pe+6)[0]
    optsz=struct.unpack_from('<H',d,pe+20)[0]
    so=pe+24+optsz
    secs=[]
    for i in range(nsec):
        nm=d[so+i*40:so+i*40+8].rstrip(b'\x00').decode('latin1')
        vs,va,rs,ra=struct.unpack_from('<IIII',d,so+i*40+8)
        secs.append((nm,va,vs,ra,rs))
    txt=[x for x in secs if x[0]=='.text'][0]
    nm,va,vs,ra,rs=txt
    b=d[ra:ra+vs]
    print("=== RIP 相对引用搜索 (.text %d 字节) ==="%len(b))
    for name,rva in [('MIndex',0x120DA0),('Data_',0x120DC0)]:
        found=[]
        for i in range(len(b)-7):
            # lea reg,[rip+disp32]: 48 8D xx disp32  或 4C 8D
            if b[i] in (0x48,0x4C) and b[i+1] in (0x8D,):
                disp=struct.unpack_from('<i',b,i+3)[0]
                target=va+i+7+disp
                if target==rva: found.append(va+i)
        print("  %s: %d 处 %s"%(name,len(found),[hex(x) for x in found[:5]]))
