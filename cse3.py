import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\sweeper\CleanSoftEng.dll'
d=open(p,'rb').read()
# 字符串 RVA 0x120DA0/0x120DC0 零引用 => 通过表引用
# 检查字符串**前后**是否有指针表（连续的 4 字节 RVA）
print("=== 字符串前 64 字节（可能是指针表）===")
i=d.find('Data_%04d_%02d_%02d.dat'.encode('utf-16-le'))
print("  字符串 @0x%X"%i)
seg=d[i-64:i]
for k in range(0,64,4):
    v=struct.unpack_from('<I',seg,k)[0]
    print("     [%+d] 0x%08X"%(k-64,v))
print()
print("=== 字符串后 64 字节 ===")
seg2=d[i+len('Data_%04d_%02d_%02d.dat'.encode('utf-16-le')):i+len('Data_%04d_%02d_%02d.dat'.encode('utf-16-le'))+64]
for k in range(0,64,4):
    v=struct.unpack_from('<I',seg2,k)[0]
    print("     [%+d] 0x%08X"%(k,v))
print()
# ★ 关键: 检查 .rdata 里是否有指向这些字符串的指针表
# 搜索 0x120DA0 和 0x120DC0 在整个文件（含未对齐）
for name,rva in [('MIndex',0x120DA0),('Data_',0x120DC0),('CIndex',0x120D8A)]:
    pat=struct.pack('<I',rva)
    hits=[]
    for off in range(len(d)-4):
        if d[off:off+4]==pat: hits.append(off)
    print("  RVA 0x%X (%s): %d 处（未对齐搜索）%s"%(rva,name,len(hits),[hex(x) for x in hits[:5]]))
