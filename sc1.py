import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
# CIndex 是明文 DWORD 数组 —— 解析看看
for f in ['CIndex_2026_10_15.dat','CIndex_2026_10_18.dat','MIndex.dat']:
    b=open(os.path.join(d,f),'rb').read()
    print("=== %s (%d 字节) ==="%(f,len(b)))
    n=min(len(b)//4,20)
    vals=struct.unpack_from('<%dI'%n,b,0)
    print("  前 %d 个 DWORD: %s"%(n,[hex(v) for v in vals]))
    # 统计
    allv=struct.unpack_from('<%dI'%(len(b)//4),b,0)
    print("  总 DWORD 数: %d"%len(allv))
    print("  最大值: 0x%X  最小值: 0x%X"%(max(allv),min(allv)))
    # 是否像递增序列
    inc=sum(1 for i in range(1,min(len(allv),2000)) if allv[i]>=allv[i-1])
    print("  前 2000 个中非递减数: %d"%inc)
    print()
