import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
b=open(os.path.join(d,'MIndex.dat'),'rb').read()
print("=== MIndex.dat 结构分析 (%d 字节) ==="%len(b))
# 观察到的模式: 10015fa5, 10015fa0, 1, 0xbb, 0,0, 3f9e376b, 1dd5cb3, ec19e19b, 0,0,0,0,0
# 尝试按固定步长解析。先找第一个 0x10015fa5 之后的下一个
pat=struct.pack('<I',0x10015fa5)
offs=[]
st=0
while True:
    i=b.find(pat,st)
    if i<0: break
    offs.append(i); st=i+1
print("  0x10015fa5 出现次数: %d"%len(offs))
print("  前 10 个偏移: %s"%[hex(o) for o in offs[:10]])
if len(offs)>2:
    diffs=[offs[i+1]-offs[i] for i in range(min(len(offs)-1,10))]
    print("  相邻偏移差: %s"%diffs)
print()
# 看 0x10015fa5 处的记录内容
for o in offs[:3]:
    n=min(80,len(b)-o)
    vals=struct.unpack_from('<%dI'%(n//4),b,o)
    print("  @0x%06X: %s"%(o,[hex(v) for v in vals[:20]]))
