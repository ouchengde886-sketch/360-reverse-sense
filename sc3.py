import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
b=open(os.path.join(d,'MIndex.dat'),'rb').read()
# 记录模式: [ptr][ptr][1][size][size2][0][float][dword][dword][0,0,0,0,0]
# @0x00: 10015fa5 10015fa0 1 bb 0 0 3f9e376b 1dd5cb3 ec19e19b 0 0 0 0 0 | 10015fa6 10015fa5 1 237 bb ...
# 从 0x00 到 0x38(56) 是 14 个 DWORD，然后 0x38 处是 10015fa6
# 但 @0x3C 是 10015fa5 -> 说明记录头是 10015fa6,10015fa5 在 0x38,0x3C
# 所以记录从 0x38 开始? 那 0x00-0x37 是文件头(56字节)
print("=== 假设文件头 56 字节，记录从 0x38 开始 ===")
rec=0x38
for i in range(4):
    o=rec+i*56
    if o+56>len(b): break
    vals=struct.unpack_from('<14I',b,o)
    print("  记录 %d @0x%06X: %s"%(i,o,[hex(v) for v in vals]))
print()
# 找所有 0x10015faX 系列（递增指针）
print("=== 搜索 0x10015fa0-0x10015faf 范围指针的出现位置 ===")
hits=[]
for o in range(0,min(len(b),2000),4):
    v=struct.unpack_from('<I',b,o)[0]
    if 0x10015fa0<=v<=0x10015faf:
        hits.append((o,hex(v)))
print("  前 20 个: %s"%hits[:20])
# 计算差值
if len(hits)>2:
    print("  相邻差: %s"%[hits[i+1][0]-hits[i][0] for i in range(min(len(hits)-1,15))])
