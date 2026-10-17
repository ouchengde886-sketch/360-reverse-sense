import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
# 找所有 'D:' 出现
print("=== 'D:' 出现位置 ===")
st=0
while True:
    i=a.find(b'D:',st)
    if i<0: break
    # 找属于哪条记录
    rec=None
    for k in range(60):
        if offs[k]<=i<offs[k+1]: rec=k; break
    print("  @0x%06X 记录 #%s +%s"%(i,rec,(i-offs[rec]) if rec is not None else '?'))
    print("     上下文: %r"%a[max(0,i-40):i+40])
    st=i+1
print()
# 统计所有可打印 ASCII 的聚集区（可能暴露未加密区域）
print("=== 可打印 ASCII 聚集区（长度>=6）===")
runs=[]
i=0
while i<len(a):
    if 32<=a[i]<127:
        j=i
        while j<len(a) and 32<=a[j]<127: j+=1
        if j-i>=6: runs.append((i,j,a[i:j]))
        i=j
    else: i+=1
print("  找到 %d 处"%len(runs))
for s,e,r in runs[:20]:
    rec=None
    for k in range(60):
        if offs[k]<=s<offs[k+1]: rec=k; break
    print("  @0x%06X len=%d 记录#%s: %r"%(s,e-s,rec,r))
