import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
seg0=a[offs[0]:offs[1]]
out0=bytes(b>>1 for b in seg0)
print("=== 记录 #0 长度 %d，>>1 输出 ==="%len(seg0))
print("  %r"%out0)
print()
# 找所有重复块的边界
i=27; j=103
print("  重复块起始: @%d 和 @%d，间隔 %d"%(i,j,j-i))
# 找该重复块的实际长度
L=0
while j+L<len(out0) and out0[i+L]==out0[j+L]: L+=1
print("  重复块长度: %d"%L)
print("  块内容: %r"%out0[i:i+L])
print()
# 检查是否还有下一个重复（周期性）
print("=== 检查周期性（间隔 %d）==="%(j-i))
period=j-i
matches=0
for k in range(len(out0)-period):
    if out0[k]==out0[k+period]: matches+=1
print("  匹配率: %d/%d = %.1f%%"%(matches,len(out0)-period,100*matches/(len(out0)-period)))
print()
# 若周期性成立，则这是**固定长度记录**
print("=== 按周期 %d 切分 ==="%period)
for k in range(0,min(len(out0),period*3),period):
    print("  [%3d] %r"%(k,out0[k:k+period]))
