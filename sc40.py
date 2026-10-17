import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
seg=a[offs[0]:offs[1]]
# ★★★ 重大结构发现: 76 字节周期 = 27 字节变量字段 + 49 字节常量模板
# 块0[27:76] == 块1[27:76] == 块2[27:76] (49 字节完全相同)
print("=== 验证 49 字节模板在三个块中是否相同 ===")
b0=seg[0:76]; b1=seg[76:152]; b2=seg[152:187]
t0=b0[27:76]
print("  块0[27:76]: %s"%t0.hex(' '))
print("  块1[27:76]: %s"%b1[27:76].hex(' '))
print("  块2[27:49]: %s"%b2[27:49].hex(' '))
print("  块0==块1 模板: %s"%(t0==b1[27:76]))
print("  块0模板前22字节==块2: %s"%(t0[:22]==b2[27:49]))
print()
# 那么记录 #0 = 头部? 还是 3 条记录?
# 187 字节 / 76 = 2.46，不是整数
# 但 27 + 76 + 76 = 179，剩 8 字节
print("  187 = 27 + 76 + 76 + 8? %s"%(27+76+76+8==187))
print()
# ★ 关键: 27 字节变量字段里有什么？比较块0和块1的变量字段
print("=== 变量字段对比 ===")
print("  块0[0:27]: %s"%b0[0:27].hex(' '))
print("  块1[0:27]: %s"%b1[0:27].hex(' '))
print("  块2[0:27]: %s"%b2[0:27].hex(' '))
print()
# 观察: 块1和块2的[0:27]是否相同?
print("  块1[0:27]==块2[0:27]: %s"%(b1[0:27]==b2[0:27]))
print()
# 前 8 字节可能是长度/类型，后面是数据
print("=== 记录 #0 前 8 字节 ===")
print("  %s"%seg[0:8].hex(' '))
# 检查其他记录的前 8 字节
print()
print("=== 其他记录的前 8 字节 ===")
for i in range(1,8):
    s=offs[i]
    print("  记录 #%d: %s"%(i,a[s:s+8].hex(' ')))
