import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
seg=a[offs[1]:offs[2]]
# 关键：若这是 6-bit 打包的**文本**，则相邻字节的 6bit 值应能拼出 8bit ASCII
# 但前面测试失败。换个思路：也许每个字节的 6bit 是**独立字符索引**，
# 指向一个 64 字符的字母表。字母表可能是标准顺序的某段。
# 
# 观察: >>1 输出中字符范围 0x40-0x7F。若直接减去 0x40 得到 0-63 索引。
# 那么明文 = ALPHABET[idx]。
# 测试: 若 ALPHABET 是 'A-Za-z0-9+/' (base64)，结果已知不可读。
# 若 ALPHABET 是 '0-9A-Za-z+/'，或 'A-Za-z0-9._'，等等。
# 
# 更系统: 用**已知明文**反推。appd.dll 里有 'hi.MID:' 和 'hi.AVE:'
# 若记录里含 'hi.MID:'，则明文中该串的字符索引应连续出现。
# 但我们不知道明文在哪里。
#
# ★ 新思路: 检查 >>1 输出中是否有**重复的子串**（对应明文重复）
out=bytes(b>>1 for b in seg)
print("=== 查找 >>1 输出中的重复子串（长度>=8）===")
seen={}
for L in [8,10,12,16]:
    found=[]
    for i in range(len(out)-L):
        s=out[i:i+L]
        if s in seen and seen[s]!=i:
            found.append((seen[s],i,s))
        seen[s]=i
    seen={}
    print("  长度 %d: %d 处重复"%(L,len(found)))
    for a1,b1,s in found[:3]:
        print("     @%d 和 @%d: %r"%(a1,b1,s))
print()
# 记录 #0 里也有重复（前面看到 'uLBNb_U\\iPOKo_AEk\\LEuFCDyVALuOLLmRLOu' 出现两次）
seg0=a[offs[0]:offs[1]]
out0=bytes(b>>1 for b in seg0)
print("=== 记录 #0 >>1 输出（找重复）===")
print("  %r"%out0[:180])
# 找重复
for L in [16,20,24]:
    for i in range(len(out0)-L):
        s=out0[i:i+L]
        j=out0.find(s,i+1)
        if j>0:
            print("  长度 %d 重复: @%d 和 @%d  %r"%(L,i,j,s))
            break
