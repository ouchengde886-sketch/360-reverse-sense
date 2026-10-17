import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
# 用全部记录的数据做搜索
allseg=b''.join(a[offs[i]:offs[i+1]] for i in range(60) if offs[i+1]<=len(a))
print("  总样本 %d 字节"%len(allseg))
v=bytes(b&0x7F for b in allseg)
print()
# ★ 决定性判据: 搜索 'hi.MID:' 'hi.AVE:' 等已知明文
kws=[b'hi.MID:',b'hi.AVE:',b'<ext>',b'CDATA',b'360',b'.exe',b'.dll',b'C:\\',b'D:\\']
print("=== 对 128 个密钥搜索已知明文 ===")
for K in range(128):
    o=bytes(x^K for x in v)
    hits=[]
    for kw in kws:
        if kw in o: hits.append(kw.decode())
    if hits:
        print("  ^0x%02X 命中: %s"%(K,hits))
print()
# 也试不做 XOR 的 >>1 输出
o2=bytes(b>>1 for b in allseg)
print("=== >>1 输出中搜索 ===")
for kw in kws:
    if kw in o2: print("  命中 %r"%kw)
print()
# ★ 换思路: 也许不是 XOR 而是**加法**
print("=== 对 128 个加法密钥搜索 ===")
for K in range(128):
    o=bytes((x+K)&0x7F for x in v)
    hits=[kw.decode() for kw in kws if kw in o]
    if hits: print("  +0x%02X 命中: %s"%(K,hits))
print()
print("=== 对 128 个减法密钥搜索 ===")
for K in range(128):
    o=bytes((x-K)&0x7F for x in v)
    hits=[kw.decode() for kw in kws if kw in o]
    if hits: print("  -0x%02X 命中: %s"%(K,hits))
