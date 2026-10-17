import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\deepscan.dll'
d=open(p,'rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+optsz
secs=[]
for i in range(nsec):
    vs,va,rs,ra=struct.unpack_from('<IIII',d,so+i*40+8)
    secs.append((va,vs,ra,rs))
def r2o(r):
    for va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
o=r2o(0x3FEE4)
b=d[o:o+0x500]
print("  +0x130 - +0x160 (param_7 作为 ecx 使用的地方):")
for i in range(0x130,0x160,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
print()
print("  手工解码:")
print("    +130: 8B C3            mov eax,ebx")
print("    +132: E8 68 19 12 00   call 0x16189F   (SEH 清理)")
print("    +137: C2 18 00         ret 0x18        ★ 6 个栈参数")
print()
print("    +13A: 55 8B EC         push ebp; mov ebp,esp   <- 新函数开始!")
print("    +13D: 51 51            push ecx; push ecx")
print("    +13F: 8B 45 18         mov eax,[ebp+0x18]")
print("    +142: 8B 4D 1C         mov ecx,[ebp+0x1C]")
print("    +145: 85 C0            test eax,eax")
print("    +147: 74 25            jz +0x16E")
print("    +149: 83 F9 04         cmp ecx,4")
print("    +14C: 76 20            jbe +0x16E")
print("    +14E: 81 38 6C 72 79 79  cmp dword[eax],'lryy'")
print("    +154: 75 18            jnz +0x16E")
print()
print("  ★ 重要：+0x13A 是**另一个函数**（ScanAveMemoryWithCode 的导出入口）!")
print("     0x3FEE4 + 0x13A = 0x4001E —— 正是 ScanAveMemoryWithCode 的 RVA!")
print()
print("  所以 0x3FEE4 处的内部实现到 +0x137 ret 0x18 就结束了。")
print("  它只有 6 个参数，ret 0x18。")
print()
print("  重新理解 ScanAveMemoryWithCode (0x4001E):")
print("    param_6 = [ebp+0x18]  必须指向 'lryy' 结构")
print("    param_7 = [ebp+0x1C]  必须 > 4（是长度！）")
print()
print("  => 我把 param_6/param_7 搞反了！")
print("     param_6 才是 'lryy' 魔数指针")
print("     param_7 是长度（必须 > 4）")
print()
print("  正确调用:")
print("    ScanAveMemoryWithCode(p2, p3, p4, p5, magicPtr, magicLen)")
print("    其中 magicPtr 指向 'lryy' 开头的结构，magicLen > 4")
print()
print("  我之前 form=1 传的是 (data,size,path,p6,magic,16)")
print("  即 param_6=p6(0x18开头), param_7=magic(0x7979726C)")
print("  但 param_7 被当作**长度**用 cmp ecx,4 —— 0x7979726C > 4 通过")
print("  而 param_6=p6 被当作魔数指针 cmp [eax],'lryy' —— 0x18 != 'lryy' 失败!")
print()
print("  => 应该传 param_6=magicPtr, param_7=16")
