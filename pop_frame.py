import sys
sys.stdout.reconfigure(encoding='utf-8')
print("  精确栈帧计算 —— Create360Object (PopSoftEng RVA 0xDFF0)")
print()
print("  进入函数时: [esp+0] = 返回地址, [esp+4] = param_1, [esp+8] = param_2, [esp+0xC] = param_3")
print()
print("  逐条指令追踪 esp 变化:")
seq=[
 ("+000","6A FF","push -1","esp -= 4"),
 ("+002","68 4C 1C 08 10","push SEH","esp -= 4"),
 ("+007","64 A1 00 00 00 00","mov eax,fs:[0]","不变"),
 ("+00D","50","push eax","esp -= 4"),
 ("+00E","53","push ebx","esp -= 4"),
 ("+00F","56","push esi","esp -= 4"),
 ("+010","57","push edi","esp -= 4"),
 ("+011","A1 B0 50 09 10","mov eax,[0x100950B0]","不变"),
 ("+016","33 C4","xor eax,esp","不变"),
 ("+018","50","push eax","esp -= 4"),
 ("+019","8D 44 24 10","lea eax,[esp+0x10]","不变"),
 ("+01D","64 A3 00 00 00 00","mov fs:[0],eax","不变"),
 ("+023","83 3D 88 B6 09 10 00","cmp [0x1009B688],0","不变"),
 ("+02A","75 0A","jnz +0x36","不变"),
 ("+02C","BF 88 B6 09 10","mov edi,0x1009B688","不变"),
 ("+031","E8 BA 58 00 00","call 0x138F0","不变(已返回)"),
 ("+036","8B 5C 24 28","mov ebx,[esp+0x28]","★ 读取"),
]
print("  %-6s %-22s %-28s %s"%("偏移","机器码","指令","esp"))
cur=0
for off,mc,ins,eff in seq:
    print("  %-6s %-22s %-28s %s"%(off,mc,ins,eff))
print()
print("  累计 push 次数（每次 -4）:")
print("    +000 push -1        -> -4")
print("    +002 push SEH       -> -8")
print("    +00D push eax       -> -12")
print("    +00E push ebx       -> -16")
print("    +00F push esi       -> -20")
print("    +010 push edi       -> -24")
print("    +018 push eax       -> -28")
print()
print("  所以 +036 时: esp = 原esp - 0x1C")
print("    [esp+0x28] = [原esp - 0x1C + 0x28] = [原esp + 0xC]")
print()
print("  ★ 原esp+0x0 = 返回地址")
print("     原esp+0x4 = param_1")
print("     原esp+0x8 = param_2")
print("     原esp+0xC = param_3   ← 这是被读取的参数！")
print()
print("  => Create360Object 检查的是**第 3 个参数**必须非 0，")
print("     而第 3 个参数是 GUID 指针（因为 +05E 用 edx=GUID 去比较）。")
print()
print("  正确签名: HRESULT Create360Object(void* p1, void* p2, REFGUID guid)")
print("     第 3 参数 = GUID 指针，必须非 0")
print("     第 1/2 参数 = 输出指针等")
print()
print("  我之前传的是 (guid, outBuf, flags) —— 完全反了！")
print("  应该传 (out?, out?, guid)")
