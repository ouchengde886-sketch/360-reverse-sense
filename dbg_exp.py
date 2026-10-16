import struct, sys
sys.stdout.reconfigure(encoding="utf-8")

p = r"C:\Users\Administrator\Desktop\360Safe\safemon\SelfProtectAPI2.dll"
d = open(p, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
opt_size = struct.unpack_from("<H", d, pe + 20)[0]
opt_off = pe + 24
dd = opt_off + 0x60
exp_rva, exp_size = struct.unpack_from("<II", d, dd)
print("exp_rva", hex(exp_rva), "size", hex(exp_size))

sec_off = pe + 24 + opt_size
nsec = struct.unpack_from("<H", d, pe + 6)[0]
secs = []
for i in range(nsec):
    o = sec_off + i * 40
    name = d[o:o + 8].rstrip(b"\0").decode("latin1")
    vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", d, o + 8)
    secs.append((name, vaddr, vsize, raddr, rsize))
    print("  sec %-8s vaddr=%08x vsize=%08x raw=%08x rsize=%08x" % (name, vaddr, vsize, raddr, rsize))


def r2o(rva):
    for n, va, vs, ra, rs in secs:
        if rs and va <= rva < va + rs:
            return ra + (rva - va)
    return None


off = r2o(exp_rva)
print("exp off", hex(off) if off else None)
vals = struct.unpack_from("<IIIIIIIIIII", d, off)
print("Characteristics=%08x TimeDateStamp=%08x Major=%d Minor=%d" % vals[:4])
print("Name rva=%08x Base=%d NumberOfFunctions=%d NumberOfNames=%d" % (vals[4], vals[5], vals[6], vals[7]))
print("AddressOfFunctions=%08x AddressOfNames=%08x AddressOfNameOrdinals=%08x" % (vals[8], vals[9], vals[10]))

no = r2o(vals[4])
print("dll name:", repr(d[no:d.find(b"\0", no)]))

ao = r2o(vals[9])
print("aname off", hex(ao) if ao else None)
for i in range(min(vals[7], 10)):
    nr = struct.unpack_from("<I", d, ao + i * 4)[0]
    n2 = r2o(nr)
    val = d[n2:d.find(b"\0", n2)] if n2 else None
    print("  name[%d] rva=%08x -> %r" % (i, nr, val))