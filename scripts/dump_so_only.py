#!/usr/bin/env python3
"""Dump SO + stack via /proc/pid/mem (no frida). Fast."""

import subprocess, struct, sys

pid = int(sys.argv[1])

# Read SP from saved regs
sp = None
with open("lib/regs_only.txt") as rf:
    for line in rf:
        if line.startswith("REG:sp:"):
            sp = int(line.strip().split(":")[2], 16)
assert sp, "SP not found"

# Parse /proc/pid/maps for SO and stack
maps = subprocess.check_output(
    ["adb", "shell", f"su 0 cat /proc/{pid}/maps"], timeout=5
).decode()

so_ranges = []
so_base = None
for line in maps.splitlines():
    if "libmetasec_ml.so" in line:
        parts = line.split()
        r = parts[0].split("-")
        start, end = int(r[0], 16), int(r[1], 16)
        so_ranges.append((start, end - start))
        if so_base is None:
            so_base = start

assert so_base, "SO not found in maps"
print(f"SO_BASE=0x{so_base:x}, {len(so_ranges)} ranges")

# Stack: 128KB around SP
stack_base = (sp - 0x4000) & ~0xFFF
stack_size = 0x20000
all_ranges = so_ranges + [(stack_base, stack_size)]

def read_mem(addr, size):
    cmd = f"su 0 dd if=/proc/{pid}/mem bs=4096 skip={addr // 4096} count={size // 4096} 2>/dev/null"
    r = subprocess.run(["adb", "shell", cmd], capture_output=True, timeout=10)
    return r.stdout if len(r.stdout) == size else None

with open("lib/memdump.bin", "wb") as f:
    f.write(struct.pack("<Q", so_base))
    f.write(struct.pack("<I", len(all_ranges)))
    for base, size in all_ranges:
        f.write(struct.pack("<QQ", base, size))
        # Page-align reads
        aligned_base = base & ~0xFFF
        aligned_size = ((base + size + 0xFFF) & ~0xFFF) - aligned_base
        d = read_mem(aligned_base, aligned_size)
        if d:
            offset = base - aligned_base
            f.write(d[offset:offset + size])
            print(f"  0x{base:x} +0x{size:x} ok")
        else:
            f.write(b"\x00" * size)
            print(f"  0x{base:x} +0x{size:x} FAILED")

print(f"Dumped {sum(s for _,s in all_ranges) // 1024}KB in {len(all_ranges)} ranges")
