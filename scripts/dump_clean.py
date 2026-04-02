#!/usr/bin/env python3
"""Dump needed memory from a CLEAN process (no Frida) using fast /proc/pid/mem reads.

Usage: python3 scripts/dump_clean.py <PID>
"""
import subprocess, struct, sys, os

pid = int(sys.argv[1])

maps_raw = subprocess.check_output(
    ["adb", "shell", f"su 0 cat /proc/{pid}/maps"], timeout=10
).decode()

# Parse maps
modules = {}
tpidr = 0
main_tid = pid  # main thread TID = PID

for line in maps_raw.splitlines():
    parts = line.split()
    if len(parts) < 1: continue
    r = parts[0].split("-")
    start, end = int(r[0], 16), int(r[1], 16)
    perms = parts[1] if len(parts) > 1 else ""
    name = parts[5].strip() if len(parts) >= 6 else ""

    if name.startswith("/") and ".so" in name:
        if name not in modules:
            modules[name] = []
        modules[name].append((start, end, perms))

    # Main thread's TLS for TPIDR
    if f"stack_and_tls:{main_tid}" in name and "rw-" in perms:
        tpidr = end - 0x3580
        print(f"Main thread TLS: TPIDR_EL0 = 0x{tpidr:x}")

# Find SO
so_path = [p for p in modules if "libmetasec_ml" in p]
if not so_path:
    print("ERROR: libmetasec_ml.so not found"); sys.exit(1)
so_path = so_path[0]
so_base = min(s for s, e, p in modules[so_path])
print(f"SO: {so_path} base=0x{so_base:x}")

# Select modules to dump
needed = ["libmetasec_ml", "libc.so", "libc++.so", "libm.so", "libdl.so", "liblog.so"]
ranges_to_dump = []

for mod_name in modules:
    for need in needed:
        if need in mod_name:
            for s, e, p in sorted(modules[mod_name]):
                size = e - s
                if size > 20 * 1024 * 1024:
                    continue
                ranges_to_dump.append((s, size))
            total = sum(e-s for s,e,p in modules[mod_name] if e-s < 20*1024*1024)
            print(f"  {os.path.basename(mod_name)}: {total//1024}KB ({len(modules[mod_name])} ranges)")
            break

# Add main thread TLS (just 128KB around TPIDR)
if tpidr:
    tls_page = tpidr & ~0xFFF
    ranges_to_dump.append((tls_page, 0x10000))
    print(f"  Main thread TLS: 0x{tls_page:x} (64KB)")

print(f"\nTotal: {len(ranges_to_dump)} ranges, {sum(s for _,s in ranges_to_dump)//1024}KB")

# Fast read via base64 encoding (avoids binary corruption over adb shell)
def read_mem_fast(addr, size):
    """Read memory using dd + base64 to avoid adb binary issues."""
    try:
        # Use /proc/pid/mem with seek in bytes
        cmd = f"su 0 dd if=/proc/{pid}/mem bs=4096 skip={addr // 4096} count={(size + 4095) // 4096} 2>/dev/null | base64"
        result = subprocess.run(["adb", "shell", cmd], capture_output=True, timeout=30)
        if result.returncode == 0 and result.stdout:
            import base64
            data = base64.b64decode(result.stdout.strip())
            # Adjust for offset within page
            offset = addr % 4096
            return data[offset:offset + size]
    except Exception as e:
        pass

    # Fallback: read in smaller chunks
    try:
        cmd = f"su 0 cat /proc/{pid}/mem 2>/dev/null | dd bs=1 skip={addr} count={size} 2>/dev/null | base64"
        # This won't work well. Try hexdump approach
        pass
    except:
        pass

    return None

# Write memdump
out_path = "lib/memdump.bin"
with open(out_path, "wb") as f:
    f.write(struct.pack("<Q", so_base))
    f.write(struct.pack("<I", len(ranges_to_dump)))

    ok = 0
    fail = 0
    for i, (base, size) in enumerate(ranges_to_dump):
        f.write(struct.pack("<QQ", base, size))
        # Read in 256KB chunks (larger = faster)
        for off in range(0, size, 262144):
            sz = min(262144, size - off)
            d = read_mem_fast(base + off, sz)
            if d and len(d) == sz:
                f.write(d)
                ok += 1
            else:
                f.write(b"\x00" * sz)
                fail += 1
        if (i + 1) % 5 == 0:
            print(f"  Progress: {i+1}/{len(ranges_to_dump)}")

print(f"\nDone: {ok} chunks ok, {fail} failed")
print(f"Saved to {out_path} ({os.path.getsize(out_path)//1024}KB)")

# Save TPIDR
if tpidr:
    with open("lib/regs_only.txt", "w") as f:
        f.write(f"REG:tpidr_el0:0x{tpidr:x}\n")
    print(f"TPIDR saved")

# Clear frida ranges
with open("lib/frida_ranges.txt", "w") as f:
    pass
print("DONE")
