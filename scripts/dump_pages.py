#!/usr/bin/env python3
"""Dump missing pages via /proc/pid/mem (no frida needed).
When a page belongs to a module, dump the whole module.

Usage: python3 dump_pages.py <PID> <missing_pages_file>
"""

import subprocess, struct, sys, os

pid = int(sys.argv[1])
pages_file = sys.argv[2]

pages = []
with open(pages_file) as f:
    for line in f:
        line = line.strip()
        if line:
            addr = int(line, 16)
            if 0x1000 <= addr <= 0x800000000000:
                pages.append(addr)

if not pages:
    print("No missing pages")
    sys.exit(0)

# Read /proc/pid/maps to find modules
maps = subprocess.check_output(
    ["adb", "shell", f"su 0 cat /proc/{pid}/maps"],
    timeout=5
).decode()

# Parse maps: find which module each page belongs to
page_modules = {}  # page -> module_path
module_ranges = {}  # module_path -> [(start, end)]

for line in maps.splitlines():
    parts = line.split()
    if len(parts) < 6:
        continue
    r = parts[0].split("-")
    start = int(r[0], 16)
    end = int(r[1], 16)
    path = parts[5] if len(parts) >= 6 else ""
    if path.startswith("/") and ".so" in path:
        if path not in module_ranges:
            module_ranges[path] = []
        module_ranges[path].append((start, end))
        for page in pages:
            if start <= page < end:
                page_modules[page] = path

# Read existing memdump to know what's already dumped
with open("lib/memdump.bin", "rb") as f:
    so_base = struct.unpack("<Q", f.read(8))[0]
    old_count = struct.unpack("<I", f.read(4))[0]
    existing = set()
    for _ in range(old_count):
        base = struct.unpack("<Q", f.read(8))[0]
        size = struct.unpack("<Q", f.read(8))[0]
        existing.add(base)
        f.seek(f.tell() + size)

# Collect ranges to dump: whole modules for module pages, single pages otherwise
new_ranges = []
dumped_modules = set()

for page in pages:
    if page in page_modules:
        mod = page_modules[page]
        if mod not in dumped_modules:
            dumped_modules.add(mod)
            mod_size = sum(e - s for s, e in module_ranges[mod])
            if mod_size > 10 * 1024 * 1024:
                # Too large — just dump the single page
                print(f"  SKIP {os.path.basename(mod)} ({mod_size//1024}KB too large), dumping page only")
                if page not in existing:
                    new_ranges.append((page, 0x1000))
                    existing.add(page)
                continue
            for start, end in module_ranges[mod]:
                if start not in existing:
                    new_ranges.append((start, end - start))
                    existing.add(start)
            print(f"  {os.path.basename(mod)}: {len(module_ranges[mod])} ranges ({mod_size//1024}KB)")
    else:
        if page not in existing:
            new_ranges.append((page, 0x1000))
            existing.add(page)

print(f"PID={pid}, {len(pages)} pages → {len(new_ranges)} new ranges ({len(dumped_modules)} modules)")

if not new_ranges:
    print("Nothing new to dump")
    sys.exit(0)

# Helper: read memory via adb /proc/pid/mem
def read_mem(addr, size):
    try:
        cmd = f"su 0 dd if=/proc/{pid}/mem bs=1 skip={addr} count={size} 2>/dev/null"
        result = subprocess.run(
            ["adb", "shell", cmd],
            capture_output=True, timeout=10
        )
        if len(result.stdout) == size:
            return result.stdout
    except:
        pass
    return None

# Update range count
new_count = old_count + len(new_ranges)
with open("lib/memdump.bin", "r+b") as f:
    f.seek(8)
    f.write(struct.pack("<I", new_count))

# Append new ranges
with open("lib/memdump.bin", "ab") as f:
    ok = 0
    fail = 0
    for base, size in new_ranges:
        f.write(struct.pack("<QQ", base, size))
        # Read in 64KB chunks
        for off in range(0, size, 65536):
            sz = min(65536, size - off)
            d = read_mem(base + off, sz)
            if d:
                f.write(d)
            else:
                f.write(b"\x00" * sz)
                fail += 1
        ok += 1

    total_kb = sum(s for _, s in new_ranges) // 1024
    print(f"Appended {len(new_ranges)} ranges ({total_kb}KB), {ok} ok, {fail} page fails")
    print(f"Total ranges now: {new_count}")

print("DONE")
