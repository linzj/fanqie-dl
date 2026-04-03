#!/usr/bin/env python3
"""Parse handle dump from Frida hook output into binary file for emulator.

Reads HANDLE=0xADDR:HEXDATA lines and creates a page-mapped binary.

Usage: python3 scripts/parse_handle_dump.py handle_dump.txt
Output: lib/handle_regions.bin

Binary format:
  Header: "HNDL" (4B) + handle_addr (8B) + so_base (8B) + tpidr (8B) + num_pages (4B)
  Per page: page_addr (8B) + data (4096B)
"""
import sys, struct, re, os

if len(sys.argv) < 2:
    print("Usage: python3 scripts/parse_handle_dump.py <dump_file>")
    sys.exit(1)

with open(sys.argv[1]) as f:
    lines = f.readlines()

so_base = 0
handle_addr = 0
tpidr = 0
sign_tid = 0

regions = {}  # addr -> bytes

for line in lines:
    line = line.strip()

    if line.startswith("SO_BASE="):
        so_base = int(line.split("=")[1], 16)
    elif line.startswith("HANDLE_ADDR="):
        handle_addr = int(line.split("=")[1], 16)
    elif line.startswith("TPIDR="):
        tpidr = int(line.split("=")[1], 16)
    elif line.startswith("SIGN_TID="):
        sign_tid = int(line.split("=")[1])

    # Parse HANDLE...=0xADDR:HEXDATA lines
    m = re.match(r'^(?:HANDLE|ENTRY)[^=]*=0x([0-9a-fA-F]+):(.+)$', line)
    if m:
        addr = int(m.group(1), 16)
        rest = m.group(2).strip()
        if rest in ("UNREADABLE", "NULL"):
            continue
        if all(c in '0123456789abcdefABCDEF' for c in rest):
            data = bytes.fromhex(rest)
            if addr not in regions or len(data) > len(regions[addr]):
                regions[addr] = data

print(f"Parsed: so_base=0x{so_base:x}, handle=0x{handle_addr:x}, tpidr=0x{tpidr:x}, tid={sign_tid}")
print(f"Regions: {len(regions)}, total {sum(len(d) for d in regions.values())} bytes")

# Merge into pages
pages = {}
for addr, data in regions.items():
    for off in range(len(data)):
        byte_addr = addr + off
        page = byte_addr & ~0xFFF
        page_off = byte_addr & 0xFFF
        if page not in pages:
            pages[page] = bytearray(0x1000)
        pages[page][page_off] = data[off]

print(f"Pages: {len(pages)} ({len(pages)*4}KB)")

# Write binary
os.makedirs("lib", exist_ok=True)
out_path = "lib/handle_regions.bin"
with open(out_path, "wb") as f:
    f.write(b'HNDL')
    f.write(struct.pack('<QQQ', handle_addr, so_base, tpidr))
    f.write(struct.pack('<I', len(pages)))
    for pa in sorted(pages.keys()):
        f.write(struct.pack('<Q', pa))
        f.write(bytes(pages[pa]))

size = os.path.getsize(out_path)
print(f"Saved: {out_path} ({size//1024}KB)")
