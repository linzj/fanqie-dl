#!/usr/bin/env python3
"""Parse handle dump from get_handle.js output and save as binary.

Usage: python3 scripts/parse_handle_dump.py /tmp/handle_dump.txt
Outputs: lib/handle_dump.bin (format: handle_addr(u64) + data_len(u32) + data)
"""
import struct, sys, re

if len(sys.argv) < 2:
    print("Usage: python3 scripts/parse_handle_dump.py <dump_file>")
    sys.exit(1)

with open(sys.argv[1]) as f:
    lines = f.readlines()

handle_addr = 0
handle_data = bytearray()
so_base = 0
pointers = []
extra_items = []

in_dump = False
for line in lines:
    line = line.strip()
    if line.startswith('HANDLE:'):
        val = line.split(':')[1].strip()
        # Parse as decimal (e.g., "533306798416 (0x7c2b8ff150)")
        num_str = val.split(' ')[0].split('(')[0].strip()
        try:
            parsed = int(num_str)
        except:
            parsed = 0
        if parsed != 0 and handle_addr == 0:
            handle_addr = parsed
            print(f"Handle: {handle_addr} (0x{handle_addr:x})")
    elif line.startswith('SO_BASE:'):
        so_base = int(line.split(':')[1].strip(), 16)
        print(f"SO base: 0x{so_base:x}")
    elif line == 'HANDLE_DUMP_START':
        in_dump = True
        handle_data = bytearray()
    elif line == 'HANDLE_DUMP_END':
        in_dump = False
    elif in_dump and line.startswith('HD:'):
        # Format: HD:0000:hexhexhex...
        parts = line.split(':')
        offset = int(parts[1], 16)
        hex_data = parts[2]
        handle_data.extend(bytes.fromhex(hex_data))
    elif line.startswith('PTR:'):
        pointers.append(line)
    elif line.startswith('EXTRA['):
        extra_items.append(line)
    elif line.startswith('TAG:'):
        print(f"  {line}")
    elif line.startswith('TYPE:'):
        print(f"  {line}")
    elif line.startswith('URL:'):
        print(f"  {line}")

if handle_addr == 0:
    print("ERROR: No handle found in dump")
    sys.exit(1)

print(f"\nHandle data: {len(handle_data)} bytes")
print(f"Pointers found: {len(pointers)}")
for p in pointers[:20]:
    print(f"  {p}")
print(f"Extra items: {len(extra_items)}")
for e in extra_items[:10]:
    print(f"  {e}")

# Save binary
out_path = "lib/handle_dump.bin"
with open(out_path, "wb") as f:
    f.write(struct.pack("<Q", handle_addr))
    f.write(struct.pack("<I", len(handle_data)))
    f.write(handle_data)

print(f"\nSaved to {out_path}")
print(f"  handle_addr=0x{handle_addr:x}")
print(f"  data_size={len(handle_data)}")

# Show first 256 bytes as hex dump
print("\nFirst 256 bytes:")
for off in range(0, min(256, len(handle_data)), 16):
    hex_str = ' '.join(f'{handle_data[off+j]:02x}' for j in range(min(16, len(handle_data)-off)))
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in handle_data[off:off+16])
    print(f"  {off:04x}: {hex_str:<48s} {ascii_str}")
