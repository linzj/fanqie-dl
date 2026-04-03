#!/usr/bin/env python3
"""Dump SO code + data segments from running process for VM emulator."""
import subprocess, struct, os

def adb_read(pid, addr, size):
    """Read memory via /proc/pid/mem."""
    cmd = f'python3 -c "import sys;f=open(\'/proc/{pid}/mem\',\'rb\');f.seek({addr});sys.stdout.buffer.write(f.read({size}))"'
    r = subprocess.run(["adb", "shell", cmd], capture_output=True, timeout=30)
    if len(r.stdout) == size:
        return r.stdout
    return None

def main():
    r = subprocess.run(["adb", "shell", "ps -A | grep com.dragon.read"], capture_output=True, text=True)
    pid = r.stdout.split()[1]
    print(f"PID={pid}")

    r = subprocess.run(["adb", "shell", f"cat /proc/{pid}/maps | grep libmetasec_ml"],
                       capture_output=True, text=True)
    lines = [l for l in r.stdout.strip().split('\n') if 'libmetasec_ml' in l]
    print(f"Found {len(lines)} mappings:")
    for l in lines:
        print(f"  {l.strip()}")

    # Parse mappings
    segments = []
    for line in lines:
        parts = line.split()
        addr_range = parts[0]
        perms = parts[1]
        file_off = int(parts[2], 16)
        start, end = [int(x, 16) for x in addr_range.split('-')]
        segments.append((start, end, perms, file_off))

    so_base = segments[0][0]
    print(f"\nSO base: 0x{so_base:x}")

    # Code segment: all r-x and rwx mappings
    code_start = None
    code_end = None
    for s, e, p, _ in segments:
        if 'x' in p:
            if code_start is None:
                code_start = s
            code_end = e

    code_size = code_end - code_start
    print(f"Code: 0x{code_start:x}-0x{code_end:x} ({code_size} bytes, {code_size//1024}KB)")

    # Data segments: r-- and rw- mappings
    data_segs = [(s, e, p) for s, e, p, _ in segments if 'x' not in p and p != '---p']

    outdir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lib')

    # Dump code
    print(f"\nDumping code segment ({code_size} bytes)...")
    code = adb_read(pid, code_start, code_size)
    if code and len(code) == code_size:
        path = os.path.join(outdir, 'so_code.bin')
        with open(path, 'wb') as f:
            f.write(code)
        print(f"  Wrote {path} ({len(code)} bytes)")
    else:
        print(f"  FAILED (got {len(code) if code else 0} bytes)")

    # Dump data segments
    for i, (s, e, p) in enumerate(data_segs):
        size = e - s
        off = s - so_base
        print(f"\nDumping data segment {i+1}: 0x{s:x}-0x{e:x} ({p}, {size} bytes, SO+0x{off:x})...")
        data = adb_read(pid, s, size)
        if data and len(data) == size:
            path = os.path.join(outdir, f'so_data{i+1}.bin')
            with open(path, 'wb') as f:
                f.write(data)
            print(f"  Wrote {path} ({len(data)} bytes)")
        else:
            print(f"  FAILED (got {len(data) if data else 0} bytes)")

    # Also dump BSS
    r2 = subprocess.run(["adb", "shell", f"cat /proc/{pid}/maps | grep anon:.bss"],
                        capture_output=True, text=True)
    for line in r2.stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        start, end = [int(x, 16) for x in parts[0].split('-')]
        size = end - start
        off = start - so_base
        print(f"\nDumping BSS: 0x{start:x}-0x{end:x} ({size} bytes, SO+0x{off:x})...")
        data = adb_read(pid, start, size)
        if data:
            path = os.path.join(outdir, 'so_bss.bin')
            with open(path, 'wb') as f:
                f.write(data)
            print(f"  Wrote {path} ({len(data)} bytes)")

    # Write metadata
    meta = f"""so_base=0x{so_base:x}
code_offset=0x{code_start - so_base:x}
code_size=0x{code_size:x}
"""
    for i, (s, e, p) in enumerate(data_segs):
        meta += f"data{i+1}_offset=0x{s - so_base:x}\ndata{i+1}_size=0x{e - s:x}\n"
    path = os.path.join(outdir, 'vm_meta.txt')
    with open(path, 'w') as f:
        f.write(meta)
    print(f"\nWrote {path}")
    print(meta)
    print("[*] DONE")

if __name__ == "__main__":
    main()
