#!/usr/bin/env python3
"""
dump_full_memory.py — 全量 dump 进程内存（所有可读区域）

用法:
  python3 scripts/dump_full_memory.py [PID]

如果不提供 PID，自动查找 com.dragon.read 进程。

输出:
  lib/full_dump/maps.txt          — 原始 /proc/pid/maps
  lib/full_dump/regions/           — 每个区域一个 .bin 文件
  lib/full_dump/manifest.txt       — 索引文件（供 emulator 加载）

加载方式:
  读 manifest.txt，每行格式: start_hex end_hex perms filename
  按顺序 mem_map + mem_write 即可重建地址空间
"""

import subprocess
import sys
import os
import base64
import time

# === Config ===
MAX_REGION_SIZE = 256 * 1024 * 1024  # 跳过 >256MB 的区域
CHUNK_SIZE = 1024 * 1024             # 1MB 分块读取
ADB_TIMEOUT = 60                     # 单次 adb 超时秒数

def run_adb(cmd, timeout=ADB_TIMEOUT):
    """Run adb shell command, return stdout bytes."""
    r = subprocess.run(
        ["adb", "shell", cmd],
        capture_output=True, timeout=timeout
    )
    return r.stdout

def get_pid():
    """Find PID of com.dragon.read."""
    r = subprocess.run(
        ["adb", "shell", "ps -A | grep com.dragon.read"],
        capture_output=True, text=True, timeout=10
    )
    for line in r.stdout.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 2 and "com.dragon.read" in line:
            return int(parts[1])
    return None

def read_mem(pid, addr, size):
    """Read process memory via /proc/pid/mem + base64.
    Returns bytes or None on failure.
    """
    page_start = addr & ~0xFFF
    page_offset = addr - page_start
    page_count = (page_offset + size + 4095) // 4096

    cmd = (
        f"dd if=/proc/{pid}/mem bs=4096 "
        f"skip={page_start // 4096} count={page_count} "
        f"2>/dev/null | base64"
    )
    try:
        raw = run_adb(cmd, timeout=ADB_TIMEOUT)
        if not raw or not raw.strip():
            return None
        data = base64.b64decode(raw.strip())
        result = data[page_offset:page_offset + size]
        if len(result) == size:
            return result
        # Partial read — pad with zeros
        if len(result) > 0:
            return result + b"\x00" * (size - len(result))
        return None
    except Exception as e:
        return None

def read_mem_chunked(pid, addr, size, label=""):
    """Read large regions in chunks, with progress."""
    result = bytearray()
    total_chunks = (size + CHUNK_SIZE - 1) // CHUNK_SIZE
    ok_chunks = 0
    fail_chunks = 0

    for i in range(total_chunks):
        off = i * CHUNK_SIZE
        chunk_size = min(CHUNK_SIZE, size - off)
        chunk_addr = addr + off

        data = read_mem(pid, chunk_addr, chunk_size)
        if data:
            result.extend(data)
            ok_chunks += 1
        else:
            result.extend(b"\x00" * chunk_size)
            fail_chunks += 1

        # Progress for large regions
        if total_chunks > 5 and (i + 1) % 5 == 0:
            pct = (i + 1) * 100 // total_chunks
            print(f"    {label} {pct}% ({i+1}/{total_chunks} chunks, {fail_chunks} failed)")

    return bytes(result), ok_chunks, fail_chunks

def main():
    # Get PID
    if len(sys.argv) > 1:
        pid = int(sys.argv[1])
    else:
        pid = get_pid()
        if not pid:
            print("ERROR: com.dragon.read not found. Pass PID manually.")
            sys.exit(1)

    print(f"[*] PID: {pid}")

    # Read maps
    maps_raw = run_adb(f"cat /proc/{pid}/maps", timeout=10).decode("utf-8", errors="replace")
    if not maps_raw.strip():
        print("ERROR: Cannot read /proc/pid/maps")
        sys.exit(1)

    # Output directory
    outdir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib", "full_dump")
    regdir = os.path.join(outdir, "regions")
    os.makedirs(regdir, exist_ok=True)

    # Save maps
    maps_path = os.path.join(outdir, "maps.txt")
    with open(maps_path, "w") as f:
        f.write(maps_raw)
    print(f"[*] Saved maps to {maps_path}")

    # Parse maps
    regions = []
    for line in maps_raw.strip().split("\n"):
        parts = line.split()
        if len(parts) < 2:
            continue
        addr_range = parts[0]
        perms = parts[1]
        offset = parts[2] if len(parts) > 2 else "0"
        name = " ".join(parts[5:]) if len(parts) >= 6 else ""

        start_s, end_s = addr_range.split("-")
        start = int(start_s, 16)
        end = int(end_s, 16)
        size = end - start

        regions.append({
            "start": start,
            "end": end,
            "size": size,
            "perms": perms,
            "offset": offset,
            "name": name,
            "line": line.strip(),
        })

    print(f"[*] Total regions: {len(regions)}")

    # Filter: only regions with at least 'r' permission
    # Skip ---p (no permission), and regions that are too large
    readable = []
    skipped_noperm = 0
    skipped_large = 0
    skipped_special = 0

    for r in regions:
        perms = r["perms"]
        name = r["name"]

        # Skip no-permission regions
        if perms == "---p" or perms == "---s":
            skipped_noperm += 1
            continue

        # Must have read permission to dump
        if "r" not in perms:
            skipped_noperm += 1
            continue

        # Skip [vvar] — kernel virtual, can't read via /proc/pid/mem
        if name == "[vvar]":
            skipped_special += 1
            continue

        # Skip extremely large regions
        if r["size"] > MAX_REGION_SIZE:
            print(f"  SKIP (too large): {r['line']} ({r['size'] // (1024*1024)}MB)")
            skipped_large += 1
            continue

        readable.append(r)

    total_size = sum(r["size"] for r in readable)
    print(f"[*] Readable regions: {len(readable)} ({total_size // (1024*1024)}MB)")
    print(f"    Skipped: {skipped_noperm} no-perm, {skipped_large} too-large, {skipped_special} special")

    # Dump each region
    manifest_lines = []
    total_ok = 0
    total_fail = 0
    t0 = time.time()

    for i, r in enumerate(readable):
        start = r["start"]
        end = r["end"]
        size = r["size"]
        perms = r["perms"]
        name = r["name"]

        filename = f"{start:016x}_{end:016x}_{perms.replace('-', '_')}.bin"
        filepath = os.path.join(regdir, filename)

        short_name = os.path.basename(name) if name else "(anon)"
        label = f"[{i+1}/{len(readable)}] 0x{start:x}-0x{end:x} {perms} {short_name} ({size//1024}KB)"

        # Read memory
        if size <= CHUNK_SIZE:
            data = read_mem(pid, start, size)
            if data:
                ok, fail = 1, 0
            else:
                data = b"\x00" * size
                ok, fail = 0, 1
        else:
            data, ok, fail = read_mem_chunked(pid, start, size, label=short_name)

        total_ok += ok
        total_fail += fail

        # Check if all zeros
        is_zero = (data == b"\x00" * size)

        # Save
        with open(filepath, "wb") as f:
            f.write(data)

        status = "ZERO" if is_zero else ("OK" if fail == 0 else f"PARTIAL({fail} failed)")
        print(f"  {label} -> {status}")

        # Manifest entry
        manifest_lines.append(
            f"{start:016x} {end:016x} {perms} {r['offset']} {filename} {name}"
        )

    elapsed = time.time() - t0

    # Save manifest
    manifest_path = os.path.join(outdir, "manifest.txt")
    with open(manifest_path, "w") as f:
        f.write(f"# PID={pid} dumped at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Format: start_hex end_hex perms file_offset filename path\n")
        f.write(f"# Total: {len(readable)} regions, {total_size} bytes\n")
        for line in manifest_lines:
            f.write(line + "\n")

    print(f"\n[*] Done in {elapsed:.1f}s")
    print(f"    Chunks: {total_ok} ok, {total_fail} failed")
    print(f"    Output: {outdir}")
    print(f"    Total size: {total_size // (1024*1024)}MB")

    # Summary of key regions
    print("\n[*] Key regions:")
    so_base = None
    for r in readable:
        name = r["name"]
        if "libmetasec_ml" in name and "x" in r["perms"]:
            if so_base is None:
                so_base = r["start"]
                print(f"    SO base: 0x{so_base:x}")
        if "stack_and_tls" in name and "rw" in r["perms"]:
            tpidr = r["end"] - 0x3580
            print(f"    TPIDR_EL0: 0x{tpidr:x} (from {name})")

    # Find heap regions
    heap_total = sum(r["size"] for r in readable if r["name"] == "[heap]" or (r["name"] == "" and "rw" in r["perms"]))
    print(f"    Heap/anon rw: {heap_total // 1024}KB")

    if so_base:
        meta_path = os.path.join(outdir, "so_meta.txt")
        with open(meta_path, "w") as f:
            f.write(f"so_base=0x{so_base:x}\n")
            f.write(f"pid={pid}\n")
        print(f"    Saved SO metadata to {meta_path}")

if __name__ == "__main__":
    main()
