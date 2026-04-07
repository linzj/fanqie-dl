#!/usr/bin/env python3
"""
dump_full_memory.py — 全量 dump 进程内存（所有可读区域）

用法:
  python3 scripts/dump_full_memory.py [PID]

如果不提供 PID，自动查找 com.dragon.read 进程。

输出:
  lib/full_dump/maps.txt          — 原始 /proc/pid/maps
  lib/full_dump/regions/<addr>.bin — 每个区域一个文件
  lib/full_dump/manifest.txt       — 索引（增量写入，crash 也安全）
  lib/full_dump/so_meta.txt        — so_base, tpidr_main
  lib/full_dump/failed.txt         — 读失败的区域列表

特性：
  - 使用 `adb exec-out su 0 sh -c "dd ..."` 直接拉二进制（无 base64 开销）
  - 增量写 manifest：每 dump 完一个区域立刻 append+flush，crash 不会丢
  - Resume：跳过已存在且大小匹配的 .bin 文件
  - 完整 TPIDR 检测：从主线程的 [anon:stack_and_tls:PID] rw 区计算
  - Ctrl-C 安全：捕获 KeyboardInterrupt 写最终总结

加载方式（emulator）:
  解析 manifest.txt，每行格式: start_hex end_hex perms file_offset filename name
"""

import base64
import os
import signal
import subprocess
import sys
import time

# === Config ===
MAX_REGION_SIZE = 256 * 1024 * 1024     # 跳过 >256MB 的区域
CHUNK_SIZE      = 4 * 1024 * 1024       # 4MB 分块（exec-out 二进制安全，可以更大）
ADB_TIMEOUT     = 30                    # 单次 adb dd 超时秒数

# Globals so signal handler can flush
MANIFEST_FH   = None
FAILED_FH     = None
DUMPED_OK     = 0
DUMPED_FAIL   = 0
DUMPED_RESUME = 0
START_TIME    = 0.0


def log(msg, *, err=False):
    """Print with flush, to stdout or stderr."""
    fh = sys.stderr if err else sys.stdout
    print(msg, file=fh, flush=True)


def run_text(args, timeout=ADB_TIMEOUT):
    """Run adb (or other) command, return stdout as text. None on failure."""
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
        return r.stdout.decode("utf-8", errors="replace")
    except Exception as e:
        log(f"  ! run_text({args[:3]}…) failed: {e}", err=True)
        return None


def adb_shell_text(cmd, timeout=ADB_TIMEOUT):
    """`adb shell` with text capture (used for maps, ps, etc.)."""
    return run_text(["adb", "shell", cmd], timeout=timeout)


def adb_exec_bin(cmd, timeout=ADB_TIMEOUT):
    """`adb exec-out` with binary capture (used for /proc/pid/mem dd output).

    `exec-out` is binary-safe — no PTY, no LF translation. Returns bytes or None.
    """
    try:
        r = subprocess.run(
            ["adb", "exec-out", cmd],
            capture_output=True,
            timeout=timeout,
        )
        return r.stdout
    except subprocess.TimeoutExpired:
        log(f"  ! TIMEOUT after {timeout}s: {cmd[:80]}…", err=True)
        return None
    except Exception as e:
        log(f"  ! adb exec-out failed: {e}", err=True)
        return None


def get_pid():
    """Find PID of com.dragon.read."""
    out = adb_shell_text("ps -A | grep com.dragon.read", timeout=10)
    if not out:
        return None
    for line in out.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 2 and "com.dragon.read" in line:
            try:
                return int(parts[1])
            except ValueError:
                continue
    return None


def read_pages(pid, page_start, page_count):
    """Read `page_count` 4KB pages starting at page index `page_start`.

    Uses `adb exec-out su 0 sh -c 'dd ...'`. Returns bytes (may be < expected
    if read failed partway). Returns None only on full timeout/error.
    """
    cmd = (
        f"su 0 sh -c 'dd if=/proc/{pid}/mem bs=4096 "
        f"skip={page_start} count={page_count} 2>/dev/null'"
    )
    return adb_exec_bin(cmd, timeout=ADB_TIMEOUT)


def dump_region(pid, start, size, filepath):
    """Dump `size` bytes starting at `start` into `filepath`.

    Strategy:
      - Pages within [start, start+size): page_start = start>>12, page_count = ceil(size/4096)
      - Read in chunks of CHUNK_SIZE bytes (== CHUNK_SIZE/4096 pages)
      - On chunk failure, fill with zeros and continue (don't abort whole region)
    Returns (ok_chunks, fail_chunks, bytes_written).
    """
    assert (start & 0xFFF) == 0, f"region start 0x{start:x} not page-aligned"
    assert (size & 0xFFF) == 0,  f"region size 0x{size:x} not page-aligned"

    pages_per_chunk = CHUNK_SIZE // 4096
    total_pages = size // 4096
    page_base = start // 4096

    ok = 0
    fail = 0
    written = 0
    tmp = filepath + ".tmp"

    with open(tmp, "wb") as f:
        for chunk_idx in range((total_pages + pages_per_chunk - 1) // pages_per_chunk):
            pages_off = chunk_idx * pages_per_chunk
            pages_n = min(pages_per_chunk, total_pages - pages_off)
            data = read_pages(pid, page_base + pages_off, pages_n)
            expected = pages_n * 4096
            if data is None or len(data) == 0:
                f.write(b"\x00" * expected)
                fail += 1
                written += expected
                continue
            if len(data) < expected:
                # partial — pad with zeros (one or more pages were unreadable)
                f.write(data)
                f.write(b"\x00" * (expected - len(data)))
                # treat as partial success
                ok += 1
                written += expected
            else:
                f.write(data[:expected])
                ok += 1
                written += expected

    os.replace(tmp, filepath)
    return ok, fail, written


def parse_maps(maps_raw):
    """Parse /proc/pid/maps into a list of region dicts."""
    regions = []
    for line in maps_raw.strip().split("\n"):
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            start_s, end_s = parts[0].split("-")
            start = int(start_s, 16)
            end = int(end_s, 16)
        except ValueError:
            continue
        perms = parts[1]
        offset = parts[2] if len(parts) > 2 else "0"
        name = " ".join(parts[5:]) if len(parts) >= 6 else ""
        regions.append({
            "start": start,
            "end": end,
            "size": end - start,
            "perms": perms,
            "offset": offset,
            "name": name,
            "line": line.strip(),
        })
    return regions


def filter_readable(regions):
    """Filter out regions that aren't worth dumping."""
    out = []
    skipped = {"noperm": 0, "large": 0, "vvar": 0}
    for r in regions:
        perms = r["perms"]
        name = r["name"]
        if "r" not in perms or perms in ("---p", "---s"):
            skipped["noperm"] += 1
            continue
        if name == "[vvar]":
            skipped["vvar"] += 1
            continue
        if r["size"] > MAX_REGION_SIZE:
            log(f"  SKIP (>{MAX_REGION_SIZE//(1024*1024)}MB): {r['line']}")
            skipped["large"] += 1
            continue
        out.append(r)
    return out, skipped


def find_so_base(regions, name_substr):
    for r in regions:
        if name_substr in r["name"] and "x" in r["perms"]:
            return r["start"]
    return None


def find_tpidr(regions, pid):
    """Compute TPIDR_EL0 = main_thread_stack_and_tls_rw.end - 0x3580.

    Main thread TID == PID on Linux.
    """
    target = f"stack_and_tls:{pid}"
    for r in regions:
        if target in r["name"] and "rw" in r["perms"]:
            return r["end"] - 0x3580
    return 0


def filename_for(start, end, perms):
    """Format used by emulator and matches existing on-disk files."""
    return f"{start:x}_{end:x}_{perms}.bin"


def write_signal_handler(signum, frame):
    """SIGINT/SIGTERM: flush manifest and exit."""
    log(f"\n[!] received signal {signum}, flushing and exiting", err=True)
    if MANIFEST_FH:
        try:
            MANIFEST_FH.flush()
            MANIFEST_FH.close()
        except Exception:
            pass
    if FAILED_FH:
        try:
            FAILED_FH.flush()
            FAILED_FH.close()
        except Exception:
            pass
    elapsed = time.time() - START_TIME
    log(f"[!] dumped {DUMPED_OK} ok, {DUMPED_FAIL} fail, {DUMPED_RESUME} resumed in {elapsed:.1f}s")
    sys.exit(130)


def main():
    global MANIFEST_FH, FAILED_FH, DUMPED_OK, DUMPED_FAIL, DUMPED_RESUME, START_TIME

    # Get PID
    if len(sys.argv) > 1:
        pid = int(sys.argv[1])
    else:
        pid = get_pid()
        if not pid:
            log("ERROR: com.dragon.read not found. Pass PID manually.", err=True)
            sys.exit(1)

    log(f"[*] PID: {pid}")

    # Read maps via adb shell (text mode is fine)
    maps_raw = adb_shell_text(f"su 0 cat /proc/{pid}/maps", timeout=15)
    if not maps_raw or not maps_raw.strip():
        log("ERROR: Cannot read /proc/pid/maps", err=True)
        sys.exit(1)

    # Output directory
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    outdir = os.path.join(repo_root, "lib", "full_dump")
    regdir = os.path.join(outdir, "regions")
    os.makedirs(regdir, exist_ok=True)

    maps_path = os.path.join(outdir, "maps.txt")
    with open(maps_path, "w") as f:
        f.write(maps_raw)
    log(f"[*] Saved maps to {maps_path}")

    regions = parse_maps(maps_raw)
    log(f"[*] Total regions in maps: {len(regions)}")

    readable, skipped = filter_readable(regions)
    total_size = sum(r["size"] for r in readable)
    log(f"[*] Readable regions: {len(readable)} ({total_size//(1024*1024)} MB)")
    log(f"    Skipped: {skipped['noperm']} no-perm, "
        f"{skipped['large']} too-large, {skipped['vvar']} vvar")

    # so_base + TPIDR
    so_base = find_so_base(regions, "libmetasec_ml")
    tpidr = find_tpidr(regions, pid)
    log(f"[*] so_base    = 0x{so_base:x}" if so_base else "[!] libmetasec_ml.so NOT FOUND")
    log(f"[*] tpidr_main = 0x{tpidr:x}" if tpidr else f"[!] stack_and_tls:{pid} NOT FOUND")

    # Write so_meta.txt up front (so even partial dump is usable)
    meta_path = os.path.join(outdir, "so_meta.txt")
    with open(meta_path, "w") as f:
        if so_base:
            f.write(f"so_base=0x{so_base:x}\n")
        if tpidr:
            f.write(f"tpidr_main=0x{tpidr:x}\n")
        f.write(f"pid={pid}\n")
    log(f"[*] Saved so_meta to {meta_path}")

    # Open manifest + failed in append mode for incremental writes.
    # We rewrite the header on each run; existing entries from prior runs are
    # preserved at the bottom (resume — duplicates are tolerable, the loader
    # uses last-wins).
    manifest_path = os.path.join(outdir, "manifest.txt")
    failed_path = os.path.join(outdir, "failed.txt")

    # Always overwrite header but keep existing entries by reading first.
    existing_entries = []
    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as f:
            for line in f:
                if not line.startswith("#") and line.strip():
                    existing_entries.append(line.rstrip("\n"))

    MANIFEST_FH = open(manifest_path, "w")
    MANIFEST_FH.write(f"# PID={pid} dumped at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    MANIFEST_FH.write("# Format: start_hex end_hex perms file_offset filename name\n")
    # Re-emit prior entries (so resumed entries stay)
    for e in existing_entries:
        MANIFEST_FH.write(e + "\n")
    MANIFEST_FH.flush()

    FAILED_FH = open(failed_path, "w")
    FAILED_FH.write(f"# PID={pid} failed regions at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    FAILED_FH.flush()

    # Build set of already-written manifest filenames (for resume)
    already_in_manifest = set()
    for e in existing_entries:
        parts = e.split()
        if len(parts) >= 5:
            already_in_manifest.add(parts[4])

    # Install signal handler
    signal.signal(signal.SIGINT, write_signal_handler)
    signal.signal(signal.SIGTERM, write_signal_handler)

    START_TIME = time.time()
    n = len(readable)

    for i, r in enumerate(readable):
        start = r["start"]
        end = r["end"]
        size = r["size"]
        perms = r["perms"]
        name = r["name"]

        fn = filename_for(start, end, perms)
        fpath = os.path.join(regdir, fn)
        short = os.path.basename(name) if name else "(anon)"
        prefix = f"[{i+1}/{n}] 0x{start:x}-0x{end:x} {perms} {short} ({size//1024}KB)"

        # Resume: skip if file exists with correct size AND already in manifest.
        if (os.path.exists(fpath) and os.path.getsize(fpath) == size
                and fn in already_in_manifest):
            DUMPED_RESUME += 1
            if (i + 1) % 200 == 0:
                log(f"  {prefix} -> RESUME ({DUMPED_RESUME} so far)")
            continue

        # Dump it
        ok, fail, written = dump_region(pid, start, size, fpath)
        if fail == 0 and written == size:
            DUMPED_OK += 1
            status = "OK"
        elif written == size and fail > 0:
            DUMPED_OK += 1
            status = f"PARTIAL({fail} chunk(s) zero-filled)"
            FAILED_FH.write(f"{start:x}-{end:x} {perms} {name} (partial: {fail} chunks failed)\n")
            FAILED_FH.flush()
        else:
            DUMPED_FAIL += 1
            status = f"FAIL (wrote {written}/{size})"
            FAILED_FH.write(f"{start:x}-{end:x} {perms} {name} (size mismatch)\n")
            FAILED_FH.flush()

        # Append to manifest (incremental)
        MANIFEST_FH.write(f"{start:x} {end:x} {perms} {r['offset']} {fn} {name}\n")
        MANIFEST_FH.flush()
        already_in_manifest.add(fn)

        if (i + 1) % 50 == 0 or status != "OK":
            log(f"  {prefix} -> {status}")

    elapsed = time.time() - START_TIME
    MANIFEST_FH.close()
    FAILED_FH.close()
    MANIFEST_FH = None
    FAILED_FH = None

    log("")
    log(f"[*] Done in {elapsed:.1f}s")
    log(f"    OK     : {DUMPED_OK}")
    log(f"    FAIL   : {DUMPED_FAIL}")
    log(f"    RESUME : {DUMPED_RESUME}")
    log(f"    Output : {outdir}")

    # Cross-check: every readable region should have a manifest entry
    if DUMPED_OK + DUMPED_FAIL + DUMPED_RESUME != len(readable):
        log(f"[!] WARN: dumped count ({DUMPED_OK+DUMPED_FAIL+DUMPED_RESUME}) "
            f"!= readable count ({len(readable)})", err=True)
    else:
        log("[*] All readable regions accounted for.")


if __name__ == "__main__":
    main()
