#!/usr/bin/env bash
# dump_all.sh — enforce ordering: clean memory dump first, then Frida dump
#
# Steps:
#   1. Kill any frida-server and force-stop the app (clean slate)
#   2. Spawn the app fresh, wait for SO to load
#   3. Run /proc/pid/mem dump (NO Frida attached)
#   4. Start frida-server, attach, run dump_vm_data.js
#
# Any deviation from this order risks bytehook/Frida contamination in the
# memory snapshot. See CLAUDE.md "Frida 注意事项".

set -euo pipefail

PKG="com.dragon.read"
SO="libmetasec_ml.so"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"

say() { printf '\n\033[1;36m[+] %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m[!] %s\033[0m\n' "$*" >&2; exit 1; }

adb_su() { adb shell "su 0 sh -c '$*'"; }

say "Step 0: clean slate (kill frida-server, force-stop $PKG)"
adb_su "pkill -9 frida-server 2>/dev/null; pkill -9 -x frida 2>/dev/null; true"
adb shell "am force-stop $PKG"
sleep 1

# Verify no frida processes remain. Use -x (exact name match) to avoid
# matching the search command line itself ("pgrep -f frida" matches its own
# parent shell, which contains the literal string "frida").
if adb_su "pgrep -x frida-server; pgrep -x frida" | grep -q .; then
    die "frida processes still running after kill — abort"
fi

say "Step 1: spawn $PKG fresh"
adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" >/dev/null

# Wait for SO to load
say "Step 2: wait for $SO to load"
PID=""
for i in $(seq 1 30); do
    PID=$(adb shell "pgrep -f $PKG" | tr -d '\r' | head -1 || true)
    if [ -n "$PID" ]; then
        if adb_su "cat /proc/$PID/maps 2>/dev/null | grep -q $SO"; then
            echo "    PID=$PID, $SO loaded"
            break
        fi
    fi
    sleep 1
done
[ -n "$PID" ] || die "App did not start"
adb_su "grep -q $SO /proc/$PID/maps" || die "$SO not loaded after 30s"

# Sanity: confirm no frida-agent in the target process
if adb_su "cat /proc/$PID/maps" | grep -q frida; then
    die "frida-agent already mapped into PID $PID — memory dump would be contaminated"
fi

say "Step 3: clean /proc/$PID/mem dump (NO Frida)"
python3 "$SCRIPT_DIR/dump_full_memory.py" "$PID"

# Re-verify still no frida contamination after dump
if adb_su "cat /proc/$PID/maps" | grep -q frida; then
    die "frida-agent appeared during memory dump — snapshot is suspect"
fi

say "Step 4: start frida-server, run dump_vm_data.js"
adb_su "/data/local/tmp/frida-server &" >/dev/null 2>&1 &
sleep 2
adb_su "pgrep frida-server" >/dev/null || die "frida-server failed to start"

mkdir -p "$REPO/lib/full_dump"
timeout 120 frida -U -p "$PID" -l "$SCRIPT_DIR/dump_all_in_one.js" --runtime=qjs \
    2>&1 | tee "$REPO/lib/full_dump/frida_dump.txt" || true

say "Step 5: merge Frida-captured TPIDR + handle into so_meta.txt"
python3 - "$REPO/lib/full_dump" <<'PYEOF'
import os, re, sys
outdir = sys.argv[1]
fd_path = os.path.join(outdir, 'frida_dump.txt')
meta_path = os.path.join(outdir, 'so_meta.txt')
fd = open(fd_path).read()
fd = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', fd)  # strip ANSI

m_so   = re.search(r'SO_BASE=0x([0-9a-f]+)', fd)
m_pid  = re.search(r'^PID=(\d+)', fd, re.M)
m_tp   = re.search(r'TPIDR=0x([0-9a-f]+)', fd)
m_tid  = re.search(r'OUR_TID=(\d+)', fd)
m_hdl  = re.search(r'^HANDLE=0x([0-9a-f]+):', fd, re.M)

if not (m_so and m_tp and m_hdl):
    print('  ! frida_dump.txt missing SO_BASE/TPIDR/HANDLE — leaving so_meta.txt as is', file=sys.stderr)
    sys.exit(0)

with open(meta_path, 'w') as f:
    f.write(f'so_base=0x{m_so.group(1)}\n')
    f.write(f'tpidr_main=0x{m_tp.group(1)}\n')
    if m_pid: f.write(f'pid={m_pid.group(1)}\n')
    if m_tid: f.write(f'sign_tid={m_tid.group(1)}\n')
    f.write(f'handle=0x{m_hdl.group(1)}\n')
print(f'  so_base    = 0x{m_so.group(1)}')
print(f'  tpidr_main = 0x{m_tp.group(1)}')
print(f'  handle     = 0x{m_hdl.group(1)}')
PYEOF

say "Done. Outputs:"
echo "    Memory dump: $REPO/lib/full_dump/"
echo "    Frida dump:  $REPO/lib/full_dump/frida_dump.txt"
echo "    so_meta:     $REPO/lib/full_dump/so_meta.txt"
