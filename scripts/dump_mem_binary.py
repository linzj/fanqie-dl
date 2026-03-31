#!/usr/bin/env python3
"""Dump process memory via Frida Python API (binary, not console strings)."""

import frida
import struct
import sys
import time

def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None

    device = frida.get_usb_device()
    if pid is None:
        for p in device.enumerate_processes():
            if "dragon.read" in p.name:
                pid = p.pid
                break
    if pid is None:
        print("App not running")
        sys.exit(1)

    print(f"[*] Attaching to PID {pid}...")
    session = device.attach(pid)

    script = session.create_script("""
    rpc.exports = {
        getRanges: function() {
            // Include all readable OR executable ranges
            var r1 = Process.enumerateRanges('r--');
            // Also include anonymous executable pages (SO's dynamic trampolines)
            var r2 = [];
            Process.enumerateRanges('--x').forEach(function(r) {
                // Only include small anonymous exec pages
                if (r.size <= 1048576 && (!r.file || !r.file.path)) r2.push(r);
            });
            // Merge and deduplicate
            var seen = {};
            var all = [];
            function addRange(r) {
                var key = r.base.toString();
                if (!seen[key]) { seen[key] = true; all.push(r); }
            }
            r1.forEach(addRange);
            r2.forEach(addRange);
            var result = [];
            for (var i = 0; i < all.length; i++) {
                var r = all[i];
                // include all ranges
                result.push({base: r.base.toString(), size: r.size});
            }
            return result;
        },
        readMem: function(addr, size) {
            try {
                return ptr(addr).readByteArray(size);
            } catch(e) {
                return null;
            }
        },
        getSoBase: function() {
            return Process.findModuleByName("libmetasec_ml.so").base.toString();
        }
    };
    """)
    script.load()
    api = script.exports_sync

    so_base = api.get_so_base()
    print(f"[+] SO base: {so_base}")

    # Get ranges
    print("[*] Enumerating ranges...")
    ranges = api.get_ranges()
    print(f"[+] {len(ranges)} ranges (<=16MB)")

    # Dump each range
    out_path = "lib/memdump.bin"
    total = 0
    with open(out_path, "wb") as f:
        # Header: so_base (8 bytes) + count (4 bytes)
        f.write(struct.pack("<Q", int(so_base, 16)))
        f.write(struct.pack("<I", len(ranges)))

        for i, rng in enumerate(ranges):
            base_addr = int(rng["base"], 16)
            size = rng["size"]
            f.write(struct.pack("<QQ", base_addr, size))

            # Read in 1MB chunks
            written = 0
            for off in range(0, size, 1048576):
                chunk_size = min(1048576, size - off)
                data = api.read_mem(hex(base_addr + off), chunk_size)
                if data is None:
                    f.write(b"\x00" * chunk_size)
                else:
                    f.write(data)
                written += chunk_size

            total += size
            if (i + 1) % 100 == 0:
                print(f"  [{i+1}/{len(ranges)}] {total // 1048576} MB")

    print(f"[+] Dumped {total // 1048576} MB in {len(ranges)} ranges to {out_path}")

    # Also save registers from the text output
    print("[+] Done. Use registers from /tmp/regs_only.txt")
    session.detach()

if __name__ == "__main__":
    main()
