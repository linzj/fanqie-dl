#!/usr/bin/env python3
"""Dump clean process memory + registers in one shot."""

import frida, struct, sys, subprocess, re, time

# Find PID
ps = subprocess.check_output(['adb', 'shell', 'ps', '-A']).decode()
m = re.search(r'(\d+)\s+\d+\s+\d+\s+\d+\s+\w+\s+\d+\s+\S\s+com\.dragon\.read', ps)
pid = int(m.group(1))
print(f"PID={pid}")

device = frida.get_usb_device()
session = device.attach(pid)

# Step 1: Get registers via Interceptor, then detach hooks
JS_HOOK = r"""
var savedRegs = null;
var m = Process.findModuleByName("libmetasec_ml.so");

rpc.exports = {
    captureRegs: function() {
        // Set up hook first
        var done = false;
        Interceptor.attach(m.base.add(0x258530), {
            onEnter: function() {
                if (done) return;
                done = true;
                savedRegs = {};
                ["x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","x19","x20","x21","x22","x23","x24","x25","x26","x27","x28","fp","lr","sp"].forEach(function(r) {
                    savedRegs[r] = this.context[r].toString();
                }, this);
            }
        });
        return "hook_set";
    },
    triggerSign: function() {
        // Java.perform must be called from Java thread
        setTimeout(function() { Java.perform(function() {
            Java.enumerateClassLoaders({
                onMatch: function(l) {
                    try {
                        l.findClass("ms.bd.c.r4");
                        Java.classFactory.loader = l;
                        var HM = Java.use("java.util.HashMap");
                        Java.choose("ms.bd.c.r4", {
                            onMatch: function(inst) {
                                var h = HM.$new();
                                inst.onCallToAddSecurityFactor(
                                    "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64&device_brand=google&os_api=35&os_version=15&device_id=3722313718058683&iid=3722313718062779&_rticket=1774940000000&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7&openudid=9809e655-067c-47fe-a937-b150bfad0be9&book_id=7373660003258862617",
                                    h);
                            },
                            onComplete: function() {}
                        });
                    } catch(e) {}
                },
                onComplete: function() {}
            });
        });
        Interceptor.detachAll();
        return savedRegs;
    },
    soBase: function() {
        return m.base.toString();
    }
};
"""

script = session.create_script(JS_HOOK)
script.load()
api = script.exports_sync

so_base = api.so_base()
print(f"SO_BASE={so_base}")

# Set up hook, trigger sign, get regs
api.capture_regs()
print("Hook set, triggering sign...")
regs = api.trigger_sign()
print(f"Captured {len(regs)} registers")

# Save regs
with open("/tmp/regs_only.txt", "w") as f:
    for k, v in regs.items():
        f.write(f"REG:{k}:{v}\n")

# Unload hook script
script.unload()
time.sleep(1)

# Step 2: Dump memory with a fresh script (no hooks)
JS_DUMP = r"""
rpc.exports = {
    getRanges: function() {
        var all = Process.enumerateRanges("r--");
        var result = [];
        for (var i = 0; i < all.length; i++)
            result.push({base: all[i].base.toString(), size: all[i].size});
        return result;
    },
    readMem: function(addr, size) {
        try { return ptr(addr).readByteArray(size); }
        catch(e) { return null; }
    }
};
"""
script2 = session.create_script(JS_DUMP)
script2.load()
api2 = script2.exports_sync

# Check GOT is clean
so_base_int = int(so_base, 16)

ranges = api2.get_ranges()
print(f"{len(ranges)} readable ranges")

with open("lib/memdump.bin", "wb") as f:
    f.write(struct.pack("<Q", so_base_int))
    f.write(struct.pack("<I", len(ranges)))
    total = 0
    for i, r in enumerate(ranges):
        base = int(r["base"], 16)
        size = r["size"]
        f.write(struct.pack("<QQ", base, size))
        for off in range(0, size, 1048576):
            sz = min(1048576, size - off)
            data = api2.read_mem(hex(base + off), sz)
            if data:
                f.write(data)
            else:
                f.write(b"\x00" * sz)
        total += size
        if (i + 1) % 200 == 0:
            print(f"  [{i+1}/{len(ranges)}] {total // 1048576} MB")
    print(f"Dumped {total // 1048576} MB")

# Dump hidden anon pages
anon = []
for addr in [0x7a6c9dc000, 0x7a6b4a3000, 0x7358759000, 0x735948a000, 0x7358763000, 0x735948e000, 0x735875a000, 0x7a465d1000]:
    data = api2.read_mem(hex(addr), 4096)
    if data:
        anon.append((addr, data))

with open("lib/anon_pages.bin", "wb") as f:
    f.write(struct.pack("<I", len(anon)))
    for addr, data in anon:
        f.write(struct.pack("<QQ", addr, 4096))
        f.write(data)
print(f"{len(anon)} anon pages")

session.detach()
print("ALL DONE")
