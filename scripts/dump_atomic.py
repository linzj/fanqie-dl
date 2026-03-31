#!/usr/bin/env python3
"""Atomic dump: hook→sign→detach→dump all in one session, one process."""

import frida, struct, sys, time

pid = int(sys.argv[1])
print(f"PID={pid}")

device = frida.get_usb_device()
session = device.attach(pid)

JS = r"""
var m = Process.findModuleByName("libmetasec_ml.so");
var regsData = null;
var signDone = false;

Interceptor.attach(m.base.add(0x17B8F8), {
    onEnter: function() {
        if (regsData) return;
        regsData = {};
        ["x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","x19","x20","x21","x22","x23","x24","x25","x26","x27","x28","fp","lr","sp"].forEach(function(r) {
            regsData[r] = this.context[r].toString();
        }, this);
    }
});

// signing will be triggered by RPC call

rpc.exports = {
    getRegs: function() { return regsData; },
    isDone: function() { return signDone; },
    triggerSign: function() {
        Java.perform(function() {
            Java.enumerateClassLoaders({
                onMatch: function(l) {
                    try {
                        l.findClass("ms.bd.c.r4");
                        Java.classFactory.loader = l;
                        Java.choose("ms.bd.c.r4", {
                            onMatch: function(i) {
                                var HM = Java.use("java.util.HashMap");
                                i.onCallToAddSecurityFactor(
                                    "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64&device_brand=google&os_api=35&os_version=15&device_id=3722313718058683&iid=3722313718062779&_rticket=1774940000000&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7&openudid=9809e655-067c-47fe-a937-b150bfad0be9&book_id=7373660003258862617",
                                    HM.$new());
                                Interceptor.detachAll();
                                signDone = true;
                            },
                            onComplete: function() {}
                        });
                    } catch(e) {}
                },
                onComplete: function() {}
            });
        });
        return signDone;
    },
    soBase: function() { return m.base.toString(); },
    getRanges: function() {
        var all = Process.enumerateRanges("r--");
        Process.enumerateRanges("--x").forEach(function(r) {
            var k = r.base.toString();
            if (!all.some(function(a) { return a.base.toString() === k; })) all.push(r);
        });
        return all.map(function(r) { return {base: r.base.toString(), size: r.size}; });
    },
    readMem: function(addr, size) {
        try { return ptr(addr).readByteArray(size); }
        catch(e) { return null; }
    }
};
"""

script = session.create_script(JS)
done = [False]
def on_msg(msg, data):
    if msg.get("type") == "send" and msg.get("payload") == "sign_done":
        done[0] = True
script.on("message", on_msg)
script.load()
api = script.exports_sync

so_base = api.so_base()
print(f"SO_BASE={so_base}")

# Trigger signing via RPC
print("Triggering sign...")
result = api.trigger_sign()
print(f"Sign result: {result}")
time.sleep(1)

regs = api.get_regs()
print(f"Regs: {len(regs)}")
with open("/tmp/regs_only.txt", "w") as f:
    for k, v in regs.items():
        f.write(f"REG:{k}:{v}\n")

# Dump
print("Dumping...")
ranges = api.get_ranges()
print(f"{len(ranges)} ranges")

so_base_int = int(so_base, 16)
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
            d = api.read_mem(hex(base + off), sz)
            if d: f.write(d)
            else: f.write(b"\x00" * sz)
        total += size
        if (i + 1) % 200 == 0: print(f"  [{i+1}/{len(ranges)}] {total // 1048576} MB")
    print(f"Dumped {total // 1048576} MB")

with open("lib/anon_pages.bin", "wb") as f:
    f.write(struct.pack("<I", 0))

session.detach()
print("DONE")
