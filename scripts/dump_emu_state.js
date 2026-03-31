// Dump COMPLETE memory state at orchestrator entry for Unicorn replay
// Captures: registers, stack, all referenced heap regions
//
// Run: frida -U -p <PID> -l scripts/dump_emu_state.js

var mod = Process.findModuleByName("libmetasec_ml.so");
var base = mod.base;
console.log("[+] SO base=" + base);

function hex(ptr, len) {
    var b = [];
    for (var i = 0; i < len; i++) b.push(('0' + ptr.add(i).readU8().toString(16)).slice(-2));
    return b.join('');
}

// Collect all memory regions we need to dump
var memRegions = {};  // addr -> {data, size}

function dumpRegion(addr, size, label) {
    try {
        var p = ptr(addr.toString());
        var key = p.toString();
        if (memRegions[key]) return; // already dumped
        var data = hex(p, size);
        memRegions[key] = {size: size, label: label};
        console.log("MEM:" + key + ":" + size + ":" + data);
    } catch(e) {}
}

// Recursively dump pointer chains from a memory region
function dumpPointers(addr, size, depth, label) {
    if (depth > 3) return;
    dumpRegion(addr, size, label);

    // Scan for pointers in this region
    for (var off = 0; off < size - 7; off += 8) {
        try {
            var val = addr.add(off).readPointer();
            // Is it a valid heap/stack pointer?
            var v = val;
            if (v.compare(ptr("0x10000")) > 0 && v.compare(ptr("0x800000000000")) < 0) {
                // Check if it's accessible
                try {
                    val.readU8();
                    // Dump 256 bytes at this pointer
                    dumpPointers(val, 256, depth + 1, label + "→p" + off);
                } catch(e) {}
            }
        } catch(e) {}
    }
}

Interceptor.attach(base.add(0x17B96C), {
    onEnter: function(args) {
        console.log("\n=== ORCHESTRATOR ENTRY ===");

        // Dump all registers
        var regs = ['x0','x1','x2','x3','x4','x5','x6','x7','x8',
                    'x9','x10','x11','x12','x13','x14','x15','x16','x17',
                    'x19','x20','x21','x22','x23','x24','x25','x26','x27','x28',
                    'fp','lr','sp'];
        for (var i = 0; i < regs.length; i++) {
            console.log("REG:" + regs[i] + ":" + this.context[regs[i]]);
        }

        // Dump stack (4KB)
        var sp = this.context.sp;
        dumpRegion(sp, 4096, "stack");

        // Dump x1 struct and its pointer chain
        dumpPointers(args[1], 512, 0, "x1");

        // Dump x2 struct and its pointer chain
        dumpPointers(args[2], 512, 0, "x2");

        // Dump the handle object (from x25 or stack)
        // x25 = tag = 0x3000001, the handle is somewhere in the call chain
        // Let's dump the frame pointer chain
        var fp = this.context.fp;
        dumpRegion(fp, 512, "fp_frame");

        // Dump fp's pointer targets
        dumpPointers(fp, 256, 0, "fp");

        // Dump important register targets
        for (var i = 19; i <= 28; i++) {
            var reg = 'x' + i;
            var val = this.context[reg];
            try {
                if (val.compare(ptr("0x10000")) > 0) {
                    val.readU8();
                    dumpPointers(val, 256, 0, reg);
                }
            } catch(e) {}
        }

        console.log("DUMP_COMPLETE");

        // Don't continue - we just need the state
        // Actually we do need to continue to avoid crash
    }
});

console.log("[+] Hook installed");

setTimeout(function() {
    Java.perform(function() {
        Java.enumerateClassLoaders({
            onMatch: function(loader) {
                try {
                    loader.findClass("ms.bd.c.r4");
                    Java.classFactory.loader = loader;
                    var HM = Java.use("java.util.HashMap");
                    Java.choose("ms.bd.c.r4", {
                        onMatch: function(inst) {
                            console.log("\n[*] Signing...");
                            var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
                                "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
                                "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
                                "&device_brand=google&os_api=35&os_version=15" +
                                "&device_id=3722313718058683&iid=3722313718062779" +
                                "&_rticket=1774940000000" +
                                "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
                                "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
                                "&book_id=7373660003258862617";
                            var h = HM.$new();
                            var r = inst.onCallToAddSecurityFactor(url, h);
                            var m = Java.cast(r, HM);
                            var it = m.keySet().iterator();
                            console.log("\n=== SIGNATURES ===");
                            while (it.hasNext()) {
                                var k = it.next();
                                console.log("SIG:" + k + ":" + m.get(k));
                            }
                            console.log("[DONE]");
                        },
                        onComplete: function() {}
                    });
                } catch(e) {}
            },
            onComplete: function() {}
        });
    });
}, 3000);
