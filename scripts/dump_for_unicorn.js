// Dump runtime state for Unicorn emulation
// Focus: BSS/data segment + signing function arguments
//
// Run: frida -U -p <PID> -l scripts/dump_for_unicorn.js

var mod = Process.findModuleByName("libmetasec_ml.so");
var base = mod.base;
var size = mod.size;
console.log("[+] SO base=" + base + " size=0x" + size.toString(16));

function hex(ptr, len) {
    var b = [];
    for (var i = 0; i < len; i++) b.push(('0' + ptr.add(i).readU8().toString(16)).slice(-2));
    return b.join('');
}

// Dump SO segments info
var ranges = mod.enumerateRanges('r--');
console.log("Segments: " + ranges.length);
for (var i = 0; i < ranges.length; i++) {
    var r = ranges[i];
    console.log("  [" + i + "] off=0x" + r.base.sub(base).toString(16) +
        " size=0x" + r.size.toString(16) + " prot=" + r.protection);
}

// Dump the rw- data segment (BSS + initialized data at runtime)
// This is the segment that differs from the on-disk SO
var rwSegStart = base.add(0x379000);
var rwSegSize = 0x59000;
console.log("\n=== RW SEGMENT (0x379000, 0x59000 bytes) ===");
// Dump in chunks to console (hex)
for (var off = 0; off < rwSegSize; off += 4096) {
    var chunkLen = Math.min(4096, rwSegSize - off);
    try {
        var d = hex(rwSegStart.add(off), chunkLen);
        // Only print non-zero chunks
        var allZero = true;
        for (var j = 0; j < d.length; j += 2) {
            if (d.substr(j, 2) !== "00") { allZero = false; break; }
        }
        if (!allZero) {
            console.log("RW:0x" + (0x379000 + off).toString(16) + ":" + d);
        }
    } catch(e) {
        console.log("RW:0x" + (0x379000 + off).toString(16) + ":UNREADABLE");
    }
}

// Also dump the rwx segments (patched code / data)
var patchSegs = [[0x17b000, 0x1000], [0x241000, 0x5000], [0x24b000, 0x1000],
                 [0x25b000, 0x2000], [0x347000, 0x2000]];
for (var s = 0; s < patchSegs.length; s++) {
    var segOff = patchSegs[s][0];
    var segSz = patchSegs[s][1];
    console.log("\nPATCH:0x" + segOff.toString(16) + ":" + hex(base.add(segOff), segSz));
}

// Hook signing functions to capture state
Interceptor.attach(base.add(0x17B96C), {
    onEnter: function(args) {
        console.log("\n=== ORCHESTRATOR 0x17B96C ===");
        // All registers
        var regs = ['x0','x1','x2','x3','x4','x5','x6','x7','x8',
                    'x9','x10','x11','x12','x13','x14','x15','x16','x17',
                    'x19','x20','x21','x22','x23','x24','x25','x26','x27','x28',
                    'fp','lr','sp'];
        for (var i = 0; i < regs.length; i++) {
            console.log("  " + regs[i] + "=" + this.context[regs[i]]);
        }
        // Dump stack
        console.log("  STACK:" + hex(this.context.sp, 1024));
        // Dump *x1 and *x2
        try { console.log("  *X1:" + hex(args[1], 256)); } catch(e) {}
        try { console.log("  *X2:" + hex(args[2], 256)); } catch(e) {}
    }
});

Interceptor.attach(base.add(0x29CCD4), {
    onEnter: function(args) {
        console.log("\n=== SIGN_ENTRY 0x29CCD4 ===");
        var regs = ['x0','x1','x2','x3','x4','x5','x6','x7','x8',
                    'x19','x20','x21','x22','x23','x24','x25','x26','x27','x28',
                    'fp','lr','sp'];
        for (var i = 0; i < regs.length; i++) {
            console.log("  " + regs[i] + "=" + this.context[regs[i]]);
        }
        try { console.log("  *X0:" + hex(args[0], 256)); } catch(e) {}
        try { console.log("  *X1:" + hex(args[1], 256)); } catch(e) {}
    }
});

Interceptor.attach(base.add(0x29CF58), {
    onEnter: function(args) {
        console.log("\n=== SIGN_DISPATCH 0x29CF58 ===");
        var regs = ['x0','x1','x2','x3','x4','x5','fp','lr','sp'];
        for (var i = 0; i < regs.length; i++) {
            console.log("  " + regs[i] + "=" + this.context[regs[i]]);
        }
        try { console.log("  *X0:" + hex(args[0], 512)); } catch(e) {}
        try { console.log("  *X1:" + hex(args[1], 512)); } catch(e) {}
    }
});

Interceptor.attach(base.add(0x283748), {
    onEnter: function(args) {
        console.log("\n=== SIGN_MAIN 0x283748 ===");
        var regs = ['x0','x1','x2','x3','x4','x5','fp','lr','sp'];
        for (var i = 0; i < regs.length; i++) {
            console.log("  " + regs[i] + "=" + this.context[regs[i]]);
        }
        // Dump vtable
        try {
            var vt = args[0].readPointer();
            console.log("  vtable=" + vt + " off=0x" + vt.sub(base).toString(16));
            for (var i = 0; i < 16; i++) {
                var e = vt.add(i*8).readPointer();
                try {
                    console.log("  vt[" + i + "]=0x" + e.sub(base).toString(16));
                } catch(ex) { console.log("  vt[" + i + "]=" + e); }
            }
        } catch(e) {}
        try { console.log("  *X0:" + hex(args[0], 512)); } catch(e) {}
        try { console.log("  *X1:" + hex(args[1], 512)); } catch(e) {}
    }
});

console.log("[+] Hooks installed, triggering sign...");

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
                            var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
                                "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
                                "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
                                "&device_brand=google&os_api=35&os_version=15" +
                                "&device_id=3722313718058683&iid=3722313718062779" +
                                "&_rticket=1774940000000" +
                                "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
                                "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
                                "&book_id=7373660003258862617";
                            console.log("\n[*] Signing...");
                            var h = HM.$new();
                            var r = inst.onCallToAddSecurityFactor(url, h);
                            var m = Java.cast(r, HM);
                            var it = m.keySet().iterator();
                            console.log("\n=== RESULT ===");
                            while (it.hasNext()) {
                                var k = it.next();
                                console.log("  " + k + "=" + m.get(k));
                            }
                            console.log("\n[DONE]");
                        },
                        onComplete: function() {}
                    });
                } catch(e) {}
            },
            onComplete: function() {}
        });
    });
}, 3000);
