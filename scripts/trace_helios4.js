// Capture the 36-byte raw Helios data BEFORE base64 encoding
// Then use MemoryAccessMonitor to find what code WRITES part1/part2
//
// Run: frida -U -p <PID> -l scripts/trace_helios4.js

var mod = Process.findModuleByName("libmetasec_ml.so");
var base = mod.base;
console.log("[+] base=" + base);

function hex(ptr, len) {
    var b = [];
    for (var i = 0; i < len; i++) b.push(('0' + ptr.add(i).readU8().toString(16)).slice(-2));
    return b.join('');
}
function soOff(addr) {
    try { var n = addr.sub(base).toInt32(); return (n >= 0 && n < 0x400000) ? "0x" + n.toString(16) : "ext"; }
    catch(e) { return "ext"; }
}

var md5Count = 0;
var phase = 0;

// Hook MD5
Interceptor.attach(base.add(0x243C34), {
    onLeave: function(ret) {
        md5Count++;
        if (md5Count === 2) phase = 2;
    }
});

// Hook B64_ENCODE high-level (sub_258C14)
// This is where the 36-byte Helios gets encoded
Interceptor.attach(base.add(0x258C14), {
    onEnter: function(args) {
        if (phase !== 2) return;

        console.log("\n[B64_ENCODE] LR=" + soOff(this.context.lr));

        // x1 is the data object: [vtable, ?, ?, len@+0xC, data@+0x10]
        try {
            var obj = args[1];
            var len = obj.add(0xC).readU32();
            var dataPtr = obj.add(0x10).readPointer();
            console.log("  data_obj=" + obj + " len=" + len + " data_ptr=" + dataPtr);

            if (len === 36) {
                console.log("  ★ THIS IS HELIOS RAW DATA ★");
                console.log("  raw_hex=" + hex(dataPtr, 36));
                var R = hex(dataPtr, 4);
                var p1 = hex(dataPtr.add(4), 16);
                var p2 = hex(dataPtr.add(20), 16);
                console.log("  R=" + R + " part1=" + p1 + " part2=" + p2);

                // Now the key question: WHERE was this 36-byte buffer written?
                // The data_ptr points to a heap buffer. We can dump the surrounding
                // memory to understand the buffer structure.
                console.log("\n  === DATA BUFFER CONTEXT ===");
                // Read the object structure
                for (var i = 0; i < 5; i++) {
                    console.log("  obj[" + (i*8) + "]=" + obj.add(i*8).readPointer());
                }

                // The 36-byte data was assembled somewhere. Let's check:
                // Is it contiguous? Were R, part1, part2 written separately?
                // We can't easily tell from here, but we can dump the stack to
                // find the caller chain.

                // Walk up the stack
                var sp = this.context.sp;
                var fp = this.context.fp;
                console.log("\n  === STACK FRAMES ===");
                console.log("  SP=" + sp + " FP=" + fp);

                // Frame walking
                var frame = fp;
                for (var i = 0; i < 10; i++) {
                    try {
                        var savedFP = frame.readPointer();
                        var savedLR = frame.add(8).readPointer();
                        var off = soOff(savedLR);
                        console.log("  frame[" + i + "] FP=" + frame + " LR=" + off);
                        if (savedFP.isNull() || off === "ext") break;
                        frame = savedFP;
                    } catch(e) { break; }
                }
            }
        } catch(e) {
            console.log("  err: " + e);
        }

        phase = 3; // only capture first Helios
    }
});

console.log("[+] Hooks ready");

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
                            md5Count = 0; phase = 0;
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
                            inst.onCallToAddSecurityFactor(url, h);
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
