// Find native function for y2.a by hooking at the JNI trampoline level
// Strategy: hook the instruction JUST BEFORE the native code enters our SO
//
// Run: frida -U -p <PID> -l scripts/find_jni_func.js

var mod = Process.findModuleByName("libmetasec_ml.so");
var base = mod.base;
console.log("[+] SO base=" + base + " size=0x" + mod.size.toString(16));

function soOff(addr) {
    try { var n = addr.sub(base).toInt32(); return (n >= 0 && n < mod.size) ? "0x" + n.toString(16) : null; }
    catch(e) { return null; }
}

// Search for "a\x00" in the SO data sections - this is the method name in JNINativeMethod
// JNINativeMethod = { const char* name, const char* signature, void* fnPtr }
// On ARM64, each field is 8 bytes (pointer)

// Actually, easier: just intercept the first instruction of the native function
// by hooking all function entries that are called right after libart JNI trampoline

// Most direct approach: hook y2.a at Java level, then inside the handler
// use Thread.backtrace() to find the native entry

Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.y2");
                Java.classFactory.loader = loader;

                var y2 = Java.use("ms.bd.c.y2");
                y2.a.overload('int', 'int', 'long', 'java.lang.String', 'java.lang.Object')
                    .implementation = function(tag, type, handle, url, extra) {

                    if (tag === 0x3000001) {
                        console.log("\n[y2.a] tag=0x" + tag.toString(16) + " url=" +
                            (url ? url.substring(0, 80) : "null"));

                        // Get native backtrace
                        var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                        console.log("  Native backtrace:");
                        for (var i = 0; i < bt.length; i++) {
                            var off = soOff(bt[i]);
                            var sym = DebugSymbol.fromAddress(bt[i]);
                            console.log("    [" + i + "] " + bt[i] +
                                (off ? " SO+" + off : "") +
                                (sym.name ? " " + sym.name : ""));
                        }
                    }

                    return this.a(tag, type, handle, url, extra);
                };
                console.log("[+] y2.a hooked");

                // Also hook at SO entries that are likely the native function
                // From JNI_OnLoad at SO+0x27b41c, the registered function should be nearby
                // Let's check what's at some candidate offsets
                var candidates = [0x27b41c, 0x176000, 0x177000, 0x178000, 0x17B000];
                for (var i = 0; i < candidates.length; i++) {
                    try {
                        var addr = base.add(candidates[i]);
                        var instr = Instruction.parse(addr);
                        console.log("  0x" + candidates[i].toString(16) + ": " + instr.mnemonic + " " + instr.opStr);
                    } catch(e) {}
                }

            } catch(e) { console.log("err: " + e); }
        },
        onComplete: function() {}
    });
});

// Trigger sign
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
                            var h = HM.$new();
                            inst.onCallToAddSecurityFactor(
                                "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?book_id=1",
                                h);
                            console.log("[DONE]");
                        },
                        onComplete: function() {}
                    });
                } catch(e) {}
            },
            onComplete: function() {}
        });
    });
}, 2000);
