// Find the EXACT native function address for y2.a
// by hooking at the JNI boundary
//
// Run: frida -U -p <PID> -l scripts/find_native_entry.js

var mod = Process.findModuleByName("libmetasec_ml.so");
var base = mod.base;
console.log("[+] SO base=" + base);

function soOff(addr) {
    try { var n = addr.sub(base).toInt32(); return (n >= 0 && n < 0x400000) ? "0x" + n.toString(16) : "ext"; }
    catch(e) { return "ext"; }
}

// Method 1: Hook art::Method::GetEntryPointFromJni to find the native pointer
// This is called when the VM invokes a native method
var artMod = Process.findModuleByName("libart.so");
if (artMod) {
    console.log("[+] libart.so base=" + artMod.base);
}

// Method 2: Use Java reflection to find the registered native
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.y2");
                Java.classFactory.loader = loader;

                var y2 = Java.use("ms.bd.c.y2");
                // Get the Method object for 'a'
                var methods = y2.class.getDeclaredMethods();
                for (var i = 0; i < methods.length; i++) {
                    var m = methods[i];
                    var name = m.getName();
                    var mods = m.getModifiers();
                    var isNative = (mods & 0x100) !== 0; // Modifier.NATIVE
                    if (isNative) {
                        console.log("[y2] native method: " + name + " sig=" + m.toGenericString());
                    }
                }
            } catch(e) {}
        },
        onComplete: function() {}
    });
});

// Method 3: Hook the actual y2.a at Java level and read x16/x17 to find native addr
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.y2");
                Java.classFactory.loader = loader;

                // Hook the native trampoline: when y2.a is called, the ART runtime
                // jumps to the JNI stub which then calls the registered native function.
                // We can find the native address by hooking RegisterNatives.

                // Actually, let's use a different approach:
                // Hook JNI_OnLoad which registers the native methods
                // But JNI_OnLoad already ran. Let's look at the JNI entry table.

                // The SO only has one export: JNI_OnLoad
                var exports = mod.enumerateExports();
                for (var i = 0; i < exports.length; i++) {
                    console.log("[export] " + exports[i].name + " @ " + exports[i].address +
                        " (SO+0x" + exports[i].address.sub(base).toString(16) + ")");
                }

                // Look for the function pointer table that was registered
                // RegisterNatives stores: {name, signature, fnPtr}
                // The fnPtr is what we need

                // Let's try another approach: hook at SO+0x17B96C (orchestrator)
                // and check what called it when we trigger a sign
                var HM = Java.use("java.util.HashMap");
                Java.choose("ms.bd.c.r4", {
                    onMatch: function(inst) {
                        // Hook the orchestrator to get full call chain
                        Interceptor.attach(base.add(0x17B96C), {
                            onEnter: function(args) {
                                console.log("\n[ORCHESTRATOR] x0=" + args[0] + " x1=" + args[1] +
                                    " x2=" + args[2]);
                                console.log("  LR=" + soOff(this.context.lr));
                                console.log("  x25=" + this.context.x25 + " (tag)");

                                // Walk the stack to find the JNI entry
                                var fp = this.context.fp;
                                console.log("\n  === CALL STACK ===");
                                for (var i = 0; i < 15; i++) {
                                    try {
                                        var savedLR = fp.add(8).readPointer();
                                        var off = soOff(savedLR);
                                        console.log("  [" + i + "] LR=" + off + " (" + savedLR + ")");
                                        fp = fp.readPointer();
                                        if (fp.isNull()) break;
                                    } catch(e) { break; }
                                }
                            }
                        });

                        console.log("\n[*] Triggering sign...");
                        var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
                            "?ac=wifi&aid=1967&book_id=7373660003258862617";
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
