// Search for crypto constants and find JNI native entry
// Run: frida -U -p <PID> -l scripts/hook_find_crypto2.js

function run() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    var base = mod.base;
    console.log("[+] SO @ " + base + " size=" + mod.size);

    // Use module ranges instead of full size to avoid unreadable pages
    console.log("\n=== Module ranges ===");
    var ranges = mod.enumerateRanges("r--");
    for (var i = 0; i < ranges.length; i++) {
        var r = ranges[i];
        var offset = r.base.sub(base);
        console.log("  " + r.base + " size=" + r.size + " offset=0x" + offset.toString(16) + " prot=" + r.protection);
    }

    // Search in each readable range
    var md5Count = 0;
    var sha256Count = 0;
    var aesCount = 0;
    var hmacCount = 0;

    for (var i = 0; i < ranges.length; i++) {
        var r = ranges[i];
        try {
            // MD5 T[1] = 0xd76aa478
            var res = Memory.scanSync(r.base, r.size, "78 a4 6a d7");
            for (var j = 0; j < res.length; j++) {
                console.log("  MD5_T1 @ 0x" + res[j].address.sub(base).toString(16));
                md5Count++;
            }
            // SHA-256 K[0] = 0x428a2f98
            res = Memory.scanSync(r.base, r.size, "98 2f 8a 42");
            for (var j = 0; j < res.length; j++) {
                console.log("  SHA256_K0 @ 0x" + res[j].address.sub(base).toString(16));
                sha256Count++;
            }
            // AES S-box
            res = Memory.scanSync(r.base, r.size, "63 7c 77 7b f2 6b 6f c5");
            for (var j = 0; j < res.length; j++) {
                console.log("  AES_SBOX @ 0x" + res[j].address.sub(base).toString(16));
                aesCount++;
            }
            // HMAC ipad 0x36 repeated
            res = Memory.scanSync(r.base, r.size, "36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36");
            for (var j = 0; j < res.length; j++) {
                console.log("  HMAC_IPAD @ 0x" + res[j].address.sub(base).toString(16));
                hmacCount++;
            }
        } catch(e) {
            console.log("  scan error in range " + i + ": " + e);
        }
    }

    console.log("\nSummary: MD5=" + md5Count + " SHA256=" + sha256Count + " AES=" + aesCount + " HMAC=" + hmacCount);

    // Find JNI native entry for y2.a
    console.log("\n=== Finding y2.a JNI entry ===");
    Java.perform(function() {
        try {
            // Hook the JNI call from the Java side to capture the native address
            var y2Found = false;
            Java.enumerateClassLoaders({
                onMatch: function(loader) {
                    if (y2Found) return;
                    try {
                        loader.findClass("ms.bd.c.y2");
                        Java.classFactory.loader = loader;
                        y2Found = true;

                        // Use Frida's built-in to find native method
                        var y2 = Java.use("ms.bd.c.y2");

                        // Hook y2.a to see thread + get backtrace
                        y2.a.implementation = function(tag, type, handle, url, extra) {
                            var tid = Process.getCurrentThreadId();
                            console.log("\ny2.a called! tag=" + tag + " type=" + type + " handle=" + handle + " tid=" + tid);

                            // Get native backtrace to find our caller
                            var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                            console.log("Backtrace:");
                            for (var i = 0; i < bt.length; i++) {
                                var addr = bt[i];
                                var modInfo = Process.findModuleByAddress(addr);
                                var offset = modInfo ? addr.sub(modInfo.base) : "?";
                                console.log("  " + addr + " (" + (modInfo ? modInfo.name + "+0x" + offset.toString(16) : "???") + ")");
                            }

                            // Call original
                            return this.a(tag, type, handle, url, extra);
                        };

                        console.log("[+] y2.a hooked, now triggering a sign call...");

                        // Trigger signing
                        var HM = Java.use("java.util.HashMap");
                        Java.choose("ms.bd.c.r4", {
                            onMatch: function(inst) {
                                var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
                                    "?ac=wifi&aid=1967&book_id=7373660003258862617";
                                var h = HM.$new();
                                inst.onCallToAddSecurityFactor(url, h);
                                console.log("[+] Sign call completed");
                            },
                            onComplete: function() {}
                        });
                    } catch(e) { console.log("[!] " + e); }
                },
                onComplete: function() {}
            });
        } catch(e) { console.log("[!] " + e); }
    });

    console.log("\n[DONE]");
}

setTimeout(run, 1000);
