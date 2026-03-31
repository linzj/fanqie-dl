// Search for additional crypto functions in the SO
// Look for MD5 constants, SHA constants, base64 encoding, etc.
// Also hook at native y2.a level to find the actual JNI function
// Run: frida -U -p <PID> -l scripts/hook_find_crypto.js

function run() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    var base = mod.base;
    console.log("[+] SO @ " + base + " size=" + mod.size);

    // Search for MD5 T constants (first few)
    // T[1] = 0xd76aa478 → LE bytes: 78 a4 6a d7
    console.log("\n=== MD5 T[1] constant (0xd76aa478) locations ===");
    var md5Results = Memory.scanSync(base, mod.size, "78 a4 6a d7");
    for (var i = 0; i < md5Results.length; i++) {
        var offset = md5Results[i].address.sub(base);
        console.log("  found at offset 0x" + offset.toString(16));
    }

    // SHA-256 K constants - first constant 0x428a2f98
    console.log("\n=== SHA-256 K[0] constant (0x428a2f98) ===");
    var sha256Results = Memory.scanSync(base, mod.size, "98 2f 8a 42");
    for (var i = 0; i < sha256Results.length; i++) {
        var offset = sha256Results[i].address.sub(base);
        console.log("  found at offset 0x" + offset.toString(16));
    }

    // SHA-1 init constant 0x67452301 (also used by MD5)
    console.log("\n=== SHA1/MD5 init H0 (0x67452301) ===");
    var sha1Results = Memory.scanSync(base, mod.size, "01 23 45 67");
    for (var i = 0; i < sha1Results.length; i++) {
        var offset = sha1Results[i].address.sub(base);
        console.log("  found at offset 0x" + offset.toString(16));
    }

    // AES S-box first bytes: 63 7c 77 7b f2 6b 6f c5
    console.log("\n=== AES S-box signature ===");
    var aesResults = Memory.scanSync(base, mod.size, "63 7c 77 7b f2 6b 6f c5");
    for (var i = 0; i < aesResults.length; i++) {
        var offset = aesResults[i].address.sub(base);
        console.log("  found at offset 0x" + offset.toString(16));
    }

    // Base64 alphabet "ABCDEFGH"
    console.log("\n=== Base64 alphabet locations ===");
    var b64Results = Memory.scanSync(base, mod.size, "41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64");
    for (var i = 0; i < b64Results.length; i++) {
        var offset = b64Results[i].address.sub(base);
        console.log("  found at offset 0x" + offset.toString(16));
    }

    // HMAC ipad constant 0x36363636
    console.log("\n=== HMAC ipad (0x36363636) ===");
    var hmacResults = Memory.scanSync(base, mod.size, "36 36 36 36 36 36 36 36");
    for (var i = 0; i < hmacResults.length; i++) {
        var offset = hmacResults[i].address.sub(base);
        console.log("  found at offset 0x" + offset.toString(16));
    }

    // Now find the JNI native for y2.a
    console.log("\n=== Finding y2.a native implementation ===");
    Java.perform(function() {
        Java.enumerateClassLoaders({
            onMatch: function(loader) {
                try {
                    loader.findClass("ms.bd.c.y2");
                    Java.classFactory.loader = loader;
                    var y2 = Java.use("ms.bd.c.y2");

                    // Try to get the native method address using reflection
                    var methods = y2.class.getDeclaredMethods();
                    for (var i = 0; i < methods.length; i++) {
                        var m = methods[i];
                        var name = m.getName();
                        var mods = m.getModifiers();
                        var isNative = (mods & 0x100) !== 0; // Modifier.NATIVE
                        if (isNative) {
                            console.log("  Native method: " + name + " params=" + m.getParameterTypes().length);
                        }
                    }

                    // Try to find the native entry using ART internals
                    // On Android, artMethod has entry_point_from_jni_ at specific offset
                    try {
                        var Method = Java.use("java.lang.reflect.Method");
                        var y2Class = y2.class;
                        var aMethod = y2Class.getDeclaredMethod("a",
                            Java.use("int").class,
                            Java.use("int").class,
                            Java.use("long").class,
                            Java.use("java.lang.String").class,
                            Java.use("java.lang.Object").class);

                        // artMethod is at Method.artMethod field
                        var artMethodField = Method.class.getDeclaredField("artMethod");
                        artMethodField.setAccessible(true);
                        var artMethodPtr = artMethodField.get(aMethod);
                        console.log("  artMethod pointer: " + artMethodPtr);

                        // The JNI entry point is typically at offset 8 or 16 in ArtMethod
                        // For Android 12+, it's usually at offset 8
                        var artPtr = ptr(artMethodPtr);
                        for (var off = 0; off <= 48; off += 8) {
                            try {
                                var entry = artPtr.add(off).readPointer();
                                // Check if this points into libmetasec_ml.so
                                if (entry.compare(base) >= 0 && entry.compare(base.add(mod.size)) < 0) {
                                    var funcOffset = entry.sub(base);
                                    console.log("  ★ Possible JNI entry at artMethod+" + off + ": 0x" + funcOffset.toString(16));
                                }
                            } catch(e) {}
                        }
                    } catch(e) {
                        console.log("  Error finding artMethod: " + e);
                    }
                } catch(e) {}
            },
            onComplete: function() {}
        });
    });

    console.log("\n[DONE]");
}

setTimeout(run, 1000);
