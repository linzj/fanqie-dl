// Deep hook for X-Helios and X-Medusa algorithm extraction
// This hooks at multiple levels to understand the complete data flow:
// 1. Java level: capture full URL input and signature output
// 2. Native level: capture SHA-256 inputs/outputs, AES keys, and decrypted strings
// 3. Differential analysis: call signing twice with different URLs to identify URL-dependent data
//
// Run: frida -U -p <PID> -l scripts/hook_helios_medusa_deep.js

var libBase = null;
var captureEnabled = false;
var captureLog = [];
var callId = 0;

function hex(ptr, len) {
    var b = [];
    for (var i = 0; i < len; i++) b.push(('0' + ptr.add(i).readU8().toString(16)).slice(-2));
    return b.join('');
}

function b64toHex(s) {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var bytes = [];
    var buf = 0, bits = 0;
    for (var i = 0; i < s.length; i++) {
        if (s[i] === '=') break;
        buf = (buf << 6) | chars.indexOf(s[i]);
        bits += 6;
        if (bits >= 8) { bits -= 8; bytes.push(('0' + ((buf >> bits) & 0xff).toString(16)).slice(-2)); }
    }
    return bytes.join('');
}

function log(msg) {
    if (captureEnabled) captureLog.push(msg);
}

function setupHooks() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not loaded"); return; }
    libBase = mod.base;

    // Hook SHA-256 full hash (sub_245630)
    Interceptor.attach(libBase.add(0x245630), {
        onEnter: function(args) {
            this.data = args[0];
            this.len = args[1].toInt32();
            this.out = args[2];
        },
        onLeave: function(ret) {
            if (!captureEnabled) return;
            var input = hex(this.data, Math.min(this.len, 1024));
            var output = hex(this.out, 32);
            log("SHA256(len=" + this.len + "): " + input.substring(0, 200) + (this.len > 100 ? "..." : ""));
            log("  => " + output);

            // Try to identify if input contains URL text
            try {
                var str = this.data.readCString(Math.min(this.len, 200));
                if (str && str.indexOf("http") !== -1) {
                    log("  [contains URL: " + str.substring(0, 100) + "...]");
                }
            } catch(e) {}
        }
    });

    // Hook AES key expansion (sub_241E9C)
    Interceptor.attach(libBase.add(0x241E9C), {
        onEnter: function(args) {
            if (!captureEnabled) return;
            var keyLen = args[2].toInt32();
            var key = hex(args[1], keyLen);
            log("AES_KEYGEN(keyLen=" + keyLen + "): key=" + key);
        }
    });

    // Hook AES-CBC encrypt wrapper area
    // sub_259C1C is AES setup that calls sub_241E9C + sub_2429F8
    Interceptor.attach(libBase.add(0x259C1C), {
        onEnter: function(args) {
            if (!captureEnabled) return;
            log("AES_SETUP_259C1C called");
        }
    });

    // Hook XOR decrypt to capture header name strings
    Interceptor.attach(libBase.add(0x167E54), {
        onEnter: function(args) { this.out = args[1]; },
        onLeave: function(ret) {
            if (!captureEnabled) return;
            try {
                var str = this.out.readCString();
                if (str && str.length > 0 && str.length < 100) {
                    log("XOR_DEC: \"" + str + "\"");
                }
            } catch(e) {}
        }
    });

    // Hook sub_283748 (the big signing function with SHA-256)
    Interceptor.attach(libBase.add(0x283748), {
        onEnter: function(args) {
            if (!captureEnabled) return;
            log("=== sub_283748 ENTER ===");
            // args[0] = some object, args[1] = url-related, args[2] = type
            try {
                // Try to read URL from args
                var ptr0 = args[0];
                var ptr1 = args[1];
                log("  arg0=" + ptr0 + " arg1=" + ptr1 + " arg2=" + args[2]);
            } catch(e) {}
        },
        onLeave: function(ret) {
            if (!captureEnabled) return;
            log("=== sub_283748 LEAVE ===");
        }
    });

    // Hook sub_29CF58 (signing dispatcher)
    Interceptor.attach(libBase.add(0x29CF58), {
        onEnter: function(args) {
            if (!captureEnabled) return;
            log("=== sub_29CF58 ENTER (signing dispatcher) ===");
            // args[0] = unsigned char** (URL strings)
            // args[1] = some value
            // args[2] = config/context
            try {
                var urlPtr = args[0].readPointer();
                if (urlPtr && !urlPtr.isNull()) {
                    var url = urlPtr.readCString();
                    if (url) log("  URL: " + url.substring(0, 200));
                }
            } catch(e) {
                log("  (could not read URL arg)");
            }
        },
        onLeave: function(ret) {
            if (!captureEnabled) return;
            log("=== sub_29CF58 LEAVE ===");
        }
    });

    // Hook sub_26732C - called in sub_283748 before SHA-256
    Interceptor.attach(libBase.add(0x26732C), {
        onEnter: function(args) {
            if (!captureEnabled) return;
            log("sub_26732C: arg0=" + args[0] + " arg1(w)=" + args[1] + " arg2=" + args[2] + " arg3=" + args[3]);
        }
    });

    // Hook sub_270020 - called in sub_283748
    Interceptor.attach(libBase.add(0x270020), {
        onEnter: function(args) {
            if (!captureEnabled) return;
            log("sub_270020: arg0=" + args[0]);
        }
    });

    console.log("[+] All native hooks installed");
}

function doSign(url) {
    var result = {};
    Java.perform(function() {
        Java.enumerateClassLoaders({
            onMatch: function(loader) {
                try {
                    loader.findClass("ms.bd.c.r4");
                    Java.classFactory.loader = loader;
                    var HM = Java.use("java.util.HashMap");
                    Java.choose("ms.bd.c.r4", {
                        onMatch: function(inst) {
                            var headers = HM.$new();
                            var r = inst.onCallToAddSecurityFactor(url, headers);
                            var map = Java.cast(r, HM);
                            var it = map.keySet().iterator();
                            while (it.hasNext()) {
                                var key = it.next();
                                result[key] = map.get(key).toString();
                            }
                        },
                        onComplete: function() {}
                    });
                } catch(e) {}
            },
            onComplete: function() {}
        });
    });
    return result;
}

function runAnalysis() {
    var tsMs = Date.now();
    var baseUrl = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
        "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
        "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
        "&device_brand=google&os_api=35&os_version=15" +
        "&device_id=3722313718058683&iid=3722313718062779" +
        "&_rticket=" + tsMs +
        "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
        "&openudid=9809e655-067c-47fe-a937-b150bfad0be9";

    var url1 = baseUrl + "&book_id=7373660003258862617";
    var url2 = baseUrl + "&book_id=1234567890";

    // === Call 1: First URL ===
    console.log("\n========================================");
    console.log("=== CALL 1: book_id=7373660003258862617 ===");
    console.log("========================================");
    captureLog = [];
    captureEnabled = true;
    var sigs1 = doSign(url1);
    captureEnabled = false;

    console.log("\nSignatures:");
    for (var k in sigs1) {
        var v = sigs1[k];
        if (k === "X-Helios") {
            console.log("  " + k + " = " + v + " (" + b64toHex(v).length/2 + " bytes)");
            console.log("    hex: " + b64toHex(v));
        } else if (k === "X-Medusa") {
            var mhex = b64toHex(v);
            console.log("  " + k + " = ...(" + v.length + " chars, " + mhex.length/2 + " bytes)");
            console.log("    first 48 bytes: " + mhex.substring(0, 96));
        } else {
            console.log("  " + k + " = " + v);
        }
    }

    console.log("\nCrypto log (" + captureLog.length + " entries):");
    for (var i = 0; i < captureLog.length; i++) {
        console.log("  [" + i + "] " + captureLog[i]);
    }
    var log1 = captureLog.slice();

    // === Call 2: Different URL ===
    console.log("\n========================================");
    console.log("=== CALL 2: book_id=1234567890 ===");
    console.log("========================================");
    captureLog = [];
    captureEnabled = true;
    var sigs2 = doSign(url2);
    captureEnabled = false;

    console.log("\nSignatures:");
    for (var k in sigs2) {
        var v = sigs2[k];
        if (k === "X-Helios") {
            console.log("  " + k + " = " + v);
            console.log("    hex: " + b64toHex(v));
        } else if (k === "X-Medusa") {
            var mhex = b64toHex(v);
            console.log("  " + k + " = ...(" + v.length + " chars, " + mhex.length/2 + " bytes)");
            console.log("    first 48 bytes: " + mhex.substring(0, 96));
        } else {
            console.log("  " + k + " = " + v);
        }
    }

    console.log("\nCrypto log (" + captureLog.length + " entries):");
    for (var i = 0; i < captureLog.length; i++) {
        console.log("  [" + i + "] " + captureLog[i]);
    }

    // === Differential analysis ===
    console.log("\n========================================");
    console.log("=== DIFFERENTIAL ANALYSIS ===");
    console.log("========================================");

    // Compare SHA-256 inputs between calls
    var sha1_inputs = log1.filter(function(l) { return l.indexOf("SHA256(") === 0; });
    var sha2_inputs = captureLog.filter(function(l) { return l.indexOf("SHA256(") === 0; });
    console.log("Call 1 SHA-256 operations: " + sha1_inputs.length);
    console.log("Call 2 SHA-256 operations: " + sha2_inputs.length);
    for (var i = 0; i < Math.min(sha1_inputs.length, sha2_inputs.length); i++) {
        var same = sha1_inputs[i] === sha2_inputs[i] ? "SAME" : "DIFFERENT";
        console.log("  SHA256[" + i + "]: " + same);
        if (same === "DIFFERENT") {
            console.log("    call1: " + sha1_inputs[i].substring(0, 120));
            console.log("    call2: " + sha2_inputs[i].substring(0, 120));
        }
    }

    // Compare AES keys
    var aes1 = log1.filter(function(l) { return l.indexOf("AES_KEYGEN") === 0; });
    var aes2 = captureLog.filter(function(l) { return l.indexOf("AES_KEYGEN") === 0; });
    console.log("\nCall 1 AES key operations: " + aes1.length);
    console.log("Call 2 AES key operations: " + aes2.length);
    for (var i = 0; i < Math.min(aes1.length, aes2.length); i++) {
        var same = aes1[i] === aes2[i] ? "SAME" : "DIFFERENT";
        console.log("  AES[" + i + "]: " + same);
        if (same === "SAME") console.log("    " + aes1[i]);
    }

    // Compare decrypted strings
    var dec1 = log1.filter(function(l) { return l.indexOf("XOR_DEC:") === 0; });
    console.log("\nDecrypted strings (call 1):");
    for (var i = 0; i < dec1.length; i++) {
        console.log("  " + dec1[i]);
    }

    console.log("\n[DONE] Copy this output and paste to Claude for algorithm reconstruction");
}

// Setup and run
setupNativeHooks();
setTimeout(function() {
    runAnalysis();
}, 2000);
