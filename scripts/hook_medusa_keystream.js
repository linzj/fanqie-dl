// Capture AES expanded key schedule and try as keystream for Medusa
// AES-128 key expansion: 16 bytes → 176 bytes (11 rounds × 16)
// Also try: capture ALL function calls between key expansion and Medusa output
//
// Run: frida -U -p <PID> -l scripts/hook_medusa_keystream.js

var libBase = null;
var expandedKey = null;
var allCalls = [];
var capturing = false;

function hex(ptr, len) {
    var b = [];
    for (var i = 0; i < len; i++) b.push(('0' + ptr.add(i).readU8().toString(16)).slice(-2));
    return b.join('');
}

function soOffset(addr) {
    try {
        var n = addr.sub(libBase).toInt32();
        if (n >= 0 && n < 0x400000) return "0x" + n.toString(16);
        return "ext";
    } catch(e) { return "ext"; }
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

function tryAscii(h) {
    var out = '';
    for (var i = 0; i < h.length; i += 2) {
        var c = parseInt(h.substr(i, 2), 16);
        out += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
    }
    return out;
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) return;
    libBase = mod.base;

    // Hook AES key expansion — read full expanded key schedule (176 bytes for AES-128)
    Interceptor.attach(libBase.add(0x241E9C), {
        onEnter: function(args) {
            this.ctx = args[0];
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                // The context structure should contain the expanded key schedule
                // Try reading 176 bytes starting from ctx
                expandedKey = hex(this.ctx, 176);
                console.log("[+] Expanded key captured (" + expandedKey.length/2 + " bytes)");
                // Also try reading more — the ctx might have extra data
                try {
                    var extra = hex(this.ctx, 256);
                    console.log("[+] First 256 bytes of ctx: " + extra.substring(0, 128) + "...");
                } catch(e) {}
            } catch(e) { console.log("[-] Key read error: " + e); }
        }
    });

    // Hook a wide range of functions called during signing to trace the flow
    // Focus on the 0x259xxx-0x25Axxx range (AES-related) and 0x263xxx
    var traceTargets = [
        [0x259C1C, "AES_MODE_SETUP"],
        [0x259CF0, "AES_DISPATCH"],
        [0x259DBC, "AES_SETUP"],
        [0x259E88, "FUNC_259E88"],
        [0x242A70, "AES_CBC"],
        [0x242C98, "AES_CTR"],
        [0x2422EC, "AES_BLOCK"],
        [0x2429F8, "AES_ONESHOT"],
        [0x242DE0, "XOR_FUNC"],
        // Additional functions that might be involved
        [0x263504, "THUNK_263504"],  // calls AES key + SHA-1
        [0x248344, "BUF_OP"],
        [0x2481FC, "CREATE_BUF"],
        [0x25BF3C, "MAP_SET"],
        [0x270020, "INIT_270020"],
        [0x32A1F0, "MALLOC"],
    ];

    for (var i = 0; i < traceTargets.length; i++) {
        (function(offset, name) {
            try {
                Interceptor.attach(libBase.add(offset), {
                    onEnter: function(args) {
                        if (!capturing) return;
                        allCalls.push({
                            func: name,
                            lr: soOffset(this.context.lr)
                        });
                    }
                });
            } catch(e) { console.log("[-] Hook " + name + " failed: " + e); }
        })(traceTargets[i][0], traceTargets[i][1]);
    }

    console.log("[+] Hooks ready");
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

setup();

setTimeout(function() {
    var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
        "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
        "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
        "&device_brand=google&os_api=35&os_version=15" +
        "&device_id=3722313718058683&iid=3722313718062779" +
        "&_rticket=1774940000000" +
        "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
        "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
        "&book_id=7373660003258862617";

    allCalls = [];
    expandedKey = null;
    capturing = true;
    var sigs = doSign(url);
    capturing = false;

    var medusaHex = b64toHex(sigs["X-Medusa"] || "");
    var bodyHex = medusaHex.substring(48);

    console.log("\n=== EXPANDED KEY SCHEDULE ===");
    if (expandedKey) {
        console.log("Full 176 bytes: " + expandedKey);

        // Try XOR body with repeated expanded key
        console.log("\n=== XOR body with expanded key (176 bytes repeated) ===");
        var dec = '';
        for (var i = 0; i < bodyHex.length; i += 2) {
            var pos = (i/2) % 176;
            var keyByte = parseInt(expandedKey.substr(pos * 2, 2), 16);
            var v = parseInt(bodyHex.substr(i, 2), 16) ^ keyByte;
            dec += ('0' + v.toString(16)).slice(-2);
        }
        console.log("first64: " + dec.substring(0, 128));
        console.log("ascii: " + tryAscii(dec.substring(0, 128)));
    }

    // Print function call sequence
    console.log("\n=== FUNCTION CALL SEQUENCE (" + allCalls.length + " calls) ===");
    var prevFunc = "";
    var repeatCount = 0;
    for (var i = 0; i < allCalls.length; i++) {
        var c = allCalls[i];
        if (c.func === prevFunc && c.func === "MALLOC") {
            repeatCount++;
            if (i === allCalls.length - 1 || allCalls[i+1].func !== c.func) {
                console.log("  ... ×" + (repeatCount+1) + " " + c.func);
                repeatCount = 0;
            }
        } else {
            console.log("[" + i + "] " + c.func + " ←" + c.lr);
            prevFunc = c.func;
            repeatCount = 0;
        }
    }

    // Count by function
    console.log("\n=== CALL COUNTS ===");
    var counts = {};
    for (var i = 0; i < allCalls.length; i++) {
        counts[allCalls[i].func] = (counts[allCalls[i].func] || 0) + 1;
    }
    for (var k in counts) {
        console.log("  " + k + ": " + counts[k]);
    }

    console.log("\n[DONE]");
}, 2000);
