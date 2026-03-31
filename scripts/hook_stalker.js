// Use Frida Stalker to trace function calls during signing
// This is heavyweight but will reveal ALL functions called
// Run: frida -U -p <PID> -l scripts/hook_stalker.js

var libBase = null;
var libEnd = null;
var callLog = [];
var capturing = false;

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

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;
    libEnd = libBase.add(mod.size);
    console.log("[+] libmetasec_ml.so @ " + libBase + " - " + libEnd + " (size=" + mod.size + ")");
}

function doSignWithStalker(url) {
    var result = {};
    var tid = Process.getCurrentThreadId();

    // Setup Stalker to trace calls within libmetasec_ml.so
    var calls = {};
    var callOrder = [];
    var callCount = 0;

    Stalker.follow(tid, {
        events: { call: true, ret: false, exec: false, block: false, compile: false },
        onReceive: function(events) {
            var parsed = Stalker.parse(events, { annotate: true, stringify: false });
            for (var i = 0; i < parsed.length; i++) {
                var ev = parsed[i];
                if (ev[0] === 'call') {
                    var from = ptr(ev[1]);
                    var target = ptr(ev[2]);
                    // Only log calls within libmetasec_ml.so
                    if (target.compare(libBase) >= 0 && target.compare(libEnd) < 0) {
                        var offset = target.sub(libBase).toInt32();
                        var offsetHex = '0x' + offset.toString(16);
                        if (!calls[offsetHex]) {
                            calls[offsetHex] = { count: 0, order: callCount };
                        }
                        calls[offsetHex].count++;
                        callCount++;
                        if (callOrder.length < 500) {
                            callOrder.push(offsetHex);
                        }
                    }
                }
            }
        }
    });

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

    Stalker.unfollow(tid);
    Stalker.flush();

    // Sort by first call order
    var sorted = Object.keys(calls).sort(function(a, b) {
        return calls[a].order - calls[b].order;
    });

    return { sigs: result, calls: calls, sorted: sorted, callOrder: callOrder, totalCalls: callCount };
}

function run() {
    var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
        "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
        "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
        "&device_brand=google&os_api=35&os_version=15" +
        "&device_id=3722313718058683&iid=3722313718062779" +
        "&_rticket=1774940000000" +
        "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
        "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
        "&book_id=7373660003258862617";

    console.log("[*] Starting Stalker trace...");
    var r = doSignWithStalker(url);

    var h = b64toHex(r.sigs["X-Helios"] || "");
    console.log("\nHelios hex: " + h);
    console.log("Total function calls: " + r.totalCalls);
    console.log("Unique functions: " + r.sorted.length);

    // Print all unique functions sorted by call order
    console.log("\n=== UNIQUE FUNCTIONS (by first call order) ===");
    for (var i = 0; i < r.sorted.length; i++) {
        var offset = r.sorted[i];
        var info = r.calls[offset];
        console.log("  " + offset + " (x" + info.count + ")");
    }

    // Print known function annotations
    var known = {
        '0x243c34': 'MD5',
        '0x245630': 'SHA256_full',
        '0x258a48': 'SHA256_wrap',
        '0x258780': 'SHA1_wrap',
        '0x241e9c': 'AES_key_expand',
        '0x243f10': 'AES_block_enc',
        '0x243e50': 'AES_block_wrap',
        '0x167e54': 'XOR_decrypt',
        '0x283748': 'sign_main',
        '0x29cf58': 'sign_dispatch',
        '0x29ccd4': 'sign_orch',
        '0x270020': 'sub_270020',
        '0x26732c': 'sub_26732C'
    };

    console.log("\n=== KNOWN FUNCTIONS ===");
    for (var k in known) {
        if (r.calls[k]) {
            console.log("  " + k + " (" + known[k] + "): x" + r.calls[k].count);
        } else {
            console.log("  " + k + " (" + known[k] + "): NOT CALLED");
        }
    }

    // Print first 100 calls in order
    console.log("\n=== FIRST 100 CALL SEQUENCE ===");
    for (var i = 0; i < Math.min(100, r.callOrder.length); i++) {
        var offset = r.callOrder[i];
        var label = known[offset] || "";
        console.log("  [" + i + "] " + offset + (label ? " (" + label + ")" : ""));
    }

    console.log("\n[DONE]");
}

setup();
setTimeout(run, 2000);
