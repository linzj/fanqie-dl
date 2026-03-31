// Check if MD5 wrapper transforms the MD5 output
// Strategy: record MD5 output buffer pointer, then check if data changed when wrapper returns
// Run: frida -U -p <PID> -l scripts/hook_md5_transform.js

var libBase = null;
var capturing = false;
var lastMD5OutPtr = null;
var lastMD5Out = "";
var results = [];

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
    if (!mod) return;
    libBase = mod.base;

    // Hook raw MD5 — capture output buffer pointer and data
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.outPtr = args[2];
            this.inLen = args[1].toInt32();
        },
        onLeave: function(ret) {
            if (!capturing) return;
            lastMD5OutPtr = this.outPtr;
            try { lastMD5Out = hex(this.outPtr, 16); } catch(e) { lastMD5Out = "ERR"; }
        }
    });

    // Hook MD5 wrapper — in onLeave, check if MD5 output buffer was modified
    var wrapN = 0;
    Interceptor.attach(libBase.add(0x258530), {
        onEnter: function(args) {
            if (!capturing) return;
            this.myN = ++wrapN;
            // Reset
            lastMD5OutPtr = null;
            lastMD5Out = "";
        },
        onLeave: function(ret) {
            if (!capturing) return;
            var entry = { n: this.myN, md5Raw: lastMD5Out, retIsNull: ret.isNull() };

            // Read from the saved MD5 output buffer to see if it changed
            if (lastMD5OutPtr) {
                try {
                    var current = hex(lastMD5OutPtr, 16);
                    entry.md5BufNow = current;
                    entry.changed = (current !== lastMD5Out);
                } catch(e) { entry.readErr = "" + e; }
            }

            // Read 64 bytes around the MD5 output buffer
            if (lastMD5OutPtr) {
                try { entry.bufContext = hex(lastMD5OutPtr.sub(16), 64); } catch(e) {}
            }

            results.push(entry);
        }
    });

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

    results = [];
    capturing = true;
    var sigs = doSign(url);
    capturing = false;

    var h = b64toHex(sigs["X-Helios"] || "");
    console.log("\nHelios: " + h);
    console.log("  R    =" + h.substring(0,8));
    console.log("  part1=" + h.substring(8,40));
    console.log("  part2=" + h.substring(40,72));

    console.log("\n=== MD5 OUTPUT BUFFER ANALYSIS ===");
    for (var i = 0; i < results.length; i++) {
        var r = results[i];
        console.log("\nWrap[" + r.n + "]:");
        console.log("  MD5 raw output  : " + r.md5Raw);
        console.log("  Buffer now      : " + (r.md5BufNow || "?"));
        console.log("  Changed?        : " + (r.changed !== undefined ? r.changed : "?"));
        console.log("  Ret null?       : " + r.retIsNull);
        if (r.bufContext) console.log("  Context[-16:+48]: " + r.bufContext);
        if (r.readErr) console.log("  Read error      : " + r.readErr);

        // Check if buffer now matches Helios parts
        if (r.md5BufNow) {
            var p1 = h.substring(8,40);
            var p2 = h.substring(40,72);
            if (r.md5BufNow === p1) console.log("  ★★★ Buffer matches part1!");
            if (r.md5BufNow === p2) console.log("  ★★★ Buffer matches part2!");
        }
    }

    console.log("\n[DONE]");
}, 3000);
