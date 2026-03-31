// Safe version: capture backtraces ONLY in onEnter, and only for MD5
// Run: frida -U -p <PID> -l scripts/hook_callers_safe.js

var libBase = null;
var libEnd = null;
var ops = [];
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

function getSOCallers(ctx) {
    try {
        var bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
        var result = [];
        for (var i = 0; i < bt.length; i++) {
            if (bt[i].compare(libBase) >= 0 && bt[i].compare(libEnd) < 0) {
                result.push('0x' + bt[i].sub(libBase).toString(16));
            }
        }
        return result;
    } catch(e) { return ["err:" + e]; }
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;
    libEnd = libBase.add(mod.size);

    // Hook MD5 — capture backtrace in onEnter, output in onLeave
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.inPtr = args[0];
            this.len = args[1].toInt32();
            this.outPtr = args[2];
            if (capturing) {
                this.callers = getSOCallers(this.context);
            }
        },
        onLeave: function(ret) {
            if (!capturing) return;
            ops.push({
                op: "MD5",
                inLen: this.len,
                input: hex(this.inPtr, Math.min(this.len, 64)),
                output: hex(this.outPtr, 16),
                callers: this.callers
            });
        }
    });

    // Hook AES key expand — backtrace in onEnter only
    Interceptor.attach(libBase.add(0x241E9C), {
        onEnter: function(args) {
            if (!capturing) return;
            var keyLen = args[2].toInt32();
            ops.push({
                op: "AES_KEY",
                key: hex(args[1], keyLen),
                callers: getSOCallers(this.context)
            });
        }
    });

    // Hook sub_270020 — backtrace in onEnter
    Interceptor.attach(libBase.add(0x270020), {
        onEnter: function(args) {
            if (!capturing) return;
            ops.push({
                op: "sub_270020",
                callers: getSOCallers(this.context)
            });
        }
    });

    // Hook SHA1 wrapper — backtrace in onEnter
    Interceptor.attach(libBase.add(0x258780), {
        onEnter: function(args) {
            if (!capturing) return;
            ops.push({
                op: "SHA1",
                callers: getSOCallers(this.context)
            });
        }
    });

    // AES wrapper count only (no backtrace to avoid crash)
    var wrapCount = 0;
    Interceptor.attach(libBase.add(0x243E50), {
        onEnter: function(args) {
            if (capturing) wrapCount++;
        }
    });

    // AES block count only
    var blockCount = 0;
    Interceptor.attach(libBase.add(0x243F10), {
        onEnter: function(args) {
            if (capturing) blockCount++;
        }
    });

    console.log("[+] All hooks installed");
    return { getWrapCount: function() { return wrapCount; }, getBlockCount: function() { return blockCount; },
             reset: function() { wrapCount = 0; blockCount = 0; }};
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

var counters = setup();

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

    ops = [];
    counters.reset();
    capturing = true;
    var sigs = doSign(url);
    capturing = false;

    var h = b64toHex(sigs["X-Helios"] || "");
    console.log("\nHelios: " + h);
    console.log("AES wrap=" + counters.getWrapCount() + " block=" + counters.getBlockCount());

    console.log("\nOps (" + ops.length + "):");
    for (var i = 0; i < ops.length; i++) {
        var e = ops[i];
        var line = "  [" + i + "] " + e.op;
        if (e.inLen !== undefined) line += " inLen=" + e.inLen;
        if (e.input) line += " in=" + e.input.substring(0, 48);
        if (e.output) line += " out=" + e.output;
        if (e.key) line += " key=" + e.key;
        if (e.callers) line += "\n      callers: " + e.callers.join(" ← ");
        console.log(line);
    }

    // Unique callers
    var allCallers = {};
    for (var i = 0; i < ops.length; i++) {
        if (ops[i].callers) {
            for (var j = 0; j < ops[i].callers.length; j++) {
                allCallers[ops[i].callers[j]] = true;
            }
        }
    }
    console.log("\nUnique SO callers:");
    Object.keys(allCallers).sort().forEach(function(c) { console.log("  " + c); });

    console.log("\n[DONE]");
}, 2000);
