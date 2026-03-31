// Hook the MD5 wrapper function at 0x258530 to see if it transforms MD5 output
// Also capture the args it receives and what it returns
// Run: frida -U -p <PID> -l scripts/hook_md5_wrapper.js

var libBase = null;
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

function soOffset(addr) {
    try {
        var off = addr.sub(libBase);
        var n = off.toInt32();
        if (n >= 0 && n < 4079616) return "0x" + n.toString(16);
        return "ext";
    } catch(e) { return "ext"; }
}

function tryHex(ptr, len) {
    try { return hex(ptr, len); } catch(e) { return "ERR"; }
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;

    // Hook MD5 wrapper at 0x258530
    // Capture args on entry, MD5 output, and wrapper return
    var md5WrapCallN = 0;
    Interceptor.attach(libBase.add(0x258530), {
        onEnter: function(args) {
            if (!capturing) return;
            md5WrapCallN++;
            this.callN = md5WrapCallN;
            this.lr = soOffset(this.context.lr);

            // Capture all first 5 args as pointers
            this.a = [];
            for (var i = 0; i < 5; i++) {
                this.a.push(args[i]);
            }

            // Try to read as struct: the IDA analysis says SHA-256 wrapper reads
            // data from struct(+12=len, +16=data_ptr). Maybe MD5 wrapper is similar.
            var entry = { op: "MD5_WRAP_ENTER_" + this.callN, lr: this.lr };
            try {
                // args[0] might be a struct pointer
                var a0 = args[0];
                entry.a0 = a0.toString();

                // Try struct interpretation: offset 12 = len, offset 16 = data ptr
                try {
                    var structLen = a0.add(12).readU32();
                    var structData = a0.add(16).readPointer();
                    if (structLen > 0 && structLen < 10000) {
                        entry.structLen = structLen;
                        entry.structData = tryHex(structData, Math.min(structLen, 32));
                    }
                } catch(e2) {}

                // Try args[1] as output buffer pointer
                entry.a1 = args[1].toString();

                // Also try reading first 16 bytes at args[1] (might be output buffer, check BEFORE and AFTER)
                try {
                    entry.a1_before = tryHex(args[1], 16);
                } catch(e3) {}
            } catch(e) { entry.err = e.toString(); }
            ops.push(entry);
        },
        onLeave: function(ret) {
            if (!capturing) return;
            var entry = { op: "MD5_WRAP_LEAVE_" + this.callN };
            entry.ret = ret.toString();

            // If return is non-NULL, try to read 16 bytes (MD5 output?) and 32 bytes
            if (!ret.isNull()) {
                try { entry.ret16 = hex(ret, 16); } catch(e) { entry.ret16err = e.toString(); }
                try { entry.ret32 = hex(ret, 32); } catch(e) {}
            }

            // Also check if a0 buffer was modified (result stored in-place?)
            try { entry.a0_after16 = hex(this.a[0], 16); } catch(e) {}

            ops.push(entry);
        }
    });

    // Hook raw MD5 for reference
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.len = args[1].toInt32();
            this.outPtr = args[2];
        },
        onLeave: function(ret) {
            if (!capturing) return;
            ops.push({
                op: "MD5_RAW",
                inLen: this.len,
                output: hex(this.outPtr, 16)
            });
        }
    });

    // Also hook the caller functions to see their args
    // 0x286df8 area: find function start for the main signing function
    // Let me hook the functions that call MD5_wrapper
    // From the call chain: 0x286df8 calls MD5_wrap for url hash
    // Let me find the function containing 0x286df8

    // Hook the function at 0x26fc98 (the init/setup function)
    Interceptor.attach(libBase.add(0x26fc98), {
        onEnter: function(args) {
            if (!capturing) return;
            ops.push({ op: "INIT_26fc98", lr: soOffset(this.context.lr) });
        }
    });

    console.log("[+] Hooks installed");
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

    ops = [];
    capturing = true;
    var sigs = doSign(url);
    capturing = false;

    var h = b64toHex(sigs["X-Helios"] || "");
    console.log("\nHelios: " + h);
    console.log("  R=" + h.substring(0,8) + " part1=" + h.substring(8,40) + " part2=" + h.substring(40,72));

    // Get the raw MD5 outputs for reference
    var md5Outs = ops.filter(function(e) { return e.op === "MD5_RAW"; }).map(function(e) { return e.output; });
    console.log("MD5 outputs: " + md5Outs.join(" | "));

    console.log("\nOps (" + ops.length + "):");
    for (var i = 0; i < ops.length; i++) {
        var e = ops[i];
        var line = "  [" + i + "] " + e.op;
        if (e.lr) line += " ← " + e.lr;
        if (e.inLen !== undefined) line += " inLen=" + e.inLen;
        if (e.output) line += " out=" + e.output;
        if (e.a0) line += " a0=" + e.a0;
        if (e.a1) line += " a1=" + e.a1;
        if (e.structLen !== undefined) line += " structLen=" + e.structLen;
        if (e.structData) line += " structData=" + e.structData;
        if (e.a1_before) line += " a1_before=" + e.a1_before;
        if (e.a1_after) line += " a1_after=" + e.a1_after;
        if (e.ret) line += " ret=" + e.ret;
        if (e.err) line += " ERR=" + e.err;
        console.log(line);
    }

    // Check if wrapper transforms MD5 output
    console.log("\n=== MD5 WRAPPER OUTPUT COMPARISON ===");
    var wrapLeaves = ops.filter(function(e) { return e.op.indexOf("MD5_WRAP_LEAVE") === 0; });
    for (var i = 0; i < wrapLeaves.length; i++) {
        var w = wrapLeaves[i];
        var rawOut = md5Outs[i] || "?";
        console.log("  Wrap " + (i+1) + ": a1_after=" + (w.a1_after || "?") + " md5_raw=" + rawOut);
        if (w.a1_after && w.a1_after !== rawOut) {
            console.log("    ★ DIFFERENT! The wrapper transforms the output!");
        } else if (w.a1_after === rawOut) {
            console.log("    Same as raw MD5");
        }
    }

    console.log("\n[DONE]");
}, 3000);
