// Simple: hook MD5 wrapper, read 16-32 bytes at return pointer if non-NULL
// Compare with raw MD5 output to see if wrapper transforms it
// Run: frida -U -p <PID> -l scripts/hook_wrap_ret.js

var libBase = null;
var capturing = false;
var md5RawOuts = [];
var wrapResults = [];

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
        var n = addr.sub(libBase).toInt32();
        if (n >= 0 && n < 4079616) return "0x" + n.toString(16);
        return "ext";
    } catch(e) { return "ext"; }
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) return;
    libBase = mod.base;

    // Raw MD5 output
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.outPtr = args[2]; this.len = args[1].toInt32();
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try { md5RawOuts.push(hex(this.outPtr, 16)); } catch(e) { md5RawOuts.push("ERR"); }
        }
    });

    // MD5 wrapper — focus on return value and stack output buffer
    Interceptor.attach(libBase.add(0x258530), {
        onEnter: function(args) {
            if (!capturing) return;
            this.lr = soOffset(this.context.lr);
            this.fp = this.context.x29;  // frame pointer
            this.a0 = args[0];
            this.a1Len = args[1].toInt32();
        },
        onLeave: function(ret) {
            if (!capturing) return;
            var entry = { lr: this.lr, inLen: this.a1Len, ret: ret.toString() };

            // Try to read from return pointer
            if (!ret.isNull()) {
                try { entry.retData = hex(ret, 32); } catch(e) { entry.retDataErr = ""+e; }
            }

            // Try to read from stack output buffer at FP-0x18 (from disassembly)
            try {
                var stackBuf = this.fp.sub(0x18);
                entry.stackOut = hex(stackBuf, 16);
            } catch(e) { entry.stackOutErr = ""+e; }

            // Also try FP-0x28, FP-0x38 (other possible offsets)
            try { entry.fpM28 = hex(this.fp.sub(0x28), 16); } catch(e) {}
            try { entry.fpM38 = hex(this.fp.sub(0x38), 16); } catch(e) {}

            wrapResults.push(entry);
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

    md5RawOuts = [];
    wrapResults = [];
    capturing = true;
    var sigs = doSign(url);
    capturing = false;

    var h = b64toHex(sigs["X-Helios"] || "");
    console.log("\nHelios: " + h);
    console.log("  R=" + h.substring(0,8));
    console.log("  part1=" + h.substring(8,40));
    console.log("  part2=" + h.substring(40,72));

    console.log("\n=== WRAPPER RESULTS ===");
    for (var i = 0; i < wrapResults.length; i++) {
        var w = wrapResults[i];
        var md5 = md5RawOuts[i] || "?";
        console.log("\nWrap[" + i + "] ← " + w.lr + " inLen=" + w.inLen);
        console.log("  MD5_raw = " + md5);
        console.log("  ret     = " + w.ret);
        if (w.retData) console.log("  ret[0:32]= " + w.retData);
        if (w.retDataErr) console.log("  retErr  = " + w.retDataErr);
        if (w.stackOut) console.log("  FP-0x18 = " + w.stackOut);
        if (w.stackOutErr) console.log("  stackErr= " + w.stackOutErr);
        if (w.fpM28) console.log("  FP-0x28 = " + w.fpM28);
        if (w.fpM38) console.log("  FP-0x38 = " + w.fpM38);

        // Check if any output matches Helios parts
        var p1 = h.substring(8,40);
        var p2 = h.substring(40,72);
        if (w.retData) {
            if (w.retData.substring(0,32) === p1) console.log("  ★★★ ret matches part1!");
            if (w.retData.substring(0,32) === p2) console.log("  ★★★ ret matches part2!");
            if (w.retData.indexOf(p1) >= 0) console.log("  ★ ret contains part1!");
            if (w.retData.indexOf(p2) >= 0) console.log("  ★ ret contains part2!");
        }
        if (w.stackOut) {
            if (w.stackOut === p1) console.log("  ★★★ stack matches part1!");
            if (w.stackOut === p2) console.log("  ★★★ stack matches part2!");
        }
    }

    console.log("\n[DONE]");
}, 3000);
