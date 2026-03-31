// Minimal: Just capture LR (return address) for each crypto call
// No Thread.backtrace — just read x30 from context
// Run: frida -U -p <PID> -l scripts/hook_lr_only.js

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
    if (!libBase) return "?";
    try {
        var off = addr.sub(libBase);
        var n = off.toInt32();
        if (n >= 0 && n < 4079616) return "0x" + n.toString(16);
        return "ext";
    } catch(e) { return "ext"; }
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;

    // MD5
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.inPtr = args[0];
            this.len = args[1].toInt32();
            this.outPtr = args[2];
            if (capturing) this.lr = soOffset(this.context.lr);
        },
        onLeave: function(ret) {
            if (!capturing) return;
            ops.push({
                op: "MD5", inLen: this.len,
                input: hex(this.inPtr, Math.min(this.len, 64)),
                output: hex(this.outPtr, 16),
                lr: this.lr
            });
        }
    });

    // AES key expand
    Interceptor.attach(libBase.add(0x241E9C), {
        onEnter: function(args) {
            if (!capturing) return;
            var keyLen = args[2].toInt32();
            ops.push({ op: "AES_KEY", key: hex(args[1], keyLen), lr: soOffset(this.context.lr) });
        }
    });

    // sub_270020
    Interceptor.attach(libBase.add(0x270020), {
        onEnter: function(args) {
            if (!capturing) return;
            ops.push({ op: "sub_270020", lr: soOffset(this.context.lr) });
        }
    });

    // SHA1 wrapper
    Interceptor.attach(libBase.add(0x258780), {
        onEnter: function(args) {
            if (!capturing) return;
            ops.push({ op: "SHA1", lr: soOffset(this.context.lr) });
        }
    });

    // AES wrapper — first 3 calls with LR
    var wrapN = 0;
    Interceptor.attach(libBase.add(0x243E50), {
        onEnter: function(args) {
            if (!capturing) return;
            wrapN++;
            if (wrapN <= 3) {
                ops.push({ op: "AES_WRAP_" + wrapN, lr: soOffset(this.context.lr) });
            }
        }
    });

    // AES block
    var blockN = 0;
    Interceptor.attach(libBase.add(0x243F10), {
        onEnter: function(args) {
            if (!capturing) return;
            blockN++;
            if (blockN <= 3) {
                ops.push({ op: "AES_BLOCK_" + blockN, lr: soOffset(this.context.lr) });
            }
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

    console.log("\nOps (" + ops.length + "):");
    for (var i = 0; i < ops.length; i++) {
        var e = ops[i];
        var line = "  [" + i + "] " + e.op;
        if (e.inLen !== undefined) line += " inLen=" + e.inLen;
        if (e.input) line += " in=" + e.input.substring(0, 48);
        if (e.output) line += " out=" + e.output;
        if (e.key) line += " key=" + e.key;
        line += " ← " + e.lr;
        console.log(line);
    }

    console.log("\n[DONE]");
}, 3000);
