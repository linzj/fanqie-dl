// Hook the ALTERNATIVE entry point of AES block encrypt at 0x242640
// The CFF code bypasses the standard entry 0x2422EC and jumps to 0x242640!
//
// 0x2422EC: full entry — uses round keys from [ctx+0x00]
// 0x242640: alt entry  — uses round keys from [ctx+0xF0]
//
// Run: frida -U -p <PID> -l scripts/hook_aes_alt_entry.js

var libBase = null;
var capturing = false;
var aesCount = 0;
var aesEntryCount = 0;
var aesOps = [];

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

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;

    // Hook standard entry
    Interceptor.attach(libBase.add(0x2422EC), {
        onEnter: function(args) {
            if (!capturing) return;
            aesEntryCount++;
            try {
                var inHex = hex(args[1], 16);
                aesOps.push({
                    entry: "0x2422EC",
                    n: aesEntryCount,
                    lr: soOffset(this.context.lr),
                    input: inHex,
                    ctx: args[0].toString()
                });
                this.outPtr = args[2];
            } catch(e) {}
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                aesOps.push({
                    entry: "0x2422EC_OUT",
                    output: hex(this.outPtr, 16)
                });
            } catch(e) {}
        }
    });

    // Hook ALTERNATIVE entry at 0x242640
    Interceptor.attach(libBase.add(0x242640), {
        onEnter: function(args) {
            if (!capturing) return;
            aesCount++;
            try {
                // x0 = ctx (key schedule), x1 = input block ptr, x2 = output ptr
                var inHex = hex(args[1], 16);
                this.outPtr = args[2];
                var entry = {
                    entry: "0x242640",
                    n: aesCount,
                    lr: soOffset(this.context.lr),
                    input: inHex,
                };
                aesOps.push(entry);
            } catch(e) {
                aesOps.push({ entry: "0x242640", err: ""+e });
            }
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                aesOps.push({
                    entry: "0x242640_OUT",
                    n: aesCount,
                    output: hex(this.outPtr, 16)
                });
            } catch(e) {}
        }
    });

    // Hook MD5 for reference
    var md5Count = 0;
    Interceptor.attach(libBase.add(0x243C34), {
        onLeave: function(ret) {
            if (!capturing) return;
            md5Count++;
            aesOps.push({ entry: "MD5_" + md5Count });
        }
    });

    // Hook AES key expansion
    Interceptor.attach(libBase.add(0x241E9C), {
        onEnter: function(args) {
            if (!capturing) return;
            try {
                aesOps.push({
                    entry: "AES_KEY_EXPAND",
                    lr: soOffset(this.context.lr),
                    key: hex(args[1], args[2].toInt32())
                });
            } catch(e) {}
        }
    });

    console.log("[+] Hooks ready (standard + alt AES entry)");
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

    aesOps = [];
    aesCount = 0;
    aesEntryCount = 0;
    capturing = true;
    var sigs = doSign(url);
    capturing = false;

    var medusaHex = b64toHex(sigs["X-Medusa"] || "");
    var heliosHex = b64toHex(sigs["X-Helios"] || "");
    console.log("\nMedusa: " + medusaHex.length/2 + " bytes, body=" + (medusaHex.length/2 - 24));
    console.log("Helios: R=" + heliosHex.substring(0,8) + " p1=" + heliosHex.substring(8,40) + " p2=" + heliosHex.substring(40,72));

    console.log("\n=== AES OPERATIONS ===");
    console.log("Standard entry (0x2422EC) calls: " + aesEntryCount);
    console.log("Alt entry (0x242640) calls: " + aesCount);

    console.log("\n=== DETAILED OPS (" + aesOps.length + ") ===");
    for (var i = 0; i < aesOps.length; i++) {
        var o = aesOps[i];
        var line = "[" + i + "] " + o.entry;
        if (o.n !== undefined) line += " #" + o.n;
        if (o.lr) line += " ←" + o.lr;
        if (o.input) line += " in=" + o.input;
        if (o.output) line += " out=" + o.output;
        if (o.key) line += " key=" + o.key;
        if (o.ctx) line += " ctx=" + o.ctx;
        if (o.note) line += " (" + o.note + ")";
        if (o.err) line += " ERR:" + o.err;
        console.log(line);
    }

    console.log("\n[DONE]");
}, 3000);
