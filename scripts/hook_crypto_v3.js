// v3: Focus on capturing MD5 outputs and AES plaintext
// We know MD5 sig is md5(data, len, out16) from IDA
// Run: frida -U -p <PID> -l scripts/hook_crypto_v3.js

var libBase = null;
var ops = [];
var capturing = false;

function hex(ptr, len) {
    var b = [];
    for (var i = 0; i < len; i++) b.push(('0' + ptr.add(i).readU8().toString(16)).slice(-2));
    return b.join('');
}

function tryAscii(h) {
    var out = '';
    for (var i = 0; i < h.length; i += 2) {
        var c = parseInt(h.substr(i, 2), 16);
        out += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
    }
    return out;
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
    console.log("[+] libmetasec_ml.so @ " + libBase);

    // ===== MD5 (sub_243C34) — capture input AND output =====
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.a0 = args[0];
            this.len = args[1].toInt32();
            this.outPtr = args[2];
        },
        onLeave: function(ret) {
            if (!capturing) return;
            var entry = { op: "MD5" };
            try {
                entry.inLen = this.len;
                entry.input = hex(this.a0, Math.min(this.len, 512));
            } catch(e) { entry.inputErr = e.toString(); }
            try {
                entry.output = hex(this.outPtr, 16);
            } catch(e) { entry.outputErr = e.toString(); }
            ops.push(entry);
        }
    });

    // ===== SHA-1 wrapper (sub_258780) =====
    Interceptor.attach(libBase.add(0x258780), {
        onEnter: function(args) {
            this.structPtr = args[0];
            this.outPtr = args[1];
            try {
                this.len = this.structPtr.add(12).readU32();
                this.dataPtr = this.structPtr.add(16).readPointer();
            } catch(e) { this.len = 0; }
        },
        onLeave: function(ret) {
            if (!capturing) return;
            var entry = { op: "SHA1" };
            try {
                entry.inLen = this.len;
                entry.input = hex(this.dataPtr, Math.min(this.len, 256));
            } catch(e) {}
            try {
                // outPtr might be null (crashed before), be extra careful
                if (!this.outPtr.isNull()) {
                    entry.output = hex(this.outPtr, 20);
                }
            } catch(e) { entry.outputErr = e.toString(); }
            ops.push(entry);
        }
    });

    // ===== AES key expansion (sub_241E9C) =====
    Interceptor.attach(libBase.add(0x241E9C), {
        onEnter: function(args) {
            if (!capturing) return;
            var keyLen = args[2].toInt32();
            ops.push({ op: "AES_KEY", keyLen: keyLen, key: hex(args[1], keyLen) });
        }
    });

    // ===== AES block encrypt (sub_243F10) — just count =====
    var aesBlockCount = 0;
    Interceptor.attach(libBase.add(0x243F10), {
        onEnter: function(args) {
            if (!capturing) return;
            aesBlockCount++;
        }
    });

    // ===== AES wrapper (sub_243E50) — count + try to capture first call's input =====
    var aesWrapCount = 0;
    Interceptor.attach(libBase.add(0x243E50), {
        onEnter: function(args) {
            if (!capturing) return;
            aesWrapCount++;
            // Only capture first 2 calls to avoid crash risk
            if (aesWrapCount <= 2) {
                try {
                    // Try to dump args for understanding calling convention
                    ops.push({
                        op: "AES_WRAP",
                        call: aesWrapCount,
                        a0: args[0].toString(),
                        a1: args[1].toString(),
                        a2: args[2].toString(),
                        a3: args[3].toString()
                    });
                } catch(e) {}
            }
        }
    });

    // ===== sub_270020 =====
    Interceptor.attach(libBase.add(0x270020), {
        onEnter: function(args) {
            if (!capturing) return;
            ops.push({ op: "sub_270020" });
        }
    });

    // ===== XOR decrypt (sub_167E54) =====
    Interceptor.attach(libBase.add(0x167E54), {
        onEnter: function(args) { this.out = args[1]; },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                var str = this.out.readCString();
                if (str && str.length > 0 && str.length < 100)
                    ops.push({ op: "XOR_DEC", str: str });
            } catch(e) {}
        }
    });

    // Expose counters via globals
    globalThis._aesBlockCount = function() { return aesBlockCount; };
    globalThis._aesWrapCount = function() { return aesWrapCount; };
    globalThis._resetCounters = function() { aesBlockCount = 0; aesWrapCount = 0; };

    console.log("[+] All hooks installed");
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

function printOps(label) {
    console.log("\n===== " + label + " =====");
    console.log("Ops count: " + ops.length);
    for (var i = 0; i < ops.length; i++) {
        var e = ops[i];
        var line = "  [" + i + "] " + e.op;
        if (e.inLen !== undefined) line += " inLen=" + e.inLen;
        if (e.keyLen) line += " keyLen=" + e.keyLen;
        if (e.key) line += " key=" + e.key;
        if (e.call) line += " #" + e.call;
        if (e.str) line += " \"" + e.str + "\"";
        if (e.input) {
            line += "\n       IN=" + e.input.substring(0, 200);
            if (e.inLen && e.inLen <= 64) line += "\n       ASCII=" + tryAscii(e.input);
        }
        if (e.output) line += "\n       OUT=" + e.output;
        if (e.inputErr) line += " inputErr=" + e.inputErr;
        if (e.outputErr) line += " outputErr=" + e.outputErr;
        if (e.a0) line += " a0=" + e.a0;
        if (e.a1) line += " a1=" + e.a1;
        if (e.a2) line += " a2=" + e.a2;
        if (e.a3) line += " a3=" + e.a3;
        console.log(line);
    }
    console.log("  AES_BLOCK_ENC count: " + globalThis._aesBlockCount());
    console.log("  AES_WRAP count: " + globalThis._aesWrapCount());
}

function run() {
    var tsMs = Date.now();
    var base = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
        "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
        "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
        "&device_brand=google&os_api=35&os_version=15" +
        "&device_id=3722313718058683&iid=3722313718062779" +
        "&_rticket=" + tsMs +
        "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
        "&openudid=9809e655-067c-47fe-a937-b150bfad0be9";
    var url1 = base + "&book_id=7373660003258862617";
    var url2 = base + "&book_id=1234567890";

    // Call 1
    ops = [];
    globalThis._resetCounters();
    capturing = true;
    var sigs1 = doSign(url1);
    capturing = false;
    var h1 = b64toHex(sigs1["X-Helios"] || "");
    var m1 = b64toHex(sigs1["X-Medusa"] || "");
    console.log("\n=== CALL 1 ===");
    console.log("X-Helios (" + h1.length/2 + "b): " + h1);
    console.log("X-Medusa first 48b: " + m1.substring(0, 96));
    printOps("CALL 1 OPS");
    var ops1 = ops.slice();

    // Call 2
    ops = [];
    globalThis._resetCounters();
    capturing = true;
    var sigs2 = doSign(url2);
    capturing = false;
    var h2 = b64toHex(sigs2["X-Helios"] || "");
    var m2 = b64toHex(sigs2["X-Medusa"] || "");
    console.log("\n=== CALL 2 ===");
    console.log("X-Helios (" + h2.length/2 + "b): " + h2);
    console.log("X-Medusa first 48b: " + m2.substring(0, 96));
    printOps("CALL 2 OPS");

    // Correlation analysis
    console.log("\n=== HELIOS STRUCTURE ANALYSIS ===");
    console.log("h1: " + h1);
    console.log("    bytes[0:4]  = " + h1.substring(0, 8) + " (random nonce)");
    console.log("    bytes[4:20] = " + h1.substring(8, 40) + " (part1, 16 bytes)");
    console.log("    bytes[20:36]= " + h1.substring(40, 72) + " (part2, 16 bytes)");
    console.log("h2: " + h2);
    console.log("    bytes[0:4]  = " + h2.substring(0, 8) + " (random nonce)");
    console.log("    bytes[4:20] = " + h2.substring(8, 40) + " (part1, 16 bytes)");
    console.log("    bytes[20:36]= " + h2.substring(40, 72) + " (part2, 16 bytes)");

    // Match MD5 outputs to Helios parts
    console.log("\n=== MD5 OUTPUT vs HELIOS CORRELATION ===");
    var md5ops1 = ops1.filter(function(e) { return e.op === "MD5" && e.output; });
    for (var i = 0; i < md5ops1.length; i++) {
        var out = md5ops1[i].output;
        var inH1 = h1.indexOf(out) >= 0;
        console.log("MD5[" + i + "] out=" + out + (inH1 ? " ★ FOUND IN HELIOS at offset " + h1.indexOf(out)/2 : ""));
    }

    console.log("\n[DONE]");
}

setup();
setTimeout(run, 2000);
