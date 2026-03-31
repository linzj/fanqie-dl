// Enhanced crypto hook v2 - captures MD5/SHA1/AES inputs and outputs
// Run: frida -U -p <PID> -l scripts/hook_crypto_v2.js

var libBase = null;
var cryptoLog = [];
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

function tryAscii(hexStr) {
    var out = '';
    for (var i = 0; i < hexStr.length; i += 2) {
        var c = parseInt(hexStr.substr(i, 2), 16);
        if (c >= 0x20 && c < 0x7f) out += String.fromCharCode(c);
        else out += '.';
    }
    return out;
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;
    console.log("[+] libmetasec_ml.so @ " + libBase);

    // ===== MD5 (sub_243C34) =====
    // Unknown calling convention. Try (data, len, out) safely.
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.a0 = args[0];
            this.a1 = args[1];
            this.a2 = args[2];
            this.possibleLen = args[1].toInt32();
        },
        onLeave: function(ret) {
            if (!capturing) return;
            var entry = { op: "MD5" };
            try {
                var len = this.possibleLen;
                if (len > 0 && len < 10000) {
                    entry.inputLen = len;
                    entry.input = hex(this.a0, Math.min(len, 256));
                    entry.inputAscii = tryAscii(entry.input.substring(0, 128));
                } else {
                    entry.a0 = this.a0.toString();
                    entry.a1 = this.a1.toString();
                    entry.a2 = this.a2.toString();
                }
            } catch(e) { entry.error = e.toString(); }
            cryptoLog.push(entry);
        }
    });

    // ===== SHA-256 full (sub_245630) =====
    Interceptor.attach(libBase.add(0x245630), {
        onEnter: function(args) {
            this.data = args[0]; this.len = args[1].toInt32(); this.out = args[2];
        },
        onLeave: function(ret) {
            if (!capturing) return;
            cryptoLog.push({
                op: "SHA256",
                inputLen: this.len,
                input: hex(this.data, Math.min(this.len, 256)),
                output: hex(this.out, 32)
            });
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
            var entry = { op: "SHA1", inputLen: this.len };
            try {
                entry.input = hex(this.dataPtr, Math.min(this.len, 256));
                entry.inputAscii = tryAscii(entry.input.substring(0, 128));
                entry.output = hex(this.outPtr, 20);
            } catch(e) { entry.error = e.toString(); }
            cryptoLog.push(entry);
        }
    });

    // ===== SHA-256 wrapper (sub_258A48) =====
    Interceptor.attach(libBase.add(0x258A48), {
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
            var entry = { op: "SHA256_WRAP", inputLen: this.len };
            try {
                entry.input = hex(this.dataPtr, Math.min(this.len, 256));
                entry.output = hex(this.outPtr, 32);
            } catch(e) { entry.error = e.toString(); }
            cryptoLog.push(entry);
        }
    });

    // ===== AES key expansion (sub_241E9C) =====
    Interceptor.attach(libBase.add(0x241E9C), {
        onEnter: function(args) {
            if (!capturing) return;
            var keyLen = args[2].toInt32();
            cryptoLog.push({
                op: "AES_KEY",
                keyLen: keyLen,
                key: hex(args[1], keyLen)
            });
        }
    });

    // ===== AES block encrypt (sub_243F10) =====
    var aesEncCount = 0;
    Interceptor.attach(libBase.add(0x243F10), {
        onEnter: function(args) {
            if (!capturing) return;
            aesEncCount++;
        }
    });

    // ===== AES block wrapper (sub_243E50) =====
    Interceptor.attach(libBase.add(0x243E50), {
        onEnter: function(args) {
            if (!capturing) return;
            cryptoLog.push({ op: "AES_WRAP_243E50", a0: args[0].toString() });
        }
    });

    // ===== XOR decrypt (sub_167E54) =====
    Interceptor.attach(libBase.add(0x167E54), {
        onEnter: function(args) { this.out = args[1]; },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                var str = this.out.readCString();
                if (str && str.length > 0 && str.length < 100) {
                    cryptoLog.push({ op: "XOR_DEC", str: str });
                }
            } catch(e) {}
        }
    });

    // ===== sub_26732C (before SHA-256 in sign func) =====
    Interceptor.attach(libBase.add(0x26732C), {
        onEnter: function(args) {
            if (!capturing) return;
            cryptoLog.push({
                op: "sub_26732C",
                a0: args[0].toString(), a1: args[1].toString(),
                a2: args[2].toString(), a3: args[3].toString()
            });
        }
    });

    // ===== sub_270020 =====
    Interceptor.attach(libBase.add(0x270020), {
        onEnter: function(args) {
            if (!capturing) return;
            cryptoLog.push({ op: "sub_270020", a0: args[0].toString() });
        }
    });

    // ===== Sign function (sub_283748) =====
    Interceptor.attach(libBase.add(0x283748), {
        onEnter: function(args) {
            if (!capturing) return;
            cryptoLog.push({ op: "SIGN_283748", phase: "enter" });
        },
        onLeave: function(ret) {
            if (!capturing) return;
            cryptoLog.push({ op: "SIGN_283748", phase: "leave" });
        }
    });

    // ===== Sign dispatcher (sub_29CF58) =====
    Interceptor.attach(libBase.add(0x29CF58), {
        onEnter: function(args) {
            if (!capturing) return;
            cryptoLog.push({ op: "SIGN_29CF58", phase: "enter" });
        },
        onLeave: function(ret) {
            if (!capturing) return;
            cryptoLog.push({ op: "SIGN_29CF58", phase: "leave" });
        }
    });

    // ===== Sign orchestrator (sub_29CCD4) =====
    Interceptor.attach(libBase.add(0x29CCD4), {
        onEnter: function(args) {
            if (!capturing) return;
            cryptoLog.push({ op: "SIGN_29CCD4", phase: "enter" });
        },
        onLeave: function(ret) {
            if (!capturing) return;
            cryptoLog.push({ op: "SIGN_29CCD4", phase: "leave" });
        }
    });

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

function run() {
    var tsMs = Date.now();
    var url1 = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
        "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
        "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
        "&device_brand=google&os_api=35&os_version=15" +
        "&device_id=3722313718058683&iid=3722313718062779" +
        "&_rticket=" + tsMs +
        "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
        "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
        "&book_id=7373660003258862617";

    var url2 = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
        "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
        "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
        "&device_brand=google&os_api=35&os_version=15" +
        "&device_id=3722313718058683&iid=3722313718062779" +
        "&_rticket=" + tsMs +
        "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
        "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
        "&book_id=1234567890";

    // ===== Call 1 =====
    console.log("\n===== CALL 1 (book_id=7373660003258862617) =====");
    cryptoLog = [];
    capturing = true;
    var sigs1 = doSign(url1);
    capturing = false;

    var helios1 = sigs1["X-Helios"] || "";
    var medusa1 = sigs1["X-Medusa"] || "";
    console.log("X-Helios hex: " + b64toHex(helios1));
    console.log("X-Medusa first 48 bytes: " + b64toHex(medusa1).substring(0, 96));

    console.log("\nCrypto ops (" + cryptoLog.length + "):");
    for (var i = 0; i < cryptoLog.length; i++) {
        var e = cryptoLog[i];
        var line = "  [" + i + "] " + e.op;
        if (e.phase) line += " " + e.phase;
        if (e.keyLen) line += " keyLen=" + e.keyLen;
        if (e.key) line += " key=" + e.key;
        if (e.inputLen !== undefined) line += " inLen=" + e.inputLen;
        if (e.input) line += "\n       in=" + e.input;
        if (e.inputAscii) line += "\n       ascii=" + e.inputAscii;
        if (e.output) line += "\n       out=" + e.output;
        if (e.plaintext) line += " pt=" + e.plaintext;
        if (e.ciphertext) line += " ct=" + e.ciphertext;
        if (e.str) line += " \"" + e.str + "\"";
        if (e.a0) line += " a0=" + e.a0;
        if (e.bt) line += " bt=[" + e.bt.join(",") + "]";
        if (e.error) line += " ERR=" + e.error;
        console.log(line);
    }
    var log1 = cryptoLog.slice();

    // ===== Call 2 =====
    console.log("\n===== CALL 2 (book_id=1234567890) =====");
    cryptoLog = [];
    capturing = true;
    var sigs2 = doSign(url2);
    capturing = false;

    var helios2 = sigs2["X-Helios"] || "";
    var medusa2 = sigs2["X-Medusa"] || "";
    console.log("X-Helios hex: " + b64toHex(helios2));
    console.log("X-Medusa first 48 bytes: " + b64toHex(medusa2).substring(0, 96));

    console.log("\nCrypto ops (" + cryptoLog.length + "):");
    for (var i = 0; i < cryptoLog.length; i++) {
        var e = cryptoLog[i];
        var line = "  [" + i + "] " + e.op;
        if (e.phase) line += " " + e.phase;
        if (e.keyLen) line += " keyLen=" + e.keyLen;
        if (e.key) line += " key=" + e.key;
        if (e.inputLen !== undefined) line += " inLen=" + e.inputLen;
        if (e.input) line += "\n       in=" + e.input;
        if (e.inputAscii) line += "\n       ascii=" + e.inputAscii;
        if (e.output) line += "\n       out=" + e.output;
        if (e.plaintext) line += " pt=" + e.plaintext;
        if (e.ciphertext) line += " ct=" + e.ciphertext;
        if (e.str) line += " \"" + e.str + "\"";
        if (e.a0) line += " a0=" + e.a0;
        if (e.error) line += " ERR=" + e.error;
        console.log(line);
    }
    var log2 = cryptoLog;

    // ===== Diff =====
    console.log("\n===== DIFFERENTIAL =====");
    // Compare SHA1 inputs/outputs
    var sha1_1 = log1.filter(function(e) { return e.op === "SHA1"; });
    var sha1_2 = log2.filter(function(e) { return e.op === "SHA1"; });
    console.log("SHA1 calls: " + sha1_1.length + " vs " + sha1_2.length);
    for (var i = 0; i < Math.max(sha1_1.length, sha1_2.length); i++) {
        if (i < sha1_1.length && i < sha1_2.length) {
            console.log("  SHA1[" + i + "] input: " + (sha1_1[i].input === sha1_2[i].input ? "SAME" : "DIFF"));
            console.log("  SHA1[" + i + "] output: " + (sha1_1[i].output === sha1_2[i].output ? "SAME" : "DIFF"));
        }
    }

    // Compare MD5
    var md5_1 = log1.filter(function(e) { return e.op === "MD5"; });
    var md5_2 = log2.filter(function(e) { return e.op === "MD5"; });
    console.log("MD5 calls: " + md5_1.length + " vs " + md5_2.length);
    for (var i = 0; i < Math.max(md5_1.length, md5_2.length); i++) {
        if (i < md5_1.length && i < md5_2.length) {
            var inSame = md5_1[i].input === md5_2[i].input;
            var outSame = md5_1[i].a2_16bytes === md5_2[i].a2_16bytes;
            console.log("  MD5[" + i + "] input: " + (inSame ? "SAME" : "DIFF") +
                " (" + (md5_1[i].inputLen || "?") + " bytes)" +
                " output_a2: " + (outSame ? "SAME" : "DIFF"));
            if (!inSame && md5_1[i].input && md5_2[i].input) {
                console.log("    c1: " + (md5_1[i].input || "").substring(0, 120));
                console.log("    c2: " + (md5_2[i].input || "").substring(0, 120));
            }
        }
    }

    // AES enc count is tracked separately
    console.log("AES_ENC block count: see aesEncCount in logs");

    console.log("\n[DONE]");
}

setup();
setTimeout(run, 2000);
