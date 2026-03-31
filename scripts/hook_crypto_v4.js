// v4: CORRECTED crypto hooks — previous versions had WRONG function IDs!
//
// CORRECTIONS:
//   sub_243F10 = SHA-1 transform (NOT AES!) — has constant 0x5A827999
//   sub_243E50 = SHA-1 update (NOT AES wrapper!) — calls sub_243F10
//   sub_2422EC = ACTUAL AES block encrypt
//   sub_242C98 = AES-CTR mode encrypt
//   sub_242A70 = AES-CBC mode encrypt
//   sub_242DE0 = XOR function (used in CTR mode)
//
// This script hooks the REAL functions to capture:
//   1. All 6 MD5 calls with input/output
//   2. AES key expansion
//   3. AES block encrypts (sub_2422EC) — NEVER hooked before!
//   4. AES-CTR/CBC calls
//   5. XOR operations (CTR plaintext/keystream)
//   6. SHA-1 update/transform (correctly labeled)
//   7. Final Helios/Medusa output
//
// Run: frida -U -p <PID> -l scripts/hook_crypto_v4.js

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

function soOffset(addr) {
    try {
        var n = addr.sub(libBase).toInt32();
        if (n >= 0 && n < 0x400000) return "0x" + n.toString(16);
        return "ext";
    } catch(e) { return "ext"; }
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;
    console.log("[+] libmetasec_ml.so @ " + libBase);

    // ===== MD5 (sub_243C34) =====
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.a0 = args[0]; this.len = args[1].toInt32(); this.outPtr = args[2];
            this.lr = soOffset(this.context.lr);
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                var inHex = hex(this.a0, Math.min(this.len, 512));
                var outHex = hex(this.outPtr, 16);
                ops.push({
                    op: "MD5", lr: this.lr, inLen: this.len,
                    input: inHex, output: outHex,
                    ascii: tryAscii(inHex.substring(0, 200))
                });
            } catch(e) { ops.push({ op: "MD5", err: ""+e }); }
        }
    });
    console.log("[+] MD5 (sub_243C34) hooked");

    // ===== AES key expansion (sub_241E9C) =====
    Interceptor.attach(libBase.add(0x241E9C), {
        onEnter: function(args) {
            if (!capturing) return;
            var keyLen = args[2].toInt32();
            try {
                ops.push({
                    op: "AES_KEY_EXPAND", lr: soOffset(this.context.lr),
                    keyLen: keyLen, key: hex(args[1], keyLen)
                });
            } catch(e) {}
        }
    });
    console.log("[+] AES key expansion (sub_241E9C) hooked");

    // ===== REAL AES block encrypt (sub_2422EC) — NEVER HOOKED BEFORE! =====
    var aesBlockN = 0;
    Interceptor.attach(libBase.add(0x2422EC), {
        onEnter: function(args) {
            if (!capturing) return;
            aesBlockN++;
            this.inPtr = args[1]; this.outPtr = args[2]; this.n = aesBlockN;
            try {
                this.inHex = hex(args[1], 16);
            } catch(e) { this.inHex = "ERR"; }
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                var outHex = hex(this.outPtr, 16);
                // Only log first 5 and last 2 to avoid spam
                if (this.n <= 5 || this.n > aesBlockN - 2) {
                    ops.push({
                        op: "AES_BLOCK_ENC", n: this.n,
                        input: this.inHex, output: outHex,
                        lr: soOffset(this.context.lr)
                    });
                } else if (this.n === 6) {
                    ops.push({ op: "AES_BLOCK_ENC", n: "6...", note: "suppressed" });
                }
            } catch(e) {}
        }
    });
    console.log("[+] AES block encrypt (sub_2422EC) hooked ★");

    // ===== AES-CTR mode (sub_242C98) =====
    Interceptor.attach(libBase.add(0x242C98), {
        onEnter: function(args) {
            if (!capturing) return;
            this.ctx = args[0]; this.inPtr = args[1]; this.outPtr = args[2];
            this.len = args[3].toInt32();
            try {
                // Read nonce/IV from ctx+488
                var nonce = hex(args[0].add(488), 16);
                var counter = args[0].add(504).readU64();
                ops.push({
                    op: "AES_CTR", lr: soOffset(this.context.lr),
                    len: this.len, nonce: nonce, counter: counter.toString(),
                    inputFirst32: hex(args[1], Math.min(this.len, 32))
                });
            } catch(e) { ops.push({ op: "AES_CTR", err: ""+e }); }
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                ops.push({
                    op: "AES_CTR_OUT",
                    outputFirst32: hex(this.outPtr, Math.min(this.len, 32)),
                    outputLast16: this.len > 32 ? hex(this.outPtr.add(this.len - 16), 16) : ""
                });
            } catch(e) {}
        }
    });
    console.log("[+] AES-CTR (sub_242C98) hooked ★");

    // ===== AES-CBC mode (sub_242A70) =====
    Interceptor.attach(libBase.add(0x242A70), {
        onEnter: function(args) {
            if (!capturing) return;
            this.inPtr = args[1]; this.outPtr = args[2]; this.len = args[3].toInt32();
            ops.push({
                op: "AES_CBC", lr: soOffset(this.context.lr),
                len: this.len,
                inputFirst32: hex(args[1], Math.min(this.len, 32))
            });
        }
    });
    console.log("[+] AES-CBC (sub_242A70) hooked ★");

    // ===== AES mode dispatch (sub_259CF0) =====
    Interceptor.attach(libBase.add(0x259CF0), {
        onEnter: function(args) {
            if (!capturing) return;
            try {
                var mode = args[0].readPointer().readU32();
                var modeNames = {0: "ECB", 1: "CBC", 2: "CTR", 3: "CFB"};
                ops.push({
                    op: "AES_DISPATCH", mode: mode,
                    modeName: modeNames[mode] || "?",
                    dataLen: args[4].toInt32(),
                    lr: soOffset(this.context.lr)
                });
            } catch(e) { ops.push({ op: "AES_DISPATCH", err: ""+e }); }
        }
    });
    console.log("[+] AES dispatch (sub_259CF0) hooked ★");

    // ===== XOR function (sub_242DE0) — captures CTR plaintext =====
    var xorN = 0;
    Interceptor.attach(libBase.add(0x242DE0), {
        onEnter: function(args) {
            if (!capturing) return;
            xorN++;
            this.n = xorN;
            this.a = args[0]; this.b = args[1]; this.out = args[2];
            this.len = args[3].toInt32();
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                if (this.n <= 3 || this.n > xorN - 1) {
                    ops.push({
                        op: "XOR", n: this.n, len: this.len,
                        a: hex(this.a, Math.min(this.len, 16)),
                        b: hex(this.b, Math.min(this.len, 16)),
                        out: hex(this.out, Math.min(this.len, 16))
                    });
                }
            } catch(e) {}
        }
    });
    console.log("[+] XOR (sub_242DE0) hooked ★");

    // ===== SHA-1 update (sub_243E50) — CORRECTLY identified =====
    var sha1UpdateN = 0;
    Interceptor.attach(libBase.add(0x243E50), {
        onEnter: function(args) {
            if (!capturing) return;
            sha1UpdateN++;
            if (sha1UpdateN <= 3) {
                try {
                    var len = args[2].toInt32();
                    ops.push({
                        op: "SHA1_UPDATE", n: sha1UpdateN,
                        len: len, inputFirst16: hex(args[1], Math.min(len, 16)),
                        lr: soOffset(this.context.lr)
                    });
                } catch(e) {}
            } else if (sha1UpdateN === 4) {
                ops.push({ op: "SHA1_UPDATE", n: "4+", note: "suppressed" });
            }
        }
    });
    console.log("[+] SHA-1 update (sub_243E50) hooked (was misidentified as AES!)");

    // ===== SHA-1 transform (sub_243F10) — CORRECTLY identified =====
    var sha1TransN = 0;
    Interceptor.attach(libBase.add(0x243F10), {
        onEnter: function(args) {
            if (!capturing) return;
            sha1TransN++;
            ops.push({ op: "SHA1_TRANSFORM", n: sha1TransN, lr: soOffset(this.context.lr) });
        }
    });
    console.log("[+] SHA-1 transform (sub_243F10) hooked (was misidentified as AES block!)");

    // ===== SHA-1 wrapper (sub_258780) =====
    Interceptor.attach(libBase.add(0x258780), {
        onEnter: function(args) {
            if (!capturing) return;
            ops.push({ op: "SHA1_WRAPPER", lr: soOffset(this.context.lr) });
        }
    });
    console.log("[+] SHA-1 wrapper (sub_258780) hooked");

    // ===== AES setup (sub_259C1C) — captures mode =====
    Interceptor.attach(libBase.add(0x259C1C), {
        onEnter: function(args) {
            if (!capturing) return;
            try {
                var mode = args[0].readPointer().readU32();
                var modeNames = {0: "ECB", 1: "CBC", 2: "CTR", 3: "CFB"};
                ops.push({
                    op: "AES_SETUP", mode: mode, modeName: modeNames[mode] || "?",
                    lr: soOffset(this.context.lr)
                });
            } catch(e) { ops.push({ op: "AES_SETUP", err: ""+e }); }
        }
    });
    console.log("[+] AES setup (sub_259C1C) hooked");

    console.log("\n[+] ALL hooks installed. Starting capture...\n");
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

    // Print signatures
    console.log("\n========== SIGNATURES ==========");
    for (var k in sigs) {
        var v = sigs[k];
        if (k === "X-Helios") {
            var hHex = b64toHex(v);
            console.log(k + " (" + hHex.length/2 + " bytes): " + hHex);
            console.log("  R=" + hHex.substring(0,8) + " part1=" + hHex.substring(8,40) + " part2=" + hHex.substring(40,72));
        } else if (k === "X-Medusa") {
            var mHex = b64toHex(v);
            console.log(k + " (" + mHex.length/2 + " bytes)");
            console.log("  header(24)=" + mHex.substring(0, 48));
            console.log("  body_first32=" + mHex.substring(48, 112));
        } else {
            console.log(k + " = " + v);
        }
    }

    // Print all operations
    console.log("\n========== CRYPTO OPS (" + ops.length + ") ==========");
    for (var i = 0; i < ops.length; i++) {
        var o = ops[i];
        var line = "[" + i + "] " + o.op;
        if (o.lr) line += " ←" + o.lr;
        if (o.n !== undefined) line += " #" + o.n;
        if (o.inLen !== undefined) line += " inLen=" + o.inLen;
        if (o.len !== undefined) line += " len=" + o.len;
        if (o.keyLen !== undefined) line += " keyLen=" + o.keyLen;
        if (o.mode !== undefined) line += " mode=" + o.mode + "(" + o.modeName + ")";
        if (o.key) line += "\n    key=" + o.key;
        if (o.input) line += "\n    in=" + o.input.substring(0, 128) + (o.input.length > 128 ? "..." : "");
        if (o.output) line += "\n    out=" + o.output;
        if (o.inputFirst32) line += "\n    inFirst32=" + o.inputFirst32;
        if (o.outputFirst32) line += "\n    outFirst32=" + o.outputFirst32;
        if (o.nonce) line += "\n    nonce=" + o.nonce + " ctr=" + o.counter;
        if (o.a) line += "\n    a=" + o.a + " b=" + o.b + " xor=" + o.out;
        if (o.ascii) line += "\n    ascii=" + o.ascii.substring(0, 80);
        if (o.note) line += " (" + o.note + ")";
        if (o.err) line += " ERR:" + o.err;
        console.log(line);
    }

    // Summary
    console.log("\n========== SUMMARY ==========");
    var counts = {};
    for (var i = 0; i < ops.length; i++) {
        counts[ops[i].op] = (counts[ops[i].op] || 0) + 1;
    }
    for (var k in counts) {
        console.log("  " + k + ": " + counts[k] + "x");
    }

    console.log("\n[DONE] Run this on the emulator and paste output here");
}

setup();
setTimeout(run, 2000);
