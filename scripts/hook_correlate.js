// Comprehensive correlation hook: captures ALL crypto ops + Helios/Medusa in single call
// Tests every possible relationship between AES blocks and Helios parts
// Key insight: previous Helios tests never captured AES alt-entry (0x242640) output!
//
// Run: frida -U -p <PID> -l scripts/hook_correlate.js

var libBase = null;
var capturing = false;
var md5Ops = [];    // {input, output, len}
var aesOps = [];    // {input, output}  (alt entry 0x242640)
var sha1Out = null;

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

function hexToByteArray(h) {
    var bytes = [];
    for (var i = 0; i < h.length; i += 2) {
        var b = parseInt(h.substr(i, 2), 16);
        bytes.push(b > 127 ? b - 256 : b);
    }
    return Java.array('byte', bytes);
}

function bytesToHex(arr) {
    var result = '';
    for (var i = 0; i < arr.length; i++) {
        var b = arr[i]; if (b < 0) b += 256;
        result += ('0' + b.toString(16)).slice(-2);
    }
    return result;
}

function xorHex(a, b) {
    var result = '';
    var len = Math.min(a.length, b.length);
    for (var i = 0; i < len; i += 2) {
        var v = parseInt(a.substr(i, 2), 16) ^ parseInt(b.substr(i, 2), 16);
        result += ('0' + v.toString(16)).slice(-2);
    }
    return result;
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;

    // MD5 (sub_243C34)
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.a0 = args[0]; this.len = args[1].toInt32(); this.outPtr = args[2];
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                md5Ops.push({
                    input: hex(this.a0, Math.min(this.len, 512)),
                    output: hex(this.outPtr, 16),
                    len: this.len
                });
            } catch(e) {}
        }
    });

    // AES block encrypt ALT ENTRY (0x242640) — the REAL one used by CFF code!
    Interceptor.attach(libBase.add(0x242640), {
        onEnter: function(args) {
            if (!capturing) return;
            try {
                this.inHex = hex(args[1], 16);
                this.outPtr = args[2];
            } catch(e) { this.inHex = null; }
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                if (this.inHex) {
                    aesOps.push({
                        input: this.inHex,
                        output: hex(this.outPtr, 16)
                    });
                }
            } catch(e) {}
        }
    });

    // Also hook standard entry just in case
    Interceptor.attach(libBase.add(0x2422EC), {
        onEnter: function(args) {
            if (!capturing) return;
            try {
                this.inHex = hex(args[1], 16);
                this.outPtr = args[2];
            } catch(e) { this.inHex = null; }
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                if (this.inHex) {
                    aesOps.push({
                        input: this.inHex,
                        output: hex(this.outPtr, 16)
                    });
                }
            } catch(e) {}
        }
    });

    // SHA-1 finalize (sub_2450AC)
    Interceptor.attach(libBase.add(0x2450AC), {
        onEnter: function(args) { this.outPtr = args[1]; },
        onLeave: function(ret) {
            if (!capturing) return;
            try { sha1Out = hex(this.outPtr, 20); } catch(e) {}
        }
    });

    // SHA-1 full (sub_2451FC)
    Interceptor.attach(libBase.add(0x2451FC), {
        onEnter: function(args) { this.outPtr = args[2]; },
        onLeave: function(ret) {
            if (!capturing) return;
            try { if (!this.outPtr.isNull()) sha1Out = hex(this.outPtr, 20); } catch(e) {}
        }
    });

    console.log("[+] All hooks installed (MD5 + AES alt/std + SHA-1)");
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
    Java.perform(function() {
        var fixedUrl = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
            "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
            "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
            "&device_brand=google&os_api=35&os_version=15" +
            "&device_id=3722313718058683&iid=3722313718062779" +
            "&_rticket=1774940000000" +
            "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
            "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
            "&book_id=7373660003258862617";

        var MD = Java.use("java.security.MessageDigest");
        var Cipher = Java.use("javax.crypto.Cipher");
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");

        var samples = [];
        for (var n = 0; n < 5; n++) {
            md5Ops = [];
            aesOps = [];
            sha1Out = null;
            capturing = true;
            var sigs = doSign(fixedUrl);
            capturing = false;

            var heliosHex = b64toHex(sigs["X-Helios"] || "");
            var medusaHex = b64toHex(sigs["X-Medusa"] || "");

            samples.push({
                R: heliosHex.substring(0, 8),
                part1: heliosHex.substring(8, 40),
                part2: heliosHex.substring(40, 72),
                medusaLen: medusaHex.length / 2,
                md5: md5Ops.slice(),
                aes: aesOps.slice(),
                sha1: sha1Out,
                H: md5Ops.map(function(d) { return d.output; })
            });
        }

        // ======== ANALYSIS ========
        console.log("\n========== CORRELATION ANALYSIS ==========");
        console.log("Samples: " + samples.length);
        console.log("AES blocks per call: " + samples[0].aes.length);
        console.log("MD5 calls per sign: " + samples[0].md5.length);

        var H0 = samples[0].H[0]; // MD5(url) - constant
        var H2 = samples[0].H[2]; // MD5(uuid) - constant
        var H3 = samples[0].H[3]; // AES key
        var H4 = samples[0].H[4]; // constant
        var H5 = samples[0].H[5]; // constant
        var SHA1 = samples[0].sha1;

        console.log("\nConstants:");
        console.log("  H0=" + H0 + " H2=" + H2 + " H3=" + H3);
        console.log("  H4=" + H4 + " H5=" + H5);
        console.log("  SHA1=" + SHA1);

        for (var i = 0; i < samples.length; i++) {
            var s = samples[i];
            console.log("\n--- Sample " + i + " ---");
            console.log("  R=" + s.R + " H1=" + s.H[1]);
            console.log("  p1=" + s.part1 + " p2=" + s.part2);
            console.log("  AES blocks: " + s.aes.length);

            // Test: does any AES output match part1 or part2?
            for (var j = 0; j < s.aes.length; j++) {
                if (s.aes[j].output === s.part1) console.log("  ★★★ AES[" + j + "].output == part1!");
                if (s.aes[j].output === s.part2) console.log("  ★★★ AES[" + j + "].output == part2!");
                if (s.aes[j].input === s.part1) console.log("  ★★★ AES[" + j + "].input == part1!");
                if (s.aes[j].input === s.part2) console.log("  ★★★ AES[" + j + "].input == part2!");
            }

            // Test: does any AES output XOR H0/H1/H2/H3/H4/H5 match?
            var keys = {"H0": H0, "H1": s.H[1], "H2": H2, "H3": H3, "H4": H4, "H5": H5};
            if (SHA1) keys["SHA1_16"] = SHA1.substring(0, 32);

            for (var j = 0; j < s.aes.length; j++) {
                var ao = s.aes[j].output;
                var ai = s.aes[j].input;
                for (var kn in keys) {
                    var kv = keys[kn];
                    if (xorHex(ao, kv) === s.part1) console.log("  ★★★ AES[" + j + "].out XOR " + kn + " == part1!");
                    if (xorHex(ao, kv) === s.part2) console.log("  ★★★ AES[" + j + "].out XOR " + kn + " == part2!");
                    if (xorHex(ai, kv) === s.part1) console.log("  ★★★ AES[" + j + "].in XOR " + kn + " == part1!");
                    if (xorHex(ai, kv) === s.part2) console.log("  ★★★ AES[" + j + "].in XOR " + kn + " == part2!");
                }
            }

            // Test: part1/part2 = AES_ECB(key, H0 XOR H1)?
            var aesKey = SecretKeySpec.$new(hexToByteArray(H3), "AES");
            var combos = [
                ["H0^H1", xorHex(H0, s.H[1])],
                ["H0^H2", xorHex(H0, H2)],
                ["H1^H2", xorHex(s.H[1], H2)],
                ["H0^H4", xorHex(H0, H4)],
                ["H0^H5", xorHex(H0, H5)],
                ["H1^H4", xorHex(s.H[1], H4)],
                ["H1^H5", xorHex(s.H[1], H5)],
                ["H4^H5", xorHex(H4, H5)],
                ["H0^H1^H4", xorHex(xorHex(H0, s.H[1]), H4)],
                ["H0^H1^H5", xorHex(xorHex(H0, s.H[1]), H5)],
            ];
            if (SHA1) {
                combos.push(["SHA1_16^H0", xorHex(SHA1.substring(0, 32), H0)]);
                combos.push(["SHA1_16^H1", xorHex(SHA1.substring(0, 32), s.H[1])]);
            }

            for (var c = 0; c < combos.length; c++) {
                var cipher = Cipher.getInstance("AES/ECB/NoPadding");
                cipher.init(1, aesKey);
                var enc = bytesToHex(cipher.doFinal(hexToByteArray(combos[c][1])));
                if (enc === s.part1) console.log("  ★★★ AES(" + combos[c][0] + ") == part1!");
                if (enc === s.part2) console.log("  ★★★ AES(" + combos[c][0] + ") == part2!");
                // Also test AES(x) XOR something
                for (var kn in keys) {
                    if (xorHex(enc, keys[kn]) === s.part1) console.log("  ★★★ AES(" + combos[c][0] + ")^" + kn + " == part1!");
                    if (xorHex(enc, keys[kn]) === s.part2) console.log("  ★★★ AES(" + combos[c][0] + ")^" + kn + " == part2!");
                }
            }

            // Test: part1 = MD5(something involving AES output)?
            if (s.aes.length > 0) {
                var aes0out = s.aes[0].output;
                var testsMd5 = [
                    ["H1+AES0out", s.H[1] + aes0out],
                    ["AES0out+H1", aes0out + s.H[1]],
                    ["H0+AES0out", H0 + aes0out],
                    ["AES0out+H0", aes0out + H0],
                    ["H1+H0+AES0out", s.H[1] + H0 + aes0out],
                ];
                for (var t = 0; t < testsMd5.length; t++) {
                    var md = MD.getInstance("MD5");
                    md.update(hexToByteArray(testsMd5[t][1]));
                    var hash = bytesToHex(md.digest());
                    if (hash === s.part1) console.log("  ★★★ MD5(" + testsMd5[t][0] + ") == part1!");
                    if (hash === s.part2) console.log("  ★★★ MD5(" + testsMd5[t][0] + ") == part2!");
                }
            }

            // Dump all AES blocks for first sample
            if (i === 0) {
                console.log("\n  All AES blocks:");
                for (var j = 0; j < s.aes.length; j++) {
                    console.log("    AES[" + j + "] in=" + s.aes[j].input + " out=" + s.aes[j].output);
                }
            }
        }

        // Cross-sample: are AES blocks constant or varying?
        if (samples.length >= 2 && samples[0].aes.length > 0) {
            console.log("\n=== Cross-sample AES analysis ===");
            var allSame = true;
            for (var j = 0; j < Math.min(samples[0].aes.length, samples[1].aes.length); j++) {
                var same = samples[0].aes[j].input === samples[1].aes[j].input;
                if (!same) allSame = false;
                if (j < 3 || !same) {
                    console.log("  AES[" + j + "] same_input=" + same);
                }
            }
            console.log("  All AES inputs constant: " + allSame);
        }

        // Medusa analysis
        console.log("\n=== MEDUSA ===");
        console.log("  Body size: " + samples[0].medusaLen);
        console.log("  AES blocks: " + samples[0].aes.length + " = " + (samples[0].aes.length * 16) + " bytes");
        console.log("  Remaining: " + (samples[0].medusaLen - 24 - samples[0].aes.length * 16) + " bytes unaccounted");

        console.log("\n[DONE]");
    });
}

setup();
setTimeout(run, 2000);
