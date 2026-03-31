// Helios-focused: collect multiple samples and test MORE combinations
// Tests things the previous scripts missed:
//   - H3 (AES key) as XOR key
//   - SHA-1 output as component
//   - Byte reversal, nibble swap, rotate
//   - Custom S-box from AES tables
//
// Run: frida -U -p <PID> -l scripts/hook_helios_v3.js

var libBase = null;
var md5Data = [];
var sha1Output = null;
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

function reverseHex(h) {
    var result = '';
    for (var i = h.length - 2; i >= 0; i -= 2) {
        result += h.substr(i, 2);
    }
    return result;
}

function rotateLeft(h, n) {
    // Rotate hex string left by n bytes
    var chars = n * 2;
    return h.substring(chars) + h.substring(0, chars);
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;

    // MD5 raw
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.a0 = args[0]; this.len = args[1].toInt32(); this.outPtr = args[2];
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                md5Data.push({
                    inLen: this.len,
                    input: hex(this.a0, Math.min(this.len, 512)),
                    output: hex(this.outPtr, 16)
                });
            } catch(e) {}
        }
    });

    // SHA-1 finalize (sub_2450AC) — capture 20-byte output
    Interceptor.attach(libBase.add(0x2450AC), {
        onEnter: function(args) {
            this.ctx = args[0]; this.outPtr = args[1];
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                sha1Output = hex(this.outPtr, 20);
            } catch(e) {}
        }
    });

    // Also try SHA-1 full (sub_2451FC)
    Interceptor.attach(libBase.add(0x2451FC), {
        onEnter: function(args) {
            this.a0 = args[0]; this.len = args[1].toInt32(); this.outPtr = args[2];
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                if (!this.outPtr.isNull()) {
                    sha1Output = hex(this.outPtr, 20);
                }
            } catch(e) {}
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

        var samples = [];
        for (var n = 0; n < 8; n++) {
            md5Data = [];
            sha1Output = null;
            capturing = true;
            var sigs = doSign(fixedUrl);
            capturing = false;

            var heliosHex = b64toHex(sigs["X-Helios"] || "");
            samples.push({
                R: heliosHex.substring(0, 8),
                part1: heliosHex.substring(8, 40),
                part2: heliosHex.substring(40, 72),
                H: md5Data.map(function(d) { return d.output; }),
                sha1: sha1Output,
                md5Inputs: md5Data
            });
        }

        var H0 = samples[0].H[0];  // MD5(url_params) — constant
        var H2 = samples[0].H[2];  // MD5(session_uuid) — constant per session
        var H3 = samples[0].H[3];  // MD5(key material) = AES key — constant
        var H4 = samples[0].H[4];  // MD5(const1) — constant
        var H5 = samples[0].H[5];  // MD5(const2) — constant
        var SHA1 = samples[0].sha1;

        console.log("\n=== CONSTANTS ===");
        console.log("H0(url)=" + H0);
        console.log("H2(uuid)=" + H2);
        console.log("H3(aes_key)=" + H3);
        console.log("H4(const1)=" + H4);
        console.log("H5(const2)=" + H5);
        console.log("SHA1=" + SHA1);

        console.log("\n=== SAMPLES ===");
        for (var i = 0; i < samples.length; i++) {
            var s = samples[i];
            console.log("S" + i + ": R=" + s.R + " H1=" + s.H[1] + " p1=" + s.part1 + " p2=" + s.part2);
        }

        // Test: is part1 XOR H1 constant?
        console.log("\n=== part1 XOR H1 ===");
        var k1_values = [];
        for (var i = 0; i < samples.length; i++) {
            var k = xorHex(samples[i].part1, samples[i].H[1]);
            k1_values.push(k);
            console.log("  S" + i + ": " + k);
        }
        var k1_const = k1_values.every(function(v) { return v === k1_values[0]; });
        console.log("  Constant? " + k1_const);

        if (k1_const) {
            var K1 = k1_values[0];
            console.log("  K1=" + K1);
            console.log("  =H0? " + (K1 === H0));
            console.log("  =H2? " + (K1 === H2));
            console.log("  =H3? " + (K1 === H3));
            console.log("  =H4? " + (K1 === H4));
            console.log("  =H5? " + (K1 === H5));
            console.log("  =H0^H2? " + (K1 === xorHex(H0, H2)));
            console.log("  =H0^H3? " + (K1 === xorHex(H0, H3)));
            console.log("  =H0^H4? " + (K1 === xorHex(H0, H4)));
            console.log("  =H0^H5? " + (K1 === xorHex(H0, H5)));
            console.log("  =H2^H3? " + (K1 === xorHex(H2, H3)));
            console.log("  =H4^H5? " + (K1 === xorHex(H4, H5)));
            console.log("  =H0^H4^H5? " + (K1 === xorHex(xorHex(H0, H4), H5)));
            if (SHA1) {
                console.log("  =SHA1[0:32]? " + (K1 === SHA1.substring(0, 32)));
                console.log("  =SHA1[0:32]^H0? " + (K1 === xorHex(SHA1.substring(0, 32), H0)));
            }
        }

        // Test: is part2 XOR H1 constant?
        console.log("\n=== part2 XOR H1 ===");
        var k2_values = [];
        for (var i = 0; i < samples.length; i++) {
            var k = xorHex(samples[i].part2, samples[i].H[1]);
            k2_values.push(k);
            console.log("  S" + i + ": " + k);
        }
        var k2_const = k2_values.every(function(v) { return v === k2_values[0]; });
        console.log("  Constant? " + k2_const);

        if (k2_const) {
            var K2 = k2_values[0];
            console.log("  K2=" + K2);
            console.log("  =H0? " + (K2 === H0));
            console.log("  =H2? " + (K2 === H2));
            console.log("  =H3? " + (K2 === H3));
            console.log("  =H4? " + (K2 === H4));
            console.log("  =H5? " + (K2 === H5));
            if (SHA1) console.log("  =SHA1[0:32]? " + (K2 === SHA1.substring(0, 32)));
        }

        // If not XOR-based, try: is part1 = MD5(H1 + constant)?
        if (!k1_const) {
            console.log("\n=== Testing MD5-based constructions ===");
            var MD = Java.use("java.security.MessageDigest");

            for (var i = 0; i < Math.min(3, samples.length); i++) {
                var s = samples[i];
                var tests = [
                    ["MD5(H1+H0)", s.H[1] + H0],
                    ["MD5(H0+H1)", H0 + s.H[1]],
                    ["MD5(H1+H3)", s.H[1] + H3],
                    ["MD5(H3+H1)", H3 + s.H[1]],
                    ["MD5(H1+H4)", s.H[1] + H4],
                    ["MD5(H1+H5)", s.H[1] + H5],
                    ["MD5(H1+H4+H5)", s.H[1] + H4 + H5],
                    ["MD5(H0+H1+H4)", H0 + s.H[1] + H4],
                    ["MD5(R+H0)", s.R + H0],
                    ["MD5(H0+R)", H0 + s.R],
                ];
                if (SHA1) {
                    tests.push(["MD5(H1+SHA1)", s.H[1] + SHA1]);
                    tests.push(["MD5(SHA1+H1)", SHA1 + s.H[1]]);
                }

                for (var t = 0; t < tests.length; t++) {
                    var md = MD.getInstance("MD5");
                    md.update(hexToByteArray(tests[t][1]));
                    var hash = bytesToHex(md.digest());
                    var match1 = (hash === s.part1) ? " ★p1★" : "";
                    var match2 = (hash === s.part2) ? " ★p2★" : "";
                    if (match1 || match2 || i === 0) {
                        console.log("  S" + i + " " + tests[t][0] + "=" + hash + match1 + match2);
                    }
                }
            }
        }

        // Test: part1 XOR part2
        console.log("\n=== part1 XOR part2 ===");
        for (var i = 0; i < samples.length; i++) {
            var x = xorHex(samples[i].part1, samples[i].part2);
            console.log("  S" + i + ": " + x);
        }
        var p12_const = samples.every(function(s) {
            return xorHex(s.part1, s.part2) === xorHex(samples[0].part1, samples[0].part2);
        });
        console.log("  Constant? " + p12_const);

        // Test: byte reversal
        console.log("\n=== Byte reversal tests ===");
        for (var i = 0; i < 2; i++) {
            var s = samples[i];
            console.log("  S" + i + " rev(H1)=" + reverseHex(s.H[1]) + " =p1? " + (reverseHex(s.H[1]) === s.part1));
        }

        // Test: part1 = H0 XOR H1 (re-verify with all samples)
        console.log("\n=== H0 XOR H1 ===");
        for (var i = 0; i < samples.length; i++) {
            var expected = xorHex(H0, samples[i].H[1]);
            console.log("  S" + i + ": " + expected + " =p1? " + (expected === samples[i].part1) + " =p2? " + (expected === samples[i].part2));
        }

        // Test: H3 XOR H1
        console.log("\n=== H3 XOR H1 ===");
        for (var i = 0; i < samples.length; i++) {
            var expected = xorHex(H3, samples[i].H[1]);
            console.log("  S" + i + ": " + expected + " =p1? " + (expected === samples[i].part1) + " =p2? " + (expected === samples[i].part2));
        }

        console.log("\n[DONE]");
    });
}

setup();
setTimeout(run, 2000);
