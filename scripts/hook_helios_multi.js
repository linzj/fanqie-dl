// Sign same URL N times, capture all MD5 inputs/outputs, analyze R→Helios mapping
// Also capture full MD5[0] input to verify it's the same across calls
// Run: frida -U -p <PID> -l scripts/hook_helios_multi.js

var libBase = null;
var md5Data = [];
var capturing = false;
var aesBlockCount = 0;

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
    for (var i = 0; i < Math.min(a.length, b.length); i += 2) {
        var v = parseInt(a.substr(i, 2), 16) ^ parseInt(b.substr(i, 2), 16);
        result += ('0' + v.toString(16)).slice(-2);
    }
    return result;
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;

    // MD5 hook — capture full input hex and output
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.a0 = args[0]; this.len = args[1].toInt32(); this.outPtr = args[2];
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                md5Data.push({
                    inLen: this.len,
                    input: hex(this.a0, this.len),
                    output: hex(this.outPtr, 16)
                });
            } catch(e) {}
        }
    });

    // AES block count
    Interceptor.attach(libBase.add(0x243F10), {
        onEnter: function(args) {
            if (capturing) aesBlockCount++;
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
        // Use fixed URL (same _rticket) so MD5[0] is constant
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
        for (var n = 0; n < 5; n++) {
            md5Data = [];
            aesBlockCount = 0;
            capturing = true;
            var sigs = doSign(fixedUrl);
            capturing = false;

            var heliosHex = b64toHex(sigs["X-Helios"] || "");
            var R = heliosHex.substring(0, 8);
            var part1 = heliosHex.substring(8, 40);
            var part2 = heliosHex.substring(40, 72);

            var sample = {
                R: R, part1: part1, part2: part2,
                H: md5Data.map(function(d) { return d.output; }),
                md5Inputs: md5Data.map(function(d) { return { len: d.inLen, hex: d.input }; }),
                aesBlocks: aesBlockCount
            };
            samples.push(sample);

            console.log("Sample " + n + ": R=" + R + " H0=" + sample.H[0] + " H1=" + sample.H[1]);
            console.log("  part1=" + part1 + " part2=" + part2);
        }

        // Verify H0 is constant (same URL → same MD5)
        console.log("\n=== VERIFICATION ===");
        var h0_same = true;
        for (var i = 1; i < samples.length; i++) {
            if (samples[i].H[0] !== samples[0].H[0]) h0_same = false;
        }
        console.log("H0 constant across calls: " + h0_same + " (" + samples[0].H[0] + ")");
        console.log("H2 constant: " + (samples[0].H[2] === samples[1].H[2]) + " (" + samples[0].H[2] + ")");
        console.log("H3(AES_KEY) constant: " + (samples[0].H[3] === samples[1].H[3]) + " (" + samples[0].H[3] + ")");
        console.log("H4 constant: " + (samples[0].H[4] === samples[1].H[4]) + " (" + samples[0].H[4] + ")");
        console.log("H5 constant: " + (samples[0].H[5] === samples[1].H[5]) + " (" + samples[0].H[5] + ")");
        console.log("AES block count: " + samples[0].aesBlocks);

        // Since H0 is constant and R varies, we can analyze R→(part1,part2) mapping
        console.log("\n=== R → HELIOS MAPPING (H0 fixed) ===");
        var H0 = samples[0].H[0];
        for (var i = 0; i < samples.length; i++) {
            var s = samples[i];
            var H1 = s.H[1]; // MD5(R + "1967")

            // XOR analysis: what constant K1 satisfies part1 = H1 XOR K1?
            var k1 = xorHex(s.part1, H1);
            var k2 = xorHex(s.part2, H1);
            console.log("Sample " + i + ":");
            console.log("  R=" + s.R + " H1=" + H1);
            console.log("  part1 XOR H1 = " + k1);
            console.log("  part2 XOR H1 = " + k2);
        }

        // Check if part1 XOR H1 is constant
        var k1_values = [];
        for (var i = 0; i < samples.length; i++) {
            k1_values.push(xorHex(samples[i].part1, samples[i].H[1]));
        }
        var k1_constant = true;
        for (var i = 1; i < k1_values.length; i++) {
            if (k1_values[i] !== k1_values[0]) k1_constant = false;
        }
        console.log("\npart1 XOR H1 constant? " + k1_constant);
        if (k1_constant) {
            console.log("  K1 = " + k1_values[0]);
            console.log("  K1 = H0? " + (k1_values[0] === H0));
            console.log("  K1 = H2? " + (k1_values[0] === samples[0].H[2]));
            console.log("  K1 = H4? " + (k1_values[0] === samples[0].H[4]));
            console.log("  K1 = H5? " + (k1_values[0] === samples[0].H[5]));
            console.log("  K1 = H0 XOR H2? " + (k1_values[0] === xorHex(H0, samples[0].H[2])));
            console.log("  K1 = H0 XOR H4? " + (k1_values[0] === xorHex(H0, samples[0].H[4])));
            console.log("  K1 = H0 XOR H5? " + (k1_values[0] === xorHex(H0, samples[0].H[5])));
            console.log("  K1 = H4 XOR H5? " + (k1_values[0] === xorHex(samples[0].H[4], samples[0].H[5])));
        }

        // Same for part2
        var k2_values = [];
        for (var i = 0; i < samples.length; i++) {
            k2_values.push(xorHex(samples[i].part2, samples[i].H[1]));
        }
        var k2_constant = true;
        for (var i = 1; i < k2_values.length; i++) {
            if (k2_values[i] !== k2_values[0]) k2_constant = false;
        }
        console.log("\npart2 XOR H1 constant? " + k2_constant);
        if (k2_constant) {
            console.log("  K2 = " + k2_values[0]);
        }

        // Check part1 XOR H0
        var k3_values = [];
        for (var i = 0; i < samples.length; i++) {
            k3_values.push(xorHex(samples[i].part1, H0));
        }
        var k3_constant = true;
        for (var i = 1; i < k3_values.length; i++) {
            if (k3_values[i] !== k3_values[0]) k3_constant = false;
        }
        console.log("part1 XOR H0 constant? " + k3_constant);

        // Is part1 = H1 XOR H0?
        console.log("\npart1 = H1 XOR H0?");
        for (var i = 0; i < samples.length; i++) {
            var expected = xorHex(samples[i].H[1], H0);
            console.log("  Sample " + i + ": " + (expected === samples[i].part1 ? "YES ★★★" : "no"));
        }

        // Is part1 = H1 XOR H4?
        console.log("part1 = H1 XOR H4?");
        for (var i = 0; i < samples.length; i++) {
            var expected = xorHex(samples[i].H[1], samples[0].H[4]);
            console.log("  Sample " + i + ": " + (expected === samples[i].part1 ? "YES ★★★" : "no"));
        }

        // Is part1 = H1 XOR H5?
        console.log("part1 = H1 XOR H5?");
        for (var i = 0; i < samples.length; i++) {
            var expected = xorHex(samples[i].H[1], samples[0].H[5]);
            console.log("  Sample " + i + ": " + (expected === samples[i].part1 ? "YES ★★★" : "no"));
        }

        // Maybe it involves AES? Let's try AES_ECB(key, R_padded)
        var Cipher = Java.use("javax.crypto.Cipher");
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        var aesKey = samples[0].H[3];
        var key = SecretKeySpec.$new(hexToByteArray(aesKey), "AES");

        console.log("\n=== AES-based R analysis ===");
        for (var i = 0; i < samples.length; i++) {
            var cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(1, key);
            // Pad R to 16 bytes and AES encrypt
            var rPad = samples[i].R + "000000000000000000000000";
            var aesR = bytesToHex(cipher.doFinal(hexToByteArray(rPad)));
            console.log("  AES(R_pad)=" + aesR + " =part1? " + (aesR === samples[i].part1));

            // AES(H1)
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(1, key);
            var aesH1 = bytesToHex(cipher.doFinal(hexToByteArray(samples[i].H[1])));
            console.log("  AES(H1)=" + aesH1 + " =part1? " + (aesH1 === samples[i].part1));
            console.log("  AES(H1) XOR H0=" + xorHex(aesH1, H0) + " =part1? " + (xorHex(aesH1, H0) === samples[i].part1));
        }

        // Full dump of MD5 inputs for the first sample
        console.log("\n=== FULL MD5 INPUTS (Sample 0) ===");
        for (var i = 0; i < samples[0].md5Inputs.length; i++) {
            var inp = samples[0].md5Inputs[i];
            console.log("MD5[" + i + "] len=" + inp.len + " hex=" + inp.hex);
        }

        console.log("\n[DONE]");
    });
}

setup();
setTimeout(run, 2000);
