// More Medusa decryption attempts:
// 1. XOR with repeated AES key
// 2. RC4 with AES key
// 3. AES-CTR with counter starting from 1
// 4. AES-CTR with SHA-1 output as nonce
// 5. Two samples XOR comparison
// 6. Check if body has protobuf-like structure
//
// Run: frida -U -p <PID> -l scripts/hook_medusa_decrypt2.js

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

function tryAscii(h) {
    var out = '';
    for (var i = 0; i < h.length; i += 2) {
        var c = parseInt(h.substr(i, 2), 16);
        out += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
    }
    return out;
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

setTimeout(function() {
    Java.perform(function() {
        var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
            "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
            "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
            "&device_brand=google&os_api=35&os_version=15" +
            "&device_id=3722313718058683&iid=3722313718062779" +
            "&_rticket=1774940000000" +
            "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
            "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
            "&book_id=7373660003258862617";

        // Collect 3 Medusa samples
        var samples = [];
        for (var n = 0; n < 3; n++) {
            var sigs = doSign(url);
            var mHex = b64toHex(sigs["X-Medusa"] || "");
            samples.push({
                header: mHex.substring(0, 48),
                body: mHex.substring(48),
                full: mHex
            });
        }

        console.log("\n=== MEDUSA SAMPLES ===");
        for (var i = 0; i < samples.length; i++) {
            console.log("S" + i + " header=" + samples[i].header);
            console.log("   body_first64=" + samples[i].body.substring(0, 128));
            console.log("   body_len=" + samples[i].body.length/2);
        }

        var keyHex = "059874c397db2a6594024f0aa1c288c4";
        var keyBytes = hexToByteArray(keyHex);
        var sha1Hex = "1509be656b6620abd6cc6c48e8156dbe5927c8f8";
        var body = samples[0].body;
        var bodyBytes = hexToByteArray(body);

        // === Test 1: XOR two Medusa bodies ===
        console.log("\n=== XOR(body0, body1) — same key test ===");
        var b0 = samples[0].body;
        var b1 = samples[1].body;
        var xorResult = '';
        var zeroCount = 0;
        for (var i = 0; i < Math.min(b0.length, b1.length); i += 2) {
            var v = parseInt(b0.substr(i, 2), 16) ^ parseInt(b1.substr(i, 2), 16);
            xorResult += ('0' + v.toString(16)).slice(-2);
            if (v === 0) zeroCount++;
        }
        console.log("XOR first64: " + xorResult.substring(0, 128));
        console.log("Zero bytes: " + zeroCount + "/" + Math.min(b0.length, b1.length)/2);
        console.log("If mostly zeros → same keystream (constant nonce = VULNERABLE)");

        // === Test 2: XOR with repeated key ===
        console.log("\n=== XOR with repeated AES key ===");
        var decXor = '';
        for (var i = 0; i < body.length; i += 2) {
            var keyByte = parseInt(keyHex.substr((i % 32), 2), 16);
            var v = parseInt(body.substr(i, 2), 16) ^ keyByte;
            decXor += ('0' + v.toString(16)).slice(-2);
        }
        console.log("first64: " + decXor.substring(0, 128));
        console.log("ascii: " + tryAscii(decXor.substring(0, 128)));

        // === Test 3: RC4 with AES key ===
        console.log("\n=== RC4 decrypt ===");
        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
            // RC4
            var rc4Key = SecretKeySpec.$new(keyBytes, "RC4");
            var cipher = Cipher.getInstance("RC4");
            cipher.init(2, rc4Key);
            var dec = cipher.doFinal(bodyBytes);
            var decHex = bytesToHex(dec);
            console.log("RC4 first64: " + decHex.substring(0, 128));
            console.log("RC4 ascii: " + tryAscii(decHex.substring(0, 128)));
        } catch(e) { console.log("RC4 error: " + e); }

        // === Test 4: RC4 with SHA-1 output as key ===
        console.log("\n=== RC4 (SHA-1 key) decrypt ===");
        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
            var sha1Bytes = hexToByteArray(sha1Hex);
            var rc4Key = SecretKeySpec.$new(sha1Bytes, "RC4");
            var cipher = Cipher.getInstance("RC4");
            cipher.init(2, rc4Key);
            var dec = cipher.doFinal(bodyBytes);
            var decHex = bytesToHex(dec);
            console.log("RC4-sha1 first64: " + decHex.substring(0, 128));
            console.log("RC4-sha1 ascii: " + tryAscii(decHex.substring(0, 128)));
        } catch(e) { console.log("RC4-sha1 error: " + e); }

        // === Test 5: AES-CTR with counter from 1, various nonce sources ===
        console.log("\n=== AES-CTR (counter=1) nonce=header[0:8] ===");
        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
            var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
            var aesKey = SecretKeySpec.$new(keyBytes, "AES");
            // Counter starts at 1: nonce(8) || 0x0000000000000001
            var ivHex = samples[0].header.substring(0, 16) + "0000000000000001";
            var cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(2, aesKey, IvParameterSpec.$new(hexToByteArray(ivHex)));
            var dec = cipher.doFinal(bodyBytes);
            var decHex = bytesToHex(dec);
            console.log("CTR-1 first64: " + decHex.substring(0, 128));
            console.log("CTR-1 ascii: " + tryAscii(decHex.substring(0, 128)));
        } catch(e) { console.log("CTR-1 error: " + e); }

        // === Test 6: Check if body XOR is same for same URL ===
        // If XOR of two bodies shows many zeros, the keystream is constant
        // meaning the "encryption" might be XOR with a constant keystream
        console.log("\n=== Body structure analysis ===");
        // Check entropy of first 64 bytes
        var freq = {};
        for (var i = 0; i < Math.min(body.length, 128); i += 2) {
            var b = body.substr(i, 2);
            freq[b] = (freq[b] || 0) + 1;
        }
        var uniqueBytes = Object.keys(freq).length;
        console.log("Unique bytes in first 64: " + uniqueBytes + "/64");
        console.log("(Low unique = pattern, High = encrypted/random)");

        // Check for protobuf patterns (field tags)
        var byte0 = parseInt(body.substr(0, 2), 16);
        console.log("body[0]=" + body.substr(0, 2) + " as protobuf: field=" + (byte0 >> 3) + " type=" + (byte0 & 7));

        // Check for zlib header
        console.log("body[0:4]=" + body.substring(0, 8) + " (zlib header would be 789c or 7801)");

        // === Test 7: XOR full body with SHA-1 hash repeated ===
        console.log("\n=== XOR with repeated SHA-1 (20 bytes) ===");
        var decSha1Xor = '';
        for (var i = 0; i < body.length; i += 2) {
            var keyByte = parseInt(sha1Hex.substr((i % 40), 2), 16);
            var v = parseInt(body.substr(i, 2), 16) ^ keyByte;
            decSha1Xor += ('0' + v.toString(16)).slice(-2);
        }
        console.log("first64: " + decSha1Xor.substring(0, 128));
        console.log("ascii: " + tryAscii(decSha1Xor.substring(0, 128)));

        console.log("\n[DONE]");
    });
}, 2000);
