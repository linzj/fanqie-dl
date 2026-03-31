// Try to decrypt Medusa body with known AES key using Java Cipher
// AES key = 059874c397db2a6594024f0aa1c288c4
// Try: ECB, CBC (IV=0), CTR with various nonces
//
// Also capture SHA-1 state to understand the 46 updates
//
// Run: frida -U -p <PID> -l scripts/hook_medusa_decrypt.js

var libBase = null;
var sha1Inputs = [];
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

function tryAscii(h) {
    var out = '';
    for (var i = 0; i < h.length; i += 2) {
        var c = parseInt(h.substr(i, 2), 16);
        out += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
    }
    return out;
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) return;
    libBase = mod.base;

    // Capture SHA-1 update inputs to understand what's being hashed
    var sha1N = 0;
    Interceptor.attach(libBase.add(0x243E50), {
        onEnter: function(args) {
            if (!capturing) return;
            sha1N++;
            try {
                var len = args[2].toInt32();
                var inputHex = hex(args[1], Math.min(len, 64));
                sha1Inputs.push({ n: sha1N, len: len, input: inputHex });
            } catch(e) {}
        }
    });

    // Capture SHA-1 finalize output
    Interceptor.attach(libBase.add(0x2450AC), {
        onEnter: function(args) {
            this.outPtr = args[1];
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                sha1Inputs.push({ n: -1, op: "SHA1_FINAL", output: hex(this.outPtr, 20) });
            } catch(e) {}
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

        sha1Inputs = [];
        capturing = true;
        var sigs = doSign(url);
        capturing = false;

        var medusaB64 = sigs["X-Medusa"] || "";
        var medusaHex = b64toHex(medusaB64);
        var headerHex = medusaHex.substring(0, 48);  // 24 bytes
        var bodyHex = medusaHex.substring(48);        // rest

        console.log("\n=== MEDUSA ===");
        console.log("Total: " + medusaHex.length/2 + " bytes");
        console.log("Header(24): " + headerHex);
        console.log("Body(" + bodyHex.length/2 + " bytes): " + bodyHex.substring(0, 128) + "...");

        // AES key
        var keyHex = "059874c397db2a6594024f0aa1c288c4";
        var keyBytes = hexToByteArray(keyHex);

        var Cipher = Java.use("javax.crypto.Cipher");
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");

        var aesKey = SecretKeySpec.$new(keyBytes, "AES");
        var bodyBytes = hexToByteArray(bodyHex);

        // Try AES-ECB decrypt
        console.log("\n=== TRY AES-ECB DECRYPT ===");
        try {
            var cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(2, aesKey);  // 2 = DECRYPT
            var dec = cipher.doFinal(bodyBytes);
            var decHex = bytesToHex(dec);
            console.log("ECB first64: " + decHex.substring(0, 128));
            console.log("ECB ascii: " + tryAscii(decHex.substring(0, 128)));
        } catch(e) { console.log("ECB error: " + e); }

        // Try AES-CBC with IV=0
        console.log("\n=== TRY AES-CBC (IV=0) DECRYPT ===");
        try {
            var iv0 = hexToByteArray("00000000000000000000000000000000");
            var cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(2, aesKey, IvParameterSpec.$new(iv0));
            var dec = cipher.doFinal(bodyBytes);
            var decHex = bytesToHex(dec);
            console.log("CBC-0 first64: " + decHex.substring(0, 128));
            console.log("CBC-0 ascii: " + tryAscii(decHex.substring(0, 128)));
        } catch(e) { console.log("CBC-0 error: " + e); }

        // Try AES-CBC with IV from header bytes 4-19
        console.log("\n=== TRY AES-CBC (IV=header[4:20]) DECRYPT ===");
        try {
            var ivHex = headerHex.substring(8, 40);  // bytes 4-19
            var ivBytes = hexToByteArray(ivHex);
            var cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(2, aesKey, IvParameterSpec.$new(ivBytes));
            var dec = cipher.doFinal(bodyBytes);
            var decHex = bytesToHex(dec);
            console.log("CBC-hdr first64: " + decHex.substring(0, 128));
            console.log("CBC-hdr ascii: " + tryAscii(decHex.substring(0, 128)));
        } catch(e) { console.log("CBC-hdr error: " + e); }

        // Try AES-CTR with nonce from header bytes 0-7
        console.log("\n=== TRY AES-CTR (nonce=header[0:8]) DECRYPT ===");
        try {
            // CTR mode: nonce(8) || counter(8) starting from 0
            var nonceHex = headerHex.substring(0, 16) + "0000000000000000";
            var ivBytes = hexToByteArray(nonceHex);
            var cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(2, aesKey, IvParameterSpec.$new(ivBytes));
            var dec = cipher.doFinal(bodyBytes);
            var decHex = bytesToHex(dec);
            console.log("CTR-0:8 first64: " + decHex.substring(0, 128));
            console.log("CTR-0:8 ascii: " + tryAscii(decHex.substring(0, 128)));
        } catch(e) { console.log("CTR-0:8 error: " + e); }

        // Try AES-CTR with nonce from header bytes 4-11
        console.log("\n=== TRY AES-CTR (nonce=header[4:12]) DECRYPT ===");
        try {
            var nonceHex = headerHex.substring(8, 24) + "0000000000000000";
            var ivBytes = hexToByteArray(nonceHex);
            var cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(2, aesKey, IvParameterSpec.$new(ivBytes));
            var dec = cipher.doFinal(bodyBytes);
            var decHex = bytesToHex(dec);
            console.log("CTR-4:12 first64: " + decHex.substring(0, 128));
            console.log("CTR-4:12 ascii: " + tryAscii(decHex.substring(0, 128)));
        } catch(e) { console.log("CTR-4:12 error: " + e); }

        // Try with full header[0:16] as IV for CTR
        console.log("\n=== TRY AES-CTR (IV=header[0:16]) DECRYPT ===");
        try {
            var ivHex = headerHex.substring(0, 32);
            var ivBytes = hexToByteArray(ivHex);
            var cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(2, aesKey, IvParameterSpec.$new(ivBytes));
            var dec = cipher.doFinal(bodyBytes);
            var decHex = bytesToHex(dec);
            console.log("CTR-full first64: " + decHex.substring(0, 128));
            console.log("CTR-full ascii: " + tryAscii(decHex.substring(0, 128)));
        } catch(e) { console.log("CTR-full error: " + e); }

        // SHA-1 inputs analysis
        console.log("\n=== SHA-1 INPUTS (" + sha1Inputs.length + ") ===");
        var totalSha1Bytes = 0;
        for (var i = 0; i < sha1Inputs.length; i++) {
            var s = sha1Inputs[i];
            if (s.op === "SHA1_FINAL") {
                console.log("  SHA1_FINAL output=" + s.output);
            } else if (i < 5 || i >= sha1Inputs.length - 3) {
                console.log("  [" + s.n + "] len=" + s.len + " in=" + s.input.substring(0, 64) + (s.input.length > 64 ? "..." : ""));
                totalSha1Bytes += s.len;
            } else if (i === 5) {
                totalSha1Bytes += s.len;
                console.log("  ... (suppressed) ...");
            } else {
                totalSha1Bytes += s.len;
            }
        }
        console.log("  Total SHA-1 input bytes: " + totalSha1Bytes);

        console.log("\n[DONE]");
    });
}, 2000);
