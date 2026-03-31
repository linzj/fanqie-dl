// Test AES-based hypotheses for Helios construction
// Run: frida -U -p <PID> -l scripts/hook_helios_verify2.js

var libBase = null;
var md5Outputs = [];
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
        var b = arr[i];
        if (b < 0) b += 256;
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

function javaMD5(hexStr) {
    var MessageDigest = Java.use("java.security.MessageDigest");
    var md = MessageDigest.getInstance("MD5");
    md.update(hexToByteArray(hexStr));
    return bytesToHex(md.digest());
}

function javaAES_ECB_encrypt(keyHex, dataHex) {
    var Cipher = Java.use("javax.crypto.Cipher");
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    var cipher = Cipher.getInstance("AES/ECB/NoPadding");
    var key = SecretKeySpec.$new(hexToByteArray(keyHex), "AES");
    cipher.init(1, key); // 1 = ENCRYPT
    var result = cipher.doFinal(hexToByteArray(dataHex));
    return bytesToHex(result);
}

function javaAES_ECB_decrypt(keyHex, dataHex) {
    var Cipher = Java.use("javax.crypto.Cipher");
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    var cipher = Cipher.getInstance("AES/ECB/NoPadding");
    var key = SecretKeySpec.$new(hexToByteArray(keyHex), "AES");
    cipher.init(2, key); // 2 = DECRYPT
    var result = cipher.doFinal(hexToByteArray(dataHex));
    return bytesToHex(result);
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;

    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.a0 = args[0]; this.len = args[1].toInt32(); this.outPtr = args[2];
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try { md5Outputs.push(hex(this.outPtr, 16)); } catch(e) {}
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
        var tsMs = Date.now();
        var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
            "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
            "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
            "&device_brand=google&os_api=35&os_version=15" +
            "&device_id=3722313718058683&iid=3722313718062779" +
            "&_rticket=" + tsMs +
            "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
            "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
            "&book_id=7373660003258862617";

        md5Outputs = [];
        capturing = true;
        var sigs = doSign(url);
        capturing = false;

        var heliosHex = b64toHex(sigs["X-Helios"] || "");
        var R = heliosHex.substring(0, 8);
        var part1 = heliosHex.substring(8, 40);
        var part2 = heliosHex.substring(40, 72);

        var H0 = md5Outputs[0]; // MD5(url_params)
        var H1 = md5Outputs[1]; // MD5(R + "1967")
        var H2 = md5Outputs[2]; // MD5(uuid + "0")
        var H3 = md5Outputs[3]; // AES key
        var H4 = md5Outputs[4]; // constant
        var H5 = md5Outputs[5]; // constant

        console.log("R=" + R + " part1=" + part1 + " part2=" + part2);
        console.log("H0=" + H0 + " H1=" + H1);
        console.log("H2=" + H2 + " H3(AES_KEY)=" + H3);
        console.log("H4=" + H4 + " H5=" + H5);

        // AES-based hypotheses
        console.log("\n=== AES HYPOTHESES ===");
        var aesKey = H3;

        // Encrypt MD5 outputs with AES
        var ae0 = javaAES_ECB_encrypt(aesKey, H0);
        console.log("AES(H0)=" + ae0);
        console.log("  =part1? " + (ae0 === part1));
        console.log("  =part2? " + (ae0 === part2));

        var ae1 = javaAES_ECB_encrypt(aesKey, H1);
        console.log("AES(H1)=" + ae1);
        console.log("  =part1? " + (ae1 === part1));
        console.log("  =part2? " + (ae1 === part2));

        // AES(H0) XOR H1 etc
        console.log("AES(H0) XOR H1=" + xorHex(ae0, H1) + " =part1? " + (xorHex(ae0, H1) === part1) + " =part2? " + (xorHex(ae0, H1) === part2));
        console.log("AES(H1) XOR H0=" + xorHex(ae1, H0) + " =part1? " + (xorHex(ae1, H0) === part1) + " =part2? " + (xorHex(ae1, H0) === part2));
        console.log("H0 XOR AES(H1)=" + xorHex(H0, ae1) + " =part1? " + (xorHex(H0, ae1) === part1));
        console.log("H1 XOR AES(H0)=" + xorHex(H1, ae0) + " =part1? " + (xorHex(H1, ae0) === part1));

        // Decrypt parts with AES to see what's inside
        var dp1 = javaAES_ECB_decrypt(aesKey, part1);
        var dp2 = javaAES_ECB_decrypt(aesKey, part2);
        console.log("\nAES_DEC(part1)=" + dp1);
        console.log("AES_DEC(part2)=" + dp2);
        // Check if decrypted parts are XOR of known values
        console.log("DEC(p1) XOR H0=" + xorHex(dp1, H0));
        console.log("DEC(p1) XOR H1=" + xorHex(dp1, H1));
        console.log("DEC(p1) XOR H2=" + xorHex(dp1, H2));
        console.log("DEC(p1) XOR H4=" + xorHex(dp1, H4));
        console.log("DEC(p1) XOR H5=" + xorHex(dp1, H5));
        console.log("DEC(p2) XOR H0=" + xorHex(dp2, H0));
        console.log("DEC(p2) XOR H1=" + xorHex(dp2, H1));
        console.log("DEC(p2) XOR H2=" + xorHex(dp2, H2));
        console.log("DEC(p2) XOR H4=" + xorHex(dp2, H4));
        console.log("DEC(p2) XOR H5=" + xorHex(dp2, H5));

        // Try AES-CBC with IV=0
        var Cipher = Java.use("javax.crypto.Cipher");
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        var iv0 = hexToByteArray("00000000000000000000000000000000");

        // AES-CBC encrypt H0+H1 with IV=0
        var cipher = Cipher.getInstance("AES/CBC/NoPadding");
        var key = SecretKeySpec.$new(hexToByteArray(aesKey), "AES");
        var ivSpec = IvParameterSpec.$new(iv0);
        cipher.init(1, key, ivSpec);
        var cbcResult = cipher.doFinal(hexToByteArray(H0 + H1));
        var cbcHex = bytesToHex(cbcResult);
        console.log("\nAES_CBC(IV=0, H0||H1)=" + cbcHex);
        console.log("  first 16=" + cbcHex.substring(0, 32) + " =part1? " + (cbcHex.substring(0, 32) === part1));
        console.log("  last  16=" + cbcHex.substring(32, 64) + " =part2? " + (cbcHex.substring(32, 64) === part2));

        // AES-CBC encrypt H1+H0 with IV=0
        cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(1, key, ivSpec);
        cbcResult = cipher.doFinal(hexToByteArray(H1 + H0));
        cbcHex = bytesToHex(cbcResult);
        console.log("AES_CBC(IV=0, H1||H0)=" + cbcHex);
        console.log("  first 16=" + cbcHex.substring(0, 32) + " =part1? " + (cbcHex.substring(0, 32) === part1));
        console.log("  last  16=" + cbcHex.substring(32, 64) + " =part2? " + (cbcHex.substring(32, 64) === part2));

        // Try H2 as IV
        ivSpec = IvParameterSpec.$new(hexToByteArray(H2));
        cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(1, key, ivSpec);
        cbcResult = cipher.doFinal(hexToByteArray(H0 + H1));
        cbcHex = bytesToHex(cbcResult);
        console.log("AES_CBC(IV=H2, H0||H1)=" + cbcHex);
        console.log("  =part1+part2? " + (cbcHex === part1 + part2));

        // Try H4 as IV
        ivSpec = IvParameterSpec.$new(hexToByteArray(H4));
        cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(1, key, ivSpec);
        cbcResult = cipher.doFinal(hexToByteArray(H0 + H1));
        cbcHex = bytesToHex(cbcResult);
        console.log("AES_CBC(IV=H4, H0||H1)=" + cbcHex);
        console.log("  =part1+part2? " + (cbcHex === part1 + part2));

        // Try H5 as IV
        ivSpec = IvParameterSpec.$new(hexToByteArray(H5));
        cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(1, key, ivSpec);
        cbcResult = cipher.doFinal(hexToByteArray(H0 + H1));
        cbcHex = bytesToHex(cbcResult);
        console.log("AES_CBC(IV=H5, H0||H1)=" + cbcHex);
        console.log("  =part1+part2? " + (cbcHex === part1 + part2));

        // Maybe decrypt part1+part2 with CBC and see if it gives H0+H1
        cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(2, key, IvParameterSpec.$new(iv0));
        var decResult = cipher.doFinal(hexToByteArray(part1 + part2));
        var decHex = bytesToHex(decResult);
        console.log("\nAES_CBC_DEC(IV=0, part1+part2)=" + decHex);
        console.log("  = H0||H1? " + (decHex === H0 + H1));
        console.log("  = H1||H0? " + (decHex === H1 + H0));
        console.log("  first16 XOR H0=" + xorHex(decHex.substring(0, 32), H0));
        console.log("  first16 XOR H1=" + xorHex(decHex.substring(0, 32), H1));

        // More complex: maybe it's AES-CBC with specific IV and different data arrangement
        // Try: data = R(4 bytes padded to 16) + H0
        var rPadded = R + "000000000000000000000000";
        cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(1, key, IvParameterSpec.$new(iv0));
        cbcResult = cipher.doFinal(hexToByteArray(rPadded + H0));
        cbcHex = bytesToHex(cbcResult);
        console.log("\nAES_CBC(IV=0, R_pad||H0)=" + cbcHex);

        // Maybe it's not AES at all for Helios, just more MD5 chains
        // MD5(H0 XOR H4 + R)
        console.log("\n=== MORE MD5 CHAINS ===");
        var t1 = javaMD5(xorHex(H0, H4) + R);
        console.log("MD5((H0^H4)+R)=" + t1 + (t1===part1?" MATCH":""));
        t1 = javaMD5(R + xorHex(H0, H4));
        console.log("MD5(R+(H0^H4))=" + t1 + (t1===part1?" MATCH":""));
        t1 = javaMD5(xorHex(H0, H5) + R);
        console.log("MD5((H0^H5)+R)=" + t1 + (t1===part1?" MATCH":""));
        t1 = javaMD5(xorHex(H1, H4));
        console.log("MD5(H1^H4)=" + t1 + (t1===part1?" MATCH":"") + (t1===part2?" MATCH":""));
        t1 = javaMD5(xorHex(H1, H5));
        console.log("MD5(H1^H5)=" + t1 + (t1===part1?" MATCH":"") + (t1===part2?" MATCH":""));
        t1 = javaMD5(xorHex(H0, H1));
        console.log("MD5(H0^H1)=" + t1 + (t1===part1?" MATCH":"") + (t1===part2?" MATCH":""));

        // Test with the url params directly (not MD5)
        // Maybe part1 = MD5(url + R)? Too long to test easily.

        // What about HMAC-like: MD5(H4 || H0 || H4)?
        t1 = javaMD5(H4 + H0 + H4);
        console.log("MD5(H4+H0+H4)=" + t1 + (t1===part1?" MATCH":""));
        t1 = javaMD5(H5 + H0 + H5);
        console.log("MD5(H5+H0+H5)=" + t1 + (t1===part1?" MATCH":""));
        t1 = javaMD5(H4 + H1 + H4);
        console.log("MD5(H4+H1+H4)=" + t1 + (t1===part2?" MATCH":""));
        t1 = javaMD5(H5 + H1 + H5);
        console.log("MD5(H5+H1+H5)=" + t1 + (t1===part2?" MATCH":""));

        // HMAC-MD5 manual: MD5(opad || MD5(ipad || msg))
        // Using H4 as ipad_key and H5 as opad_key:
        var inner1 = javaMD5(H4 + H0);
        var outer1 = javaMD5(H5 + inner1);
        console.log("HMAC-like(H4,H5,H0): inner=" + inner1 + " outer=" + outer1 + (outer1===part1?" MATCH!":""));
        inner1 = javaMD5(H5 + H0);
        outer1 = javaMD5(H4 + inner1);
        console.log("HMAC-like(H5,H4,H0): inner=" + inner1 + " outer=" + outer1 + (outer1===part1?" MATCH!":""));

        // What about full URL param bytes (not hex) in MD5?
        // The MD5[0] already does this.

        // Let me try: part1 = MD5(H0 || H1 || H4 || H5)?
        t1 = javaMD5(H0 + H1 + H4 + H5);
        console.log("MD5(H0+H1+H4+H5)=" + t1 + (t1===part1?" MATCH":""));
        t1 = javaMD5(H4 + H0 + H5 + H1);
        console.log("MD5(H4+H0+H5+H1)=" + t1 + (t1===part1?" MATCH":""));
        t1 = javaMD5(H4 + H5 + H0 + H1);
        console.log("MD5(H4+H5+H0+H1)=" + t1 + (t1===part1?" MATCH":""));

        console.log("\n[DONE]");
    });
}

setup();
setTimeout(run, 2000);
