// Verify Helios algorithm by computing MD5 variants with Java MessageDigest
// and comparing against actual Helios output
// Run: frida -U -p <PID> -l scripts/hook_helios_verify.js

var libBase = null;
var md5Inputs = [];
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

function hexToBytes(h) {
    var bytes = [];
    for (var i = 0; i < h.length; i += 2) bytes.push(parseInt(h.substr(i, 2), 16));
    return bytes;
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;

    // Hook MD5 to capture inputs and outputs
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.a0 = args[0];
            this.len = args[1].toInt32();
            this.outPtr = args[2];
        },
        onLeave: function(ret) {
            if (!capturing) return;
            try {
                var input = hex(this.a0, Math.min(this.len, 512));
                var output = hex(this.outPtr, 16);
                md5Inputs.push({ hex: input, len: this.len });
                md5Outputs.push(output);
            } catch(e) {}
        }
    });

    console.log("[+] Hooks installed");
}

function javaMD5(hexStr) {
    // Use Java's MessageDigest to compute MD5
    var MessageDigest = Java.use("java.security.MessageDigest");
    var md = MessageDigest.getInstance("MD5");
    var bytes = hexToBytes(hexStr);
    var byteArray = Java.array('byte', bytes.map(function(b) { return b > 127 ? b - 256 : b; }));
    md.update(byteArray);
    var digest = md.digest();
    var result = '';
    for (var i = 0; i < digest.length; i++) {
        var b = digest[i];
        if (b < 0) b += 256;
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

        md5Inputs = [];
        md5Outputs = [];
        capturing = true;
        var sigs = doSign(url);
        capturing = false;

        var heliosHex = b64toHex(sigs["X-Helios"] || "");
        var R = heliosHex.substring(0, 8);
        var part1 = heliosHex.substring(8, 40);
        var part2 = heliosHex.substring(40, 72);

        console.log("\n=== CAPTURED DATA ===");
        console.log("Helios: " + heliosHex);
        console.log("  R     = " + R);
        console.log("  part1 = " + part1);
        console.log("  part2 = " + part2);
        for (var i = 0; i < md5Outputs.length; i++) {
            console.log("  MD5[" + i + "] in(" + md5Inputs[i].len + ")=" + md5Inputs[i].hex.substring(0,64) + "... out=" + md5Outputs[i]);
        }

        // H0=MD5(url), H1=MD5(R+"1967"), H2=MD5(uuid), H3=AES_KEY, H4, H5
        var H0 = md5Outputs[0] || "";
        var H1 = md5Outputs[1] || "";
        var H2 = md5Outputs[2] || "";
        var H3 = md5Outputs[3] || "";
        var H4 = md5Outputs[4] || "";
        var H5 = md5Outputs[5] || "";

        console.log("\n=== TESTING HYPOTHESES FOR part1 ===");
        console.log("Target part1: " + part1);

        // Test: MD5(H0 + H1)
        var t1 = javaMD5(H0 + H1);
        console.log("MD5(H0+H1)       = " + t1 + (t1 === part1 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H1 + H0)
        var t2 = javaMD5(H1 + H0);
        console.log("MD5(H1+H0)       = " + t2 + (t2 === part1 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H0 + R)
        var t3 = javaMD5(H0 + R);
        console.log("MD5(H0+R)        = " + t3 + (t3 === part1 ? " ★★★ MATCH!" : ""));

        // Test: MD5(R + H0)
        var t4 = javaMD5(R + H0);
        console.log("MD5(R+H0)        = " + t4 + (t4 === part1 ? " ★★★ MATCH!" : ""));

        // Test: H0 XOR H1
        var t5 = xorHex(H0, H1);
        console.log("H0 XOR H1        = " + t5 + (t5 === part1 ? " ★★★ MATCH!" : ""));

        // Test: H0 XOR H4
        var t6 = xorHex(H0, H4);
        console.log("H0 XOR H4        = " + t6 + (t6 === part1 ? " ★★★ MATCH!" : ""));

        // Test: H0 XOR H5
        var t7 = xorHex(H0, H5);
        console.log("H0 XOR H5        = " + t7 + (t7 === part1 ? " ★★★ MATCH!" : ""));

        // Test: H1 XOR H4
        var t8 = xorHex(H1, H4);
        console.log("H1 XOR H4        = " + t8 + (t8 === part1 ? " ★★★ MATCH!" : ""));

        // Test: H1 XOR H5
        var t9 = xorHex(H1, H5);
        console.log("H1 XOR H5        = " + t9 + (t9 === part1 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H0 + H2)
        var t10 = javaMD5(H0 + H2);
        console.log("MD5(H0+H2)       = " + t10 + (t10 === part1 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H0 + H3)
        var t11 = javaMD5(H0 + H3);
        console.log("MD5(H0+H3)       = " + t11 + (t11 === part1 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H0 + H4 + H5)
        var t12 = javaMD5(H0 + H4 + H5);
        console.log("MD5(H0+H4+H5)    = " + t12 + (t12 === part1 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H4 + H0)
        var t13 = javaMD5(H4 + H0);
        console.log("MD5(H4+H0)       = " + t13 + (t13 === part1 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H5 + H0)
        var t14 = javaMD5(H5 + H0);
        console.log("MD5(H5+H0)       = " + t14 + (t14 === part1 ? " ★★★ MATCH!" : ""));

        // Test: MD5(R + H0 + H1)
        var t15 = javaMD5(R + H0 + H1);
        console.log("MD5(R+H0+H1)     = " + t15 + (t15 === part1 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H0 + H1 + R)
        var t16 = javaMD5(H0 + H1 + R);
        console.log("MD5(H0+H1+R)     = " + t16 + (t16 === part1 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H1 + H0 + H2)
        var t17 = javaMD5(H1 + H0 + H2);
        console.log("MD5(H1+H0+H2)    = " + t17 + (t17 === part1 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H0 + H2 + H1)
        var t18 = javaMD5(H0 + H2 + H1);
        console.log("MD5(H0+H2+H1)    = " + t18 + (t18 === part1 ? " ★★★ MATCH!" : ""));

        console.log("\n=== TESTING HYPOTHESES FOR part2 ===");
        console.log("Target part2: " + part2);

        // Test: MD5(H1 + H0)
        var u1 = javaMD5(H1 + H0);
        console.log("MD5(H1+H0)       = " + u1 + (u1 === part2 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H0 + H1)
        var u2 = javaMD5(H0 + H1);
        console.log("MD5(H0+H1)       = " + u2 + (u2 === part2 ? " ★★★ MATCH!" : ""));

        // Test: H1 XOR H2
        var u3 = xorHex(H1, H2);
        console.log("H1 XOR H2        = " + u3 + (u3 === part2 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H1 + H2)
        var u4 = javaMD5(H1 + H2);
        console.log("MD5(H1+H2)       = " + u4 + (u4 === part2 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H1 + H4)
        var u5 = javaMD5(H1 + H4);
        console.log("MD5(H1+H4)       = " + u5 + (u5 === part2 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H4 + H1)
        var u6 = javaMD5(H4 + H1);
        console.log("MD5(H4+H1)       = " + u6 + (u6 === part2 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H5 + H1)
        var u7 = javaMD5(H5 + H1);
        console.log("MD5(H5+H1)       = " + u7 + (u7 === part2 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H1 + H5)
        var u8 = javaMD5(H1 + H5);
        console.log("MD5(H1+H5)       = " + u8 + (u8 === part2 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H4 + H5)
        var u9 = javaMD5(H4 + H5);
        console.log("MD5(H4+H5)       = " + u9 + (u9 === part2 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H5 + H4)
        var u10 = javaMD5(H5 + H4);
        console.log("MD5(H5+H4)       = " + u10 + (u10 === part2 ? " ★★★ MATCH!" : ""));

        // Test: H0 XOR H4 for part2
        var u11 = xorHex(H0, H4);
        console.log("H0 XOR H4        = " + u11 + (u11 === part2 ? " ★★★ MATCH!" : ""));

        // Test: H1 XOR H4
        var u12 = xorHex(H1, H4);
        console.log("H1 XOR H4        = " + u12 + (u12 === part2 ? " ★★★ MATCH!" : ""));

        // Test: H1 XOR H5
        var u13 = xorHex(H1, H5);
        console.log("H1 XOR H5        = " + u13 + (u13 === part2 ? " ★★★ MATCH!" : ""));

        // Test: MD5(R + H1 + H0)
        var u14 = javaMD5(R + H1 + H0);
        console.log("MD5(R+H1+H0)     = " + u14 + (u14 === part2 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H1 + R + H0)
        var u15 = javaMD5(H1 + R + H0);
        console.log("MD5(H1+R+H0)     = " + u15 + (u15 === part2 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H0 + H1 + H2)
        var u16 = javaMD5(H0 + H1 + H2);
        console.log("MD5(H0+H1+H2)    = " + u16 + (u16 === part2 ? " ★★★ MATCH!" : ""));

        // Test: MD5(H1 + H0 + H3)
        var u17 = javaMD5(H1 + H0 + H3);
        console.log("MD5(H1+H0+H3)    = " + u17 + (u17 === part2 ? " ★★★ MATCH!" : ""));

        // Maybe part2 = MD5(part1 + something)?
        var u18 = javaMD5(part1 + H0);
        console.log("MD5(part1+H0)    = " + u18 + (u18 === part2 ? " ★★★ MATCH!" : ""));

        var u19 = javaMD5(part1 + H1);
        console.log("MD5(part1+H1)    = " + u19 + (u19 === part2 ? " ★★★ MATCH!" : ""));

        var u20 = javaMD5(part1 + R);
        console.log("MD5(part1+R)     = " + u20 + (u20 === part2 ? " ★★★ MATCH!" : ""));

        var u21 = javaMD5(part1 + H2);
        console.log("MD5(part1+H2)    = " + u21 + (u21 === part2 ? " ★★★ MATCH!" : ""));

        console.log("\n[DONE]");
    });
}

setup();
setTimeout(run, 2000);
