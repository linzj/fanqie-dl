// 深入分析 X-Ladon 的4字节构成
// 观察: 同一秒内调用, ts相同但 ladon 不同 => 有随机成分
// 某些 ladon 高位是 0x1e/0x11, 某些是 0x0f/0x00 => 可能与 URL 有关

var r4Instance = null;
var HashMapClass = null;

Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                Java.classFactory.loader = loader;
                HashMapClass = Java.use("java.util.HashMap");
                Java.choose("ms.bd.c.r4", {
                    onMatch: function(inst) {
                        r4Instance = inst;
                        console.log("[+] Ready\n");
                        analyze();
                    },
                    onComplete: function() {}
                });
            } catch(e) {}
        },
        onComplete: function() {}
    });
});

function sign(url) {
    var result = {};
    var headers = HashMapClass.$new();
    try {
        var r = r4Instance.onCallToAddSecurityFactor(url, headers);
        var map = Java.cast(r, HashMapClass);
        var it = map.keySet().iterator();
        while (it.hasNext()) {
            var key = it.next();
            result[key] = map.get(key).toString();
        }
    } catch(e) { result.error = e.toString(); }
    return result;
}

function b64toBytes(s) {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var bytes = [];
    var buf = 0, bits = 0;
    for (var i = 0; i < s.length; i++) {
        if (s[i] === '=') break;
        buf = (buf << 6) | chars.indexOf(s[i]);
        bits += 6;
        if (bits >= 8) { bits -= 8; bytes.push((buf >> bits) & 0xff); }
    }
    return bytes;
}

function hex(bytes) {
    return bytes.map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join('');
}

function analyze() {
    console.log("=== 分析1: 同一URL连续调用20次 (观察Ladon随机性) ===");
    var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?aid=1967&device_id=3405654380789289&book_id=7373660003258862617";
    var ladons = [];
    var gorgons = [];
    for (var i = 0; i < 20; i++) {
        var r = sign(url);
        var lb = b64toBytes(r["X-Ladon"]);
        var ts = parseInt(r["X-Khronos"]);
        ladons.push({ts: ts, bytes: lb, hex: hex(lb)});
        gorgons.push(r["X-Gorgon"]);
        console.log("#" + i + " ts=" + ts + " ladon=" + hex(lb) + " gorgon=" + r["X-Gorgon"].substring(0, 20));
    }

    // Check: is ladon[0] XOR ladon[1] constant?
    console.log("\nLadon XOR pairs:");
    for (var i = 0; i < ladons.length - 1; i++) {
        var xor = [];
        for (var j = 0; j < 4; j++) {
            xor.push(ladons[i].bytes[j] ^ ladons[i+1].bytes[j]);
        }
        console.log("  #" + i + " ^ #" + (i+1) + " = " + hex(xor));
    }

    console.log("\n=== 分析2: Gorgon 前缀分析 (8404后面的字节) ===");
    for (var i = 0; i < gorgons.length; i++) {
        // 8404XXXXYYYY...  -> parse as hex bytes
        var g = gorgons[i];
        // format: 8404 BBCC 0000 ....
        console.log("#" + i + " " + g.substring(0, 12) + " | " + g.substring(12));
    }

    console.log("\n=== 分析3: Medusa 前缀分析 ===");
    var r1 = sign(url);
    var r2 = sign(url);
    if (r1["X-Medusa"] && r2["X-Medusa"]) {
        var m1 = b64toBytes(r1["X-Medusa"]);
        var m2 = b64toBytes(r2["X-Medusa"]);
        console.log("Medusa1 len=" + m1.length + " first16=" + hex(m1.slice(0, 16)));
        console.log("Medusa2 len=" + m2.length + " first16=" + hex(m2.slice(0, 16)));
        // Check common prefix
        var common = 0;
        for (var i = 0; i < Math.min(m1.length, m2.length); i++) {
            if (m1[i] === m2[i]) common++;
            else break;
        }
        console.log("Common prefix bytes: " + common);
        if (common > 0) {
            console.log("Common prefix: " + hex(m1.slice(0, common)));
        }
        // XOR first 16 different bytes
        console.log("XOR at offset " + common + ": " + hex(m1.slice(common, common+16).map(function(b, i) { return b ^ m2[common + i]; })));
    }

    console.log("\n=== 分析4: Ladon 与 URL 参数的关系 ===");
    // 固定 timestamp, 改变 URL 参数
    var urls = [
        "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?aid=1967&device_id=3405654380789289&book_id=1",
        "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?aid=1967&device_id=3405654380789289&book_id=2",
        "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?aid=1967&device_id=3405654380789289&book_id=3",
    ];
    for (var i = 0; i < urls.length; i++) {
        // Call twice each to see variation
        var ra = sign(urls[i]);
        var rb = sign(urls[i]);
        console.log("book_id=" + (i+1) + " ladonA=" + hex(b64toBytes(ra["X-Ladon"])) + " ladonB=" + hex(b64toBytes(rb["X-Ladon"])));
    }

    console.log("\n=== 分析5: Gorgon 算法验证 ===");
    // Our impl uses version 0404, real app uses 8404
    // The 8404 prefix might mean a different algorithm version
    // Let's look at the full Gorgon structure
    var gr = sign(url);
    var gorgon = gr["X-Gorgon"];
    console.log("Full Gorgon: " + gorgon);
    console.log("Length: " + gorgon.length + " chars = " + (gorgon.length/2) + " bytes hex");
    // Parse: VVVVBBBBSSSS + 19 bytes data
    console.log("Version: " + gorgon.substring(0, 4));  // 8404
    console.log("Byte 2-3: " + gorgon.substring(4, 8)); // varies
    console.log("Byte 4-5: " + gorgon.substring(8, 12)); // often 0000
    console.log("Data (19 bytes): " + gorgon.substring(12));

    console.log("\n[DONE]");
}
