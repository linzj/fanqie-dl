// 深入分析 X-Helios 和 X-Medusa 的算法
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
    var r = r4Instance.onCallToAddSecurityFactor(url, headers);
    var map = Java.cast(r, HashMapClass);
    var it = map.keySet().iterator();
    while (it.hasNext()) {
        var key = it.next();
        result[key] = map.get(key).toString();
    }
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
    var base = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
        "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
        "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
        "&device_brand=google&os_api=35&os_version=15" +
        "&device_id=3722313718058683&iid=3722313718062779";

    console.log("=== Part 1: X-Helios structure ===");
    // Same URL, multiple calls
    for (var i = 0; i < 5; i++) {
        var ts = Date.now();
        var url = base + "&_rticket=" + ts + "&book_id=7373660003258862617";
        var r = sign(url);
        var hb = b64toBytes(r["X-Helios"]);
        console.log("#" + i + " ts=" + r["X-Khronos"] + " helios(" + hb.length + ")=" + hex(hb));
    }

    console.log("\n=== Part 2: X-Medusa structure ===");
    for (var i = 0; i < 3; i++) {
        var ts = Date.now();
        var url = base + "&_rticket=" + ts + "&book_id=7373660003258862617";
        var r = sign(url);
        var mb = b64toBytes(r["X-Medusa"]);
        var tsBytes = parseInt(r["X-Khronos"]);
        console.log("#" + i + " ts=" + r["X-Khronos"] + " (0x" + tsBytes.toString(16) + ")");
        console.log("  medusa len=" + mb.length);
        console.log("  first 40 bytes: " + hex(mb.slice(0, 40)));
        console.log("  last  16 bytes: " + hex(mb.slice(-16)));

        // Check if timestamp LE appears
        var tsLE = [tsBytes & 0xff, (tsBytes >> 8) & 0xff, (tsBytes >> 16) & 0xff, (tsBytes >> 24) & 0xff];
        console.log("  ts LE: " + hex(tsLE));

        // Search for ts in medusa
        for (var j = 0; j < mb.length - 3; j++) {
            if (mb[j] === tsLE[0] && mb[j+1] === tsLE[1] && mb[j+2] === tsLE[2] && mb[j+3] === tsLE[3]) {
                console.log("  Found ts LE at offset " + j);
            }
        }
    }

    console.log("\n=== Part 3: Medusa diff between two calls (same URL) ===");
    var ts1 = Date.now();
    var url1 = base + "&_rticket=" + ts1 + "&book_id=7373660003258862617";
    var r1 = sign(url1);
    var r2 = sign(url1); // Same URL, called immediately after
    var m1 = b64toBytes(r1["X-Medusa"]);
    var m2 = b64toBytes(r2["X-Medusa"]);

    // Find common prefix
    var cp = 0;
    while (cp < Math.min(m1.length, m2.length) && m1[cp] === m2[cp]) cp++;
    console.log("Common prefix: " + cp + " bytes");
    console.log("m1[" + cp + "..+16]: " + hex(m1.slice(cp, cp+16)));
    console.log("m2[" + cp + "..+16]: " + hex(m2.slice(cp, cp+16)));

    // Find common suffix
    var cs = 0;
    while (cs < Math.min(m1.length, m2.length) && m1[m1.length-1-cs] === m2[m2.length-1-cs]) cs++;
    console.log("Common suffix: " + cs + " bytes");

    // Check if medusa has a header that indicates algorithm/version
    console.log("m1 header (first 32): " + hex(m1.slice(0, 32)));
    console.log("m2 header (first 32): " + hex(m2.slice(0, 32)));

    console.log("\n=== Part 4: Different URLs, same timestamp ===");
    var ts3 = Date.now();
    var urls = [
        base + "&_rticket=" + ts3 + "&book_id=1",
        base + "&_rticket=" + ts3 + "&book_id=2",
        base + "&_rticket=" + ts3 + "&book_id=3",
    ];
    for (var i = 0; i < urls.length; i++) {
        var r = sign(urls[i]);
        var hb = b64toBytes(r["X-Helios"]);
        var mb = b64toBytes(r["X-Medusa"]);
        console.log("book_id=" + (i+1) + ":");
        console.log("  helios: " + hex(hb));
        console.log("  medusa first 32: " + hex(mb.slice(0, 32)));
        console.log("  medusa len: " + mb.length);
    }

    console.log("\n=== Part 5: Helios + Medusa replayability ===");
    // Can we reuse the same Helios/Medusa for different timestamps?
    // Output curl commands to test
    var freshUrl = base + "&_rticket=" + Date.now() + "&book_id=7373660003258862617";
    var freshSigs = sign(freshUrl);

    console.log("FRESH_HELIOS=" + freshSigs["X-Helios"]);
    console.log("FRESH_MEDUSA_LEN=" + freshSigs["X-Medusa"].length);
    console.log("FRESH_TS=" + freshSigs["X-Khronos"]);
    console.log("FRESH_URL=" + freshUrl.substring(0, 100) + "...");

    // Test: use these Helios/Medusa with a different _rticket
    var testUrl = base + "&_rticket=" + (Date.now() + 5000) + "&book_id=7373660003258862617";
    console.log("\nCURL_REPLAY_TEST:");
    console.log("curl -s -w '\\n%{http_code} %{size_download}' '" + testUrl + "' " +
        "-H 'User-Agent: com.dragon.read/71332 (Linux; U; Android 15; zh_CN; sdk_gphone64_arm64; Build/AP3A.241105.008;tt-ok/3.12.13.20)' " +
        "-H 'Accept: application/json' -H 'Accept-Encoding: identity' " +
        "-H 'sdk-version: 2' -H 'lc: 101' -H 'passport-sdk-version: 5051451' " +
        "-H 'x-tt-store-region: cn-gd' -H 'x-tt-store-region-src: did' " +
        "-H 'X-SS-REQ-TICKET: " + Date.now() + "' " +
        "-H 'x-reading-request: " + Date.now() + "-abcd' " +
        "-H 'X-Helios: " + freshSigs["X-Helios"] + "' " +
        "-H 'X-Medusa: " + freshSigs["X-Medusa"] + "'");

    console.log("\n[DONE]");
}
