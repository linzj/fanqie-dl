// 深入调查签名算法：用不同输入测试，观察输出变化规律
// 目标：理解 X-Argus(5字节), X-Ladon(5字节), X-Gorgon(8404版本) 的算法

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
                        console.log("[+] r4 instance captured, starting analysis...\n");
                        runAnalysis();
                    },
                    onComplete: function() {}
                });
            } catch(e) {}
        },
        onComplete: function() {}
    });
});

function callSign(url) {
    var result = {};
    var headers = HashMapClass.$new();
    try {
        var signResult = r4Instance.onCallToAddSecurityFactor(url, headers);
        var map = Java.cast(signResult, HashMapClass);
        var it = map.keySet().iterator();
        while (it.hasNext()) {
            var key = it.next();
            result[key] = map.get(key).toString();
        }
    } catch(e) {
        result.error = e.toString();
    }
    return result;
}

function b64decode(s) {
    // Simple base64 to hex
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var bytes = [];
    var buf = 0, bits = 0;
    for (var i = 0; i < s.length; i++) {
        if (s[i] === '=') break;
        buf = (buf << 6) | chars.indexOf(s[i]);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            bytes.push((buf >> bits) & 0xff);
        }
    }
    return bytes;
}

function toHex(bytes) {
    return bytes.map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join('');
}

function runAnalysis() {
    var baseParams = "ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32&device_platform=android&os=android&ssmix=a&device_type=Pixel+4&device_brand=google&os_api=28&os_version=9";
    var baseUrl = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/";

    console.log("========================================");
    console.log("=== 测试1: 相同URL连续调用两次 ===");
    console.log("========================================");
    var url1 = baseUrl + "?" + baseParams + "&device_id=3405654380789289&iid=987654321&book_id=7373660003258862617";
    var r1a = callSign(url1);
    var r1b = callSign(url1);
    console.log("第1次:");
    printResult(r1a);
    console.log("第2次:");
    printResult(r1b);
    console.log("Khronos相同? " + (r1a["X-Khronos"] === r1b["X-Khronos"]));
    console.log("Argus相同? " + (r1a["X-Argus"] === r1b["X-Argus"]));
    console.log("Ladon相同? " + (r1a["X-Ladon"] === r1b["X-Ladon"]));
    console.log("Gorgon相同? " + (r1a["X-Gorgon"] === r1b["X-Gorgon"]));

    console.log("\n========================================");
    console.log("=== 测试2: 不同 book_id ===");
    console.log("========================================");
    var url2 = baseUrl + "?" + baseParams + "&device_id=3405654380789289&iid=987654321&book_id=9999999999";
    var r2 = callSign(url2);
    printResult(r2);

    console.log("\n========================================");
    console.log("=== 测试3: 不同 device_id ===");
    console.log("========================================");
    var url3 = baseUrl + "?" + baseParams + "&device_id=1111111111&iid=987654321&book_id=7373660003258862617";
    var r3 = callSign(url3);
    printResult(r3);

    console.log("\n========================================");
    console.log("=== 测试4: 不同endpoint (search) ===");
    console.log("========================================");
    var url4 = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/search/tab/v?" + baseParams + "&device_id=3405654380789289&iid=987654321&query=test&offset=0&count=10";
    var r4 = callSign(url4);
    printResult(r4);

    console.log("\n========================================");
    console.log("=== 测试5: 最小参数 ===");
    console.log("========================================");
    var url5 = baseUrl + "?aid=1967&device_id=3405654380789289";
    var r5 = callSign(url5);
    printResult(r5);

    console.log("\n========================================");
    console.log("=== 测试6: 解码分析 ===");
    console.log("========================================");
    // Decode all X-Argus values
    var tests = [r1a, r1b, r2, r3, r4, r5];
    var labels = ["test1a", "test1b", "test2", "test3", "test4", "test5"];
    for (var i = 0; i < tests.length; i++) {
        if (tests[i]["X-Argus"]) {
            var argusBytes = b64decode(tests[i]["X-Argus"]);
            var ladonBytes = b64decode(tests[i]["X-Ladon"]);
            console.log(labels[i] + ":");
            console.log("  Argus bytes(" + argusBytes.length + "): " + toHex(argusBytes));
            console.log("  Ladon bytes(" + ladonBytes.length + "): " + toHex(ladonBytes));
            console.log("  Khronos: " + tests[i]["X-Khronos"]);
            // Check if Argus/Ladon relate to timestamp
            var ts = parseInt(tests[i]["X-Khronos"]);
            console.log("  ts hex: " + ts.toString(16));
            console.log("  ts bytes LE: " + toHex([ts&0xff, (ts>>8)&0xff, (ts>>16)&0xff, (ts>>24)&0xff]));
            console.log("  ts bytes BE: " + toHex([(ts>>24)&0xff, (ts>>16)&0xff, (ts>>8)&0xff, ts&0xff]));
        }
    }

    console.log("\n========================================");
    console.log("=== 测试7: 快速连续调用5次，观察变化 ===");
    console.log("========================================");
    for (var i = 0; i < 5; i++) {
        var r = callSign(url1);
        var argusHex = toHex(b64decode(r["X-Argus"]));
        var ladonHex = toHex(b64decode(r["X-Ladon"]));
        console.log("#" + i + " ts=" + r["X-Khronos"] + " argus=" + argusHex + " ladon=" + ladonHex + " gorgon=" + r["X-Gorgon"].substring(0, 12));
    }

    console.log("\n========================================");
    console.log("=== 测试8: X-Helios 分析 ===");
    console.log("========================================");
    if (r1a["X-Helios"]) {
        var heliosBytes = b64decode(r1a["X-Helios"]);
        console.log("Helios bytes(" + heliosBytes.length + "): " + toHex(heliosBytes));
    }

    console.log("\n[DONE] Analysis complete");
}

function printResult(r) {
    var order = ["X-Khronos", "X-Gorgon", "X-Argus", "X-Ladon", "X-Helios", "X-Medusa"];
    for (var i = 0; i < order.length; i++) {
        var k = order[i];
        if (r[k]) {
            var v = r[k];
            if (k === "X-Medusa") v = v.substring(0, 60) + "...(" + v.length + " chars)";
            console.log("  " + k + " = " + v);
        }
    }
}
