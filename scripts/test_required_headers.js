// 测试哪些签名头是服务端实际验证的
// 方法：用真实签名发请求，然后逐个去掉/修改签名头，观察响应

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
                        testHeaders();
                    },
                    onComplete: function() {}
                });
            } catch(e) {}
        },
        onComplete: function() {}
    });
});

function getSignatures(url) {
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

function httpGet(url, extraHeaders) {
    // Use OkHttp from the app
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Request = Java.use("okhttp3.Request");
    var RequestBuilder = Java.use("okhttp3.Request$Builder");

    var builder = RequestBuilder.$new();
    builder.url(url);

    // Add common headers
    builder.addHeader("User-Agent", "com.dragon.read/71332 (Linux; U; Android 9; zh_CN; Pixel 4; Build/PQ3B.190801.002;tt-ok/3.12.13.20)");
    builder.addHeader("Accept", "application/json; charset=utf-8,application/x-protobuf");
    builder.addHeader("sdk-version", "2");

    // Add extra headers
    for (var k in extraHeaders) {
        builder.addHeader(k, extraHeaders[k]);
    }

    var request = builder.build();
    var client = OkHttpClient.$new();

    try {
        var response = client.newCall(request).execute();
        var code = response.code();
        var body = response.body().string();
        return {code: code, length: body.length, preview: body.substring(0, 200)};
    } catch(e) {
        return {error: e.toString()};
    }
}

function testHeaders() {
    var baseUrl = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/";
    var params = "ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32&device_platform=android&os=android&ssmix=a&device_type=Pixel+4&device_brand=google&os_api=28&os_version=9&device_id=3405654380789289&iid=987654321&book_id=7373660003258862617";
    var fullUrl = baseUrl + "?" + params;

    // Get real signatures
    var sigs = getSignatures(fullUrl);
    console.log("Real signatures:");
    for (var k in sigs) {
        var v = sigs[k];
        if (v.length > 40) v = v.substring(0, 40) + "...";
        console.log("  " + k + " = " + v);
    }

    // Test 1: All real signatures
    console.log("\n=== Test 1: All real signatures ===");
    var r1 = httpGet(fullUrl, sigs);
    console.log("Result: code=" + r1.code + " len=" + r1.length + " body=" + (r1.preview || r1.error));

    // Test 2: No signatures at all
    console.log("\n=== Test 2: No signatures ===");
    var r2 = httpGet(fullUrl, {});
    console.log("Result: code=" + r2.code + " len=" + r2.length + " body=" + (r2.preview || r2.error));

    // Test 3: Only X-Khronos
    console.log("\n=== Test 3: Only X-Khronos ===");
    var r3 = httpGet(fullUrl, {"X-Khronos": sigs["X-Khronos"]});
    console.log("Result: code=" + r3.code + " len=" + r3.length + " body=" + (r3.preview || r3.error));

    // Test 4: Gorgon + Khronos only
    console.log("\n=== Test 4: X-Gorgon + X-Khronos ===");
    var r4 = httpGet(fullUrl, {
        "X-Gorgon": sigs["X-Gorgon"],
        "X-Khronos": sigs["X-Khronos"]
    });
    console.log("Result: code=" + r4.code + " len=" + r4.length + " body=" + (r4.preview || r4.error));

    // Test 5: Gorgon + Khronos + Argus
    console.log("\n=== Test 5: X-Gorgon + X-Khronos + X-Argus ===");
    var r5 = httpGet(fullUrl, {
        "X-Gorgon": sigs["X-Gorgon"],
        "X-Khronos": sigs["X-Khronos"],
        "X-Argus": sigs["X-Argus"]
    });
    console.log("Result: code=" + r5.code + " len=" + r5.length + " body=" + (r5.preview || r5.error));

    // Test 6: All except X-Medusa
    console.log("\n=== Test 6: All except X-Medusa ===");
    var h6 = {};
    for (var k in sigs) {
        if (k !== "X-Medusa") h6[k] = sigs[k];
    }
    var r6 = httpGet(fullUrl, h6);
    console.log("Result: code=" + r6.code + " len=" + r6.length + " body=" + (r6.preview || r6.error));

    // Test 7: All except X-Helios
    console.log("\n=== Test 7: All except X-Helios ===");
    var h7 = {};
    for (var k in sigs) {
        if (k !== "X-Helios") h7[k] = sigs[k];
    }
    var r7 = httpGet(fullUrl, h7);
    console.log("Result: code=" + r7.code + " len=" + r7.length + " body=" + (r7.preview || r7.error));

    // Test 8: All except X-Ladon
    console.log("\n=== Test 8: All except X-Ladon ===");
    var h8 = {};
    for (var k in sigs) {
        if (k !== "X-Ladon") h8[k] = sigs[k];
    }
    var r8 = httpGet(fullUrl, h8);
    console.log("Result: code=" + r8.code + " len=" + r8.length + " body=" + (r8.preview || r8.error));

    // Test 9: All except X-Argus
    console.log("\n=== Test 9: All except X-Argus ===");
    var h9 = {};
    for (var k in sigs) {
        if (k !== "X-Argus") h9[k] = sigs[k];
    }
    var r9 = httpGet(fullUrl, h9);
    console.log("Result: code=" + r9.code + " len=" + r9.length + " body=" + (r9.preview || r9.error));

    // Test 10: Real Gorgon + fake others (random Argus/Ladon)
    console.log("\n=== Test 10: Real Gorgon + fake Argus/Ladon ===");
    var h10 = {
        "X-Gorgon": sigs["X-Gorgon"],
        "X-Khronos": sigs["X-Khronos"],
        "X-Argus": "AAAABB==",
        "X-Ladon": "CCCCDD==",
        "X-Helios": sigs["X-Helios"],
        "X-Medusa": sigs["X-Medusa"]
    };
    var r10 = httpGet(fullUrl, h10);
    console.log("Result: code=" + r10.code + " len=" + r10.length + " body=" + (r10.preview || r10.error));

    // Test 11: Correct Argus (timestamp LE) + real Gorgon + fake rest
    console.log("\n=== Test 11: Correct Argus(ts LE) + real Gorgon + fake Ladon ===");
    var h11 = {
        "X-Gorgon": sigs["X-Gorgon"],
        "X-Khronos": sigs["X-Khronos"],
        "X-Argus": sigs["X-Argus"],
        "X-Ladon": "CCCCDD==",
    };
    var r11 = httpGet(fullUrl, h11);
    console.log("Result: code=" + r11.code + " len=" + r11.length + " body=" + (r11.preview || r11.error));

    // Test 12: Only Gorgon + Khronos + Argus + Ladon (no Helios/Medusa)
    console.log("\n=== Test 12: Gorgon + Khronos + Argus + Ladon (no Helios/Medusa) ===");
    var h12 = {
        "X-Gorgon": sigs["X-Gorgon"],
        "X-Khronos": sigs["X-Khronos"],
        "X-Argus": sigs["X-Argus"],
        "X-Ladon": sigs["X-Ladon"],
    };
    var r12 = httpGet(fullUrl, h12);
    console.log("Result: code=" + r12.code + " len=" + r12.length + " body=" + (r12.preview || r12.error));

    console.log("\n[DONE] Header requirement analysis complete");
}
