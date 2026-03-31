// 简单方案：获取签名，输出 curl 命令让宿主机测试

var r4Instance = null;
var HashMapClass = null;
var appDeviceId = "3722313718058683";
var appIid = "3722313718062779";

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
                        generateCurlCommands();
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

function generateCurlCommands() {
    var ts = Math.floor(Date.now() / 1000);
    var tsMs = Date.now();

    // Test 1: book detail
    var url1 = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
        "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
        "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
        "&device_brand=google&os_api=35&os_version=15" +
        "&device_id=" + appDeviceId +
        "&iid=" + appIid +
        "&_rticket=" + tsMs +
        "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
        "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
        "&book_id=7373660003258862617";

    var sigs1 = sign(url1);

    console.log("=== CURL COMMAND (book detail with ALL headers) ===");
    var curl = "curl -s -w '\\nHTTP_CODE:%{http_code} SIZE:%{size_download}' \\\n";
    curl += "  '" + url1 + "' \\\n";
    curl += "  -H 'User-Agent: com.dragon.read/71332 (Linux; U; Android 15; zh_CN; sdk_gphone64_arm64; Build/AP3A.241105.008;tt-ok/3.12.13.20)' \\\n";
    curl += "  -H 'Accept: application/json' \\\n";
    curl += "  -H 'Accept-Encoding: identity' \\\n";
    curl += "  -H 'sdk-version: 2' \\\n";
    curl += "  -H 'lc: 101' \\\n";
    curl += "  -H 'passport-sdk-version: 5051451' \\\n";
    curl += "  -H 'x-tt-store-region: cn-gd' \\\n";
    curl += "  -H 'x-tt-store-region-src: did' \\\n";
    curl += "  -H 'X-SS-REQ-TICKET: " + tsMs + "' \\\n";
    curl += "  -H 'x-reading-request: " + tsMs + "-abcd1234' \\\n";

    for (var k in sigs1) {
        var v = sigs1[k];
        curl += "  -H '" + k + ": " + v + "' \\\n";
    }
    console.log(curl);

    // Test 2: same but without Helios/Medusa
    console.log("\n=== CURL COMMAND (without Helios/Medusa) ===");
    var curl2 = "curl -s -w '\\nHTTP_CODE:%{http_code} SIZE:%{size_download}' \\\n";
    curl2 += "  '" + url1 + "' \\\n";
    curl2 += "  -H 'User-Agent: com.dragon.read/71332 (Linux; U; Android 15; zh_CN; sdk_gphone64_arm64; Build/AP3A.241105.008;tt-ok/3.12.13.20)' \\\n";
    curl2 += "  -H 'Accept: application/json' \\\n";
    curl2 += "  -H 'sdk-version: 2' \\\n";
    curl2 += "  -H 'lc: 101' \\\n";
    curl2 += "  -H 'X-SS-REQ-TICKET: " + tsMs + "' \\\n";
    curl2 += "  -H 'x-reading-request: " + tsMs + "-abcd1234' \\\n";
    for (var k in sigs1) {
        if (k !== "X-Helios" && k !== "X-Medusa") {
            curl2 += "  -H '" + k + ": " + sigs1[k] + "' \\\n";
        }
    }
    console.log(curl2);

    // Test 3: ONLY Gorgon + Khronos
    console.log("\n=== CURL COMMAND (only Gorgon + Khronos) ===");
    var curl3 = "curl -s -w '\\nHTTP_CODE:%{http_code} SIZE:%{size_download}' \\\n";
    curl3 += "  '" + url1 + "' \\\n";
    curl3 += "  -H 'User-Agent: com.dragon.read/71332 (Linux; U; Android 15; zh_CN; sdk_gphone64_arm64; Build/AP3A.241105.008;tt-ok/3.12.13.20)' \\\n";
    curl3 += "  -H 'Accept: application/json' \\\n";
    curl3 += "  -H 'sdk-version: 2' \\\n";
    curl3 += "  -H 'lc: 101' \\\n";
    curl3 += "  -H 'X-SS-REQ-TICKET: " + tsMs + "' \\\n";
    curl3 += "  -H 'x-reading-request: " + tsMs + "-abcd1234' \\\n";
    curl3 += "  -H 'X-Gorgon: " + sigs1["X-Gorgon"] + "' \\\n";
    curl3 += "  -H 'X-Khronos: " + sigs1["X-Khronos"] + "' \\\n";
    console.log(curl3);

    // Test 4: NO signatures at all
    console.log("\n=== CURL COMMAND (no signatures) ===");
    var curl4 = "curl -s -w '\\nHTTP_CODE:%{http_code} SIZE:%{size_download}' \\\n";
    curl4 += "  '" + url1 + "' \\\n";
    curl4 += "  -H 'User-Agent: com.dragon.read/71332 (Linux; U; Android 15; zh_CN; sdk_gphone64_arm64; Build/AP3A.241105.008;tt-ok/3.12.13.20)' \\\n";
    curl4 += "  -H 'Accept: application/json' \\\n";
    curl4 += "  -H 'sdk-version: 2' \\\n";
    curl4 += "  -H 'lc: 101' \\\n";
    console.log(curl4);

    console.log("\n[DONE] Copy and run these curl commands on the host");
}
