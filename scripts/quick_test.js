// 生成签名并立即输出 curl 测试脚本
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
                        generate();
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

function generate() {
    var ts = Math.floor(Date.now() / 1000);
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

    var sigs = sign(url);

    // Output as a shell script
    var common = "curl -s -w '\\n%{http_code} %{size_download}' '" + url + "' ";
    common += "-H 'User-Agent: com.dragon.read/71332 (Linux; U; Android 15; zh_CN; sdk_gphone64_arm64; Build/AP3A.241105.008;tt-ok/3.12.13.20)' ";
    common += "-H 'Accept: application/json' -H 'Accept-Encoding: identity' ";
    common += "-H 'sdk-version: 2' -H 'lc: 101' ";
    common += "-H 'passport-sdk-version: 5051451' ";
    common += "-H 'x-tt-store-region: cn-gd' -H 'x-tt-store-region-src: did' ";
    common += "-H 'X-SS-REQ-TICKET: " + tsMs + "' ";
    common += "-H 'x-reading-request: " + tsMs + "-abcd1234' ";

    var sigHeaders = "";
    for (var k in sigs) {
        sigHeaders += "-H '" + k + ": " + sigs[k] + "' ";
    }

    // Build script: test all combinations rapidly
    console.log("#!/bin/bash");
    console.log("# Auto-generated at " + new Date().toISOString());
    console.log("echo '=== T1: ALL headers ==='");
    console.log(common + sigHeaders);
    console.log("");

    console.log("echo '=== T2: No Medusa ==='");
    var noMedusa = "";
    for (var k in sigs) {
        if (k !== "X-Medusa") noMedusa += "-H '" + k + ": " + sigs[k] + "' ";
    }
    console.log(common + noMedusa);
    console.log("");

    console.log("echo '=== T3: No Helios ==='");
    var noHelios = "";
    for (var k in sigs) {
        if (k !== "X-Helios") noHelios += "-H '" + k + ": " + sigs[k] + "' ";
    }
    console.log(common + noHelios);
    console.log("");

    console.log("echo '=== T4: No Ladon ==='");
    var noLadon = "";
    for (var k in sigs) {
        if (k !== "X-Ladon") noLadon += "-H '" + k + ": " + sigs[k] + "' ";
    }
    console.log(common + noLadon);
    console.log("");

    console.log("echo '=== T5: No Argus ==='");
    var noArgus = "";
    for (var k in sigs) {
        if (k !== "X-Argus") noArgus += "-H '" + k + ": " + sigs[k] + "' ";
    }
    console.log(common + noArgus);
    console.log("");

    console.log("echo '=== T6: No Gorgon ==='");
    var noGorgon = "";
    for (var k in sigs) {
        if (k !== "X-Gorgon") noGorgon += "-H '" + k + ": " + sigs[k] + "' ";
    }
    console.log(common + noGorgon);
    console.log("");

    console.log("echo '=== T7: Gorgon+Khronos+Argus+Ladon only ==='");
    console.log(common + "-H 'X-Gorgon: " + sigs["X-Gorgon"] + "' -H 'X-Khronos: " + sigs["X-Khronos"] + "' -H 'X-Argus: " + sigs["X-Argus"] + "' -H 'X-Ladon: " + sigs["X-Ladon"] + "' ");
    console.log("");

    console.log("echo '=== T8: No signatures ==='");
    console.log(common);
    console.log("");

    console.log("echo '=== T9: Fake Argus (random 4 bytes) + real rest ==='");
    var fakeArgusHeaders = "";
    for (var k in sigs) {
        if (k === "X-Argus") {
            fakeArgusHeaders += "-H 'X-Argus: AAAA' ";
        } else {
            fakeArgusHeaders += "-H '" + k + ": " + sigs[k] + "' ";
        }
    }
    console.log(common + fakeArgusHeaders);
    console.log("");

    console.log("echo '=== T10: Fake Ladon (random 4 bytes) + real rest ==='");
    var fakeLadonHeaders = "";
    for (var k in sigs) {
        if (k === "X-Ladon") {
            fakeLadonHeaders += "-H 'X-Ladon: AAAA' ";
        } else {
            fakeLadonHeaders += "-H '" + k + ": " + sigs[k] + "' ";
        }
    }
    console.log(common + fakeLadonHeaders);

    console.log("\n# Run: frida ... | grep -v '^#' > /tmp/test.sh && bash /tmp/test.sh");
}
