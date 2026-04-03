/**
 * capture_and_curl.js — 捕获完整签名 + 输出 curl 命令
 * 用法: frida -U -p PID -l scripts/capture_and_curl.js
 */
'use strict';

Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try { loader.findClass("ms.bd.c.r4"); } catch(e) { return; }
            Java.classFactory.loader = loader;
            var HM = Java.use("java.util.HashMap");

            Java.choose("ms.bd.c.r4", {
                onMatch: function(inst) {
                    var ts = Math.floor(Date.now() / 1000);
                    var tsMs = Date.now();
                    var qs = "ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
                        "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
                        "&device_brand=google&os_api=35&os_version=15" +
                        "&device_id=3722313718058683&iid=3722313718062779" +
                        "&_rticket=" + tsMs +
                        "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
                        "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
                        "&book_id=7373660003258862617";
                    var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?" + qs;

                    var h = HM.$new();
                    var r = inst.onCallToAddSecurityFactor(url, h);
                    var m = Java.cast(r, HM);

                    // Build curl
                    var curl = "curl -s '" + url + "'";
                    curl += " -H 'User-Agent: com.dragon.read/71332 (Linux; U; Android 15; zh_CN; sdk_gphone64_arm64; Build/AP3A.241105.008;tt-ok/3.12.13.20)'";
                    curl += " -H 'Accept: application/json'";
                    curl += " -H 'sdk-version: 2'";
                    curl += " -H 'X-SS-REQ-TICKET: " + tsMs + "'";

                    var it = m.keySet().iterator();
                    while (it.hasNext()) {
                        var k = it.next();
                        var v = m.get(k).toString();
                        curl += " -H '" + k + ": " + v + "'";
                        console.log(k + "=" + v.substring(0, 60) + (v.length > 60 ? "..." : ""));
                    }

                    console.log("\n=== CURL ===");
                    console.log(curl);
                    console.log("\n=== END ===");
                },
                onComplete: function() {}
            });
        },
        onComplete: function() {}
    });
});
