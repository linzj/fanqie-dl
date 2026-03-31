// Hook real app traffic + 用正确的 device_id 测试
// 1. 监控 app 自己的 HTTP 请求
// 2. 用正确的 device_id 和 iid 手动发请求

var appDeviceId = "3722313718058683";
var appIid = "3722313718062779";

Java.perform(function() {
    // Hook Response.body() to see response data
    try {
        var ResponseBody = Java.use("okhttp3.ResponseBody");
        var BufferedSource = Java.use("okio.BufferedSource");
        var Buffer = Java.use("okio.Buffer");

        // Hook at a higher level - the callback
        var Callback = Java.use("okhttp3.Callback");

        // Actually, let's hook the retrofit/network layer
        // Hook HttpUrl.toString to see URL construction
    } catch(e) {}

    // 主要方法：Hook SecurityFactorInterceptor
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                Java.classFactory.loader = loader;

                // Hook the OkHttp3SecurityFactorInterceptor
                try {
                    var interceptorClass = Java.use("com.bytedance.frameworks.baselib.network.http.interceptor.OkHttp3SecurityFactorInterceptor");
                    interceptorClass.intercept.implementation = function(chain) {
                        var request = chain.request();
                        var url = request.url().toString();

                        if (url.indexOf("bookapi") !== -1 || url.indexOf("search") !== -1 || url.indexOf("crypt") !== -1) {
                            console.log("\n=== SecurityFactorInterceptor ===");
                            console.log("URL: " + url.substring(0, 200));
                        }

                        var resp = this.intercept(chain);

                        if (url.indexOf("bookapi") !== -1 || url.indexOf("search") !== -1 || url.indexOf("crypt") !== -1) {
                            // Log the modified request (with signatures)
                            var modReq = resp.request();
                            var headers = modReq.headers();
                            console.log("Signed headers:");
                            for (var i = 0; i < headers.size(); i++) {
                                var name = headers.name(i);
                                if (name.startsWith("X-") || name.startsWith("x-")) {
                                    var val = headers.value(i);
                                    if (val.length > 80) val = val.substring(0, 80) + "...";
                                    console.log("  " + name + ": " + val);
                                }
                            }

                            console.log("Response code: " + resp.code());
                            try {
                                var body = resp.peekBody(Java.use("java.lang.Long").parseLong("10240")).string();
                                console.log("Response body len: " + body.length);
                                if (body.length > 0 && body.length < 1000) {
                                    console.log("Body: " + body);
                                } else if (body.length > 0) {
                                    console.log("Body preview: " + body.substring(0, 500));
                                }
                            } catch(e) {
                                console.log("Cannot read body: " + e);
                            }
                        }

                        return resp;
                    };
                    console.log("[+] SecurityFactorInterceptor hooked");
                } catch(e) {
                    console.log("[!] Cannot hook SecurityFactorInterceptor: " + e);
                    console.log("    Trying alternative hooks...");

                    // Alternative: hook r4 and RealCall
                    var r4Class = Java.use("ms.bd.c.r4");
                    r4Class.onCallToAddSecurityFactor.implementation = function(url, headers) {
                        var result = this.onCallToAddSecurityFactor(url, headers);
                        if (url && (url.indexOf("bookapi") !== -1 || url.indexOf("search") !== -1)) {
                            console.log("\n[r4.sign] URL: " + url.substring(0, 150));
                            var map = Java.cast(result, Java.use("java.util.HashMap"));
                            var it = map.keySet().iterator();
                            while (it.hasNext()) {
                                var key = it.next();
                                var val = map.get(key).toString();
                                if (val.length > 60) val = val.substring(0, 60) + "...";
                                console.log("  " + key + " = " + val);
                            }
                        }
                        return result;
                    };
                    console.log("[+] r4.onCallToAddSecurityFactor hooked (fallback)");
                }

                // 手动发请求测试
                setTimeout(function() {
                    Java.perform(function() {
                        console.log("\n=== Manual test with correct device_id ===");

                        var HashMapClass = Java.use("java.util.HashMap");
                        var r4Instance = null;

                        Java.choose("ms.bd.c.r4", {
                            onMatch: function(inst) { r4Instance = inst; },
                            onComplete: function() {}
                        });

                        if (!r4Instance) {
                            console.log("[!] No r4 instance");
                            return;
                        }

                        // Use the REAL device_id and iid
                        var ts = Math.floor(Date.now() / 1000);
                        var tsMs = Date.now();
                        var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
                            "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
                            "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
                            "&device_brand=google&os_api=35&os_version=15" +
                            "&device_id=" + appDeviceId +
                            "&iid=" + appIid +
                            "&_rticket=" + tsMs +
                            "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
                            "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
                            "&book_id=7373660003258862617";

                        console.log("URL: " + url.substring(0, 150) + "...");

                        // Get real signatures
                        var headers = HashMapClass.$new();
                        var sigs = r4Instance.onCallToAddSecurityFactor(url, headers);
                        var sigMap = Java.cast(sigs, HashMapClass);

                        // Build request
                        var RequestBuilder = Java.use("okhttp3.Request$Builder");
                        var rb = RequestBuilder.$new();
                        rb.url(url);
                        rb.addHeader("User-Agent", "com.dragon.read/71332 (Linux; U; Android 15; zh_CN; sdk_gphone64_arm64; Build/AP3A.241105.008;tt-ok/3.12.13.20)");
                        rb.addHeader("Accept", "application/json; charset=utf-8,application/x-protobuf");
                        rb.addHeader("Accept-Encoding", "gzip");
                        rb.addHeader("sdk-version", "2");
                        rb.addHeader("lc", "101");
                        rb.addHeader("passport-sdk-version", "5051451");
                        rb.addHeader("x-tt-store-region", "cn-gd");
                        rb.addHeader("x-tt-store-region-src", "did");
                        rb.addHeader("X-SS-REQ-TICKET", tsMs.toString());

                        var rng = Math.floor(Math.random() * 0xFFFFFFFF).toString(16);
                        rb.addHeader("x-reading-request", tsMs + "-" + rng);

                        // Add all signature headers
                        var sigIt = sigMap.keySet().iterator();
                        while (sigIt.hasNext()) {
                            var k = sigIt.next();
                            rb.addHeader(k, sigMap.get(k).toString());
                        }

                        // Use app's existing client
                        var existingClient = null;
                        Java.choose("okhttp3.OkHttpClient", {
                            onMatch: function(inst) {
                                if (existingClient === null) existingClient = inst;
                            },
                            onComplete: function() {}
                        });

                        if (existingClient) {
                            var req = rb.build();
                            console.log("[*] Sending request...");

                            // Use a new thread to avoid blocking
                            var Thread = Java.use("java.lang.Thread");
                            var Runnable = Java.use("java.lang.Runnable");

                            var runnable = Java.registerClass({
                                name: "com.test.HttpRunnable",
                                implements: [Runnable],
                                methods: {
                                    run: function() {
                                        try {
                                            var response = existingClient.newCall(req).execute();
                                            console.log("[+] Response code: " + response.code());

                                            // Response headers
                                            var respHeaders = response.headers();
                                            for (var i = 0; i < respHeaders.size(); i++) {
                                                console.log("  " + respHeaders.name(i) + ": " + respHeaders.value(i));
                                            }

                                            var bodyStr = response.body().string();
                                            console.log("[+] Body length: " + bodyStr.length);
                                            if (bodyStr.length > 0) {
                                                console.log("[+] Body: " + bodyStr.substring(0, Math.min(1000, bodyStr.length)));
                                            }
                                        } catch(e) {
                                            console.log("[!] HTTP error: " + e);
                                        }
                                    }
                                }
                            });

                            var t = Thread.$new(runnable.$new());
                            t.start();
                        }
                    });
                }, 3000);

            } catch(e) {}
        },
        onComplete: function() {}
    });
});
