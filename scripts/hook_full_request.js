// Hook OkHttp interceptor to capture FULL request headers + response
// Also try making request with app's own OkHttpClient

Java.perform(function() {
    // Hook the actual interceptor chain to see what headers the app sends
    try {
        var Interceptor = Java.use("okhttp3.Interceptor");
        var Chain = Java.use("okhttp3.Interceptor$Chain");
        var Request = Java.use("okhttp3.Request");
        var Response = Java.use("okhttp3.Response");
        var Headers = Java.use("okhttp3.Headers");

        // Hook RealCall.execute or enqueue
        var RealCall = Java.use("okhttp3.RealCall");

        // Hook the execute method
        RealCall.execute.implementation = function() {
            var req = this.request();
            var url = req.url().toString();

            // Only log our target APIs
            if (url.indexOf("bookapi") !== -1 || url.indexOf("search") !== -1 || url.indexOf("registerkey") !== -1) {
                console.log("\n======== HTTP Request ========");
                console.log("Method: " + req.method());
                console.log("URL: " + url);

                var headers = req.headers();
                var headerCount = headers.size();
                console.log("Headers (" + headerCount + "):");
                for (var i = 0; i < headerCount; i++) {
                    var name = headers.name(i);
                    var value = headers.value(i);
                    if (value && value.length > 100) value = value.substring(0, 100) + "...";
                    console.log("  " + name + ": " + value);
                }

                if (req.body() !== null) {
                    console.log("Body: (present, type=" + req.body().contentType() + ")");
                }

                var resp = this.execute();
                var respCode = resp.code();
                var respBody = resp.peekBody(Java.use("java.lang.Long").parseLong("10240")).string();
                console.log("\n--- Response ---");
                console.log("Status: " + respCode);
                console.log("Body length: " + respBody.length);
                if (respBody.length > 0) {
                    console.log("Body: " + respBody.substring(0, Math.min(500, respBody.length)));
                }
                console.log("================================\n");

                return resp;
            }

            return this.execute();
        };
        console.log("[+] RealCall.execute hooked");
    } catch(e) {
        console.log("[!] RealCall hook error: " + e);
    }

    // Also hook enqueue for async calls
    try {
        var RealCall = Java.use("okhttp3.RealCall");
        RealCall.enqueue.implementation = function(callback) {
            var req = this.request();
            var url = req.url().toString();

            if (url.indexOf("bookapi") !== -1 || url.indexOf("search") !== -1 || url.indexOf("registerkey") !== -1 || url.indexOf("crypt") !== -1) {
                console.log("\n======== HTTP Request (async) ========");
                console.log("Method: " + req.method());
                console.log("URL: " + url);

                var headers = req.headers();
                var headerCount = headers.size();
                console.log("Headers (" + headerCount + "):");
                for (var i = 0; i < headerCount; i++) {
                    var name = headers.name(i);
                    var value = headers.value(i);
                    if (value && value.length > 100) value = value.substring(0, 100) + "...";
                    console.log("  " + name + ": " + value);
                }
                console.log("================================\n");
            }

            this.enqueue(callback);
        };
        console.log("[+] RealCall.enqueue hooked");
    } catch(e) {
        console.log("[!] RealCall.enqueue hook error: " + e);
    }

    // Now try to use the app's own HTTP client to make a request
    // First, find the app's OkHttpClient instance
    setTimeout(function() {
        console.log("\n[*] Attempting to use app's own HTTP client...");

        try {
            // Try to find the app's HTTP client class
            Java.enumerateClassLoaders({
                onMatch: function(loader) {
                    try {
                        // Look for the app's API client
                        loader.findClass("com.dragon.read");
                        Java.classFactory.loader = loader;
                    } catch(e) {}
                },
                onComplete: function() {}
            });

            // Use OkHttpClient.Builder for proper config
            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            var Builder = Java.use("okhttp3.OkHttpClient$Builder");
            var RequestBuilder = Java.use("okhttp3.Request$Builder");

            // Find an existing client instance
            var existingClient = null;
            Java.choose("okhttp3.OkHttpClient", {
                onMatch: function(inst) {
                    if (existingClient === null) {
                        existingClient = inst;
                    }
                },
                onComplete: function() {}
            });

            if (existingClient) {
                console.log("[+] Found existing OkHttpClient");

                // Build request with full headers matching the app
                var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32&device_platform=android&os=android&ssmix=a&device_type=Pixel+4&device_brand=google&os_api=28&os_version=9&device_id=3405654380789289&iid=987654321&book_id=7373660003258862617";

                // Get real signatures
                var HashMapClass = Java.use("java.util.HashMap");
                Java.enumerateClassLoaders({
                    onMatch: function(loader) {
                        try {
                            loader.findClass("ms.bd.c.r4");
                            Java.classFactory.loader = loader;
                            Java.choose("ms.bd.c.r4", {
                                onMatch: function(r4inst) {
                                    var headers = HashMapClass.$new();
                                    var sigs = r4inst.onCallToAddSecurityFactor(url, headers);
                                    var sigMap = Java.cast(sigs, HashMapClass);

                                    var rb = RequestBuilder.$new();
                                    rb.url(url);
                                    rb.addHeader("User-Agent", "com.dragon.read/71332 (Linux; U; Android 9; zh_CN; Pixel 4; Build/PQ3B.190801.002;tt-ok/3.12.13.20)");
                                    rb.addHeader("Accept", "application/json; charset=utf-8,application/x-protobuf");
                                    rb.addHeader("sdk-version", "2");
                                    rb.addHeader("lc", "101");
                                    rb.addHeader("passport-sdk-version", "5051451");
                                    rb.addHeader("x-tt-store-region", "cn-gd");
                                    rb.addHeader("x-tt-store-region-src", "did");

                                    var ts = sigMap.get("X-Khronos").toString();
                                    rb.addHeader("X-SS-REQ-TICKET", (parseInt(ts) * 1000).toString());

                                    var rng = Math.floor(Math.random() * 0xFFFFFFFF).toString(16);
                                    rb.addHeader("x-reading-request", (parseInt(ts) * 1000) + "-" + rng);

                                    // Add all signature headers
                                    var it = sigMap.keySet().iterator();
                                    while (it.hasNext()) {
                                        var k = it.next();
                                        rb.addHeader(k, sigMap.get(k).toString());
                                    }

                                    var req = rb.build();
                                    console.log("[*] Making request with app's client + real signatures...");

                                    // Print all headers
                                    var reqHeaders = req.headers();
                                    for (var i = 0; i < reqHeaders.size(); i++) {
                                        var v = reqHeaders.value(i);
                                        if (v.length > 80) v = v.substring(0, 80) + "...";
                                        console.log("  " + reqHeaders.name(i) + ": " + v);
                                    }

                                    try {
                                        var resp = existingClient.newCall(req).execute();
                                        var respBody = resp.peekBody(Java.use("java.lang.Long").parseLong("10240")).string();
                                        console.log("[+] Response: code=" + resp.code() + " len=" + respBody.length);
                                        if (respBody.length > 0) {
                                            console.log("[+] Body: " + respBody.substring(0, Math.min(500, respBody.length)));
                                        } else {
                                            console.log("[!] Empty response body");
                                            // Check response headers
                                            var respHeaders = resp.headers();
                                            for (var i = 0; i < respHeaders.size(); i++) {
                                                console.log("  resp " + respHeaders.name(i) + ": " + respHeaders.value(i));
                                            }
                                        }
                                    } catch(e) {
                                        console.log("[!] Request error: " + e);
                                    }
                                },
                                onComplete: function() {}
                            });
                        } catch(e) {}
                    },
                    onComplete: function() {}
                });
            } else {
                console.log("[!] No existing OkHttpClient found");
            }
        } catch(e) {
            console.log("[!] Error: " + e);
        }
    }, 3000);
});
