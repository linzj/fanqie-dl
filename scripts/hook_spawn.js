// Hook for spawn mode - waits for Java runtime to be ready
console.log("[*] Script loaded, waiting for Java runtime...");

Java.performNow(function() {
    console.log("[*] Java runtime ready, installing hooks...");

    var callCount = 0;

    // Hook r4.onCallToAddSecurityFactor
    try {
        var r4 = Java.use("ms.bd.c.r4");
        r4.onCallToAddSecurityFactor.implementation = function(url, headers) {
            callCount++;
            var n = callCount;
            console.log("\n=== [" + n + "] onCallToAddSecurityFactor ===");
            console.log("[" + n + "] URL: " + url);

            if (headers) {
                var it = headers.entrySet().iterator();
                while (it.hasNext()) {
                    var e = it.next();
                    console.log("[" + n + "] IN: " + e.getKey() + " = " + e.getValue());
                }
            }

            var result = this.onCallToAddSecurityFactor(url, headers);

            if (result) {
                var it2 = result.entrySet().iterator();
                while (it2.hasNext()) {
                    var e2 = it2.next();
                    console.log("[" + n + "] OUT: " + e2.getKey() + " = " + e2.getValue());
                }
            } else {
                console.log("[" + n + "] OUT: null");
            }
            console.log("=== [" + n + "] END ===\n");
            return result;
        };
        console.log("[+] Hooked r4.onCallToAddSecurityFactor");
    } catch(e) {
        console.log("[-] r4 not loaded yet: " + e.message);
    }

    // Hook MSManager.frameSign
    try {
        var MSManager = Java.use("com.bytedance.mobsec.metasec.ml.MSManager");
        MSManager.frameSign.implementation = function(url, type) {
            console.log("[frameSign] type=" + type + " url=" + url.substring(0, Math.min(url.length, 300)));
            var result = this.frameSign(url, type);
            if (result) {
                var it = result.entrySet().iterator();
                while (it.hasNext()) {
                    var e = it.next();
                    console.log("[frameSign OUT] " + e.getKey() + " = " + e.getValue());
                }
            }
            return result;
        };
        console.log("[+] Hooked MSManager.frameSign");
    } catch(e) {
        console.log("[-] MSManager not loaded yet: " + e.message);
    }

    // Hook OkHttp interceptor
    try {
        var interceptor = Java.use("com.bytedance.frameworks.baselib.network.http.ok3.impl.OkHttp3SecurityFactorInterceptor");
        interceptor.intercept.implementation = function(chain) {
            var request = chain.request();
            var url = request.url().toString();
            console.log("[INTERCEPT] " + url.substring(0, Math.min(url.length, 200)));
            return this.intercept(chain);
        };
        console.log("[+] Hooked OkHttp3SecurityFactorInterceptor");
    } catch(e) {
        console.log("[-] Interceptor not loaded yet: " + e.message);
    }

    // Hook addHeader for X- headers
    try {
        var Builder = Java.use("okhttp3.Request$Builder");
        Builder.addHeader.implementation = function(name, value) {
            var n = name.toString();
            if (n.indexOf("X-G") === 0 || n.indexOf("X-A") === 0 || n.indexOf("X-L") === 0 ||
                n.indexOf("X-K") === 0 || n.indexOf("X-H") === 0 || n.indexOf("X-M") === 0) {
                console.log("[addHeader] " + n + " = " + value);
            }
            return this.addHeader(name, value);
        };
        console.log("[+] Hooked addHeader");
    } catch(e) {
        console.log("[-] addHeader not available: " + e.message);
    }

    console.log("[*] All hooks installed!");
});
