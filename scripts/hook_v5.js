// Attach mode - enumerate classloaders to find the right one
Java.perform(function() {
    console.log("[*] Java.perform entered");

    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                console.log("[+] Found r4 in: " + loader);
                Java.classFactory.loader = loader;

                // Hook r4
                var r4 = Java.use("ms.bd.c.r4");
                r4.onCallToAddSecurityFactor.implementation = function(url, headers) {
                    console.log("\n=== SIGN CALL ===");
                    console.log("URL: " + url);
                    var result = this.onCallToAddSecurityFactor(url, headers);
                    if (result) {
                        var it = result.entrySet().iterator();
                        while (it.hasNext()) {
                            var e = it.next();
                            console.log("OUT: " + e.getKey() + " = " + e.getValue());
                        }
                    }
                    console.log("=== END ===\n");
                    return result;
                };
                console.log("[+] r4 hooked");

                // Hook MSManager
                var MSManager = Java.use("com.bytedance.mobsec.metasec.ml.MSManager");
                MSManager.frameSign.implementation = function(url, type) {
                    console.log("[frameSign] type=" + type + " url=" + url);
                    var result = this.frameSign(url, type);
                    if (result) {
                        var it = result.entrySet().iterator();
                        while (it.hasNext()) {
                            var e = it.next();
                            console.log("[frameSign] " + e.getKey() + " = " + e.getValue());
                        }
                    }
                    return result;
                };
                console.log("[+] MSManager hooked");

                // Hook interceptor
                var interceptor = Java.use("com.bytedance.frameworks.baselib.network.http.ok3.impl.OkHttp3SecurityFactorInterceptor");
                interceptor.intercept.implementation = function(chain) {
                    var request = chain.request();
                    console.log("[INTERCEPT] " + request.url().toString().substring(0, 200));
                    return this.intercept(chain);
                };
                console.log("[+] interceptor hooked");

            } catch(e) {
                // Not this classloader
            }
        },
        onComplete: function() {
            console.log("[*] Classloader scan complete");
        }
    });

    // Also hook URL.openConnection as a fallback to catch ALL HTTP requests
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            console.log("[URL.open] " + this.toString());
            return this.openConnection();
        };
        console.log("[+] URL.openConnection hooked");
    } catch(e) {
        console.log("[-] URL.openConnection: " + e);
    }

    // Hook HttpURLConnection
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.setRequestProperty.implementation = function(key, value) {
            if (key.indexOf("X-") === 0) {
                console.log("[setRequestProperty] " + key + " = " + value);
            }
            return this.setRequestProperty(key, value);
        };
        console.log("[+] HttpURLConnection.setRequestProperty hooked");
    } catch(e) {
        console.log("[-] HttpURLConnection: " + e);
    }

    console.log("[*] Ready - waiting for API calls...");
});
