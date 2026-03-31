// Hook with proper classloader enumeration for spawn mode
console.log("[*] Script loaded");

function installHooks() {
    console.log("[*] Attempting to install hooks...");

    var hooked = false;

    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                console.log("[+] Found r4 in classloader: " + loader);

                Java.classFactory.loader = loader;

                // Hook r4.onCallToAddSecurityFactor
                var r4 = Java.use("ms.bd.c.r4");
                r4.onCallToAddSecurityFactor.implementation = function(url, headers) {
                    console.log("\n=== onCallToAddSecurityFactor ===");
                    console.log("URL: " + url);
                    if (headers) {
                        var it = headers.entrySet().iterator();
                        while (it.hasNext()) {
                            var e = it.next();
                            console.log("IN: " + e.getKey() + " = " + e.getValue());
                        }
                    }
                    var result = this.onCallToAddSecurityFactor(url, headers);
                    if (result) {
                        var it2 = result.entrySet().iterator();
                        while (it2.hasNext()) {
                            var e2 = it2.next();
                            console.log("OUT: " + e2.getKey() + " = " + e2.getValue());
                        }
                    }
                    console.log("=== END ===\n");
                    return result;
                };
                console.log("[+] Hooked r4.onCallToAddSecurityFactor");

                // Hook MSManager.frameSign
                try {
                    var MSManager = Java.use("com.bytedance.mobsec.metasec.ml.MSManager");
                    MSManager.frameSign.implementation = function(url, type) {
                        console.log("[frameSign] type=" + type);
                        console.log("[frameSign] url=" + url);
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
                    console.log("[-] MSManager hook failed: " + e.message);
                }

                // Hook OkHttp interceptor
                try {
                    var interceptor = Java.use("com.bytedance.frameworks.baselib.network.http.ok3.impl.OkHttp3SecurityFactorInterceptor");
                    interceptor.intercept.implementation = function(chain) {
                        var request = chain.request();
                        var url = request.url().toString();
                        console.log("[INTERCEPT] " + url.substring(0, 200));
                        return this.intercept(chain);
                    };
                    console.log("[+] Hooked interceptor");
                } catch(e) {
                    console.log("[-] interceptor: " + e.message);
                }

                // Hook addHeader for signature headers
                try {
                    var Builder = Java.use("okhttp3.Request$Builder");
                    Builder.addHeader.implementation = function(name, value) {
                        var n = name.toString();
                        if (n.indexOf("X-Gorgon") === 0 || n.indexOf("X-Argus") === 0 ||
                            n.indexOf("X-Ladon") === 0 || n.indexOf("X-Khronos") === 0 ||
                            n.indexOf("X-Helios") === 0 || n.indexOf("X-Medusa") === 0) {
                            console.log("[SIGN HDR] " + n + " = " + value);
                        }
                        return this.addHeader(name, value);
                    };
                    console.log("[+] Hooked addHeader");
                } catch(e) {
                    console.log("[-] addHeader: " + e.message);
                }

                hooked = true;
            } catch(e) {
                // This classloader doesn't have our class
            }
        },
        onComplete: function() {
            if (hooked) {
                console.log("[*] All hooks installed successfully!");
            } else {
                console.log("[-] r4 class not found in any classloader, retrying in 3s...");
                setTimeout(installHooks, 3000);
            }
        }
    });
}

// For spawn mode, wait for app to initialize
setTimeout(function() {
    Java.perform(function() {
        installHooks();
    });
}, 5000);
