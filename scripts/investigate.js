// Frida investigation script: RPC signing proxy + native crypto hooks
// Usage: frida -U -p <PID> -l investigate.js
// Then use RPC: rpc.exports.sign(url, headersJson) -> signaturesJson

var r4Instance = null;
var HashMapClass = null;

// ============ 1. Capture r4 instance ============
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
                        console.log("[+] r4 instance captured");
                    },
                    onComplete: function() {}
                });
            } catch(e) {}
        },
        onComplete: function() {
            if (r4Instance) {
                console.log("[+] Ready for signing requests");
                // Run initial test
                testSign();
            } else {
                console.log("[!] r4 instance not found - app may need to be restarted");
            }
        }
    });
});

// ============ 2. RPC exports for external use ============
rpc.exports = {
    // Sign a URL with real app signatures
    sign: function(url, headersJson) {
        var result = {};
        Java.perform(function() {
            if (!r4Instance) {
                result = {error: "r4 instance not found"};
                return;
            }
            var headers = HashMapClass.$new();
            if (headersJson) {
                var h = JSON.parse(headersJson);
                for (var k in h) {
                    headers.put(k, h[k]);
                }
            }
            try {
                var signResult = r4Instance.onCallToAddSecurityFactor(url, headers);
                var map = Java.cast(signResult, HashMapClass);
                var it = map.keySet().iterator();
                while (it.hasNext()) {
                    var key = it.next();
                    result[key] = map.get(key).toString();
                }
            } catch(e) {
                result = {error: e.toString()};
            }
        });
        return JSON.stringify(result);
    },

    // Check if ready
    ping: function() {
        return r4Instance !== null ? "ready" : "not_ready";
    }
};

// ============ 3. Hook OkHttp interceptor to see real requests ============
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                Java.classFactory.loader = loader;

                var r4Class = Java.use("ms.bd.c.r4");
                r4Class.onCallToAddSecurityFactor.implementation = function(url, headers) {
                    console.log("\n[INTERCEPT] onCallToAddSecurityFactor called");
                    console.log("  URL: " + (url ? url.toString().substring(0, 200) : "null"));

                    var result = this.onCallToAddSecurityFactor(url, headers);
                    if (result !== null) {
                        var map = Java.cast(result, HashMapClass);
                        var it = map.keySet().iterator();
                        while (it.hasNext()) {
                            var key = it.next();
                            var val = map.get(key);
                            console.log("  " + key + " = " + val);
                        }
                    }
                    return result;
                };
                console.log("[+] r4.onCallToAddSecurityFactor hooked");
            } catch(e) {}
        },
        onComplete: function() {}
    });
});

// ============ 4. Hook native y2.a to see JNI calls ============
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.y2");
                Java.classFactory.loader = loader;

                var y2Class = Java.use("ms.bd.c.y2");
                y2Class.a.overload('int', 'int', 'long', 'java.lang.String', 'java.lang.Object').implementation = function(tag, type, handle, url, extra) {
                    console.log("\n[NATIVE] y2.a called:");
                    console.log("  tag=" + tag + " (0x" + tag.toString(16) + ")");
                    console.log("  type=" + type);
                    console.log("  handle=" + handle);
                    console.log("  url=" + (url ? url.substring(0, 150) : "null"));
                    if (extra !== null) {
                        try {
                            var arr = Java.array('java.lang.String', Java.cast(extra, Java.use('[Ljava.lang.String;')));
                            console.log("  extra (String[]): length=" + arr.length);
                            for (var i = 0; i < Math.min(arr.length, 20); i++) {
                                console.log("    [" + i + "] " + arr[i]);
                            }
                        } catch(e) {
                            console.log("  extra: " + extra);
                        }
                    }

                    var result = this.a(tag, type, handle, url, extra);

                    if (result !== null) {
                        try {
                            var resArr = Java.array('java.lang.String', Java.cast(result, Java.use('[Ljava.lang.String;')));
                            console.log("  result (String[]): length=" + resArr.length);
                            for (var i = 0; i < resArr.length; i++) {
                                console.log("    [" + i + "] " + resArr[i]);
                            }
                        } catch(e) {
                            console.log("  result: " + result);
                        }
                    }
                    return result;
                };
                console.log("[+] y2.a hooked");
            } catch(e) {}
        },
        onComplete: function() {}
    });
});

// ============ 5. Hook libmetasec_ml.so crypto functions ============
var libBase = null;
Java.perform(function() {
    // Wait a bit for SO to be loaded
    setTimeout(function() {
        try {
            var mod = Process.findModuleByName("libmetasec_ml.so");
            if (mod) {
                libBase = mod.base;
                console.log("[+] libmetasec_ml.so base: " + libBase + " size: " + mod.size);

                // Hook SHA-256 if present (番茄小说 uses SHA-256 not SM3)
                var exports = mod.enumerateExports();
                console.log("[+] Exports: " + exports.length);
                for (var i = 0; i < exports.length; i++) {
                    console.log("  export: " + exports[i].name + " @ " + exports[i].address);
                }

                // Hook sub_245354 (SHA-256 hash function from IDA analysis)
                // Offset may vary - let's hook common crypto functions
                hookCryptoFunctions(mod);
            } else {
                console.log("[!] libmetasec_ml.so not found");
            }
        } catch(e) {
            console.log("[!] SO hook error: " + e);
        }
    }, 1000);
});

function hookCryptoFunctions(mod) {
    // Hook RegisterNatives to find JNI function mappings
    var registerNatives = Module.findExportByName("libart.so", "jniRegisterNativeMethods") ||
                          Module.findExportByName("libart.so", "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi");

    if (registerNatives) {
        Interceptor.attach(registerNatives, {
            onEnter: function(args) {
                // args: JNIEnv*, jclass, JNINativeMethod*, nMethods
                var nMethods = args[3].toInt32();
                var methods = args[2];
                console.log("\n[RegisterNatives] " + nMethods + " methods");
                for (var i = 0; i < nMethods; i++) {
                    var namePtr = methods.add(i * Process.pointerSize * 3).readPointer();
                    var sigPtr = methods.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer();
                    var fnPtr = methods.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();
                    try {
                        var name = namePtr.readCString();
                        var sig = sigPtr.readCString();
                        console.log("  [" + i + "] " + name + " " + sig + " @ " + fnPtr);

                        // Check if this function is in libmetasec_ml.so
                        var fnMod = Process.findModuleByAddress(fnPtr);
                        if (fnMod && fnMod.name === "libmetasec_ml.so") {
                            var offset = fnPtr.sub(fnMod.base);
                            console.log("    -> libmetasec_ml.so + " + offset);
                        }
                    } catch(e) {}
                }
            }
        });
        console.log("[+] RegisterNatives hooked");
    }
}

// ============ 6. Test signing ============
function testSign() {
    Java.perform(function() {
        if (!r4Instance) return;

        var testUrl = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32&device_platform=android&os=android&ssmix=a&device_type=Pixel+4&device_brand=google&os_api=28&os_version=9&device_id=3405654380789289&iid=987654321&book_id=7373660003258862617";

        console.log("\n=== Test Sign ===");
        console.log("URL: " + testUrl.substring(0, 150) + "...");

        var headers = HashMapClass.$new();
        try {
            var result = r4Instance.onCallToAddSecurityFactor(testUrl, headers);
            var map = Java.cast(result, HashMapClass);
            var it = map.keySet().iterator();
            while (it.hasNext()) {
                var key = it.next();
                console.log("  " + key + " = " + map.get(key));
            }
        } catch(e) {
            console.log("[!] testSign error: " + e);
        }
    });
}
