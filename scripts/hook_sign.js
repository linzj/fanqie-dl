// Hook 签名调用链: r4.onCallToAddSecurityFactor → MSManager.frameSign
// 用法: frida -U -n "番茄免费小说" -l scripts/hook_sign.js

Java.perform(function() {
    console.log("[*] Hooking signing functions...");

    // Hook r4.onCallToAddSecurityFactor
    var r4 = Java.use("ms.bd.c.r4");
    r4.onCallToAddSecurityFactor.implementation = function(url, headers) {
        console.log("\n========== onCallToAddSecurityFactor ==========");
        console.log("[INPUT] URL: " + url);

        // Print input headers
        if (headers) {
            var it = headers.entrySet().iterator();
            while (it.hasNext()) {
                var entry = it.next();
                console.log("[INPUT HEADER] " + entry.getKey() + " = " + entry.getValue());
            }
        }

        var result = this.onCallToAddSecurityFactor(url, headers);

        // Print output headers (签名结果)
        if (result) {
            var it2 = result.entrySet().iterator();
            while (it2.hasNext()) {
                var entry2 = it2.next();
                console.log("[OUTPUT] " + entry2.getKey() + " = " + entry2.getValue());
            }
        } else {
            console.log("[OUTPUT] null");
        }
        console.log("================================================\n");
        return result;
    };

    // Hook MSManager.frameSign
    var MSManager = Java.use("com.bytedance.mobsec.metasec.ml.MSManager");
    MSManager.frameSign.implementation = function(url, type) {
        console.log("\n---------- MSManager.frameSign ----------");
        console.log("[frameSign INPUT] url: " + url);
        console.log("[frameSign INPUT] type: " + type);

        var result = this.frameSign(url, type);

        if (result) {
            var it = result.entrySet().iterator();
            while (it.hasNext()) {
                var entry = it.next();
                console.log("[frameSign OUTPUT] " + entry.getKey() + " = " + entry.getValue());
            }
        } else {
            console.log("[frameSign OUTPUT] null");
        }
        console.log("-----------------------------------------\n");
        return result;
    };

    // Hook OkHttp3SecurityFactorInterceptor for full context
    var interceptor = Java.use("com.bytedance.frameworks.baselib.network.http.ok3.impl.OkHttp3SecurityFactorInterceptor");
    var methods = interceptor.class.getDeclaredMethods();
    console.log("[*] OkHttp3SecurityFactorInterceptor methods:");
    for (var i = 0; i < methods.length; i++) {
        console.log("  " + methods[i].toString());
    }

    console.log("[*] Hooks installed! Trigger a search in the app...");
});
