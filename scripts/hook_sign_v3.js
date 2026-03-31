// Hook 签名调用链 - 使用 console.log 输出
Java.perform(function() {
    console.log("[*] Hooking signing functions...");

    var callCount = 0;

    // Hook r4.onCallToAddSecurityFactor
    var r4 = Java.use("ms.bd.c.r4");
    r4.onCallToAddSecurityFactor.implementation = function(url, headers) {
        callCount++;
        var n = callCount;
        console.log("\n========== [" + n + "] onCallToAddSecurityFactor ==========");
        console.log("[" + n + "] INPUT URL: " + url);

        if (headers) {
            var it = headers.entrySet().iterator();
            while (it.hasNext()) {
                var entry = it.next();
                console.log("[" + n + "] INPUT_HDR: " + entry.getKey() + " = " + entry.getValue());
            }
        }

        var result = this.onCallToAddSecurityFactor(url, headers);

        if (result) {
            var it2 = result.entrySet().iterator();
            while (it2.hasNext()) {
                var entry2 = it2.next();
                console.log("[" + n + "] OUTPUT: " + entry2.getKey() + " = " + entry2.getValue());
            }
        } else {
            console.log("[" + n + "] OUTPUT: null");
        }
        console.log("========== [" + n + "] END ==========\n");
        return result;
    };

    // Hook MSManager.frameSign
    var MSManager = Java.use("com.bytedance.mobsec.metasec.ml.MSManager");
    MSManager.frameSign.implementation = function(url, type) {
        console.log("[frameSign] url=" + url.substring(0, Math.min(url.length, 200)));
        console.log("[frameSign] type=" + type);
        var result = this.frameSign(url, type);
        if (result) {
            var it = result.entrySet().iterator();
            while (it.hasNext()) {
                var entry = it.next();
                console.log("[frameSign OUT] " + entry.getKey() + " = " + entry.getValue());
            }
        }
        return result;
    };

    console.log("[*] Hooks installed! Waiting for API calls...");
});
