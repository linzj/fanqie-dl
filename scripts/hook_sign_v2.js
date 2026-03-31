// Hook 签名调用链 - 将结果输出到日志
// 用法: frida -U -n "番茄免费小说" -l scripts/hook_sign_v2.js -q

var callCount = 0;

Java.perform(function() {
    send("[*] Hooking signing functions...");

    // Hook r4.onCallToAddSecurityFactor
    var r4 = Java.use("ms.bd.c.r4");
    r4.onCallToAddSecurityFactor.implementation = function(url, headers) {
        callCount++;
        var n = callCount;
        send("\n========== [" + n + "] onCallToAddSecurityFactor ==========");
        send("[" + n + "] INPUT URL: " + url);

        if (headers) {
            var it = headers.entrySet().iterator();
            while (it.hasNext()) {
                var entry = it.next();
                send("[" + n + "] INPUT_HDR: " + entry.getKey() + " = " + entry.getValue());
            }
        }

        var result = this.onCallToAddSecurityFactor(url, headers);

        if (result) {
            var it2 = result.entrySet().iterator();
            while (it2.hasNext()) {
                var entry2 = it2.next();
                send("[" + n + "] OUTPUT: " + entry2.getKey() + " = " + entry2.getValue());
            }
        } else {
            send("[" + n + "] OUTPUT: null");
        }
        send("========== [" + n + "] END ==========\n");
        return result;
    };

    // Hook MSManager.frameSign
    var MSManager = Java.use("com.bytedance.mobsec.metasec.ml.MSManager");
    MSManager.frameSign.implementation = function(url, type) {
        send("[frameSign] url=" + url + " type=" + type);
        var result = this.frameSign(url, type);
        if (result) {
            var it = result.entrySet().iterator();
            while (it.hasNext()) {
                var entry = it.next();
                send("[frameSign OUT] " + entry.getKey() + " = " + entry.getValue());
            }
        }
        return result;
    };

    send("[*] Hooks installed successfully!");
});
