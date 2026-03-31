// 全面 Hook：OkHttp interceptor + 所有签名入口
Java.perform(function() {
    console.log("[*] Installing comprehensive hooks...");

    // 1. Hook OkHttp3SecurityFactorInterceptor.intercept - 拦截所有带签名的请求
    try {
        var interceptor = Java.use("com.bytedance.frameworks.baselib.network.http.ok3.impl.OkHttp3SecurityFactorInterceptor");
        interceptor.intercept.implementation = function(chain) {
            var request = chain.request();
            var url = request.url().toString();
            console.log("\n[INTERCEPT] URL: " + url);

            var response = this.intercept(chain);

            // 打印最终请求的 headers（包含签名）
            // response 已发出，我们看不到修改后的 request，但可以通过下面的 hook 看到
            return response;
        };
        console.log("[+] Hooked OkHttp3SecurityFactorInterceptor.intercept");
    } catch(e) {
        console.log("[-] Failed to hook interceptor: " + e);
    }

    // 2. Hook r4.onCallToAddSecurityFactor
    try {
        var r4 = Java.use("ms.bd.c.r4");
        r4.onCallToAddSecurityFactor.implementation = function(url, headers) {
            console.log("\n[r4.sign] URL: " + url);
            var result = this.onCallToAddSecurityFactor(url, headers);
            if (result) {
                var it = result.entrySet().iterator();
                while (it.hasNext()) {
                    var e = it.next();
                    console.log("[r4.sign OUT] " + e.getKey() + " = " + e.getValue());
                }
            }
            return result;
        };
        console.log("[+] Hooked r4.onCallToAddSecurityFactor");
    } catch(e) {
        console.log("[-] Failed to hook r4: " + e);
    }

    // 3. Hook MSManager.frameSign
    try {
        var MSManager = Java.use("com.bytedance.mobsec.metasec.ml.MSManager");
        MSManager.frameSign.implementation = function(url, type) {
            console.log("[frameSign] type=" + type + " url=" + url.substring(0, Math.min(url.length, 200)));
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
        console.log("[-] Failed to hook MSManager: " + e);
    }

    // 4. Hook OkHttp Request.Builder 的 addHeader 方法来看签名头被添加的时机
    try {
        var RequestBuilder = Java.use("okhttp3.Request$Builder");
        RequestBuilder.addHeader.implementation = function(name, value) {
            if (name.indexOf("X-") === 0 || name.indexOf("x-") === 0) {
                console.log("[addHeader] " + name + " = " + value);
            }
            return this.addHeader(name, value);
        };
        console.log("[+] Hooked Request.Builder.addHeader");
    } catch(e) {
        console.log("[-] Failed to hook addHeader: " + e);
    }

    // 5. Hook OkHttp Request.Builder 的 header 方法
    try {
        var RequestBuilder = Java.use("okhttp3.Request$Builder");
        RequestBuilder.header.implementation = function(name, value) {
            if (name.indexOf("X-") === 0 || name.indexOf("x-") === 0) {
                console.log("[header] " + name + " = " + value);
            }
            return this.header(name, value);
        };
        console.log("[+] Hooked Request.Builder.header");
    } catch(e) {
        console.log("[-] Failed to hook header: " + e);
    }

    console.log("[*] All hooks installed! Trigger a search...");
});
