// 用固定参数调用 APP 签名，与 Rust 实现对比
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                Java.classFactory.loader = loader;

                // 用与 Rust 测试相同的参数
                var testParams = "ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32&device_platform=android&os=android&ssmix=a&device_type=Pixel+4&device_brand=google&os_api=28&os_version=9&device_id=123456789&iid=987654321&_rticket=1700000000000";
                var fullUrl = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/search/tab/v?" + testParams + "&query=test&offset=0&count=10&search_source=1";

                console.log("=== APP Sign (full URL) ===");
                console.log("URL: " + fullUrl.substring(0, 150) + "...");

                var HashMap = Java.use("java.util.HashMap");
                var headers = HashMap.$new();

                Java.choose("ms.bd.c.r4", {
                    onMatch: function(inst) {
                        try {
                            var result = inst.onCallToAddSecurityFactor(fullUrl, headers);
                            var map = Java.cast(result, HashMap);
                            var it = map.keySet().iterator();
                            while (it.hasNext()) {
                                var key = it.next();
                                console.log("  " + key + " = " + map.get(key));
                            }
                        } catch(e) {
                            console.log("Error: " + e);
                        }

                        // Also test with query-only (no host)
                        console.log("\n=== APP Sign (query only) ===");
                        try {
                            var result2 = inst.onCallToAddSecurityFactor("https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/search/tab/v?" + testParams, headers);
                            var map2 = Java.cast(result2, HashMap);
                            var it2 = map2.keySet().iterator();
                            while (it2.hasNext()) {
                                var key2 = it2.next();
                                console.log("  " + key2 + " = " + map2.get(key2));
                            }
                        } catch(e) {
                            console.log("Error: " + e);
                        }

                        // Also call frameSign directly for raw output
                        console.log("\n=== frameSign raw ===");
                        var utils = Java.use("com.bytedance.mobsec.metasec.ml.MSManagerUtils");
                        var mgr = utils.get("1967");
                        if (mgr !== null) {
                            var fsResult = mgr.frameSign(fullUrl, 1);
                            var fsMap = Java.cast(fsResult, HashMap);
                            var it3 = fsMap.keySet().iterator();
                            while (it3.hasNext()) {
                                var key3 = it3.next();
                                console.log("  " + key3 + " = " + fsMap.get(key3));
                            }
                        }

                        // Check what r4.onCallToAddSecurityFactor actually does with frameSign output
                        // by examining the decompiled code logic
                        console.log("\n=== Examining r4 internals ===");
                        // r4 has field 'a' of type s4
                        console.log("r4.a = " + inst.a.value);
                        var s4inst = inst.a.value;
                        console.log("s4 class: " + s4inst.$className);

                        // s4 has method a(long) - possibly init with timestamp
                        var s4methods = s4inst.getClass().getDeclaredMethods();
                        for (var i = 0; i < s4methods.length; i++) {
                            console.log("s4 method: " + s4methods[i]);
                        }

                        // Look for native methods in s4
                        var s4fields = s4inst.getClass().getDeclaredFields();
                        for (var i = 0; i < s4fields.length; i++) {
                            s4fields[i].setAccessible(true);
                            try {
                                console.log("s4 field: " + s4fields[i].getName() + " = " + s4fields[i].get(s4inst));
                            } catch(e) {
                                console.log("s4 field: " + s4fields[i].getName() + " (unreadable)");
                            }
                        }
                    },
                    onComplete: function() {}
                });

            } catch(e) {}
        },
        onComplete: function() {
            console.log("\n[*] Done");
        }
    });
});
