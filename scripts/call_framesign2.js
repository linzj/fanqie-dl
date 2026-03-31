// Call frameSign and properly handle the return value
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                Java.classFactory.loader = loader;
                console.log("[+] Correct classloader set");

                var utils = Java.use("com.bytedance.mobsec.metasec.ml.MSManagerUtils");
                var mgr = utils.get("1967");

                if (mgr === null) {
                    console.log("[!] MSManagerUtils.get returned null");
                    return;
                }
                console.log("[+] Got MSManager");

                var testUrl = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/search/tab/v?query=test&offset=0&count=10&search_source=1&aid=1967&device_id=123456789&iid=987654321";

                console.log("[*] Calling frameSign...");
                var result = mgr.frameSign(testUrl, 1);

                console.log("[*] Result type: " + result.$className);
                console.log("[*] Result toString: " + result.toString());

                // Try different ways to read the map
                try {
                    // Cast to HashMap explicitly
                    var HashMap = Java.use("java.util.HashMap");
                    var map = Java.cast(result, HashMap);
                    var keySet = map.keySet();
                    var iterator = keySet.iterator();
                    while (iterator.hasNext()) {
                        var key = iterator.next();
                        var val = map.get(key);
                        console.log("  " + key + " = " + val);
                    }
                } catch(e) {
                    console.log("[!] HashMap cast failed: " + e);

                    // Try as generic Map
                    try {
                        var Map = Java.use("java.util.Map");
                        var m = Java.cast(result, Map);
                        console.log("Map size: " + m.size());
                        var entries = m.entrySet();
                        var Set = Java.use("java.util.Set");
                        var s = Java.cast(entries, Set);
                        var it = s.iterator();
                        while (it.hasNext()) {
                            var entry = it.next();
                            console.log("  " + entry.toString());
                        }
                    } catch(e2) {
                        console.log("[!] Map cast also failed: " + e2);
                        // Just print the toString
                        console.log("Raw: " + result);
                    }
                }

            } catch(e) {}
        },
        onComplete: function() {
            console.log("[*] Done");
        }
    });
});
