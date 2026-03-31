// Sign proxy: expose r4.onCallToAddSecurityFactor as an RPC endpoint
// This allows external code to request signatures via frida RPC

var r4Instance = null;

Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                Java.classFactory.loader = loader;

                Java.choose("ms.bd.c.r4", {
                    onMatch: function(inst) {
                        r4Instance = inst;
                        console.log("[+] r4 instance captured");
                    },
                    onComplete: function() {}
                });
            } catch(e) {}
        },
        onComplete: function() {}
    });
});

// Test: call sign multiple times with different URLs
function testSign() {
    Java.perform(function() {
        if (r4Instance === null) {
            console.log("[!] No r4 instance");
            return;
        }

        var HashMap = Java.use("java.util.HashMap");
        var ts = Math.floor(Date.now() / 1000);

        var urls = [
            "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/search/tab/v?query=test&offset=0&count=10&search_source=1&aid=1967&device_id=123456789&iid=987654321",
            "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/search/tab/v?query=hello&offset=0&count=10&search_source=1&aid=1967&device_id=123456789&iid=987654321",
            "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v?book_id=7100000&aid=1967&device_id=123456789&iid=987654321",
        ];

        for (var i = 0; i < urls.length; i++) {
            var headers = HashMap.$new();
            console.log("\n--- Sign #" + (i+1) + " ---");
            console.log("URL: " + urls[i].substring(0, 120));

            try {
                var result = r4Instance.onCallToAddSecurityFactor(urls[i], headers);
                var map = Java.cast(result, HashMap);
                var it = map.keySet().iterator();
                while (it.hasNext()) {
                    var key = it.next();
                    console.log("  " + key + " = " + map.get(key));
                }
            } catch(e) {
                console.log("[!] Error: " + e);
            }
        }

        // Also call the same URL twice to see if results differ
        console.log("\n--- Same URL, 2nd call ---");
        var headers2 = HashMap.$new();
        try {
            var result2 = r4Instance.onCallToAddSecurityFactor(urls[0], headers2);
            var map2 = Java.cast(result2, HashMap);
            var it2 = map2.keySet().iterator();
            while (it2.hasNext()) {
                var key2 = it2.next();
                console.log("  " + key2 + " = " + map2.get(key2));
            }
        } catch(e) {
            console.log("[!] Error: " + e);
        }
    });
}

// Call testSign immediately after Java.perform completes
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                Java.classFactory.loader = loader;

                Java.choose("ms.bd.c.r4", {
                    onMatch: function(inst) {
                        r4Instance = inst;
                    },
                    onComplete: function() {
                        if (r4Instance !== null) {
                            testSign();
                        }
                    }
                });
            } catch(e) {}
        },
        onComplete: function() {}
    });
});
