// Call r4.onCallToAddSecurityFactor directly and get X-Gorgon etc headers
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                Java.classFactory.loader = loader;
                console.log("[+] Correct classloader");

                // Find r4 instance
                Java.choose("ms.bd.c.r4", {
                    onMatch: function(inst) {
                        console.log("[+] Found r4 instance");

                        // Need to pass correct parameters
                        var HashMap = Java.use("java.util.HashMap");
                        var headers = HashMap.$new();

                        // Build a realistic URL (query string only, based on ISSUE.md)
                        var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/search/tab/v?query=test&offset=0&count=10&search_source=1&aid=1967&device_id=123456789&iid=987654321";

                        console.log("[*] Calling onCallToAddSecurityFactor...");
                        console.log("[*] URL: " + url);

                        try {
                            var result = inst.onCallToAddSecurityFactor(url, headers);

                            if (result !== null) {
                                console.log("[+] Got result, type: " + result.$className);
                                var map = Java.cast(result, HashMap);
                                var keySet = map.keySet();
                                var it = keySet.iterator();
                                while (it.hasNext()) {
                                    var key = it.next();
                                    var val = map.get(key);
                                    console.log("  " + key + " = " + val);
                                }
                            } else {
                                console.log("[!] null result");
                            }
                        } catch(e) {
                            console.log("[!] Call error: " + e);
                            console.log("[!] Stack: " + e.stack);
                        }

                        // Also try passing URL as just the path/query without host
                        try {
                            var url2 = "/reading/bookapi/search/tab/v?query=test&offset=0&count=10&search_source=1&aid=1967&device_id=123456789&iid=987654321";
                            console.log("\n[*] Trying with path-only URL...");
                            var result2 = inst.onCallToAddSecurityFactor(url2, headers);
                            if (result2 !== null) {
                                var map2 = Java.cast(result2, HashMap);
                                var it2 = map2.keySet().iterator();
                                while (it2.hasNext()) {
                                    var k = it2.next();
                                    console.log("  " + k + " = " + map2.get(k));
                                }
                            }
                        } catch(e) {
                            console.log("[!] Path-only error: " + e);
                        }
                    },
                    onComplete: function() {
                        console.log("[*] r4 scan done");
                    }
                });

                // Also examine the s4 class (r4.a field) which might be the actual signer
                try {
                    var s4cls = Java.use("ms.bd.c.s4");
                    var methods = s4cls.class.getDeclaredMethods();
                    console.log("\n[*] s4 methods:");
                    for (var i = 0; i < methods.length; i++) {
                        console.log("  " + methods[i].toString());
                    }
                } catch(e) {
                    console.log("[!] s4 error: " + e);
                }

                // Examine the full r4 class source
                try {
                    var r4cls = Java.use("ms.bd.c.r4");
                    // Check if there are more overloads
                    console.log("\n[*] r4 method overloads:");
                    var overloads = r4cls.onCallToAddSecurityFactor.overloads;
                    for (var i = 0; i < overloads.length; i++) {
                        console.log("  overload " + i + ": " + overloads[i].argumentTypes.map(function(t) { return t.className; }).join(", "));
                    }
                } catch(e) {
                    console.log("[!] r4 overload check: " + e);
                }

            } catch(e) {}
        },
        onComplete: function() {
            console.log("[*] All complete");
        }
    });
});
