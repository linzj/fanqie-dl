// Directly call MSManager.frameSign to get valid signatures
Java.perform(function() {
    console.log("[*] Enumerating classloaders...");

    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                console.log("[+] Found correct classloader");
                Java.classFactory.loader = loader;

                // Method 1: Find existing MSManager instance
                console.log("[*] Looking for MSManager instances...");
                Java.choose("com.bytedance.mobsec.metasec.ml.MSManager", {
                    onMatch: function(instance) {
                        console.log("[+] Found MSManager instance");

                        var testUrl = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/search/tab/v?query=test&offset=0&count=10&search_source=1&aid=1967&device_id=123456789&iid=987654321";
                        console.log("[*] Calling frameSign with test URL...");
                        try {
                            var result = instance.frameSign(testUrl, 1);
                            if (result !== null) {
                                console.log("[+] frameSign returned results:");
                                var it = result.entrySet().iterator();
                                while (it.hasNext()) {
                                    var e = it.next();
                                    console.log("  " + e.getKey() + " = " + e.getValue());
                                }
                            } else {
                                console.log("[!] frameSign returned null");
                            }
                        } catch(e) {
                            console.log("[!] frameSign error: " + e);
                        }
                    },
                    onComplete: function() {
                        console.log("[*] Instance scan done");
                    }
                });

                // Method 2: Use MSManagerUtils.get
                try {
                    var utils = Java.use("com.bytedance.mobsec.metasec.ml.MSManagerUtils");
                    console.log("[*] Trying MSManagerUtils.get('1967')...");
                    var mgr = utils.get("1967");
                    if (mgr !== null) {
                        console.log("[+] Got MSManager via MSManagerUtils.get('1967')");

                        var url2 = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/search/tab/v?query=hello&offset=0&count=10&search_source=1&aid=1967";
                        var result2 = mgr.frameSign(url2, 1);
                        if (result2 !== null) {
                            console.log("[+] frameSign via utils returned:");
                            var it2 = result2.entrySet().iterator();
                            while (it2.hasNext()) {
                                var e2 = it2.next();
                                console.log("  " + e2.getKey() + " = " + e2.getValue());
                            }
                        } else {
                            console.log("[!] null result from utils path");
                        }
                    } else {
                        console.log("[!] MSManagerUtils.get('1967') returned null, trying other keys...");
                        // Try other common app IDs
                        var keys = ["1967", "com.dragon.read", "dragon", "fqnovel"];
                        for (var i = 0; i < keys.length; i++) {
                            var m = utils.get(keys[i]);
                            if (m !== null) {
                                console.log("[+] Found with key: " + keys[i]);
                                break;
                            }
                        }
                    }
                } catch(e) {
                    console.log("[!] MSManagerUtils error: " + e);
                }

                // Method 3: Hook and call r4 directly
                try {
                    var r4 = Java.use("ms.bd.c.r4");
                    Java.choose("ms.bd.c.r4", {
                        onMatch: function(inst) {
                            console.log("[+] Found r4 instance");
                            var HashMap = Java.use("java.util.HashMap");
                            var headers = HashMap.$new();
                            headers.put("User-Agent", "com.dragon.read/71332");
                            var url3 = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/search/tab/v?query=test&aid=1967";
                            try {
                                var r = inst.onCallToAddSecurityFactor(url3, headers);
                                if (r !== null) {
                                    console.log("[+] r4.onCallToAddSecurityFactor returned:");
                                    var it3 = r.entrySet().iterator();
                                    while (it3.hasNext()) {
                                        var e3 = it3.next();
                                        console.log("  " + e3.getKey() + " = " + e3.getValue());
                                    }
                                }
                            } catch(e) {
                                console.log("[!] r4 call error: " + e);
                            }
                        },
                        onComplete: function() {
                            console.log("[*] r4 scan done");
                        }
                    });
                } catch(e) {
                    console.log("[!] r4 error: " + e);
                }

            } catch(e) {
                // Not this classloader
            }
        },
        onComplete: function() {
            console.log("[*] All done");
        }
    });
});
