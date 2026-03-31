// Use Stalker to dump instruction trace during Medusa encryption
// Strategy: start Stalker on the signing thread when AES key expansion fires,
// stop after the last MD5 call (MD5[5]), dump all executed blocks in SO range.
//
// Run: frida -U -p <PID> -l scripts/hook_stalker_medusa.js

var libBase = null;
var libEnd = null;
var stalkerTid = null;
var stalkerStarted = false;
var stalkerBlocks = [];  // [startOffset, size] pairs
var md5Count = 0;

function soOffset(addr) {
    try {
        var n = addr.sub(libBase).toInt32();
        if (n >= 0 && n < 0x400000) return n;
        return -1;
    } catch(e) { return -1; }
}

function b64toHex(s) {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var bytes = [];
    var buf = 0, bits = 0;
    for (var i = 0; i < s.length; i++) {
        if (s[i] === '=') break;
        buf = (buf << 6) | chars.indexOf(s[i]);
        bits += 6;
        if (bits >= 8) { bits -= 8; bytes.push(('0' + ((buf >> bits) & 0xff).toString(16)).slice(-2)); }
    }
    return bytes.join('');
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;
    libEnd = libBase.add(mod.size);
    console.log("[+] SO @ " + libBase + " size=" + mod.size);

    // Hook AES key expansion — START Stalker here
    Interceptor.attach(libBase.add(0x241E9C), {
        onEnter: function(args) {
            if (stalkerStarted) return;
            stalkerStarted = true;
            stalkerTid = Process.getCurrentThreadId();
            console.log("[+] Starting Stalker on tid=" + stalkerTid);

            var base = libBase;
            var end = libEnd;

            Stalker.follow(stalkerTid, {
                transform: function(iterator) {
                    var instruction = iterator.next();
                    var startAddr = instruction.address;
                    var off = soOffset(startAddr);

                    // Only instrument blocks within the SO
                    var inSO = (off >= 0);

                    do {
                        if (inSO) {
                            iterator.putCallout(function(context) {
                                var pc = context.pc;
                                var pcOff = soOffset(pc);
                                if (pcOff >= 0) {
                                    stalkerBlocks.push(pcOff);
                                }
                            });
                        }
                        iterator.keep();
                    } while ((instruction = iterator.next()) !== null);
                }
            });
            console.log("[+] Stalker started");
        }
    });

    // Hook MD5 — stop Stalker after the 6th call (MD5[5])
    Interceptor.attach(libBase.add(0x243C34), {
        onLeave: function(ret) {
            if (!stalkerStarted) return;
            md5Count++;
            if (md5Count >= 6) {
                console.log("[+] MD5 #6 done, stopping Stalker...");
                Stalker.unfollow(stalkerTid);
                Stalker.flush();
                stalkerStarted = false;
                console.log("[+] Stalker stopped. Captured " + stalkerBlocks.length + " instruction offsets");
            }
        }
    });

    console.log("[+] Hooks ready, waiting for sign call...");
}

function doSign(url) {
    var result = {};
    Java.perform(function() {
        Java.enumerateClassLoaders({
            onMatch: function(loader) {
                try {
                    loader.findClass("ms.bd.c.r4");
                    Java.classFactory.loader = loader;
                    var HM = Java.use("java.util.HashMap");
                    Java.choose("ms.bd.c.r4", {
                        onMatch: function(inst) {
                            var headers = HM.$new();
                            var r = inst.onCallToAddSecurityFactor(url, headers);
                            var map = Java.cast(r, HM);
                            var it = map.keySet().iterator();
                            while (it.hasNext()) {
                                var key = it.next();
                                result[key] = map.get(key).toString();
                            }
                        },
                        onComplete: function() {}
                    });
                } catch(e) {}
            },
            onComplete: function() {}
        });
    });
    return result;
}

setup();

setTimeout(function() {
    var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
        "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
        "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
        "&device_brand=google&os_api=35&os_version=15" +
        "&device_id=3722313718058683&iid=3722313718062779" +
        "&_rticket=1774940000000" +
        "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
        "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
        "&book_id=7373660003258862617";

    stalkerBlocks = [];
    md5Count = 0;
    stalkerStarted = false;

    console.log("[*] Calling doSign...");
    var sigs = doSign(url);
    console.log("[*] doSign returned");

    // Wait for Stalker to flush
    setTimeout(function() {
        Stalker.flush();

        console.log("\n=== STALKER RESULTS ===");
        console.log("Total instruction records: " + stalkerBlocks.length);

        if (stalkerBlocks.length === 0) {
            console.log("[!] No instructions captured — Stalker might have run on wrong thread");
            console.log("[DONE]");
            return;
        }

        // Deduplicate and sort unique offsets
        var unique = {};
        for (var i = 0; i < stalkerBlocks.length; i++) {
            unique[stalkerBlocks[i]] = (unique[stalkerBlocks[i]] || 0) + 1;
        }

        // Sort by offset
        var offsets = Object.keys(unique).map(Number).sort(function(a, b) { return a - b; });
        console.log("Unique PC offsets: " + offsets.length);

        // Group by function range (0x1000 buckets)
        var buckets = {};
        for (var i = 0; i < offsets.length; i++) {
            var bucket = (offsets[i] & 0xFFF000);
            if (!buckets[bucket]) buckets[bucket] = [];
            buckets[bucket].push(offsets[i]);
        }

        console.log("\n=== ADDRESS RANGES EXECUTED ===");
        var bucketKeys = Object.keys(buckets).map(Number).sort(function(a,b){return a-b;});
        for (var i = 0; i < bucketKeys.length; i++) {
            var bk = bucketKeys[i];
            var addrs = buckets[bk];
            console.log("0x" + bk.toString(16) + ": " + addrs.length + " unique PCs, range [0x" +
                addrs[0].toString(16) + " - 0x" + addrs[addrs.length-1].toString(16) + "]");
        }

        // Print execution sequence (first 500 offsets, compressed)
        console.log("\n=== EXECUTION TRACE (first 1000) ===");
        var limit = Math.min(stalkerBlocks.length, 1000);
        var line = "";
        for (var i = 0; i < limit; i++) {
            line += stalkerBlocks[i].toString(16) + " ";
            if ((i + 1) % 20 === 0) {
                console.log(line.trim());
                line = "";
            }
        }
        if (line) console.log(line.trim());

        // Print hottest offsets (most frequently executed)
        console.log("\n=== HOT SPOTS (top 30) ===");
        var sorted = Object.entries(unique).sort(function(a, b) { return b[1] - a[1]; });
        for (var i = 0; i < Math.min(30, sorted.length); i++) {
            console.log("  0x" + parseInt(sorted[i][0]).toString(16) + ": " + sorted[i][1] + "x");
        }

        console.log("\n[DONE]");
    }, 2000);
}, 2000);
