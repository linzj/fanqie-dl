// Stalker v2: lightweight — use events: {call: true, block: true}
// Only capture BL/BLR calls and basic block entries within SO range
// Start when AES key expansion fires, stop after 6th MD5
//
// Run: frida -U -p <PID> -l scripts/hook_stalker_v2.js

var libBase = null;
var libSize = 0;
var stalkerTid = null;
var stalkerStarted = false;
var md5Count = 0;
var callEvents = [];
var blockEvents = [];

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
    libSize = mod.size;
    console.log("[+] SO @ " + libBase + " size=0x" + libSize.toString(16));

    // Hook AES key expansion — START Stalker
    Interceptor.attach(libBase.add(0x241E9C), {
        onEnter: function(args) {
            if (stalkerStarted) return;
            stalkerStarted = true;
            stalkerTid = Process.getCurrentThreadId();
            console.log("[+] Starting Stalker on tid=" + stalkerTid);

            Stalker.follow(stalkerTid, {
                events: {
                    call: true,    // BL/BLR instructions
                    ret: false,
                    exec: false,
                    block: false,
                    compile: false
                },
                onReceive: function(events) {
                    var parsed = Stalker.parse(events, { annotate: true, stringify: false });
                    for (var i = 0; i < parsed.length; i++) {
                        var ev = parsed[i];
                        // ev = ["call", from, to, depth] or similar
                        callEvents.push(ev);
                    }
                }
            });
            console.log("[+] Stalker started (call events only)");
        }
    });

    // Hook MD5 — count and stop after 6th
    Interceptor.attach(libBase.add(0x243C34), {
        onLeave: function(ret) {
            if (!stalkerStarted) return;
            md5Count++;
            if (md5Count >= 6) {
                console.log("[+] MD5 #6 done, scheduling Stalker stop...");
                var tid = stalkerTid;
                setTimeout(function() {
                    Stalker.unfollow(tid);
                    Stalker.flush();
                    stalkerStarted = false;
                    console.log("[+] Stalker stopped");
                    printResults();
                }, 100);
            }
        }
    });

    console.log("[+] Hooks ready");
}

function printResults() {
    console.log("\n=== STALKER CALL EVENTS (" + callEvents.length + ") ===");

    var soBase = libBase;
    var soSize = libSize;

    for (var i = 0; i < callEvents.length; i++) {
        var ev = callEvents[i];
        var parts = [];
        for (var j = 0; j < ev.length; j++) {
            var v = ev[j];
            if (typeof v === 'object' && v !== null) {
                // It's a NativePointer
                try {
                    var off = v.sub(soBase);
                    var n = off.toInt32();
                    if (n >= 0 && n < soSize) {
                        parts.push("0x" + n.toString(16));
                    } else {
                        parts.push(v.toString());
                    }
                } catch(e) {
                    parts.push(v.toString());
                }
            } else {
                parts.push(String(v));
            }
        }
        if (i < 500 || i >= callEvents.length - 50) {
            console.log("[" + i + "] " + parts.join(" → "));
        } else if (i === 500) {
            console.log("... (suppressed middle) ...");
        }
    }

    // Filter to SO-internal calls
    console.log("\n=== SO-INTERNAL CALLS ===");
    var internalCalls = [];
    for (var i = 0; i < callEvents.length; i++) {
        var ev = callEvents[i];
        if (ev.length >= 3) {
            try {
                var from = ev[1];
                var to = ev[2];
                var fromOff = from.sub(soBase).toInt32();
                var toOff = to.sub(soBase).toInt32();
                if (fromOff >= 0 && fromOff < soSize && toOff >= 0 && toOff < soSize) {
                    internalCalls.push({ from: fromOff, to: toOff, depth: ev.length > 3 ? ev[3] : 0 });
                }
            } catch(e) {}
        }
    }

    console.log("Total SO-internal calls: " + internalCalls.length);
    for (var i = 0; i < internalCalls.length; i++) {
        var c = internalCalls[i];
        console.log("  0x" + c.from.toString(16) + " → 0x" + c.to.toString(16));
    }

    // Unique call targets
    console.log("\n=== UNIQUE CALL TARGETS ===");
    var targets = {};
    for (var i = 0; i < internalCalls.length; i++) {
        var t = internalCalls[i].to;
        targets[t] = (targets[t] || 0) + 1;
    }
    var sortedTargets = Object.entries(targets).sort(function(a,b) { return parseInt(a[0]) - parseInt(b[0]); });
    for (var i = 0; i < sortedTargets.length; i++) {
        console.log("  0x" + parseInt(sortedTargets[i][0]).toString(16) + ": " + sortedTargets[i][1] + "x");
    }

    console.log("\n[DONE]");
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

    callEvents = [];
    md5Count = 0;
    stalkerStarted = false;

    console.log("[*] Calling doSign...");
    var sigs = doSign(url);
    console.log("[*] doSign returned, waiting for Stalker flush...");
}, 3000);
