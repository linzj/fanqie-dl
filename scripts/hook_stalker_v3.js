// Stalker v3: use Stalker.exclude() to avoid code slab allocation crash
// Exclude ALL modules except libmetasec_ml.so
// Capture exec events (basic blocks) within the SO only
//
// Run: frida -U -p <PID> -l scripts/hook_stalker_v3.js

var libBase = null;
var libSize = 0;
var stalkerTid = null;
var stalkerStarted = false;
var md5Count = 0;
var traceData = [];

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

    // Exclude ALL other modules from Stalker
    var excluded = 0;
    Process.enumerateModules().forEach(function(m) {
        if (m.name !== "libmetasec_ml.so") {
            Stalker.exclude(m);
            excluded++;
        }
    });
    console.log("[+] Excluded " + excluded + " modules from Stalker");

    // Hook AES key expansion — START Stalker
    Interceptor.attach(libBase.add(0x241E9C), {
        onEnter: function(args) {
            if (stalkerStarted) return;
            stalkerStarted = true;
            stalkerTid = Process.getCurrentThreadId();
            console.log("[+] Starting Stalker on tid=" + stalkerTid);

            Stalker.follow(stalkerTid, {
                events: {
                    call: true,
                    block: false,
                    ret: false,
                    exec: false,
                    compile: false
                },
                onReceive: function(events) {
                    var parsed = Stalker.parse(events, {
                        annotate: true,
                        stringify: false
                    });
                    for (var i = 0; i < parsed.length; i++) {
                        traceData.push(parsed[i]);
                    }
                }
            });
            console.log("[+] Stalker following (call events, other modules excluded)");
        }
    });

    // Stop Stalker after 6th MD5
    Interceptor.attach(libBase.add(0x243C34), {
        onLeave: function(ret) {
            if (!stalkerStarted) return;
            md5Count++;
            if (md5Count >= 6) {
                console.log("[+] 6th MD5 done, stopping Stalker...");
                Stalker.unfollow(stalkerTid);
                stalkerStarted = false;
            }
        }
    });

    console.log("[+] Hooks ready");
}

function printResults() {
    Stalker.flush();

    console.log("\n=== STALKER TRACE (" + traceData.length + " events) ===");

    var base = libBase;
    var sz = libSize;

    // Parse call events: [type, from, to, depth]
    var calls = [];
    for (var i = 0; i < traceData.length; i++) {
        var ev = traceData[i];
        if (ev.length < 3) continue;
        var type = ev[0];
        var from = ev[1];
        var to = ev[2];

        var fromOff = -1, toOff = -1;
        try { fromOff = from.sub(base).toInt32(); } catch(e) {}
        try { toOff = to.sub(base).toInt32(); } catch(e) {}

        var fromStr = (fromOff >= 0 && fromOff < sz) ? "0x" + fromOff.toString(16) : from.toString();
        var toStr = (toOff >= 0 && toOff < sz) ? "0x" + toOff.toString(16) : to.toString();

        calls.push({
            type: type, from: fromStr, to: toStr,
            fromOff: fromOff, toOff: toOff
        });
    }

    // Print all calls
    for (var i = 0; i < calls.length; i++) {
        var c = calls[i];
        console.log("[" + i + "] " + c.type + " " + c.from + " → " + c.to);
    }

    // Unique call targets within SO
    console.log("\n=== UNIQUE SO CALL TARGETS ===");
    var targets = {};
    for (var i = 0; i < calls.length; i++) {
        if (calls[i].toOff >= 0 && calls[i].toOff < sz) {
            targets[calls[i].toOff] = (targets[calls[i].toOff] || 0) + 1;
        }
    }
    var sorted = Object.entries(targets).sort(function(a,b) { return parseInt(a[0]) - parseInt(b[0]); });
    for (var i = 0; i < sorted.length; i++) {
        console.log("  0x" + parseInt(sorted[i][0]).toString(16) + ": " + sorted[i][1] + "x");
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

    traceData = [];
    md5Count = 0;
    stalkerStarted = false;

    console.log("[*] Calling doSign...");
    var sigs = doSign(url);
    console.log("[*] doSign returned");

    setTimeout(printResults, 1000);
}, 3000);
