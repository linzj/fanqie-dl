// Stalker v2: Follow thread from WITHIN the Java.perform callback
// Run: frida -U -p <PID> -l scripts/hook_stalker2.js

var libBase = null;
var libSize = 0;

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

function run() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;
    libSize = mod.size;
    console.log("[+] SO @ " + libBase + " size=" + libSize);

    Java.perform(function() {
        Java.enumerateClassLoaders({
            onMatch: function(loader) {
                try {
                    loader.findClass("ms.bd.c.r4");
                    Java.classFactory.loader = loader;
                    var HM = Java.use("java.util.HashMap");
                    Java.choose("ms.bd.c.r4", {
                        onMatch: function(inst) {
                            var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
                                "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
                                "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
                                "&device_brand=google&os_api=35&os_version=15" +
                                "&device_id=3722313718058683&iid=3722313718062779" +
                                "&_rticket=1774940000000" +
                                "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
                                "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
                                "&book_id=7373660003258862617";

                            var tid = Process.getCurrentThreadId();
                            console.log("[*] Thread ID: " + tid);

                            // Accumulate calls using transform
                            var callTargets = {};
                            var callSeq = [];
                            var seqLimit = 2000;

                            Stalker.follow(tid, {
                                events: { call: false, ret: false, exec: false },
                                transform: function(iterator) {
                                    var inst;
                                    while ((inst = iterator.next()) !== null) {
                                        // Check for BL/BLR instructions (ARM64 call)
                                        var mnemonic = inst.mnemonic;
                                        if (mnemonic === 'bl' || mnemonic === 'blr') {
                                            iterator.putCallout(function(ctx) {
                                                // Get the target from the link register or immediate
                                                var pc = ctx.pc;
                                                // For BL, the target is in the instruction
                                                // For BLR, it's in a register
                                                // Either way, after this callout, we can check x30 (LR)
                                                // Actually, let's check PC of next instruction vs where we are
                                            });
                                        }
                                        iterator.keep();
                                    }
                                }
                            });

                            var headers = HM.$new();
                            var r = inst.onCallToAddSecurityFactor(url, headers);

                            Stalker.unfollow(tid);
                            Stalker.flush();
                            Stalker.garbageCollect();

                            var map = Java.cast(r, HM);
                            var helios = map.get("X-Helios").toString();
                            console.log("Helios hex: " + b64toHex(helios));
                            console.log("[DONE - stalker approach doesn't easily capture BL targets]");

                            // Alternative: just dump all functions manually
                        },
                        onComplete: function() {}
                    });
                } catch(e) { console.log("[!] " + e); }
            },
            onComplete: function() {}
        });
    });
}

setTimeout(run, 1000);
