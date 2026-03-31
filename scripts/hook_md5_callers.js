// Hook MD5 to capture call stack (return addresses) for each call
// This tells us what code is CALLING MD5 and what it does with the result
// Run: frida -U -p <PID> -l scripts/hook_md5_callers.js

var libBase = null;
var ops = [];
var capturing = false;

function hex(ptr, len) {
    var b = [];
    for (var i = 0; i < len; i++) b.push(('0' + ptr.add(i).readU8().toString(16)).slice(-2));
    return b.join('');
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
    var libEnd = libBase.add(mod.size);

    // Hook MD5 with full backtrace
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.inPtr = args[0];
            this.len = args[1].toInt32();
            this.outPtr = args[2];
            if (capturing) {
                // Get backtrace - only show addresses within libmetasec_ml.so
                var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                this.callers = [];
                for (var i = 0; i < bt.length; i++) {
                    var addr = bt[i];
                    if (addr.compare(libBase) >= 0 && addr.compare(libEnd) < 0) {
                        this.callers.push('0x' + addr.sub(libBase).toString(16));
                    }
                }
            }
        },
        onLeave: function(ret) {
            if (!capturing) return;
            ops.push({
                op: "MD5",
                inLen: this.len,
                input: hex(this.inPtr, Math.min(this.len, 64)),
                output: hex(this.outPtr, 16),
                callers: this.callers
            });
        }
    });

    // Hook AES key expand with backtrace
    Interceptor.attach(libBase.add(0x241E9C), {
        onEnter: function(args) {
            if (!capturing) return;
            var keyLen = args[2].toInt32();
            var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
            var callers = [];
            for (var i = 0; i < bt.length; i++) {
                var addr = bt[i];
                if (addr.compare(libBase) >= 0 && addr.compare(libEnd) < 0) {
                    callers.push('0x' + addr.sub(libBase).toString(16));
                }
            }
            ops.push({
                op: "AES_KEY",
                key: hex(args[1], keyLen),
                callers: callers
            });
        }
    });

    // Hook SHA1 wrapper with backtrace
    Interceptor.attach(libBase.add(0x258780), {
        onEnter: function(args) {
            if (!capturing) return;
            var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
            var callers = [];
            for (var i = 0; i < bt.length; i++) {
                var addr = bt[i];
                if (addr.compare(libBase) >= 0 && addr.compare(libEnd) < 0) {
                    callers.push('0x' + addr.sub(libBase).toString(16));
                }
            }
            ops.push({ op: "SHA1", callers: callers });
        }
    });

    // Hook sub_270020 with backtrace
    Interceptor.attach(libBase.add(0x270020), {
        onEnter: function(args) {
            if (!capturing) return;
            var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
            var callers = [];
            for (var i = 0; i < bt.length; i++) {
                var addr = bt[i];
                if (addr.compare(libBase) >= 0 && addr.compare(libEnd) < 0) {
                    callers.push('0x' + addr.sub(libBase).toString(16));
                }
            }
            ops.push({ op: "sub_270020", callers: callers });
        }
    });

    // Hook AES block (sub_243F10) with backtrace
    Interceptor.attach(libBase.add(0x243F10), {
        onEnter: function(args) {
            if (!capturing) return;
            var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
            var callers = [];
            for (var i = 0; i < bt.length; i++) {
                var addr = bt[i];
                if (addr.compare(libBase) >= 0 && addr.compare(libEnd) < 0) {
                    callers.push('0x' + addr.sub(libBase).toString(16));
                }
            }
            ops.push({ op: "AES_BLOCK", callers: callers });
        }
    });

    // Hook AES wrapper (sub_243E50) - just first call with backtrace
    var wrapCount = 0;
    Interceptor.attach(libBase.add(0x243E50), {
        onEnter: function(args) {
            if (!capturing) return;
            wrapCount++;
            if (wrapCount <= 2) {
                var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                var callers = [];
                for (var i = 0; i < bt.length; i++) {
                    var addr = bt[i];
                    if (addr.compare(libBase) >= 0 && addr.compare(libEnd) < 0) {
                        callers.push('0x' + addr.sub(libBase).toString(16));
                    }
                }
                ops.push({ op: "AES_WRAP_" + wrapCount, callers: callers });
            }
        }
    });

    console.log("[+] All hooks installed");
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

function run() {
    var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
        "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
        "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
        "&device_brand=google&os_api=35&os_version=15" +
        "&device_id=3722313718058683&iid=3722313718062779" +
        "&_rticket=1774940000000" +
        "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
        "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
        "&book_id=7373660003258862617";

    ops = [];
    capturing = true;
    var sigs = doSign(url);
    capturing = false;

    var h = b64toHex(sigs["X-Helios"] || "");
    console.log("\nHelios: " + h);
    console.log("  R=" + h.substring(0,8) + " part1=" + h.substring(8,40) + " part2=" + h.substring(40,72));

    console.log("\nOps (" + ops.length + "):");
    for (var i = 0; i < ops.length; i++) {
        var e = ops[i];
        var line = "  [" + i + "] " + e.op;
        if (e.inLen !== undefined) line += " inLen=" + e.inLen;
        if (e.input) line += " in=" + e.input.substring(0, 48);
        if (e.output) line += " out=" + e.output;
        if (e.key) line += " key=" + e.key;
        if (e.callers && e.callers.length > 0) line += "\n      callers: " + e.callers.join(" ← ");
        console.log(line);
    }

    // Collect unique caller addresses
    var allCallers = {};
    for (var i = 0; i < ops.length; i++) {
        if (ops[i].callers) {
            for (var j = 0; j < ops[i].callers.length; j++) {
                allCallers[ops[i].callers[j]] = true;
            }
        }
    }
    console.log("\n=== UNIQUE CALLER FUNCTIONS IN SO ===");
    var sorted = Object.keys(allCallers).sort();
    for (var i = 0; i < sorted.length; i++) {
        console.log("  " + sorted[i]);
    }

    console.log("\n[DONE]");
}

setup();
setTimeout(run, 2000);
