// Deep trace: capture Helios raw bytes + the 32-byte hex buffer at 0x287b44
// Also capture CREATE_BUF calls between MD5[1] and X-Helios to find ALL intermediates
//
// Run: frida -U -p <PID> -l scripts/trace_helios3.js

var mod = Process.findModuleByName("libmetasec_ml.so");
var base = mod.base;
console.log("[+] base=" + base);

function hex(ptr, len) {
    var b = [];
    for (var i = 0; i < len; i++) b.push(('0' + ptr.add(i).readU8().toString(16)).slice(-2));
    return b.join('');
}
function soOff(addr) {
    try { var n = addr.sub(base).toInt32(); return (n >= 0 && n < 0x400000) ? "0x" + n.toString(16) : "ext"; }
    catch(e) { return "ext"; }
}

var md5Count = 0;
var phase = 0; // 2 = between MD5[1] and X-Helios

// Hook MD5
Interceptor.attach(base.add(0x243C34), {
    onEnter: function(args) {
        this.outPtr = args[2]; this.len = args[1].toInt32();
        this.inPtr = args[0];
    },
    onLeave: function(ret) {
        md5Count++;
        if (md5Count <= 2) {
            try {
                var out = hex(this.outPtr, 16);
                console.log("[MD5#" + md5Count + "] len=" + this.len + " out=" + out);
                if (md5Count === 1) {
                    console.log("  H0=" + out);
                }
                if (md5Count === 2) {
                    // Capture R from the input (first 4 bytes before "1967")
                    var R = hex(this.inPtr, 4);
                    console.log("  R=" + R + " H1=" + out);
                    phase = 2;
                }
            } catch(e) {}
        }
    }
});

// Hook CREATE_BUF (sub_2481FC) — capture ALL buffer creations
Interceptor.attach(base.add(0x2481FC), {
    onEnter: function(args) {
        if (phase !== 2) return;
        try {
            var len = args[2].toInt32();
            if (len > 0 && len <= 200) {
                var data = hex(args[1], len);
                var lr = soOff(this.context.lr);
                console.log("[CREATE_BUF] len=" + len + " LR=" + lr + " data=" + data);
                // Try to interpret as ASCII
                try {
                    var ascii = args[1].readUtf8String(len);
                    if (ascii && ascii.length > 2) {
                        console.log("  ASCII: \"" + ascii + "\"");
                    }
                } catch(e) {}
            }
        } catch(e) {}
    }
});

// BUF_OP removed — too many calls, may trigger anti-debug

// Hook base64 high-level (sub_258C14) — this encodes Helios
Interceptor.attach(base.add(0x258C14), {
    onEnter: function(args) {
        if (phase !== 2) return;
        var lr = soOff(this.context.lr);
        console.log("[B64_ENCODE] LR=" + lr);
        try {
            // arg1 is the data object to encode
            var obj = args[1];
            var len = obj.add(0xC).readU32();
            var dataPtr = obj.add(0x10).readPointer();
            if (len > 0 && len <= 100) {
                console.log("  input_raw_len=" + len + " input_raw=" + hex(dataPtr, len));
            }
        } catch(e) {}
    },
    onLeave: function(ret) {
        if (phase !== 2) return;
        // After base64 encoding, check what was produced
        try {
            var obj = this.context.x0 || ret;
        } catch(e) {}
    }
});

// Hook MAP_SET to detect X-Helios boundary
Interceptor.attach(base.add(0x25BF3C), {
    onEnter: function(args) {
        if (phase !== 2) return;
        try {
            var keyObj = args[1];
            var keyLen = keyObj.add(0xC).readU32();
            var keyData = keyObj.add(0x10).readPointer();
            if (keyLen === 8 && keyData.readUtf8String(8) === "X-Helios") {
                var valObj = args[2];
                var valLen = valObj.add(0xC).readU32();
                var valData = valObj.add(0x10).readPointer();
                console.log("\n[X-Helios SET] val_b64=" + hex(valData, valLen));
                console.log("  LR=" + soOff(this.context.lr));
                phase = 3;
            }
        } catch(e) {}
    }
});

// ALLOC_BUF removed — may trigger anti-debug

console.log("[+] Hooks ready");

setTimeout(function() {
    Java.perform(function() {
        Java.enumerateClassLoaders({
            onMatch: function(loader) {
                try {
                    loader.findClass("ms.bd.c.r4");
                    Java.classFactory.loader = loader;
                    var HM = Java.use("java.util.HashMap");
                    Java.choose("ms.bd.c.r4", {
                        onMatch: function(inst) {
                            md5Count = 0; phase = 0;
                            var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
                                "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
                                "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
                                "&device_brand=google&os_api=35&os_version=15" +
                                "&device_id=3722313718058683&iid=3722313718062779" +
                                "&_rticket=1774940000000" +
                                "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
                                "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
                                "&book_id=7373660003258862617";
                            console.log("\n[*] Signing...");
                            var h = HM.$new();
                            inst.onCallToAddSecurityFactor(url, h);
                            console.log("[DONE]");
                        },
                        onComplete: function() {}
                    });
                } catch(e) {}
            },
            onComplete: function() {}
        });
    });
}, 3000);
