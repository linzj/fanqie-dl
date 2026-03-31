// Find WHERE Helios 36 bytes are base64-encoded
// Hook all base64 paths + the buffer creation functions
//
// Run: frida -U -p <PID> -l scripts/trace_helios2.js

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
var phase = 0; // 0=before sign, 1=after MD5[0], 2=after MD5[1], 3=after helios

// Hook MD5
Interceptor.attach(base.add(0x243C34), {
    onLeave: function(ret) {
        md5Count++;
        if (md5Count === 1) phase = 1;
        if (md5Count === 2) { phase = 2; console.log("[*] MD5#2 done, watching for Helios..."); }
    }
});

// Hook sub_2456AC (base64 encoder - low level)
Interceptor.attach(base.add(0x2456AC), {
    onEnter: function(args) {
        if (phase < 2 || phase > 2) return;
        var inLen = args[1].toInt32();
        console.log("[B64_LOW] inlen=" + inLen + " LR=" + soOff(this.context.lr));
        if (inLen > 0 && inLen <= 100) {
            console.log("  input=" + hex(args[0], inLen));
        }
    }
});

// Hook sub_258C84 (base64 wrapper - malloc+encode)
Interceptor.attach(base.add(0x258C84), {
    onEnter: function(args) {
        if (phase < 2 || phase > 2) return;
        console.log("[B64_WRAP] LR=" + soOff(this.context.lr) +
            " x0=" + args[0] + " x1=" + args[1]);
        // x0 might be the data object: [vtable, ?, ?, len@+0xC, data@+0x10]
        try {
            var len = args[0].add(0xC).readU32();
            var dataPtr = args[0].add(0x10).readPointer();
            if (len > 0 && len <= 100) {
                console.log("  obj_len=" + len + " obj_data=" + hex(dataPtr, len));
            }
        } catch(e) {}
    }
});

// Hook sub_258C14 (base64 high-level)
Interceptor.attach(base.add(0x258C14), {
    onEnter: function(args) {
        if (phase < 2 || phase > 2) return;
        console.log("[B64_HIGH] LR=" + soOff(this.context.lr) +
            " x0=" + args[0] + " x1=" + args[1]);
        try {
            var len = args[1].add(0xC).readU32();
            var dataPtr = args[1].add(0x10).readPointer();
            if (len > 0 && len <= 100) {
                console.log("  obj_len=" + len + " obj_data=" + hex(dataPtr, len));
            }
        } catch(e) {}
    }
});

// Hook sub_2481FC (CREATE_BUF) — Helios bytes might be assembled here
Interceptor.attach(base.add(0x2481FC), {
    onEnter: function(args) {
        if (phase !== 2) return;
        try {
            var len = args[2].toInt32();
            if (len >= 32 && len <= 48) {
                console.log("[CREATE_BUF] len=" + len + " data=" + hex(args[1], len) +
                    " LR=" + soOff(this.context.lr));
            }
        } catch(e) {}
    }
});

// Hook sub_248344 (BUF_OP) — buffer append/copy
Interceptor.attach(base.add(0x248344), {
    onEnter: function(args) {
        if (phase !== 2) return;
        try {
            // Try to read buffer data
            console.log("[BUF_OP] x0=" + args[0] + " x1=" + args[1] +
                " LR=" + soOff(this.context.lr));
        } catch(e) {}
    }
});

// Hook MAP_SET to detect X-Helios
Interceptor.attach(base.add(0x25BF3C), {
    onEnter: function(args) {
        if (phase !== 2) return;
        try {
            var keyObj = args[1];
            var keyLen = keyObj.add(0xC).readU32();
            var keyData = keyObj.add(0x10).readPointer();
            if (keyLen === 8) {
                var keyStr = keyData.readUtf8String(8);
                if (keyStr === "X-Helios") {
                    console.log("\n[MAP_SET:X-Helios] LR=" + soOff(this.context.lr));
                    var valObj = args[2];
                    var valLen = valObj.add(0xC).readU32();
                    var valData = valObj.add(0x10).readPointer();
                    console.log("  val_len=" + valLen + " val=" + hex(valData, valLen));
                    phase = 3;
                }
            }
        } catch(e) {}
    }
});

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
