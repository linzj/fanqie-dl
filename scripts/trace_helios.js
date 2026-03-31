// Minimal trace: only MD5 + MAP_SET to find Helios boundaries
// Run: frida -U -p <PID> -l scripts/trace_helios.js

var mod = Process.findModuleByName("libmetasec_ml.so");
var base = mod.base;
console.log("[+] base=" + base);

function hex(ptr, len) {
    var b = [];
    for (var i = 0; i < len; i++) b.push(('0' + ptr.add(i).readU8().toString(16)).slice(-2));
    return b.join('');
}

function soOff(addr) {
    try {
        var n = addr.sub(base).toInt32();
        return (n >= 0 && n < 0x400000) ? "0x" + n.toString(16) : "ext";
    } catch(e) { return "ext"; }
}

var md5Count = 0;
var mapSetCount = 0;

// Hook MD5 (PLT entry) — captures all MD5 calls
Interceptor.attach(base.add(0x243C34), {
    onEnter: function(args) {
        this.outPtr = args[2];
        this.len = args[1].toInt32();
        this.lr = soOff(this.context.lr);
    },
    onLeave: function(ret) {
        md5Count++;
        try {
            console.log("[MD5#" + md5Count + "] len=" + this.len +
                " out=" + hex(this.outPtr, 16) + " LR=" + this.lr);
        } catch(e) {}
    }
});

// Hook MAP_SET (sub_25BF3C) — captures when headers are written
Interceptor.attach(base.add(0x25BF3C), {
    onEnter: function(args) {
        mapSetCount++;
        try {
            var keyObj = args[1];
            var keyLen = keyObj.add(0xC).readU32();
            var keyData = keyObj.add(0x10).readPointer();
            var keyStr = keyLen < 50 ? keyData.readUtf8String(keyLen) : "?";

            var valObj = args[2];
            var valLen = valObj.add(0xC).readU32();
            var valData = valObj.add(0x10).readPointer();

            console.log("[MAP_SET#" + mapSetCount + "] key=\"" + keyStr +
                "\" val_len=" + valLen + " LR=" + soOff(this.context.lr));

            if (keyStr === "X-Helios") {
                console.log("  HELIOS_BASE64=" + hex(valData, valLen));
                // Dump all registers at this point
                var regs = ['x0','x1','x2','x3','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28','fp','lr','sp'];
                for (var i = 0; i < regs.length; i++) {
                    console.log("  " + regs[i] + "=" + this.context[regs[i]]);
                }

                // Dump the Helios raw bytes (decode from base64 object)
                console.log("\n  === HELIOS CONSTRUCTION CONTEXT ===");

                // Walk the stack to find the signing function's frame
                var sp = this.context.sp;
                console.log("  Stack[0..256]=" + hex(sp, 256));
            }
        } catch(e) {
            console.log("[MAP_SET#" + mapSetCount + "] err: " + e);
        }
    }
});

// Hook base64 encoder to see what gets encoded near Helios
Interceptor.attach(base.add(0x2456AC), {
    onEnter: function(args) {
        try {
            var inLen = args[1].toInt32();
            if (inLen > 0 && inLen <= 100) {
                console.log("[BASE64] inlen=" + inLen + " in=" + hex(args[0], inLen) +
                    " LR=" + soOff(this.context.lr));
            }
        } catch(e) {}
    }
});

// Hook XOR decrypt — might be used to decrypt "X-Helios" string
Interceptor.attach(base.add(0x167E54), {
    onEnter: function(args) {
        try {
            var len = args[2].toInt32();
            console.log("[XOR_DECRYPT] len=" + len + " LR=" + soOff(this.context.lr));
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
                            md5Count = 0;
                            mapSetCount = 0;

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
                            var r = inst.onCallToAddSecurityFactor(url, h);
                            var m = Java.cast(r, HM);
                            console.log("\n=== RESULT ===");
                            var it = m.keySet().iterator();
                            while (it.hasNext()) {
                                var k = it.next();
                                var v = m.get(k).toString();
                                console.log("  " + k + "=" + v.substring(0, 80));
                            }
                            console.log("\n[DONE]");
                        },
                        onComplete: function() {}
                    });
                } catch(e) {}
            },
            onComplete: function() {}
        });
    });
}, 3000);
