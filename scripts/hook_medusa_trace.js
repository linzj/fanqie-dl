// Trace what happens AFTER AES key expansion to find Medusa encryption
// We know: AES key expand (sub_241E9C) is called from 0x25a3f4 (inside sub_259DBC)
// But NO standard AES encrypt functions are called after that!
//
// Strategy:
// 1. Hook AES key expand, capture the expanded key schedule pointer
// 2. Hook sub_259DBC (AES setup) entry/exit to see full flow
// 3. Hook sub_259CF0 (AES dispatch) with relaxed mode reading
// 4. Try hooking sub_2429F8 (AES keygen+encrypt one-shot)
// 5. Hook all functions in the 0x259xxx range that might handle encryption
//
// Run: frida -U -p <PID> -l scripts/hook_medusa_trace.js

var libBase = null;
var ops = [];
var capturing = false;

function hex(ptr, len) {
    var b = [];
    for (var i = 0; i < len; i++) b.push(('0' + ptr.add(i).readU8().toString(16)).slice(-2));
    return b.join('');
}

function soOffset(addr) {
    try {
        var n = addr.sub(libBase).toInt32();
        if (n >= 0 && n < 0x400000) return "0x" + n.toString(16);
        return "ext";
    } catch(e) { return "ext"; }
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
    console.log("[+] base @ " + libBase);

    // === AES key expansion (sub_241E9C) — capture expanded key ctx pointer ===
    Interceptor.attach(libBase.add(0x241E9C), {
        onEnter: function(args) {
            if (!capturing) return;
            this.ctx = args[0];
            try {
                ops.push({
                    op: "AES_KEY_EXPAND",
                    lr: soOffset(this.context.lr),
                    ctx: args[0].toString(),
                    keyLen: args[2].toInt32(),
                    key: hex(args[1], args[2].toInt32())
                });
            } catch(e) {}
        }
    });

    // === sub_259DBC (AES setup — calls key expansion) ===
    Interceptor.attach(libBase.add(0x259DBC), {
        onEnter: function(args) {
            if (!capturing) return;
            this.a0 = args[0]; this.a1 = args[1]; this.a2 = args[2]; this.a3 = args[3];
            ops.push({
                op: "AES_SETUP_259DBC_ENTER",
                lr: soOffset(this.context.lr),
                a0: args[0].toString(),
                a1: args[1].toString(),
                a2_keyLen: args[2].toInt32(),
                a3_mode: args[3].toInt32()
            });
        },
        onLeave: function(ret) {
            if (!capturing) return;
            ops.push({
                op: "AES_SETUP_259DBC_LEAVE",
                ret: ret.toString()
            });
        }
    });

    // === sub_259CF0 (AES dispatch encrypt) — try different mode reading ===
    Interceptor.attach(libBase.add(0x259CF0), {
        onEnter: function(args) {
            if (!capturing) return;
            try {
                // Try reading mode at different offsets
                var a0 = args[0];
                var entry = {
                    op: "AES_DISPATCH_259CF0",
                    lr: soOffset(this.context.lr),
                    a0: a0.toString()
                };
                // Try various offsets for mode
                for (var off = 0; off <= 16; off += 4) {
                    try { entry["a0_off" + off] = a0.add(off).readU32(); } catch(e) {}
                }
                entry.dataLen = args[4].toInt32();
                ops.push(entry);
            } catch(e) { ops.push({ op: "AES_DISPATCH_259CF0", err: ""+e }); }
        }
    });

    // === sub_2429F8 (AES keygen+encrypt one-shot) ===
    Interceptor.attach(libBase.add(0x2429F8), {
        onEnter: function(args) {
            if (!capturing) return;
            ops.push({
                op: "AES_ONESHOT_2429F8",
                lr: soOffset(this.context.lr)
            });
        }
    });

    // === sub_2422EC (real AES block encrypt) ===
    var aesBlockN = 0;
    Interceptor.attach(libBase.add(0x2422EC), {
        onEnter: function(args) {
            if (!capturing) return;
            aesBlockN++;
            ops.push({ op: "AES_BLOCK_2422EC", n: aesBlockN, lr: soOffset(this.context.lr) });
        }
    });

    // === sub_242A70 (AES-CBC) ===
    Interceptor.attach(libBase.add(0x242A70), {
        onEnter: function(args) {
            if (!capturing) return;
            ops.push({ op: "AES_CBC_242A70", lr: soOffset(this.context.lr), len: args[3].toInt32() });
        }
    });

    // === sub_242C98 (AES-CTR) ===
    Interceptor.attach(libBase.add(0x242C98), {
        onEnter: function(args) {
            if (!capturing) return;
            ops.push({ op: "AES_CTR_242C98", lr: soOffset(this.context.lr), len: args[3].toInt32() });
        }
    });

    // === sub_259C1C (AES mode setup — mode select) ===
    Interceptor.attach(libBase.add(0x259C1C), {
        onEnter: function(args) {
            if (!capturing) return;
            var entry = { op: "AES_MODE_SETUP_259C1C", lr: soOffset(this.context.lr) };
            try {
                // args layout might be: (ctx, key, keyLen, mode, iv/nonce)
                entry.a0 = args[0].toString();
                entry.a1 = args[1].toString();
                entry.a2 = args[2].toInt32();
                entry.a3 = args[3].toInt32();
                entry.a4 = args[4].toString();
            } catch(e) {}
            ops.push(entry);
        }
    });

    // === Hook functions in the signing path that might do Medusa encryption ===
    // sub_259DBC is AES setup, caller is 0x26351c area
    // Let's hook sub_259CF0 more broadly

    // Hook sub_259D78 (might be AES encrypt wrapper)
    try {
        Interceptor.attach(libBase.add(0x259D78), {
            onEnter: function(args) {
                if (!capturing) return;
                ops.push({ op: "FUNC_259D78", lr: soOffset(this.context.lr) });
            }
        });
    } catch(e) {}

    // Hook sub_25A3F4 area - this is where key expand is called from
    // 0x25a3f4 is INSIDE sub_259DBC, not a separate function

    // Hook sub_259CF0+0x4 in case the entry point is slightly different
    // Actually let's hook sub_259E88 (after setup, might be encrypt entry)
    try {
        Interceptor.attach(libBase.add(0x259E88), {
            onEnter: function(args) {
                if (!capturing) return;
                ops.push({ op: "FUNC_259E88", lr: soOffset(this.context.lr) });
            }
        });
    } catch(e) { console.log("  259E88 hook failed: " + e); }

    // Hook SHA-1 calls to count them properly
    var sha1UpdateCount = 0;
    Interceptor.attach(libBase.add(0x243E50), {
        onEnter: function(args) {
            if (!capturing) return;
            sha1UpdateCount++;
        }
    });

    var sha1TransCount = 0;
    Interceptor.attach(libBase.add(0x243F10), {
        onEnter: function(args) {
            if (!capturing) return;
            sha1TransCount++;
        }
    });

    // Store counters for summary
    globalThis._sha1UpdateCount = function() { return sha1UpdateCount; };
    globalThis._sha1TransCount = function() { return sha1TransCount; };
    globalThis._aesBlockCount = function() { return aesBlockN; };

    console.log("[+] All hooks installed\n");
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

    ops = [];
    capturing = true;
    var sigs = doSign(url);
    capturing = false;

    // Print Medusa full hex
    var medusaHex = b64toHex(sigs["X-Medusa"] || "");
    console.log("Medusa (" + medusaHex.length/2 + " bytes):");
    console.log("  header(24)=" + medusaHex.substring(0, 48));
    console.log("  body_len=" + (medusaHex.length/2 - 24));

    var heliosHex = b64toHex(sigs["X-Helios"] || "");
    console.log("Helios: R=" + heliosHex.substring(0,8) + " p1=" + heliosHex.substring(8,40) + " p2=" + heliosHex.substring(40,72));

    console.log("\n=== ALL OPS ===");
    for (var i = 0; i < ops.length; i++) {
        var o = ops[i];
        var line = "[" + i + "] " + o.op;
        for (var k in o) {
            if (k === "op") continue;
            line += " " + k + "=" + o[k];
        }
        console.log(line);
    }

    console.log("\n=== COUNTS ===");
    console.log("  SHA-1 update: " + globalThis._sha1UpdateCount());
    console.log("  SHA-1 transform: " + globalThis._sha1TransCount());
    console.log("  AES block encrypt: " + globalThis._aesBlockCount());

    console.log("\n[DONE]");
}, 2000);
