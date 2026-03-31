// Hook INSIDE AES block encrypt (sub_2422EC) — entry point is bypassed by CFF!
// simpleperf shows execution at 0x242640-0x2429B4
// Strategy: hook several internal addresses to detect AES rounds
//
// Also: disassemble sub_2422EC to find what the entry point does vs mid-function jump
//
// Run: frida -U -p <PID> -l scripts/hook_aes_deep.js

var libBase = null;
var capturing = false;
var aesHits = [];

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
    console.log("[+] base=" + libBase);

    // First: disassemble sub_2422EC to understand the entry vs the hot zone
    console.log("\n=== DISASM sub_2422EC (entry) ===");
    var addr = libBase.add(0x2422EC);
    for (var i = 0; i < 30; i++) {
        try {
            var instr = Instruction.parse(addr);
            var off = addr.sub(libBase).toInt32();
            console.log("0x" + off.toString(16) + ": " + instr.mnemonic + " " + instr.opStr);
            addr = addr.add(instr.size);
        } catch(e) { addr = addr.add(4); }
    }

    // Disassemble hot zone 0x242620-0x242850
    console.log("\n=== DISASM AES hot zone (0x242620-0x242860) ===");
    addr = libBase.add(0x242620);
    var end = libBase.add(0x242860);
    while (addr.compare(end) < 0) {
        try {
            var instr = Instruction.parse(addr);
            var off = addr.sub(libBase).toInt32();
            console.log("0x" + off.toString(16) + ": " + instr.mnemonic + " " + instr.opStr);
            addr = addr.add(instr.size);
        } catch(e) { addr = addr.add(4); }
    }

    // Hook several internal AES addresses
    // Pick addresses from simpleperf hot spots
    var hookPoints = [0x242640, 0x242730, 0x2427D8, 0x242984];

    for (var i = 0; i < hookPoints.length; i++) {
        (function(off) {
            try {
                Interceptor.attach(libBase.add(off), {
                    onEnter: function(args) {
                        if (!capturing) return;
                        aesHits.push({
                            pc: off,
                            lr: soOffset(this.context.lr),
                            // Read some registers to understand state
                            x0: this.context.x0.toString(),
                            x1: this.context.x1.toString(),
                            x2: this.context.x2.toString(),
                        });
                    }
                });
                console.log("[+] Hooked AES internal 0x" + off.toString(16));
            } catch(e) {
                console.log("[-] Hook 0x" + off.toString(16) + " failed: " + e);
            }
        })(hookPoints[i]);
    }

    // Also hook the normal entry point to confirm it's NOT called
    Interceptor.attach(libBase.add(0x2422EC), {
        onEnter: function(args) {
            if (!capturing) return;
            aesHits.push({ pc: 0x2422EC, note: "ENTRY_CALLED!", lr: soOffset(this.context.lr) });
        }
    });
    console.log("[+] Hooked AES entry 0x2422EC");

    console.log("[+] Ready");
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

    aesHits = [];
    capturing = true;
    console.log("\n[*] Signing...");
    var sigs = doSign(url);
    capturing = false;

    var medusaHex = b64toHex(sigs["X-Medusa"] || "");
    console.log("Medusa: " + medusaHex.length/2 + " bytes");

    console.log("\n=== AES INTERNAL HITS (" + aesHits.length + ") ===");
    for (var i = 0; i < Math.min(aesHits.length, 200); i++) {
        var h = aesHits[i];
        var line = "[" + i + "] pc=0x" + h.pc.toString(16) + " lr=" + h.lr;
        if (h.note) line += " " + h.note;
        if (h.x0) line += " x0=" + h.x0;
        console.log(line);
    }

    // Count by PC
    console.log("\n=== COUNTS BY PC ===");
    var counts = {};
    for (var i = 0; i < aesHits.length; i++) {
        counts[aesHits[i].pc] = (counts[aesHits[i].pc] || 0) + 1;
    }
    for (var k in counts) {
        console.log("  0x" + parseInt(k).toString(16) + ": " + counts[k] + "x");
    }

    console.log("\n[DONE]");
}, 3000);
