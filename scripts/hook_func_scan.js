// Scan SO for function prologues in signing-related ranges, hook them all
// This gives us function-level tracing without Stalker
//
// ARM64 function prologue patterns:
//   STP X29, X30, [SP, #-imm]!  →  0xA9xx7BFD
//   SUB SP, SP, #imm            →  0xD10xxxFF (alternative)
//
// We scan ranges: 0x240000-0x264000, 0x269000-0x270000, 0x283000-0x290000
//
// Run: frida -U -p <PID> -l scripts/hook_func_scan.js

var libBase = null;
var libSize = 0;
var funcTrace = [];
var capturing = false;

function soOffset(addr) {
    try {
        var n = addr.sub(libBase).toInt32();
        if (n >= 0 && n < libSize) return n;
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

function hex(ptr, len) {
    var b = [];
    for (var i = 0; i < len; i++) b.push(('0' + ptr.add(i).readU8().toString(16)).slice(-2));
    return b.join('');
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;
    libSize = mod.size;
    console.log("[+] SO @ " + libBase + " size=0x" + libSize.toString(16));

    // Scan for function prologues
    var ranges = [
        [0x155000, 0x170000],  // low-level utils
        [0x190000, 0x1A6000],  // buffer/string ops
        [0x240000, 0x264000],  // crypto + signing wrappers
        [0x269000, 0x272000],  // init/signing
        [0x283000, 0x2A0000],  // signing functions
        [0x296000, 0x29E000],  // dispatch
        [0x32A000, 0x32B000],  // malloc
    ];

    var hookedCount = 0;
    var funcAddrs = [];

    for (var r = 0; r < ranges.length; r++) {
        var start = ranges[r][0];
        var end = ranges[r][1];

        for (var off = start; off < end; off += 4) {
            var addr = libBase.add(off);
            try {
                var instr = addr.readU32();
                // STP X29, X30, [SP, #imm]! (pre-index): mask bits 31-23 + 15-0
                // Also match STP signed-offset and PACIASP prologue
                var isSTP_pre = ((instr & 0xFF80FFFF) === 0xA9807BFD);   // STP pre-index
                var isSTP_off = ((instr & 0xFF80FFFF) === 0xA9007BFD);   // STP signed offset
                var isPACIASP = (instr === 0xD503233F);                   // PACIASP
                if (isSTP_pre || isSTP_off || isPACIASP) {
                    funcAddrs.push(off);
                }
            } catch(e) {}
        }
    }

    console.log("[+] Found " + funcAddrs.length + " function prologues");

    // Hook each one
    for (var i = 0; i < funcAddrs.length; i++) {
        (function(offset) {
            try {
                Interceptor.attach(libBase.add(offset), {
                    onEnter: function(args) {
                        if (!capturing) return;
                        funcTrace.push({
                            f: offset,
                            lr: soOffset(this.context.lr)
                        });
                    }
                });
                hookedCount++;
            } catch(e) {
                // Some addresses might conflict with existing hooks
            }
        })(funcAddrs[i]);
    }

    console.log("[+] Hooked " + hookedCount + "/" + funcAddrs.length + " functions");
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

    funcTrace = [];
    capturing = true;
    console.log("[*] Signing...");
    var sigs = doSign(url);
    capturing = false;
    console.log("[*] Done. Trace has " + funcTrace.length + " entries");

    // Print full trace
    console.log("\n=== FUNCTION CALL TRACE ===");
    for (var i = 0; i < funcTrace.length; i++) {
        var t = funcTrace[i];
        var lrStr = (t.lr >= 0) ? "0x" + t.lr.toString(16) : "ext";
        console.log("[" + i + "] 0x" + t.f.toString(16) + " ← " + lrStr);
    }

    // Unique functions called
    console.log("\n=== UNIQUE FUNCTIONS ===");
    var counts = {};
    for (var i = 0; i < funcTrace.length; i++) {
        counts[funcTrace[i].f] = (counts[funcTrace[i].f] || 0) + 1;
    }
    var sorted = Object.entries(counts).sort(function(a,b) { return parseInt(a[0]) - parseInt(b[0]); });
    for (var i = 0; i < sorted.length; i++) {
        console.log("  0x" + parseInt(sorted[i][0]).toString(16) + ": " + sorted[i][1] + "x");
    }

    // Unknown functions (not in our known set)
    var known = [
        0x241E9C, 0x2422EC, 0x2429F8, 0x242A70, 0x242C98, 0x242DE0,
        0x243C34, 0x243E50, 0x243F10, 0x2450AC, 0x2451FC, 0x245354, 0x245630,
        0x248344, 0x2481FC, 0x258530, 0x258780, 0x258A48,
        0x259C1C, 0x259CF0, 0x259DBC,
        0x25BF3C, 0x270020, 0x32A1F0,
        0x167E54, 0x162944, 0x15E1A8
    ];
    console.log("\n=== UNKNOWN FUNCTIONS (not previously identified) ===");
    for (var i = 0; i < sorted.length; i++) {
        var addr = parseInt(sorted[i][0]);
        if (known.indexOf(addr) < 0) {
            console.log("  ★ 0x" + addr.toString(16) + ": " + sorted[i][1] + "x");
        }
    }

    console.log("\n[DONE]");
}, 3000);
