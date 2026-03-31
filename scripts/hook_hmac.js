// Hook HMAC function near offset 0x121b34 and capture its I/O during signing
// Run: frida -U -p <PID> -l scripts/hook_hmac.js

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

function tryReadStr(ptr, maxLen) {
    try {
        var s = ptr.readCString(maxLen || 64);
        if (!s) return null;
        // Check if mostly printable
        var printable = 0;
        for (var i = 0; i < s.length; i++) {
            var c = s.charCodeAt(i);
            if (c >= 0x20 && c < 0x7f) printable++;
        }
        if (printable > s.length * 0.5) return s;
        return null;
    } catch(e) { return null; }
}

function setup() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return; }
    libBase = mod.base;
    console.log("[+] SO @ " + libBase);

    // Examine the code around 0x121b34 to find function boundaries
    // The HMAC ipad (0x36 repeated) is at 0x121b34
    // Let's look at nearby instructions to find function prologue
    console.log("\n=== Code near HMAC ipad (0x121b34) ===");
    // Disassemble backwards from 0x121b34 to find function start
    // On ARM64, functions typically start with STP X29, X30, [SP, #-imm]!
    // Let's check several candidate addresses before 0x121b34

    // Look for the function that CONTAINS the ipad constant
    // It might be embedded as .quad or immediate data within a function
    // Let's scan for function prologues (STP pattern) before 0x121b34
    var ipadAddr = libBase.add(0x121b34);
    console.log("HMAC ipad at " + ipadAddr);

    // Read bytes around to understand the context
    console.log("Bytes at ipad-16: " + hex(ipadAddr.sub(16), 48));

    // Try to find functions that reference this address
    // For now, let's hook functions at several offsets before 0x121b34
    // and see which ones get called during signing

    // Common HMAC-MD5 function signatures: hmac_md5(key, keyLen, data, dataLen, output)
    // Typical: 4-5 args, returns void, output is 16 bytes

    // Let's scan for function entries near the ipad.
    // ARM64 function prologues usually have STP x29, x30, [sp, #-X]!
    // STP x29, x30 = bytes fd 7b .. a9 (where .. is the offset)
    var candidates = [];
    for (var off = 0x121000; off <= 0x121b34; off += 4) {
        try {
            var instr = Instruction.parse(libBase.add(off));
            if (instr.mnemonic === 'stp' && instr.toString().indexOf('x29') >= 0 && instr.toString().indexOf('x30') >= 0) {
                candidates.push(off);
            }
        } catch(e) {}
    }
    console.log("Function prologues near ipad: " + candidates.map(function(o) { return '0x' + o.toString(16); }).join(', '));

    // Hook the last few candidates (closest to ipad) plus other strategic offsets
    var hookOffsets = candidates.slice(-5);

    // Also look for functions that might be HMAC entry points
    // Add some manually selected offsets around the area
    // The HMAC function should be relatively large (>100 bytes)
    if (hookOffsets.length === 0) {
        // Scan more broadly
        for (var off = 0x120000; off <= 0x122000; off += 4) {
            try {
                var instr = Instruction.parse(libBase.add(off));
                if (instr.mnemonic === 'stp' && instr.toString().indexOf('x29') >= 0) {
                    hookOffsets.push(off);
                }
            } catch(e) {}
        }
    }

    console.log("Hooking " + hookOffsets.length + " candidate functions");
    for (var i = 0; i < hookOffsets.length; i++) {
        (function(off) {
            try {
                Interceptor.attach(libBase.add(off), {
                    onEnter: function(args) {
                        if (!capturing) return;
                        var entry = { op: "FUNC_0x" + off.toString(16) };
                        // Try to read args as potential HMAC params
                        try {
                            entry.a0 = args[0].toString();
                            entry.a1 = args[1].toString();
                            entry.a2 = args[2].toString();
                            entry.a3 = args[3].toString();
                            entry.a4 = args[4] ? args[4].toString() : "?";

                            // Try reading a1 as length
                            var len = args[1].toInt32();
                            if (len > 0 && len < 1000) {
                                entry.a0_data = hex(args[0], Math.min(len, 64));
                                entry.a0_len = len;
                            }
                        } catch(e) {}
                        ops.push(entry);
                    },
                    onLeave: function(ret) {
                        if (!capturing) return;
                        ops.push({ op: "RET_0x" + off.toString(16), ret: ret.toString() });
                    }
                });
                console.log("  Hooked 0x" + off.toString(16));
            } catch(e) {
                console.log("  Failed 0x" + off.toString(16) + ": " + e);
            }
        })(hookOffsets[i]);
    }

    // Also hook our known crypto functions
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            if (!capturing) return;
            this.len = args[1].toInt32();
            this.outPtr = args[2];
            this.inPtr = args[0];
        },
        onLeave: function(ret) {
            if (!capturing) return;
            ops.push({
                op: "MD5",
                inLen: this.len,
                input: hex(this.inPtr, Math.min(this.len, 64)),
                output: hex(this.outPtr, 16)
            });
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

function run2() {
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
    console.log("\nHelios hex: " + h);
    console.log("  R=" + h.substring(0,8) + " part1=" + h.substring(8,40) + " part2=" + h.substring(40,72));

    console.log("\nOps (" + ops.length + "):");
    for (var i = 0; i < ops.length; i++) {
        var e = ops[i];
        var line = "  [" + i + "] " + e.op;
        if (e.inLen !== undefined) line += " inLen=" + e.inLen;
        if (e.input) line += " in=" + e.input.substring(0, 64);
        if (e.output) line += " out=" + e.output;
        if (e.a0 && !e.input) line += " a0=" + e.a0;
        if (e.a1) line += " a1=" + e.a1;
        if (e.a0_len) line += " a0_data(" + e.a0_len + ")=" + e.a0_data;
        if (e.ret) line += " ret=" + e.ret;
        console.log(line);
    }

    console.log("\n[DONE]");
}

setup();
setTimeout(run2, 2000);
