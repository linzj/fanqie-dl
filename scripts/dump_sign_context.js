// Dump everything needed for Unicorn emulation of the signing function
// 1. Find the native function address for y2.a (registered via JNI)
// 2. Hook it, dump registers + arguments at entry
// 3. Dump SO memory segments
// 4. Capture all external calls (malloc/free/etc.) for replay
//
// Run: frida -U -p <PID> -l scripts/dump_sign_context.js

var libBase = null;
var libSize = 0;
var libEnd = null;
var nativeFnAddr = null;  // address of the native impl of y2.a

// ============ Helpers ============
function hex(ptr, len) {
    var b = [];
    for (var i = 0; i < len; i++) b.push(('0' + ptr.add(i).readU8().toString(16)).slice(-2));
    return b.join('');
}

function soOffset(addr) {
    try {
        var n = addr.sub(libBase).toInt32();
        if (n >= 0 && n < libSize) return "0x" + n.toString(16);
        return null;
    } catch(e) { return null; }
}

// ============ Step 1: Find SO and native function ============
function findSO() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) { console.log("[!] SO not found"); return false; }
    libBase = mod.base;
    libSize = mod.size;
    libEnd = libBase.add(libSize);
    console.log("[+] libmetasec_ml.so base=" + libBase + " size=0x" + libSize.toString(16));
    return true;
}

// ============ Step 2: Hook RegisterNatives to find y2.a native impl ============
function hookRegisterNatives() {
    // The SO uses JNI RegisterNatives in JNI_OnLoad
    // But JNI_OnLoad already ran. We need to find the registered function.
    // Alternative: hook y2.a at Java level to get the entry, then
    // hook the JNI call to find the native offset.

    // From investigate.js, we know y2.a is the native entry.
    // Let's hook it at Java level and trace into native.
    console.log("[*] Looking for y2.a native address...");
}

// ============ Step 3: Dump memory state during signing ============
var externalCalls = [];
var mallocMap = {};  // addr -> size
var heapDumps = [];  // {addr, size, data} for allocated regions

function hookExternals() {
    // Hook malloc
    var mallocAddr = Module.findExportByName("libc.so", "malloc");
    if (mallocAddr) {
        Interceptor.attach(mallocAddr, {
            onEnter: function(args) {
                this.size = args[0].toInt32();
            },
            onLeave: function(ret) {
                if (this.capturing) {
                    mallocMap[ret.toString()] = this.size;
                    externalCalls.push({fn: "malloc", size: this.size, ret: ret.toString()});
                }
            }
        });
    }

    // Hook free
    var freeAddr = Module.findExportByName("libc.so", "free");
    if (freeAddr) {
        Interceptor.attach(freeAddr, {
            onEnter: function(args) {
                if (this.capturing) {
                    externalCalls.push({fn: "free", ptr: args[0].toString()});
                }
            }
        });
    }

    // Hook memcpy
    var memcpyAddr = Module.findExportByName("libc.so", "memcpy");
    if (memcpyAddr) {
        Interceptor.attach(memcpyAddr, {
            onEnter: function(args) {
                if (this.capturing) {
                    var dst = args[0]; var src = args[1]; var len = args[2].toInt32();
                    if (len > 0 && len < 4096) {
                        externalCalls.push({
                            fn: "memcpy", dst: dst.toString(), src: src.toString(),
                            len: len, data: hex(src, Math.min(len, 256))
                        });
                    }
                }
            }
        });
    }
}

// ============ Main: hook y2.a and dump ============
function main() {
    if (!findSO()) return;

    Java.perform(function() {
        Java.enumerateClassLoaders({
            onMatch: function(loader) {
                try {
                    loader.findClass("ms.bd.c.y2");
                    Java.classFactory.loader = loader;

                    var y2Class = Java.use("ms.bd.c.y2");
                    var HM = Java.use("java.util.HashMap");

                    // Hook y2.a to capture native call
                    y2Class.a.overload('int', 'int', 'long', 'java.lang.String', 'java.lang.Object').implementation = function(tag, type, handle, url, extra) {
                        console.log("\n========== y2.a CALLED ==========");
                        console.log("  tag=0x" + tag.toString(16) + " type=" + type + " handle=" + handle);
                        console.log("  url=" + (url ? url.substring(0, 200) : "null"));

                        // Call original
                        var result = this.a(tag, type, handle, url, extra);

                        if (result !== null && tag === 0x3000001) {
                            try {
                                var resArr = Java.array('java.lang.String',
                                    Java.cast(result, Java.use('[Ljava.lang.String;')));
                                console.log("  result length=" + resArr.length);
                                for (var i = 0; i < resArr.length; i++) {
                                    console.log("  [" + i + "] " + resArr[i]);
                                }
                            } catch(e) {}
                        }
                        return result;
                    };
                    console.log("[+] y2.a hooked");

                    // Now find r4 instance and do a test sign to trigger the hook
                    Java.choose("ms.bd.c.r4", {
                        onMatch: function(inst) {
                            console.log("[+] r4 instance found");

                            // Hook all crypto functions to trace the signing flow
                            hookCryptoForDump();

                            // Do a test sign
                            setTimeout(function() {
                                console.log("\n[*] Starting test sign...");
                                externalCalls = [];

                                var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
                                    "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
                                    "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
                                    "&device_brand=google&os_api=35&os_version=15" +
                                    "&device_id=3722313718058683&iid=3722313718062779" +
                                    "&_rticket=1774940000000" +
                                    "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
                                    "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
                                    "&book_id=7373660003258862617";

                                var h = HM.$new();
                                var r = inst.onCallToAddSecurityFactor(url, h);
                                var m = Java.cast(r, HM);
                                var it = m.keySet().iterator();
                                var sigs = {};
                                while (it.hasNext()) {
                                    var k = it.next();
                                    sigs[k] = m.get(k).toString();
                                }
                                console.log("\n=== SIGNATURES ===");
                                console.log(JSON.stringify(sigs, null, 2));

                                // Dump SO segments
                                dumpSOSegments();

                            }, 1000);
                        },
                        onComplete: function() {}
                    });
                } catch(e) {}
            },
            onComplete: function() {}
        });
    });
}

function hookCryptoForDump() {
    // Hook all known crypto functions to capture full I/O with memory context

    // MD5 (sub_243C34) — capture input buffer addresses
    Interceptor.attach(libBase.add(0x243C34), {
        onEnter: function(args) {
            this.inputPtr = args[0];
            this.inputLen = args[1].toInt32();
            this.outPtr = args[2];
            console.log("\n[MD5] input_ptr=" + args[0] + " len=" + this.inputLen +
                " out_ptr=" + args[2]);
            if (this.inputLen > 0 && this.inputLen < 1024) {
                console.log("  input_hex=" + hex(this.inputPtr, this.inputLen));
            }
            // Dump input memory region info
            console.log("  input_so_off=" + soOffset(this.inputPtr));
            console.log("  out_so_off=" + soOffset(this.outPtr));
        },
        onLeave: function(ret) {
            console.log("  output=" + hex(this.outPtr, 16));
            // Record output address for tracking
            console.log("  out_addr=" + this.outPtr);
        }
    });

    // AES key expansion (sub_241E9C)
    Interceptor.attach(libBase.add(0x241E9C), {
        onEnter: function(args) {
            this.ctxPtr = args[0];
            var keyLen = args[2].toInt32();
            console.log("\n[AES_KEY_EXPAND] ctx=" + args[0] + " key=" + hex(args[1], keyLen) +
                " keylen=" + keyLen);
        }
    });

    // AES block encrypt alt entry (0x242640) — the one actually called
    Interceptor.attach(libBase.add(0x242640), {
        onEnter: function(args) {
            this.inHex = hex(args[1], 16);
            this.outPtr = args[2];
        },
        onLeave: function(ret) {
            console.log("[AES_ECB] in=" + this.inHex + " out=" + hex(this.outPtr, 16));
        }
    });

    // SHA-1 finalize (sub_2450AC)
    Interceptor.attach(libBase.add(0x2450AC), {
        onEnter: function(args) { this.outPtr = args[1]; },
        onLeave: function(ret) {
            try {
                console.log("[SHA1] output=" + hex(this.outPtr, 20));
            } catch(e) {}
        }
    });

    // Hook sub_25BF3C (map_set) — this is where headers are set
    Interceptor.attach(libBase.add(0x25BF3C), {
        onEnter: function(args) {
            try {
                // args might be: map, key_obj, value_obj
                console.log("\n[MAP_SET] args: x0=" + args[0] + " x1=" + args[1] +
                    " x2=" + args[2] + " x3=" + args[3]);
                // Try to read buffer contents from the objects
                // Buffer object: [vtable, ?, ?, len@+0xC, data_ptr@+0x10]
                for (var i = 1; i <= 3; i++) {
                    try {
                        var obj = args[i];
                        var len = obj.add(0xC).readU32();
                        var dataPtr = obj.add(0x10).readPointer();
                        if (len > 0 && len < 4096) {
                            var data = hex(dataPtr, Math.min(len, 128));
                            console.log("  arg" + i + " len=" + len + " data=" + data);
                        }
                    } catch(e) {}
                }
            } catch(e) {}
        }
    });

    // Hook base64 encoder (sub_2456AC) to capture what gets encoded
    Interceptor.attach(libBase.add(0x2456AC), {
        onEnter: function(args) {
            try {
                // base64_encode(input, input_len, output, output_len_ptr)
                var inLen = args[1].toInt32();
                if (inLen > 0 && inLen < 2048) {
                    console.log("\n[BASE64_ENC] input_len=" + inLen);
                    console.log("  input_hex=" + hex(args[0], Math.min(inLen, 200)));
                    console.log("  input_addr=" + args[0] + " so_off=" + soOffset(args[0]));
                }
            } catch(e) {}
        }
    });

    // Hook sub_17B96C (top-level orchestrator) to see full flow
    Interceptor.attach(libBase.add(0x17B96C), {
        onEnter: function(args) {
            console.log("\n[ORCHESTRATOR 0x17B96C] entry");
            console.log("  x0=" + args[0] + " x1=" + args[1] + " x2=" + args[2]);
            // Dump stack
            console.log("  sp=" + this.context.sp);
            console.log("  lr=" + soOffset(this.context.lr));
        },
        onLeave: function(ret) {
            console.log("[ORCHESTRATOR 0x17B96C] return x0=" + ret);
        }
    });

    console.log("[+] All crypto hooks installed for dump");
}

function dumpSOSegments() {
    console.log("\n=== SO MEMORY DUMP INFO ===");

    var mod = Process.findModuleByName("libmetasec_ml.so");
    console.log("Base: " + mod.base);
    console.log("Size: 0x" + mod.size.toString(16));

    // Enumerate memory ranges
    var ranges = mod.enumerateRanges('r--');
    console.log("Ranges: " + ranges.length);
    for (var i = 0; i < ranges.length; i++) {
        var r = ranges[i];
        var off = r.base.sub(mod.base);
        console.log("  [" + i + "] base=" + r.base + " off=0x" + off.toString(16) +
            " size=0x" + r.size.toString(16) + " prot=" + r.protection);
    }

    // Dump the .data/.bss section (global state needed for emulation)
    // Typically after .text in ELF layout
    console.log("\n=== KEY GLOBAL DATA ===");

    // AES S-box tables (from ISSUE.md: qword_93B78, qword_93698, qword_93EF0, qword_94320)
    var sboxOffsets = [0x93698, 0x93B78, 0x93EF0, 0x94320];
    for (var i = 0; i < sboxOffsets.length; i++) {
        var off = sboxOffsets[i];
        console.log("  S-box 0x" + off.toString(16) + ": " + hex(mod.base.add(off), 32) + "...");
    }

    // Base64 table at 0x95C80
    console.log("  Base64 table: " + hex(mod.base.add(0x95C80), 64));

    console.log("\n[DUMP DONE]");
}

main();
