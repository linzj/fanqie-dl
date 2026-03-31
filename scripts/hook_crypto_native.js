// Hook native crypto functions in libmetasec_ml.so to reverse X-Helios and X-Medusa
// Run: frida -U -p <PID> -l scripts/hook_crypto_native.js
//
// This hooks SHA-256, AES key expansion, and AES block encrypt at the native level
// to capture all crypto operations during signature generation.
// Then triggers a signing call and dumps all observed crypto operations.

var libBase = null;
var cryptoLog = [];
var capturing = false;

function hexdump(ptr, len) {
    var bytes = [];
    for (var i = 0; i < len; i++) {
        bytes.push(('0' + ptr.add(i).readU8().toString(16)).slice(-2));
    }
    return bytes.join('');
}

function setupNativeHooks() {
    var mod = Process.findModuleByName("libmetasec_ml.so");
    if (!mod) {
        console.log("[!] libmetasec_ml.so not found");
        return;
    }
    libBase = mod.base;
    console.log("[+] libmetasec_ml.so @ " + libBase + " size=" + mod.size);

    // ========== Hook SHA-256 full hash: sub_245630 ==========
    // void sub_245630(void* data, uint32_t len, uint8_t out[32])
    var sha256_full = libBase.add(0x245630);
    Interceptor.attach(sha256_full, {
        onEnter: function(args) {
            this.data = args[0];
            this.len = args[1].toInt32();
            this.out = args[2];
            if (capturing) {
                var input = hexdump(this.data, Math.min(this.len, 512));
                cryptoLog.push({
                    op: "SHA256",
                    phase: "enter",
                    len: this.len,
                    input: input,
                    caller: Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n    ')
                });
            }
        },
        onLeave: function(ret) {
            if (capturing) {
                var output = hexdump(this.out, 32);
                cryptoLog.push({
                    op: "SHA256",
                    phase: "leave",
                    len: this.len,
                    output: output
                });
            }
        }
    });
    console.log("[+] SHA-256 (sub_245630) hooked");

    // ========== Hook SHA-256 wrapper: sub_258A48 ==========
    // This is the wrapper that extracts data/len from a struct
    var sha256_wrap = libBase.add(0x258A48);
    Interceptor.attach(sha256_wrap, {
        onEnter: function(args) {
            if (capturing) {
                var a1 = args[0];
                var len = a1.add(12).readU32();
                var dataPtr = a1.add(16).readPointer();
                var input = hexdump(dataPtr, Math.min(len, 512));
                cryptoLog.push({
                    op: "SHA256_WRAP",
                    phase: "enter",
                    len: len,
                    input: input
                });
            }
        }
    });
    console.log("[+] SHA-256 wrapper (sub_258A48) hooked");

    // ========== Hook SHA-1 wrapper: sub_258780 ==========
    var sha1_wrap = libBase.add(0x258780);
    Interceptor.attach(sha1_wrap, {
        onEnter: function(args) {
            if (capturing) {
                var a1 = args[0];
                var len = a1.add(12).readU32();
                var dataPtr = a1.add(16).readPointer();
                var input = hexdump(dataPtr, Math.min(len, 512));
                cryptoLog.push({
                    op: "SHA1_WRAP",
                    phase: "enter",
                    len: len,
                    input: input
                });
            }
        }
    });
    console.log("[+] SHA-1 wrapper (sub_258780) hooked");

    // ========== Hook AES key expansion: sub_241E9C ==========
    // sub_241E9C(ctx, key, key_len_bytes)
    var aes_keyexp = libBase.add(0x241E9C);
    Interceptor.attach(aes_keyexp, {
        onEnter: function(args) {
            if (capturing) {
                var key = args[1];
                var keyLen = args[2].toInt32();
                cryptoLog.push({
                    op: "AES_KEY_EXPAND",
                    keyLen: keyLen,
                    key: hexdump(key, keyLen)
                });
            }
        }
    });
    console.log("[+] AES key expansion (sub_241E9C) hooked");

    // ========== Hook AES block encrypt: sub_243F10 ==========
    var aes_enc = libBase.add(0x243F10);
    var aes_count = 0;
    Interceptor.attach(aes_enc, {
        onEnter: function(args) {
            if (capturing) {
                aes_count++;
                if (aes_count <= 10) {
                    // Only log first 10 AES block encrypts to avoid spam
                    cryptoLog.push({
                        op: "AES_BLOCK_ENC",
                        count: aes_count
                    });
                }
            }
        }
    });
    console.log("[+] AES block encrypt (sub_243F10) hooked");

    // ========== Hook MD5: sub_243C34 ==========
    var md5_func = libBase.add(0x243C34);
    Interceptor.attach(md5_func, {
        onEnter: function(args) {
            if (capturing) {
                cryptoLog.push({
                    op: "MD5",
                    phase: "enter"
                });
            }
        }
    });
    console.log("[+] MD5 (sub_243C34) hooked");

    // ========== Hook XOR string decrypt: sub_167E54 ==========
    var xor_decrypt = libBase.add(0x167E54);
    Interceptor.attach(xor_decrypt, {
        onEnter: function(args) {
            this.enc = args[0];
            this.out = args[1];
            this.key = args[2];
        },
        onLeave: function(ret) {
            if (capturing) {
                // Try to read the decrypted output as a C string
                try {
                    var str = this.out.readCString();
                    if (str && str.length > 0 && str.length < 200) {
                        cryptoLog.push({
                            op: "XOR_DECRYPT",
                            result: str
                        });
                    }
                } catch(e) {}
            }
        }
    });
    console.log("[+] XOR decrypt (sub_167E54) hooked");

    // ========== Hook the signing function sub_283748 ==========
    var sign_func = libBase.add(0x283748);
    Interceptor.attach(sign_func, {
        onEnter: function(args) {
            if (capturing) {
                cryptoLog.push({ op: "SIGN_FUNC_283748", phase: "enter" });
            }
        },
        onLeave: function(ret) {
            if (capturing) {
                cryptoLog.push({ op: "SIGN_FUNC_283748", phase: "leave" });
            }
        }
    });
    console.log("[+] Sign function (sub_283748) hooked");

    // ========== Hook the signing orchestrator sub_29CCD4 ==========
    var sign_orch = libBase.add(0x29CCD4);
    Interceptor.attach(sign_orch, {
        onEnter: function(args) {
            if (capturing) {
                cryptoLog.push({ op: "SIGN_ORCH_29CCD4", phase: "enter" });
            }
        },
        onLeave: function(ret) {
            if (capturing) {
                cryptoLog.push({ op: "SIGN_ORCH_29CCD4", phase: "leave" });
            }
        }
    });
    console.log("[+] Sign orchestrator (sub_29CCD4) hooked");
}

// ========== Trigger a signing call and capture crypto operations ==========
function captureSigningCrypto() {
    Java.perform(function() {
        Java.enumerateClassLoaders({
            onMatch: function(loader) {
                try {
                    loader.findClass("ms.bd.c.r4");
                    Java.classFactory.loader = loader;
                    var HM = Java.use("java.util.HashMap");

                    Java.choose("ms.bd.c.r4", {
                        onMatch: function(inst) {
                            var tsMs = Date.now();
                            var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
                                "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
                                "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
                                "&device_brand=google&os_api=35&os_version=15" +
                                "&device_id=3722313718058683&iid=3722313718062779" +
                                "&_rticket=" + tsMs +
                                "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
                                "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
                                "&book_id=7373660003258862617";

                            console.log("\n[*] Triggering signing call...");
                            console.log("[*] URL: " + url.substring(0, 120) + "...\n");

                            // Start capturing
                            cryptoLog = [];
                            capturing = true;

                            var headers = HM.$new();
                            var result = inst.onCallToAddSecurityFactor(url, headers);

                            // Stop capturing
                            capturing = false;

                            // Print results
                            var map = Java.cast(result, HM);
                            console.log("\n======== SIGNATURES ========");
                            var it = map.keySet().iterator();
                            while (it.hasNext()) {
                                var key = it.next();
                                var val = map.get(key).toString();
                                if (val.length > 80) val = val.substring(0, 80) + "...(" + map.get(key).toString().length + ")";
                                console.log("  " + key + " = " + val);
                            }

                            console.log("\n======== CRYPTO OPERATIONS (" + cryptoLog.length + " total) ========");
                            for (var i = 0; i < cryptoLog.length; i++) {
                                var entry = cryptoLog[i];
                                var line = "[" + i + "] " + entry.op;
                                if (entry.phase) line += " (" + entry.phase + ")";
                                if (entry.len !== undefined) line += " len=" + entry.len;
                                if (entry.keyLen !== undefined) line += " keyLen=" + entry.keyLen;
                                if (entry.key) line += " key=" + entry.key;
                                if (entry.input) line += "\n      input=" + entry.input;
                                if (entry.output) line += "\n      output=" + entry.output;
                                if (entry.result) line += " str=\"" + entry.result + "\"";
                                if (entry.count) line += " #" + entry.count;
                                if (entry.caller) line += "\n      caller:\n    " + entry.caller;
                                console.log(line);
                            }

                            console.log("\n======== SUMMARY ========");
                            var ops = {};
                            for (var i = 0; i < cryptoLog.length; i++) {
                                var op = cryptoLog[i].op;
                                ops[op] = (ops[op] || 0) + 1;
                            }
                            for (var op in ops) {
                                console.log("  " + op + ": " + ops[op] + "x");
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
}

// ========== Setup ==========
setupNativeHooks();

// Wait a bit for hooks to settle, then capture
setTimeout(function() {
    captureSigningCrypto();
}, 2000);
