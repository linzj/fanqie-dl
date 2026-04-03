/**
 * capture_medusa.js — 捕获完整 Medusa 输出 + 所有中间 crypto 值
 * 用法: frida -U -p PID -l scripts/capture_medusa.js
 */
'use strict';

var mod = Process.findModuleByName('libmetasec_ml.so');
if (!mod) { console.log('[!] SO not loaded'); }
else {
    var base = mod.base;
    console.log('[*] SO base: ' + base);

    function toHex(buf) {
        var arr = new Uint8Array(buf);
        var s = '';
        for (var i = 0; i < arr.length; i++) {
            s += ('0' + arr[i].toString(16)).slice(-2);
        }
        return s;
    }

    // Hook y2.a via Java to capture the complete output
    Java.perform(function() {
        Java.enumerateClassLoaders({
            onMatch: function(loader) {
                try { loader.findClass("ms.bd.c.r4"); } catch(e) { return; }
                Java.classFactory.loader = loader;

                var HM = Java.use("java.util.HashMap");
                var BA = Java.use("[B");  // byte[]

                // Do 3 samples with same URL
                for (var sample = 0; sample < 3; sample++) {
                    Java.choose("ms.bd.c.r4", {
                        onMatch: function(inst) {
                            var ts = Date.now();
                            var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
                                "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
                                "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
                                "&device_brand=google&os_api=35&os_version=15" +
                                "&device_id=3722313718058683&iid=3722313718062779" +
                                "&_rticket=" + ts +
                                "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
                                "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
                                "&book_id=7373660003258862617";

                            var h = HM.$new();
                            var r = inst.onCallToAddSecurityFactor(url, h);
                            var m = Java.cast(r, HM);

                            console.log('\n=== SAMPLE ' + sample + ' ts=' + ts + ' ===');
                            console.log('URL=' + url);

                            var it = m.keySet().iterator();
                            while (it.hasNext()) {
                                var k = it.next();
                                var v = m.get(k).toString();
                                console.log(k + '=' + v);

                                // Decode X-Medusa base64
                                if (k === 'X-Medusa') {
                                    try {
                                        var B64 = Java.use('android.util.Base64');
                                        var decoded = B64.decode(v, 0);
                                        var jba = Java.cast(decoded, BA);
                                        var hex = '';
                                        for (var i = 0; i < jba.length; i++) {
                                            var b = jba[i] & 0xff;
                                            hex += ('0' + b.toString(16)).slice(-2);
                                        }
                                        console.log('X-Medusa-hex=' + hex);
                                        console.log('X-Medusa-len=' + jba.length);
                                    } catch(e) {
                                        console.log('decode error: ' + e);
                                    }
                                }
                                if (k === 'X-Helios') {
                                    try {
                                        var B64 = Java.use('android.util.Base64');
                                        var decoded = B64.decode(v, 0);
                                        var jba = Java.cast(decoded, BA);
                                        var hex = '';
                                        for (var i = 0; i < jba.length; i++) {
                                            var b = jba[i] & 0xff;
                                            hex += ('0' + b.toString(16)).slice(-2);
                                        }
                                        console.log('X-Helios-hex=' + hex);
                                    } catch(e) {}
                                }
                            }
                        },
                        onComplete: function() {}
                    });
                }
                console.log('\n[*] All samples captured');
            },
            onComplete: function() {}
        });
    });
}
