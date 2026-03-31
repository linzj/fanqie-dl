// Dump process memory as binary file + registers as text
// Output: /data/data/com.dragon.read/cache/memdump.bin (binary)
//         console REG: lines (text)
//
// Binary format: [u32 count] then per range: [u64 base][u64 size][raw bytes]
//
// Run: frida -U -p <PID> -l scripts/dump_full_memory.js

var mod = Process.findModuleByName("libmetasec_ml.so");
console.log("SO_BASE=" + mod.base);

var savedRegs = null;
var dumped = false;

Interceptor.attach(mod.base.add(0x258530), {
    onEnter: function() {
        if (savedRegs) return;
        savedRegs = {};
        ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x13','x14','x15','x16','x17',
         'x19','x20','x21','x22','x23','x24','x25','x26','x27','x28','fp','lr','sp'].forEach(function(r) {
            savedRegs[r] = this.context[r].toString();
        }, this);
        console.log("REGS_OK");
    }
});

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
                            var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
                                "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
                                "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
                                "&device_brand=google&os_api=35&os_version=15" +
                                "&device_id=3722313718058683&iid=3722313718062779" +
                                "&_rticket=1774940000000" +
                                "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
                                "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
                                "&book_id=7373660003258862617";
                            console.log("SIGNING...");
                            var r = inst.onCallToAddSecurityFactor(url, HM.$new());
                            var m = Java.cast(r, HM);
                            var it = m.keySet().iterator();
                            while (it.hasNext()) { var k = it.next(); console.log("SIG:" + k + ":" + m.get(k)); }

                            // Print regs
                            for (var k in savedRegs) console.log("REG:" + k + ":" + savedRegs[k]);

                            // Dump memory as binary
                            console.log("DUMPING...");
                            var all = Process.enumerateRangesSync('r--');
                            // Filter: skip huge segments (>16MB) that aren't the SO
                            var ranges = [];
                            for (var i = 0; i < all.length; i++) {
                                if (all[i].size <= 16777216) ranges.push(all[i]);
                                else if (all[i].file && all[i].file.path.indexOf("libmetasec") >= 0) ranges.push(all[i]);
                            }
                            console.log("RANGES=" + ranges.length);

                            var f = new File("/data/data/com.dragon.read/cache/memdump.bin", "wb");
                            // Header
                            var hdr = new ArrayBuffer(4);
                            new DataView(hdr).setUint32(0, ranges.length, true);
                            f.write(hdr);

                            var total = 0;
                            for (var i = 0; i < ranges.length; i++) {
                                var rng = ranges[i];
                                var h = new ArrayBuffer(16);
                                var dv = new DataView(h);
                                var bLo = parseInt(rng.base.and(ptr("0xFFFFFFFF")).toString());
                                var bHi = parseInt(rng.base.shr(32).and(ptr("0xFFFFFFFF")).toString());
                                dv.setUint32(0, bLo, true);
                                dv.setUint32(4, bHi, true);
                                dv.setUint32(8, rng.size, true);
                                dv.setUint32(12, 0, true);
                                f.write(h);

                                for (var off = 0; off < rng.size; off += 1048576) {
                                    var sz = Math.min(1048576, rng.size - off);
                                    try { f.write(rng.base.add(off).readByteArray(sz)); }
                                    catch(e) { f.write(new ArrayBuffer(sz)); }
                                }
                                total += rng.size;
                                if ((i+1) % 100 === 0) console.log("P:" + (i+1) + "/" + ranges.length);
                            }
                            f.close();
                            console.log("DONE:" + (total/1048576).toFixed(0) + "MB:" + ranges.length + "ranges");
                        },
                        onComplete: function() {}
                    });
                } catch(e) {}
            },
            onComplete: function() {}
        });
    });
}, 3000);
