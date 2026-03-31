// Dump ALL GOT entries with resolution info
// Run: frida -U -p <PID> -l scripts/dump_got_full.js

var mod = Process.findModuleByName("libmetasec_ml.so");
var base = mod.base;
var size = mod.size;
console.log("BASE=" + base + " SIZE=0x" + size.toString(16));

// Scan all rw- segments for pointers
// GOT entries are 8-byte pointers that either point inside the SO or to external modules
var rwStart = 0x379000;
var rwEnd = rwStart + 0x59000;

console.log("\n=== ALL GOT/DATA POINTERS ===");
for (var off = rwStart; off < rwEnd; off += 8) {
    try {
        var val = base.add(off).readPointer();
        var valN = val;

        // Check if it points somewhere meaningful
        if (val.compare(ptr("0x1000")) > 0) {
            var targetMod = null;
            try { targetMod = Process.findModuleByAddress(val); } catch(e) {}

            if (targetMod) {
                var targetOff = val.sub(targetMod.base);
                if (targetMod.name === "libmetasec_ml.so") {
                    console.log("GOT:0x" + off.toString(16) + ":SELF:0x" + targetOff.toString(16));
                } else {
                    // Try to find export name
                    var name = "";
                    try { name = DebugSymbol.fromAddress(val).name || ""; } catch(e) {}
                    console.log("GOT:0x" + off.toString(16) + ":EXT:" + targetMod.name + ":0x" + targetOff.toString(16) + ":" + name);
                }
            }
        }
    } catch(e) {}
}

console.log("\n[DONE]");
