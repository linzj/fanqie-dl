// Dump the entire SO from memory (with GOT resolved) to device file
// Then pull with adb
//
// Run: frida -U -p <PID> -l scripts/dump_so_memory.js

var mod = Process.findModuleByName("libmetasec_ml.so");
console.log("[+] base=" + mod.base + " size=0x" + mod.size.toString(16));

// Dump entire SO image from memory
// Write to a temp file accessible by adb pull
var path = "/data/data/com.dragon.read/cache/so_memdump.bin";
var f = new File(path, "wb");
var chunkSize = 65536;
for (var off = 0; off < mod.size; off += chunkSize) {
    var sz = Math.min(chunkSize, mod.size - off);
    try {
        var data = mod.base.add(off).readByteArray(sz);
        f.write(data);
    } catch(e) {
        // Unreadable, write zeros
        f.write(new ArrayBuffer(sz));
        console.log("[!] Unreadable at off=0x" + off.toString(16));
    }
}
f.close();
console.log("[+] Dumped " + mod.size + " bytes to " + path);

// Also dump GOT entries for analysis
// .got is typically in the rw- section
// Let's find all PLT stubs that jump to GOT entries
console.log("\n=== PLT/GOT ANALYSIS ===");
// The SO has no standard exports except JNI_OnLoad
// Let's scan for BL instructions in the first few bytes of known functions
// to find PLT trampolines

// Check what's at 0x243C34 (MD5 entry)
var md5Entry = mod.base.add(0x243C34);
var instr1 = Instruction.parse(md5Entry);
var instr2 = Instruction.parse(md5Entry.add(instr1.size));
console.log("MD5[0]: " + instr1.mnemonic + " " + instr1.opStr);
console.log("MD5[1]: " + instr2.mnemonic + " " + instr2.opStr);

// Disassemble a few more
var addr = md5Entry;
for (var i = 0; i < 10; i++) {
    var instr = Instruction.parse(addr);
    var off = addr.sub(mod.base).toInt32();
    console.log("0x" + off.toString(16) + ": " + instr.mnemonic + " " + instr.opStr);
    addr = addr.add(instr.size);
}

// Find what sub_32A1F0 (malloc wrapper) does
console.log("\n=== MALLOC WRAPPER 0x32A1F0 ===");
addr = mod.base.add(0x32A1F0);
for (var i = 0; i < 10; i++) {
    var instr = Instruction.parse(addr);
    var off = addr.sub(mod.base).toInt32();
    console.log("0x" + off.toString(16) + ": " + instr.mnemonic + " " + instr.opStr);
    addr = addr.add(instr.size);
}

// Scan for external function pointers in GOT
// GOT is typically at the end of the data segment
console.log("\n=== EXTERNAL REFS (scanning GOT area 0x379000-0x3D2000) ===");
var extRefs = {};
var gotStart = 0x379000;
var gotEnd = 0x3D2000;
for (var off = gotStart; off < gotEnd; off += 8) {
    try {
        var val = mod.base.add(off).readU64();
        // Check if it points outside the SO
        if (val > 0x1000 && (val < mod.base.toInt32() || val > mod.base.add(mod.size).toInt32())) {
            // Try to find what module this belongs to
            try {
                var targetMod = Process.findModuleByAddress(ptr(val.toString()));
                if (targetMod) {
                    var targetOff = ptr(val.toString()).sub(targetMod.base);
                    var key = targetMod.name;
                    if (!extRefs[key]) extRefs[key] = [];
                    if (extRefs[key].length < 10) {
                        extRefs[key].push("GOT+0x" + off.toString(16) + " → " + targetMod.name + "+0x" + targetOff.toString(16));
                    }
                }
            } catch(e) {}
        }
    } catch(e) {}
}
for (var k in extRefs) {
    console.log("\n" + k + " (" + extRefs[k].length + " refs):");
    for (var i = 0; i < extRefs[k].length; i++) {
        console.log("  " + extRefs[k][i]);
    }
}

console.log("\n[DONE]");
