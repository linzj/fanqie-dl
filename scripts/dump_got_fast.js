// Fast GOT dump: only external refs + MD5 PLT resolution
var mod = Process.findModuleByName("libmetasec_ml.so");
var base = mod.base;
console.log("BASE=" + base);

// 1. What does the MD5 PLT stub (0x243C34) actually point to?
var gotAddr = base.add(0x243C3C); // from "ldr x16, #0x7624045c3c" which is PC+offset
// Actually the instruction is: ldr x16, [literal_addr]
// Let me compute: PC=base+0x243C34, offset is encoded in instruction
var instrBytes = base.add(0x243C34).readByteArray(4);
var instrWord = new Uint32Array(instrBytes)[0];
// LDR (literal) encoding: imm19 = bits[23:5], offset = imm19 << 2
var imm19 = (instrWord >> 5) & 0x7FFFF;
if (imm19 & 0x40000) imm19 = imm19 - 0x80000; // sign extend
var litOffset = imm19 * 4;
var gotEntry = base.add(0x243C34 + litOffset);
var gotOff = gotEntry.sub(base);
var target = gotEntry.readPointer();
var targetOff = target.sub(base);
console.log("MD5 PLT: GOT@0x" + gotOff.toString(16) + " → 0x" + targetOff.toString(16));

// 2. Scan all PLT stubs (they have pattern: ldr x16, [literal]; br x16)
// PLT section is around 0x241000-0x246000
console.log("\n=== PLT STUBS ===");
for (var off = 0x241000; off < 0x246000; off += 8) {
    try {
        var i1 = base.add(off).readU32();
        var i2 = base.add(off + 4).readU32();
        // ldr x16, #imm = 0x58000010 | (imm19 << 5)
        // br x16 = 0xD61F0200
        if ((i1 & 0xFF00001F) === 0x58000010 && i2 === 0xD61F0200) {
            var imm = ((i1 >> 5) & 0x7FFFF);
            if (imm & 0x40000) imm = imm - 0x80000;
            var litAddr = base.add(off + imm * 4);
            var tgt = litAddr.readPointer();
            var tgtOff = null;
            var extName = "";
            try {
                tgtOff = tgt.sub(base);
                if (tgtOff.toInt32() >= 0 && tgtOff.toInt32() < mod.size) {
                    console.log("PLT:0x" + off.toString(16) + ":SELF:0x" + tgtOff.toString(16));
                } else {
                    throw "external";
                }
            } catch(e) {
                try { extName = DebugSymbol.fromAddress(tgt).name || ""; } catch(e2) {}
                var extMod = null;
                try { extMod = Process.findModuleByAddress(tgt); } catch(e2) {}
                var extInfo = extMod ? extMod.name : "unknown";
                console.log("PLT:0x" + off.toString(16) + ":EXT:" + extInfo + ":" + tgt + ":" + extName);
            }
        }
    } catch(e) {}
}

console.log("\n[DONE]");
