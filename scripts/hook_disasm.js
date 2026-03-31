// Disassemble code around the MD5 call sites to understand data flow
// Run: frida -U -p <PID> -l scripts/hook_disasm.js

var mod = Process.findModuleByName("libmetasec_ml.so");
if (!mod) { console.log("[!] SO not found"); }
var base = mod.base;

function disasm(offset, count) {
    console.log("\n=== Disassembly at 0x" + offset.toString(16) + " (" + count + " instructions) ===");
    var addr = base.add(offset);
    for (var i = 0; i < count; i++) {
        try {
            var instr = Instruction.parse(addr);
            var off = addr.sub(base).toInt32();
            console.log("  0x" + off.toString(16) + ": " + instr.mnemonic + " " + instr.opStr);
            addr = addr.add(instr.size);
        } catch(e) {
            console.log("  0x" + addr.sub(base).toInt32().toString(16) + ": <parse error>");
            addr = addr.add(4);
        }
    }
}

// The MD5 wrapper at 0x258530 — disassemble the full function
console.log("=== MD5 wrapper function (0x258530) ===");
disasm(0x258530, 80);

// 0x288bd4 — caller that computes MD5 of (random + "1967")
// This is the return address AFTER calling MD5_wrapper
// So the instruction at 0x288bd4 is right after the BL to 0x258530
// Let's disassemble from 0x288bd4 onwards to see what happens with H1
console.log("\n=== After MD5(random+aid) call at 0x288bd4 ===");
disasm(0x288bd4, 60);

// 0x286df8 — caller that computes MD5 of url params
console.log("\n=== After MD5(url_params) call at 0x286df8 ===");
disasm(0x286df8, 40);

// 0x2887e8 — caller for UUID and constants
console.log("\n=== After MD5(uuid/constants) call at 0x2887e8 ===");
disasm(0x2887e8, 40);

console.log("\n[DONE]");
