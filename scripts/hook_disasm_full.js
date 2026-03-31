// Disassemble key signing functions and dump for offline analysis
// Focus on: the signing function area (0x285xxx-0x289xxx) and
// the Medusa construction area (0x259xxx-0x264xxx)
//
// Also: trace CFF switch dispatcher by hooking basic block transitions
//
// Run: frida -U -p <PID> -l scripts/hook_disasm_full.js

var mod = Process.findModuleByName("libmetasec_ml.so");
if (!mod) { console.log("[!] SO not found"); }
var base = mod.base;

function disasmRange(startOff, endOff, label) {
    console.log("\n=== " + label + " (0x" + startOff.toString(16) + " - 0x" + endOff.toString(16) + ") ===");
    var addr = base.add(startOff);
    var end = base.add(endOff);
    var count = 0;
    while (addr.compare(end) < 0) {
        try {
            var instr = Instruction.parse(addr);
            var off = addr.sub(base).toInt32();
            // Mark known functions
            var label = "";
            switch(off) {
                case 0x241E9C: label = " ; AES_KEY_EXPAND"; break;
                case 0x2422EC: label = " ; AES_BLOCK_ENC"; break;
                case 0x2429F8: label = " ; AES_KEYGEN_ENC"; break;
                case 0x242A70: label = " ; AES_CBC"; break;
                case 0x242C98: label = " ; AES_CTR"; break;
                case 0x242DE0: label = " ; XOR_FUNC"; break;
                case 0x243C34: label = " ; MD5"; break;
                case 0x243E50: label = " ; SHA1_UPDATE"; break;
                case 0x243F10: label = " ; SHA1_TRANSFORM"; break;
                case 0x2450AC: label = " ; SHA1_FINALIZE"; break;
                case 0x2451FC: label = " ; SHA1_FULL"; break;
                case 0x248344: label = " ; BUF_OP"; break;
                case 0x2481FC: label = " ; CREATE_BUF"; break;
                case 0x258530: label = " ; MD5_WRAPPER"; break;
                case 0x258780: label = " ; SHA1_WRAPPER"; break;
                case 0x259C1C: label = " ; AES_MODE_SETUP"; break;
                case 0x259CF0: label = " ; AES_DISPATCH"; break;
                case 0x259DBC: label = " ; AES_SETUP"; break;
                case 0x25BF3C: label = " ; MAP_SET"; break;
                case 0x270020: label = " ; INIT_270020"; break;
                case 0x32A1F0: label = " ; MALLOC"; break;
            }
            console.log("0x" + off.toString(16) + ": " + instr.mnemonic + " " + instr.opStr + label);
            addr = addr.add(instr.size);
            count++;
        } catch(e) {
            var off = addr.sub(base).toInt32();
            console.log("0x" + off.toString(16) + ": .word 0x" + addr.readU32().toString(16));
            addr = addr.add(4);
            count++;
        }
    }
    console.log("; " + count + " instructions");
}

// Key areas to disassemble:

// 1. AES setup + dispatch area (where Medusa encryption should happen)
disasmRange(0x259DBC, 0x25A900, "AES_SETUP sub_259DBC + nearby");

// 2. The function at 0x263000-0x263600 (calls AES key, SHA-1, buffer ops)
disasmRange(0x2630A0, 0x263600, "MEDUSA_CRYPTO sub_263xxx");

// 3. Signing main function area - around thunks
//    0x286b58 contains MD5(URL) call, 0x288bbc contains MD5(R+1967)
disasmRange(0x2878E0, 0x287C00, "SIGNING_MEDUSA_BUILD 0x2878E0");

// 4. The area around 0x261400-0x261800 (seen in trace, calls malloc)
disasmRange(0x261400, 0x261800, "FUNC_0x261400");

console.log("\n[DONE]");
