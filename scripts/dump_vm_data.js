/**
 * dump_vm_data.js — 一次性 dump Medusa VM 所需的所有数据表
 *
 * 用法: frida -f com.dragon.read -l scripts/dump_vm_data.js
 *
 * 做什么:
 * 1. 等待 SO 加载
 * 2. 读取 off_37A6D0 和 off_37A730 数据表（各 12 个指针）
 * 3. 跟随每个指针 dump 目标内存 (256 bytes each)
 * 4. 输出 hex 数据供 emulator 使用
 */

'use strict';

function waitForModule(name) {
    return new Promise(resolve => {
        const check = () => {
            const m = Module.findBaseAddress(name);
            if (m) resolve(m);
            else setTimeout(check, 100);
        };
        check();
    });
}

async function main() {
    const soName = 'libmetasec_ml.so';
    console.log('[*] Waiting for ' + soName + '...');
    const base = await waitForModule(soName);
    console.log('[*] SO base: ' + base);

    // Wait a bit for initialization
    await new Promise(r => setTimeout(r, 3000));

    // Data table offsets (from IDA analysis)
    const TABLE_A_OFF = 0x37A6D0; // off_37A6D0: 12 pointers
    const TABLE_B_OFF = 0x37A730; // off_37A730: 12 pointers

    const NUM_ENTRIES_A = 12;
    const NUM_ENTRIES_B = 12;
    const DUMP_SIZE = 256; // bytes to dump at each pointer target

    function dumpTable(name, offset, count) {
        const tableAddr = base.add(offset);
        console.log('\n=== ' + name + ' at ' + tableAddr + ' (SO+' + offset.toString(16) + ') ===');

        const ptrs = [];
        for (let i = 0; i < count; i++) {
            const ptr = tableAddr.add(i * 8).readPointer();
            ptrs.push(ptr);
            console.log('  [' + i + '] ' + ptr);
        }

        // Dump each target
        for (let i = 0; i < count; i++) {
            const ptr = ptrs[i];
            if (ptr.isNull()) {
                console.log('\nENTRY_' + name + '_' + i + ': NULL');
                continue;
            }
            try {
                const data = ptr.readByteArray(DUMP_SIZE);
                const hex = Array.from(new Uint8Array(data))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
                console.log('\nENTRY_' + name + '_' + i + '_ADDR=' + ptr);
                console.log('ENTRY_' + name + '_' + i + '_DATA=' + hex);
            } catch (e) {
                console.log('\nENTRY_' + name + '_' + i + ': READ ERROR at ' + ptr + ': ' + e);
            }
        }

        // Also dump the table itself as raw bytes
        const tableData = tableAddr.readByteArray(count * 8);
        const tableHex = Array.from(new Uint8Array(tableData))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
        console.log('\nTABLE_' + name + '_RAW=' + tableHex);
    }

    // Also dump the dispatch table pointer value
    const dispatchPtrOff = 0x3798D8;
    const dispatchPtr = base.add(dispatchPtrOff).readPointer();
    console.log('\n=== Dispatch table ===');
    console.log('DISPATCH_PTR=' + dispatchPtr + ' (at SO+' + dispatchPtrOff.toString(16) + ')');

    // Dump data tables
    dumpTable('A', TABLE_A_OFF, NUM_ENTRIES_A);
    dumpTable('B', TABLE_B_OFF, NUM_ENTRIES_B);

    // Also dump the bytecodes (verify they match)
    const bc1 = base.add(0x118F50).readByteArray(256);
    const bc2 = base.add(0x119050).readByteArray(256);
    console.log('\nBYTECODE_HELIOS=' + Array.from(new Uint8Array(bc1)).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('BYTECODE_MEDUSA=' + Array.from(new Uint8Array(bc2)).map(b => b.toString(16).padStart(2, '0')).join(''));

    console.log('\n[*] Done! Copy the output above.');
    console.log('[*] Lines starting with ENTRY_, TABLE_, BYTECODE_, DISPATCH_ are the data needed.');
}

main().catch(e => console.error('[!] Error:', e));
