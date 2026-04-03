/**
 * dump_handle.js — Hook JNI 入口拿到 handle 地址，递归 dump handle 及其指针链
 */
'use strict';

var mod = Process.findModuleByName('libmetasec_ml.so');
var base = mod.base;
console.log('SO_BASE=' + base);

var tpidrCode = Memory.alloc(Process.pageSize);
Memory.protect(tpidrCode, Process.pageSize, 'rwx');
tpidrCode.writeU32(0xd53bd040);
tpidrCode.add(4).writeU32(0xd65f03c0);
var readTpidr = new NativeFunction(tpidrCode, 'pointer', []);

function toHex(arr) {
    var b = new Uint8Array(arr);
    var h = '';
    for (var i = 0; i < b.length; i++) h += ('0' + b[i].toString(16)).slice(-2);
    return h;
}

function safeRead(addr, size) {
    try { return addr.readByteArray(size); } catch (e) { return null; }
}

// 递归 dump: 读一块内存，找里面的指针，继续读
var dumped = {};  // addr -> true, 防止循环
var dumpOutput = [];

function dumpRegion(label, addr, size, depth) {
    if (depth > 3) return;  // 最多 3 层
    var key = addr.toString();
    if (dumped[key]) return;
    dumped[key] = true;

    var data = safeRead(addr, size);
    if (!data) {
        console.log(label + '=' + addr + ':UNREADABLE');
        return;
    }

    console.log(label + '=' + addr + ':' + toHex(data));

    // 在数据中找指针（每 8 字节对齐），递归读取
    var bytes = new Uint8Array(data);
    for (var off = 0; off < size - 7; off += 8) {
        // 读 little-endian u64
        var lo = bytes[off] | (bytes[off+1] << 8) | (bytes[off+2] << 16) | (bytes[off+3] << 24);
        var hi = bytes[off+4] | (bytes[off+5] << 8) | (bytes[off+6] << 16) | (bytes[off+7] << 24);
        // 组合为 Number (精度够用到 2^53)
        var val = (hi >>> 0) * 0x100000000 + (lo >>> 0);

        // 看起来像指针: 0x7a... 到 0x7f... 范围
        if (val > 0x7a00000000 && val < 0x800000000000 && val !== 0) {
            var p = ptr('0x' + val.toString(16));
            var pKey = p.toString();
            if (!dumped[pKey]) {
                dumpRegion(label + '+0x' + off.toString(16), p, 256, depth + 1);
            }
        }
    }
}

var jniEntry = base.add(0x26e684);
var handleDumped = false;

Interceptor.attach(jniEntry, {
    onEnter: function (args) {
        var tag = args[2].toInt32();
        var handle = args[4];

        if (tag === 0x3000001 && !handle.isNull() && !handleDumped) {
            handleDumped = true;
            console.log('\n=== HANDLE DUMP ===');
            console.log('SIGN_TID=' + Process.getCurrentThreadId());
            console.log('TPIDR=' + readTpidr());
            console.log('HANDLE_ADDR=' + handle);

            // handle 是 ~4KB 对象，先读 4096 bytes
            console.log('\n--- handle raw (4KB) ---');
            dumpRegion('HANDLE', handle, 4096, 0);

            // 也读 handle 附近的条目（每 0x40 一组）
            console.log('\n--- handle entries ---');
            for (var i = 0; i < 64; i++) {
                var entryAddr = handle.add(i * 0x40);
                var entryData = safeRead(entryAddr, 0x40);
                if (!entryData) break;

                var bytes = new Uint8Array(entryData);
                var allZero = true;
                for (var j = 0; j < bytes.length; j++) {
                    if (bytes[j] !== 0) { allZero = false; break; }
                }
                if (allZero) continue;

                console.log('ENTRY[' + i + ']=' + entryAddr + ':' + toHex(entryData));

                // 读 entry 内的指针目标
                for (var off = 0; off < 0x40; off += 8) {
                    try {
                        var p = entryAddr.add(off).readPointer();
                        var pVal = parseInt(p.toString().replace('0x', ''), 16);
                        if (pVal > 0x7a00000000 && pVal < 0x800000000000) {
                            var target = safeRead(p, 256);
                            if (target) {
                                console.log('  +0x' + off.toString(16) + '->' + p + ':' + toHex(target));
                            }
                        }
                    } catch (e) {}
                }
            }

            console.log('\n=== HANDLE DUMP DONE ===');
        }
    }
});

// 触发签名
Java.perform(function () {
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try { loader.findClass('ms.bd.c.r4'); } catch (e) { return; }
            Java.classFactory.loader = loader;
            var HM = Java.use('java.util.HashMap');
            Java.choose('ms.bd.c.r4', {
                onMatch: function (inst) {
                    inst.onCallToAddSecurityFactor(
                        'https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?aid=1967&device_id=3722313718058683&_rticket=' + Date.now() + '&book_id=7373660003258862617',
                        HM.$new());
                    console.log('SIGN_DONE');
                },
                onComplete: function () {}
            });
        },
        onComplete: function () {}
    });
});
