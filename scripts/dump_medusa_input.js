/**
 * dump_medusa_input.js — 签名时记录所有 VM 调用的完整输入
 * 输出: TPIDR, 每个 VM call 的 args/TABLE_A/TABLE_B/packed/callback, X-Medusa 结果
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

function dumpPtr(label, addr, size) {
    if (addr.isNull()) { console.log(label + '=NULL'); return; }
    var d = safeRead(addr, size);
    if (d) {
        console.log(label + '=' + addr + ':' + toHex(d));
    } else {
        console.log(label + '=' + addr + ':UNREADABLE');
    }
}

function followPtrs(label, base_addr, count, dataSize) {
    for (var i = 0; i < count; i++) {
        try {
            var p = base_addr.add(i * 8).readPointer();
            if (p.isNull()) { console.log(label + '[' + i + ']=NULL'); continue; }
            var d = safeRead(p, dataSize);
            if (d) {
                console.log(label + '[' + i + ']=' + p + ':' + toHex(d));
            } else {
                console.log(label + '[' + i + ']=' + p + ':UNREADABLE');
            }
        } catch (e) {
            console.log(label + '[' + i + ']=ERR');
        }
    }
}

var vmEntry = base.add(0x168324);
var callNum = 0;

Interceptor.attach(vmEntry, {
    onEnter: function (args) {
        callNum++;
        var bcOff = (args[0].sub(base).toInt32() >>> 0);
        console.log('\n--- VM_CALL ' + callNum + ' bc=SO+0x' + bcOff.toString(16) + ' ---');

        if (callNum === 1) {
            console.log('SIGN_TID=' + Process.getCurrentThreadId());
            console.log('TPIDR=' + readTpidr());
        }

        // args
        console.log('X0=' + args[0] + ' X1=' + args[1] + ' X2=' + args[2] + ' X3=' + args[3] + ' X4=' + args[4]);

        // packed_args (X1): 48 bytes + follow 6 pointers (256B each)
        dumpPtr('PACKED', args[1], 48);
        followPtrs('PACKED_PTR', args[1], 6, 256);

        // TABLE_A (X2): 12 pointers, read 512B at each
        if (!args[2].isNull()) followPtrs('TA', args[2], 12, 512);

        // TABLE_B (X3): 12 pointers, read 512B at each
        if (!args[3].isNull()) followPtrs('TB', args[3], 12, 512);

        // callback (X4): 48 bytes + follow 6 pointers (256B each)
        dumpPtr('CB', args[4], 48);
        followPtrs('CB_PTR', args[4], 6, 256);
    },
    onLeave: function (retval) {
        console.log('VM_RET ' + callNum + ' = ' + retval);
    }
});

// Hook HashMap.put for headers
Java.perform(function () {
    var HashMap = Java.use('java.util.HashMap');
    var origPut = HashMap.put.overload('java.lang.Object', 'java.lang.Object');
    var capturing = false;
    origPut.implementation = function (key, val) {
        if (capturing) {
            var k = key ? key.toString() : '';
            if (k.indexOf('X-') === 0) {
                console.log('\nHEADER ' + k + '=' + (val ? val.toString() : ''));
            }
        }
        return origPut.call(this, key, val);
    };

    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try { loader.findClass('ms.bd.c.r4'); } catch (e) { return; }
            Java.classFactory.loader = loader;
            var HM = Java.use('java.util.HashMap');
            Java.choose('ms.bd.c.r4', {
                onMatch: function (inst) {
                    var url = 'https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/' +
                        '?ac=wifi&aid=1967&device_id=3722313718058683&_rticket=' + Date.now() +
                        '&book_id=7373660003258862617';
                    capturing = true;
                    console.log('\n=== SIGN_START url=' + url + ' ===');
                    inst.onCallToAddSecurityFactor(url, HM.$new());
                    capturing = false;
                    console.log('\n=== SIGN_DONE vm_calls=' + callNum + ' ===');
                },
                onComplete: function () {}
            });
        },
        onComplete: function () {}
    });
});
