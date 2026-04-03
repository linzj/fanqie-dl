/**
 * hook_sign_flow.js — Hook JNI 入口 + VM dispatcher，记录完整签名流程
 *
 * 1. Hook JNI native 入口 SO+0x26e684 标记签名开始/结束
 * 2. Hook VM dispatcher SO+0x168324 的每次调用
 * 3. Log 字节码地址、TABLE_A/B 地址、返回值
 */
'use strict';

var mod = Process.findModuleByName('libmetasec_ml.so');
var base = mod.base;
console.log('SO_BASE=' + base);

function toHex(arr) {
    var b = new Uint8Array(arr);
    var h = '';
    for (var i = 0; i < b.length; i++) h += ('0' + b[i].toString(16)).slice(-2);
    return h;
}

function safeRead(addr, size) {
    try { return addr.readByteArray(size); } catch (e) { return null; }
}

// === Hook JNI 入口 SO+0x26e684 ===
var jniEntry = base.add(0x26e684);
var signCount = 0;
var inSign = false;

Interceptor.attach(jniEntry, {
    onEnter: function (args) {
        signCount++;
        inSign = true;
        // args: x0=JNIEnv, x1=jobject, x2=tag, x3=type, x4=handle, x5=url, x6=extra
        var tag = args[2].toInt32();
        var type = args[3].toInt32();
        var handle = args[4];
        console.log('\n======== JNI_ENTER #' + signCount +
            ' tag=0x' + (tag >>> 0).toString(16) +
            ' type=' + type +
            ' handle=' + handle + ' ========');
    },
    onLeave: function (retval) {
        inSign = false;
        console.log('======== JNI_LEAVE #' + signCount + ' ret=' + retval + ' ========\n');
    }
});

// === Hook VM dispatcher SO+0x168324 ===
var vmEntry = base.add(0x168324);
var vmCallNum = 0;

Interceptor.attach(vmEntry, {
    onEnter: function (args) {
        vmCallNum++;
        var bcOff = (args[0].sub(base).toInt32() >>> 0);
        var tblA = args[2];
        var tblB = args[3];

        console.log('  VM_ENTER #' + vmCallNum +
            ' bc=SO+0x' + bcOff.toString(16) +
            ' tblA=' + tblA +
            ' tblB=' + tblB);

        // 第一次记录线程信息
        if (vmCallNum === 1) {
            // 读 TPIDR
            var tpidrCode = Memory.alloc(8);
            Memory.protect(tpidrCode, Process.pageSize, 'rwx');
            tpidrCode.writeU32(0xd53bd040);
            tpidrCode.add(4).writeU32(0xd65f03c0);
            var readTpidr = new NativeFunction(tpidrCode, 'pointer', []);
            console.log('    TID=' + Process.getCurrentThreadId() + ' TPIDR=' + readTpidr());
        }

        // packed_args (X1) 简要信息
        var packed = args[1];
        var pData = safeRead(packed, 48);
        if (pData) console.log('    packed=' + toHex(pData));

        // TABLE_A 非空时列出 12 个指针
        if (!tblA.isNull()) {
            var aOff = (tblA.sub(base).toInt32() >>> 0);
            var aInfo = 'SO+0x' + aOff.toString(16) + ' [';
            for (var i = 0; i < 12; i++) {
                try {
                    var p = tblA.add(i * 8).readPointer();
                    var readable = false;
                    try { p.readU8(); readable = true; } catch (e) {}
                    aInfo += (i > 0 ? ',' : '') + (p.isNull() ? 'NULL' : (readable ? 'R' : 'U'));
                } catch (e) { aInfo += (i > 0 ? ',' : '') + 'E'; }
            }
            console.log('    tblA_detail=' + aInfo + ']');
        }

        if (!tblB.isNull()) {
            var bOff = (tblB.sub(base).toInt32() >>> 0);
            var bInfo = 'SO+0x' + bOff.toString(16) + ' [';
            for (var i = 0; i < 12; i++) {
                try {
                    var p = tblB.add(i * 8).readPointer();
                    var readable = false;
                    try { p.readU8(); readable = true; } catch (e) {}
                    bInfo += (i > 0 ? ',' : '') + (p.isNull() ? 'NULL' : (readable ? 'R' : 'U'));
                } catch (e) { bInfo += (i > 0 ? ',' : '') + 'E'; }
            }
            console.log('    tblB_detail=' + bInfo + ']');
        }

        // callback (X4)
        var cb = args[4];
        if (!cb.isNull()) {
            var cbData = safeRead(cb, 48);
            if (cbData) console.log('    cb=' + toHex(cbData));
        }
    },
    onLeave: function (retval) {
        console.log('  VM_LEAVE #' + vmCallNum + ' ret=' + retval);
    }
});

// 触发签名
Java.perform(function () {
    var HashMap = Java.use('java.util.HashMap');
    var origPut = HashMap.put.overload('java.lang.Object', 'java.lang.Object');
    origPut.implementation = function (key, val) {
        var k = key ? key.toString() : '';
        if (inSign && k.indexOf('X-') === 0) {
            console.log('  HEADER ' + k + '=' + (val ? val.toString().substring(0, 100) : ''));
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
                    console.log('TRIGGER url=' + url);
                    inst.onCallToAddSecurityFactor(url, HM.$new());
                    console.log('TRIGGER_DONE');
                },
                onComplete: function () {}
            });
        },
        onComplete: function () {}
    });
});
