/**
 * hook_medusa_vm.js — 监控所有 VM 调用，特别关注 Medusa (SO+0x119050)
 * 同时拦截签名结果，看是否产生了 X-Medusa header
 */
'use strict';

var mod = Process.findModuleByName('libmetasec_ml.so');
var base = mod.base;
console.log('SO_BASE=' + base);

function toHex(byteArray) {
    var bytes = new Uint8Array(byteArray);
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
        hex += ('0' + bytes[i].toString(16)).slice(-2);
    }
    return hex;
}

var vmEntry = base.add(0x168324);
var callNum = 0;

Interceptor.attach(vmEntry, {
    onEnter: function (args) {
        callNum++;
        var bcAddr = args[0];
        var bcOff = bcAddr.sub(base).toInt32() >>> 0;
        var isMedusa = (bcOff === 0x119050);
        var isHelios = (bcOff === 0x118f50);
        var label = isMedusa ? ' *** MEDUSA ***' : (isHelios ? ' (Helios)' : '');

        console.log('VM #' + callNum + ' bc=SO+0x' + bcOff.toString(16) + label);
        console.log('  X0(bc)=' + args[0] + ' X1(packed)=' + args[1] +
            ' X2(tblA)=' + args[2] + ' X3(tblB)=' + args[3] + ' X4(cb)=' + args[4]);

        // 对 Medusa 或任何有非 NULL TABLE_A/B 的调用，详细 dump
        var tblA = args[2];
        var tblB = args[3];
        if (!tblA.isNull() || isMedusa) {
            console.log('  --- TABLE_A ---');
            for (var i = 0; i < 12; i++) {
                try {
                    var p = tblA.add(i * 8).readPointer();
                    var readable = false;
                    var data = '';
                    try {
                        data = toHex(p.readByteArray(32));
                        readable = true;
                    } catch (e) {}
                    console.log('  A[' + i + ']=' + p + (readable ? ' DATA=' + data : ' UNREADABLE'));
                } catch (e) {}
            }
            console.log('  --- TABLE_B ---');
            for (var i = 0; i < 12; i++) {
                try {
                    var p = tblB.add(i * 8).readPointer();
                    var readable = false;
                    var data = '';
                    try {
                        data = toHex(p.readByteArray(32));
                        readable = true;
                    } catch (e) {}
                    console.log('  B[' + i + ']=' + p + (readable ? ' DATA=' + data : ' UNREADABLE'));
                } catch (e) {}
            }
        }
    }
});

// 拦截签名结果 — hook HashMap.put 看 X-Medusa 是否被设置
Java.perform(function () {
    // Hook HashMap.put to see what headers are added
    var HashMap = Java.use('java.util.HashMap');
    var origPut = HashMap.put.overload('java.lang.Object', 'java.lang.Object');
    var inSign = false;
    origPut.implementation = function (key, val) {
        if (inSign) {
            var k = key ? key.toString() : '';
            var v = val ? val.toString() : '';
            if (k.indexOf('X-') === 0 || k.indexOf('x-') === 0) {
                console.log('HEADER: ' + k + '=' + v.substring(0, 80));
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
                    console.log('=== SIGN START ===');
                    inSign = true;
                    inst.onCallToAddSecurityFactor(url, HM.$new());
                    inSign = false;
                    console.log('=== SIGN DONE === (VM calls: ' + callNum + ')');
                },
                onComplete: function () {}
            });
        },
        onComplete: function () {}
    });
});
