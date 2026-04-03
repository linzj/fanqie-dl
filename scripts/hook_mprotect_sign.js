/**
 * hook_mprotect_sign.js — 监控签名期间的 mprotect 调用，找暗区解锁时机
 */
'use strict';

var mod = Process.findModuleByName('libmetasec_ml.so');
var base = mod.base;
var soEnd = base.add(0x400000); // approximate SO + reservation end
console.log('SO_BASE=' + base);

var libc = Process.findModuleByName('libc.so');

// Hook mprotect
var mprotectAddr = libc.findExportByName('mprotect');
var signing = false;
var mprotectCalls = [];

Interceptor.attach(mprotectAddr, {
    onEnter: function (args) {
        if (!signing) return;
        var addr = args[0];
        var len = args[1].toInt32();
        var prot = args[2].toInt32();
        var protStr = '';
        if (prot & 1) protStr += 'R';
        if (prot & 2) protStr += 'W';
        if (prot & 4) protStr += 'X';
        if (prot === 0) protStr = 'NONE';

        // 只关注 SO 附近的暗区
        var addrVal = parseInt(addr.toString().replace('0x',''), 16);
        var baseVal = parseInt(base.toString().replace('0x',''), 16);
        var diff = addrVal - baseVal;

        if (diff > 0 && diff < 0x2000000) {
            console.log('MPROTECT: ' + addr + ' len=0x' + len.toString(16) + ' prot=' + protStr +
                ' (SO+0x' + diff.toString(16) + ')');
            mprotectCalls.push({addr: addr, len: len, prot: prot, protStr: protStr});
        }
    }
});

// Hook mmap/mmap64 too
var mmapAddr = libc.findExportByName('mmap64') || libc.findExportByName('mmap');
if (mmapAddr) {
    Interceptor.attach(mmapAddr, {
        onEnter: function (args) {
            if (!signing) return;
            this.addr = args[0];
            this.len = args[1].toInt32();
            this.prot = args[2].toInt32();
        },
        onLeave: function (retval) {
            if (!signing) return;
            if (retval.compare(ptr('-1')) === 0) return;
            var diff = retval.sub(base).toInt32();
            if (diff > 0 && diff < 0x2000000) {
                console.log('MMAP: ' + retval + ' len=0x' + this.len.toString(16) +
                    ' prot=' + this.prot + ' (SO+0x' + diff.toString(16) + ')');
            }
        }
    });
}

// Hook sigaction to find SIGSEGV handler
var sigactionAddr = libc.findExportByName('sigaction');
if (sigactionAddr) {
    Interceptor.attach(sigactionAddr, {
        onEnter: function (args) {
            var sig = args[0].toInt32();
            if (sig === 11) { // SIGSEGV
                console.log('SIGACTION(SIGSEGV) handler=' + args[1].readPointer());
            }
        }
    });
}

// Also hook signal
var signalAddr = libc.findExportByName('signal');
if (signalAddr) {
    Interceptor.attach(signalAddr, {
        onEnter: function (args) {
            var sig = args[0].toInt32();
            if (sig === 11) {
                console.log('SIGNAL(SIGSEGV) handler=' + args[1]);
            }
        }
    });
}

// Hook VM entry to mark signing period
var vmEntry = base.add(0x168324);
Interceptor.attach(vmEntry, {
    onEnter: function (args) {
        var bcOff = args[0].sub(base).toInt32();
        console.log('VM_ENTER bc=SO+0x' + (bcOff >>> 0).toString(16));
    },
    onLeave: function () {
        console.log('VM_LEAVE mprotect_calls_during_vm=' + mprotectCalls.length);
    }
});

// Trigger signing
console.log('--- START ---');
signing = true;
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
                    signing = false;
                    console.log('SIGN_DONE total_mprotect=' + mprotectCalls.length);
                },
                onComplete: function () {}
            });
        },
        onComplete: function () {}
    });
});
