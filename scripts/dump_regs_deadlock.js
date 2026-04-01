// Capture registers at SO+0x286DF4 then DEADLOCK the thread
// So host can dump via /proc/pid/mem while state is frozen
var m = Process.findModuleByName('libmetasec_ml.so');
var done = false;

Interceptor.attach(m.base.add(0x286DF4), {
    onEnter: function() {
        if (done) return;
        done = true;
        var regs = ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11',
                    'x12','x13','x14','x15','x16','x17','x19','x20','x21','x22',
                    'x23','x24','x25','x26','x27','x28','fp','lr','sp'];
        regs.forEach(function(r) { console.log('REG:' + r + ':' + this.context[r]); }, this);
        var code = Memory.alloc(Process.pageSize);
        Memory.patchCode(code, 8, function(c) {
            c.writeByteArray([0x40,0xD0,0x3B,0xD5, 0xC0,0x03,0x5F,0xD6]);
        });
        console.log('REG:tpidr_el0:' + new NativeFunction(code, 'pointer', [])());
        console.log('REGS_DONE_DUMP_NOW');
        // Deadlock: sleep in a loop (thread stays at function entry)
        while(true) { Thread.sleep(1); }
    }
});

setTimeout(function() {
    Java.perform(function() {
        Java.enumerateClassLoaders({
            onMatch: function(l) {
                try {
                    l.findClass('ms.bd.c.r4');
                    Java.classFactory.loader = l;
                    Java.choose('ms.bd.c.r4', {
                        onMatch: function(i) {
                            i.onCallToAddSecurityFactor(
                                'https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?aid=1967&version_code=71332&device_platform=android&book_id=7372053034241116214',
                                Java.use('java.util.HashMap').$new());
                        },
                        onComplete: function() {}
                    });
                } catch(e) {}
            },
            onComplete: function() {}
        });
    });
}, 2000);
