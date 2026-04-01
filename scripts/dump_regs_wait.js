// Hook SO+0x286DF4 and WAIT for app to naturally trigger signing
// No Java.perform trigger — user interacts with app manually
var m = Process.findModuleByName('libmetasec_ml.so');
console.log('SO_BASE=' + m.base);
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
        // Deadlock thread so host can dump via /proc/pid/mem
        while(true) { Thread.sleep(1); }
    }
});
console.log('HOOK_SET — interact with app to trigger signing');
