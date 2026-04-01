// Frida CLI script: capture registers AND stack at SO+0x286DF4
// Usage: frida -U -p <PID> -l dump_regs_and_stack.js

var m = Process.findModuleByName('libmetasec_ml.so');
console.log('SO_BASE=' + m.base);
var done = false;

Interceptor.attach(m.base.add(0x286DF4), {
    onEnter: function() {
        if (done) return;
        done = true;

        // Capture registers
        var regs = ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11',
                    'x12','x13','x14','x15','x16','x17','x19','x20','x21','x22',
                    'x23','x24','x25','x26','x27','x28','fp','lr','sp'];
        regs.forEach(function(r) {
            console.log('REG:' + r + ':' + this.context[r]);
        }, this);

        // Capture stack: 128KB from SP-16KB to SP+112KB
        var sp = this.context.sp;
        var stackBase = sp.and(ptr('0xFFFFFFFFFFFFF000')).sub(0x4000); // 16KB below SP, page-aligned
        var stackSize = 0x20000; // 128KB total

        console.log('STACK_BASE:' + stackBase);
        console.log('STACK_SIZE:' + stackSize);

        try {
            // Write stack to /data/local/tmp/stack_dump.bin
            var fd = new File('/data/local/tmp/stack_dump.bin', 'wb');
            var chunk = 4096;
            for (var off = 0; off < stackSize; off += chunk) {
                try {
                    var data = stackBase.add(off).readByteArray(chunk);
                    fd.write(data);
                } catch(e) {
                    // Page not readable, write zeros
                    fd.write(new ArrayBuffer(chunk));
                }
            }
            fd.close();
            console.log('STACK_DUMPED:' + stackSize);
        } catch(e) {
            console.log('STACK_ERROR:' + e);
        }

        console.log('REGS_CAPTURED');
    }
});

// Trigger signing after 3 seconds
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
                                'https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64&device_brand=google&os_api=35&os_version=15&device_id=3722313718058683&iid=3722313718062779&_rticket=1774940000000&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7&openudid=9809e655-067c-47fe-a937-b150bfad0be9&book_id=7373660003258862617',
                                Java.use('java.util.HashMap').$new());
                            Interceptor.detachAll();
                            console.log('SIGN_DONE');
                        },
                        onComplete: function() {}
                    });
                } catch(e) {}
            },
            onComplete: function() {}
        });
    });
}, 3000);
