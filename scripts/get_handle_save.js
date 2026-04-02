// Get handle and dump to device file, then exit immediately
// Usage: frida -U -f com.dragon.read -l scripts/get_handle_save.js
var done = false;
Java.perform(function() {
    var y2 = Java.use('ms.bd.c.y2');
    y2.a.overload('int', 'int', 'long', 'java.lang.String', 'java.lang.Object').implementation = function(tag, type, handle, url, extra) {
        if (!done && handle != 0) {
            done = true;
            var handlePtr = ptr(handle);
            var data = handlePtr.readByteArray(4096);
            // Write handle address + data to device file
            var f = new File('/data/local/tmp/handle_dump.bin', 'wb');
            // Write address as 8 bytes LE
            var addrBuf = Memory.alloc(8);
            addrBuf.writeU64(uint64(handle.toString()));
            f.write(addrBuf.readByteArray(8));
            // Write size as 4 bytes LE
            var sizeBuf = Memory.alloc(4);
            sizeBuf.writeU32(4096);
            f.write(sizeBuf.readByteArray(4));
            // Write data
            f.write(data);
            f.close();
            console.log('SAVED handle=0x' + handle.toString(16) + ' to /data/local/tmp/handle_dump.bin');
        }
        return this.a(tag, type, handle, url, extra);
    };
    console.log('Hook set - waiting for non-zero handle call');
});
