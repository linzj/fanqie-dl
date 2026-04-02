// Get MetaSec native handle value and dump its memory
// Usage: timeout 30 frida -U -p <PID> -l scripts/get_handle.js
// Then interact with app to trigger signing
Java.perform(function() {
    try {
        var y2 = Java.use('ms.bd.c.y2');

        y2.a.overload('int', 'int', 'long', 'java.lang.String', 'java.lang.Object').implementation = function(tag, type, handle, url, extra) {
            console.log('=== y2.a called ===');
            console.log('TAG:' + tag + ' (0x' + tag.toString(16) + ')');
            console.log('TYPE:' + type);
            console.log('HANDLE:' + handle + ' (0x' + handle.toString(16) + ')');
            console.log('URL:' + (url ? url.substring(0, 100) : 'null'));

            // Dump handle memory (it's a native pointer cast to long)
            if (handle != 0) {
                var handlePtr = ptr(handle);
                console.log('HANDLE_PTR:' + handlePtr);

                // Dump 4KB around handle
                try {
                    var data = handlePtr.readByteArray(4096);
                    console.log('HANDLE_DUMP_START');
                    // Output as hex lines (64 bytes per line)
                    var view = new Uint8Array(data);
                    for (var off = 0; off < view.length; off += 64) {
                        var hex = '';
                        for (var j = 0; j < 64 && off + j < view.length; j++) {
                            hex += ('0' + view[off + j].toString(16)).slice(-2);
                        }
                        console.log('HD:' + off.toString(16).padStart(4, '0') + ':' + hex);
                    }
                    console.log('HANDLE_DUMP_END');

                    // Also dump pointers found in the handle struct
                    // Follow first 32 quadwords as potential pointers
                    var m = Process.findModuleByName('libmetasec_ml.so');
                    console.log('SO_BASE:' + m.base);
                    for (var i = 0; i < 64; i++) {
                        try {
                            var val = handlePtr.add(i * 8).readU64();
                            // Check if it looks like a valid pointer
                            if (val > 0x700000000000 && val < 0x800000000000) {
                                var soOff = val - m.base.toInt64();
                                if (soOff >= 0 && soOff < 0x400000) {
                                    console.log('PTR:+' + (i*8).toString(16) + ':0x' + val.toString(16) + ' (SO+0x' + soOff.toString(16) + ')');
                                } else {
                                    // Try to read 64 bytes from this pointer
                                    try {
                                        var pdata = ptr(val.toString()).readByteArray(64);
                                        var pview = new Uint8Array(pdata);
                                        var phex = '';
                                        for (var j = 0; j < 64; j++) {
                                            phex += ('0' + pview[j].toString(16)).slice(-2);
                                        }
                                        console.log('PTR:+' + (i*8).toString(16) + ':0x' + val.toString(16) + ' → ' + phex);
                                    } catch(e2) {
                                        console.log('PTR:+' + (i*8).toString(16) + ':0x' + val.toString(16) + ' (unreadable)');
                                    }
                                }
                            } else if (val > 0x10000 && val < 0x700000000000 && val != 0) {
                                console.log('PTR:+' + (i*8).toString(16) + ':0x' + val.toString(16) + ' (low-range)');
                            }
                        } catch(e3) {}
                    }
                } catch(e) {
                    console.log('DUMP_ERROR:' + e);
                }
            }

            // Also dump extra array if present
            if (extra !== null) {
                try {
                    var arr = Java.cast(extra, Java.use('[Ljava.lang.Object;'));
                    console.log('EXTRA_LEN:' + arr.length);
                    for (var i = 0; i < Math.min(arr.length, 20); i++) {
                        var elem = arr[i];
                        console.log('EXTRA[' + i + ']:' + (elem ? elem.toString().substring(0, 100) : 'null'));
                    }
                } catch(e) {
                    console.log('EXTRA:not-array:' + extra);
                }
            }

            // Call original
            var result = this.a(tag, type, handle, url, extra);
            console.log('RESULT:' + result);
            return result;
        };
        console.log('Hook set — interact with app to trigger signing');
    } catch(e) {
        console.log('Error: ' + e);
    }
});
