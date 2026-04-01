// Hook JNI RegisterNatives to find the native implementation of y2.a
// Usage: timeout 30 frida -U -p <PID> -l scripts/hook_register_natives.js
//
// RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods)
// JNINativeMethod = { const char *name, const char *signature, void *fnPtr }

var libart = Process.findModuleByName('libart.so');
var m = Process.findModuleByName('libmetasec_ml.so');
console.log('SO_BASE=' + m.base);

// Find RegisterNatives in libart
var registerNatives = Module.findExportByName('libart.so', '_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi');
if (!registerNatives) {
    // Try alternative symbol
    registerNatives = Module.findExportByName('libart.so', 'RegisterNatives');
}
if (!registerNatives) {
    // Scan for it via JNIEnv function table
    console.log('RegisterNatives not found by name, trying JNIEnv table...');
    // JNIEnv->functions->RegisterNatives is at offset 215*8 on 64-bit
    // We'll hook it when JNI_OnLoad is called instead
}

if (registerNatives) {
    console.log('RegisterNatives at ' + registerNatives);
    Interceptor.attach(registerNatives, {
        onEnter: function(args) {
            var env = args[0];
            var clazz = args[1];
            var methods = args[2];
            var nMethods = args[3].toInt32();

            // Get class name
            var getClassName = new NativeFunction(
                Module.findExportByName('libart.so', '_ZN3art6mirror5Class12GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE')
                || ptr(0), 'pointer', ['pointer', 'pointer']);

            for (var i = 0; i < nMethods; i++) {
                var namePtr = methods.add(i * 24).readPointer();
                var sigPtr = methods.add(i * 24 + 8).readPointer();
                var fnPtr = methods.add(i * 24 + 16).readPointer();

                var name = namePtr.readCString();
                var sig = sigPtr.readCString();
                var soOffset = fnPtr.sub(m.base);

                console.log('NATIVE: ' + name + ' ' + sig + ' → SO+0x' + soOffset.toString(16) + ' (' + fnPtr + ')');
            }
        }
    });
} else {
    console.log('RegisterNatives not found, hooking JNI_OnLoad instead');
}

// Also hook JNI_OnLoad to see when it's called
var jniOnLoad = m.base.add(0x28741c);  // from ISSUE.md
console.log('JNI_OnLoad at SO+0x28741c (' + jniOnLoad + ')');
try {
    Interceptor.attach(jniOnLoad, {
        onEnter: function() {
            console.log('JNI_OnLoad called!');
        }
    });
} catch(e) {
    console.log('JNI_OnLoad hook failed: ' + e);
    // JNI_OnLoad already ran, hook RegisterNatives via JNIEnv function table
    // On ART, we can find the JNIEnv function table from any thread
}

// Alternative: hook the JNIEnv->RegisterNatives function pointer directly
// JNIEnv is a pointer to JNINativeInterface which has RegisterNatives at index 215
Java.perform(function() {
    var env = Java.vm.tryGetEnv();
    if (env) {
        // JNIEnv* → JNINativeInterface_** → functions table
        var envPtr = ptr(env.handle);
        var functionsPtr = envPtr.readPointer(); // JNINativeInterface_*
        // RegisterNatives is at offset 215 in the function table
        var regNativesPtr = functionsPtr.add(215 * Process.pointerSize).readPointer();
        console.log('JNIEnv->RegisterNatives at ' + regNativesPtr);

        if (!registerNatives) {
            Interceptor.attach(regNativesPtr, {
                onEnter: function(args) {
                    var methods = args[2];
                    var nMethods = args[3].toInt32();
                    for (var i = 0; i < nMethods; i++) {
                        var namePtr = methods.add(i * 24).readPointer();
                        var sigPtr = methods.add(i * 24 + 8).readPointer();
                        var fnPtr = methods.add(i * 24 + 16).readPointer();
                        var name = namePtr.readCString();
                        var sig = sigPtr.readCString();
                        var soOff = fnPtr.sub(m.base);
                        if (soOff.compare(ptr(0x400000)) < 0 && soOff.compare(ptr(0)) >= 0) {
                            console.log('NATIVE: ' + name + ' ' + sig + ' → SO+0x' + soOff.toString(16));
                        }
                    }
                }
            });
        }
    }
});

console.log('Hooks set. RegisterNatives already called during JNI_OnLoad.');
console.log('If no NATIVE output, the registration already happened.');
console.log('Trying to find registered methods via ART internals...');

// Try to find the native method directly by searching ART's method registry
Java.perform(function() {
    try {
        var y2 = Java.use('ms.bd.c.y2');
        // Get the Method object for 'a'
        var methods = y2.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            var method = methods[i];
            if (method.getName() === 'a' && method.toString().indexOf('native') !== -1) {
                console.log('Found native method: ' + method.toString());
                // Get ArtMethod pointer
                var artMethod = method.getArtMethod ? method.getArtMethod() : null;
                if (artMethod) {
                    console.log('ArtMethod: ' + artMethod);
                    // entry_point_from_jni_ is at offset 32 on ARM64 ART
                    var jniEntry = ptr(artMethod).add(32).readPointer();
                    var soOff = jniEntry.sub(m.base);
                    console.log('JNI entry: ' + jniEntry + ' = SO+0x' + soOff.toString(16));
                }
            }
        }
    } catch(e) {
        console.log('Error finding method: ' + e);
    }
});
