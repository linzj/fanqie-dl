#!/usr/bin/env python3
"""Test frida hook with proper runtime specification."""
import frida
import sys
import time

JS_CODE = r"""
Java.perform(function() {
    console.log("[*] Java.perform entered");

    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                console.log("[+] Found correct classloader");
                Java.classFactory.loader = loader;

                // Direct test: find MSManager instance and call frameSign
                Java.choose("com.bytedance.mobsec.metasec.ml.MSManager", {
                    onMatch: function(instance) {
                        console.log("[+] MSManager instance: " + instance);
                        try {
                            var testUrl = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/search/tab/v?query=test&aid=1967&device_id=123456&iid=789";
                            console.log("[*] Calling frameSign...");
                            var result = instance.frameSign(testUrl, 1);
                            if (result !== null) {
                                var it = result.entrySet().iterator();
                                while (it.hasNext()) {
                                    var e = it.next();
                                    console.log("[SIGN] " + e.getKey() + " = " + e.getValue());
                                }
                            } else {
                                console.log("[!] frameSign returned null");
                            }
                        } catch(e) {
                            console.log("[!] frameSign error: " + e);
                        }
                    },
                    onComplete: function() {
                        console.log("[*] MSManager scan done");
                    }
                });

                // Also try MSManagerUtils.get to get an instance
                try {
                    var utils = Java.use("com.bytedance.mobsec.metasec.ml.MSManagerUtils");
                    console.log("[*] Trying MSManagerUtils.get('1967')...");
                    var mgr = utils.get("1967");
                    if (mgr !== null) {
                        console.log("[+] Got MSManager via utils.get");
                        var testUrl2 = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/search/tab/v?query=hello&aid=1967";
                        var result2 = mgr.frameSign(testUrl2, 1);
                        if (result2 !== null) {
                            var it2 = result2.entrySet().iterator();
                            while (it2.hasNext()) {
                                var e2 = it2.next();
                                console.log("[SIGN2] " + e2.getKey() + " = " + e2.getValue());
                            }
                        } else {
                            console.log("[!] frameSign returned null");
                        }
                    } else {
                        console.log("[!] MSManagerUtils.get returned null");
                    }
                } catch(e) {
                    console.log("[!] MSManagerUtils error: " + e);
                }

            } catch(e) {
                // Not this classloader
            }
        },
        onComplete: function() {
            console.log("[*] Done");
        }
    });
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[MSG] {message['payload']}", flush=True)
    elif message['type'] == 'error':
        print(f"[ERR] {message.get('description', '')}", flush=True)
        if 'stack' in message:
            for line in message['stack'].split('\n')[:5]:
                print(f"  {line}", flush=True)
    else:
        print(f"[???] {message}", flush=True)

def main():
    pid = int(sys.argv[1])
    print(f"Attaching to PID {pid}...")

    device = frida.get_usb_device()
    session = device.attach(pid)

    # Specify runtime='v8' explicitly
    script = session.create_script(JS_CODE, runtime='v8')
    script.on('message', on_message)
    script.load()

    print("Waiting for results...")
    time.sleep(15)
    print("Done.")
    session.detach()

if __name__ == "__main__":
    main()
