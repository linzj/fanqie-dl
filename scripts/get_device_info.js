// 获取 app 真实的 device_id, iid, 以及 hook 实际的 API 请求看完整 URL

Java.perform(function() {
    // 方法1: 从 SharedPreferences 获取设备信息
    var Activity = Java.use("android.app.Activity");
    var Context = Java.use("android.content.Context");
    var SharedPreferences = Java.use("android.content.SharedPreferences");

    Java.choose("android.app.Activity", {
        onMatch: function(activity) {
            console.log("[+] Found activity: " + activity.getClass().getName());

            // Check common SharedPreferences files for device info
            var prefNames = ["tt_msssdk_sp", "msssdk", "device_info", "meta_sec_sp", "tt_push_sp"];
            for (var i = 0; i < prefNames.length; i++) {
                try {
                    var prefs = activity.getSharedPreferences(prefNames[i], 0);
                    var allEntries = prefs.getAll();
                    if (allEntries.size() > 0) {
                        console.log("\n[SharedPrefs] " + prefNames[i] + " (" + allEntries.size() + " entries):");
                        var it = allEntries.keySet().iterator();
                        while (it.hasNext()) {
                            var key = it.next();
                            var val = allEntries.get(key);
                            var str = val ? val.toString() : "null";
                            if (str.length > 100) str = str.substring(0, 100) + "...";
                            if (key.indexOf("device") !== -1 || key.indexOf("iid") !== -1 ||
                                key.indexOf("install") !== -1 || key.indexOf("did") !== -1 ||
                                key.indexOf("aid") !== -1 || key.indexOf("uuid") !== -1 ||
                                key.indexOf("key") !== -1 || key.indexOf("token") !== -1 ||
                                key.indexOf("openudid") !== -1 || key.indexOf("cdid") !== -1) {
                                console.log("  " + key + " = " + str);
                            }
                        }
                    }
                } catch(e) {}
            }

            // Try more preferences
            var morePrefs = ["pref_key_new_session_info", "dragon_pref"];
            for (var i = 0; i < morePrefs.length; i++) {
                try {
                    var prefs = activity.getSharedPreferences(morePrefs[i], 0);
                    var allEntries = prefs.getAll();
                    if (allEntries.size() > 0) {
                        console.log("\n[SharedPrefs] " + morePrefs[i] + " (" + allEntries.size() + " entries):");
                        var it = allEntries.keySet().iterator();
                        while (it.hasNext()) {
                            var key = it.next();
                            var val = allEntries.get(key);
                            var str = val ? val.toString() : "null";
                            if (str.length > 100) str = str.substring(0, 100) + "...";
                            console.log("  " + key + " = " + str);
                        }
                    }
                } catch(e) {}
            }
        },
        onComplete: function() {}
    });

    // 方法2: 直接列出 shared_prefs 目录下的所有文件
    try {
        var Runtime = Java.use("java.lang.Runtime");
        var rt = Runtime.getRuntime();
        var proc = rt.exec("ls /data/data/com.dragon.read/shared_prefs/");
        var is = proc.getInputStream();
        var BufferedReader = Java.use("java.io.BufferedReader");
        var InputStreamReader = Java.use("java.io.InputStreamReader");
        var reader = BufferedReader.$new(InputStreamReader.$new(is));
        var line;
        console.log("\n[SharedPrefs files]:");
        while ((line = reader.readLine()) !== null) {
            console.log("  " + line);
        }
    } catch(e) {
        console.log("[!] Cannot list shared_prefs: " + e);
    }

    // 方法3: Hook URL builder to capture actual device_id from app's requests
    // Trigger an actual search to see real URLs
    console.log("\n[*] Triggering actual app search via adb tap...");
});

// 方法4: 尝试从 TTNetInit 获取设备信息
Java.perform(function() {
    try {
        var classes = [
            "com.bytedance.frameworks.baselib.network.http.NetworkParams",
            "com.ss.android.deviceregister.DeviceRegisterHelper",
            "com.bytedance.applog.AppLog",
        ];

        for (var i = 0; i < classes.length; i++) {
            try {
                var cls = Java.use(classes[i]);
                var methods = cls.class.getDeclaredMethods();
                console.log("\n[Class] " + classes[i] + " methods:");
                for (var j = 0; j < Math.min(methods.length, 10); j++) {
                    console.log("  " + methods[j].getName());
                }
            } catch(e) {}
        }
    } catch(e) {}

    // Try AppLog for device_id
    try {
        var AppLog = Java.use("com.bytedance.applog.AppLog");
        console.log("\n[AppLog]:");
        try { console.log("  getDid: " + AppLog.getDid()); } catch(e) {}
        try { console.log("  getIid: " + AppLog.getIid()); } catch(e) {}
        try { console.log("  getAid: " + AppLog.getAid()); } catch(e) {}
        try { console.log("  getDeviceId: " + AppLog.getDeviceId()); } catch(e) {}
    } catch(e) {
        console.log("[!] AppLog not found: " + e);
    }
});
