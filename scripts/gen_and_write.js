// 生成签名，写入设备文件 /data/local/tmp/sigs.txt
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                Java.classFactory.loader = loader;
                var HM = Java.use("java.util.HashMap");
                Java.choose("ms.bd.c.r4", {
                    onMatch: function(inst) {
                        var ts = Math.floor(Date.now() / 1000);
                        var tsMs = Date.now();
                        var url = "https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/" +
                            "?ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32" +
                            "&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64" +
                            "&device_brand=google&os_api=35&os_version=15" +
                            "&device_id=3722313718058683&iid=3722313718062779" +
                            "&_rticket=" + tsMs +
                            "&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7" +
                            "&openudid=9809e655-067c-47fe-a937-b150bfad0be9" +
                            "&book_id=7373660003258862617";

                        var h = HM.$new();
                        var r = inst.onCallToAddSecurityFactor(url, h);
                        var m = Java.cast(r, HM);

                        var lines = "URL=" + url + "\nTSMS=" + tsMs + "\n";
                        var it = m.keySet().iterator();
                        while (it.hasNext()) {
                            var k = it.next();
                            lines += k.replace(/-/g, "_") + "=" + m.get(k).toString() + "\n";
                        }
                        lines += "DONE=1\n";

                        // Write to file using Java
                        var FileWriter = Java.use("java.io.FileWriter");
                        var fw = FileWriter.$new("/data/local/tmp/sigs.txt");
                        fw.write(lines);
                        fw.close();
                        console.log("[+] Wrote sigs to /data/local/tmp/sigs.txt");
                    },
                    onComplete: function() {}
                });
            } catch(e) { console.log("[!] " + e); }
        },
        onComplete: function() {}
    });
});
