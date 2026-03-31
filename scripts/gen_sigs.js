// 生成签名，通过 console.log 输出 JSON
var found = false;
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            if (found) return;
            try {
                loader.findClass("ms.bd.c.r4");
            } catch(e) {
                return; // not this loader
            }
            found = true;
            Java.classFactory.loader = loader;
            var HM = Java.use("java.util.HashMap");
            Java.choose("ms.bd.c.r4", {
                onMatch: function(inst) {
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
                    var obj = {url: url, tsMs: tsMs};
                    var it = m.keySet().iterator();
                    while (it.hasNext()) {
                        var k = it.next();
                        obj[k] = m.get(k).toString();
                    }
                    console.log("SIGS_JSON:" + JSON.stringify(obj));
                },
                onComplete: function() {}
            });
        },
        onComplete: function() {}
    });
});
