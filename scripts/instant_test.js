// 生成签名后立即写入文件，让shell脚本马上执行
var r4Instance = null;
var HashMapClass = null;

Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                Java.classFactory.loader = loader;
                HashMapClass = Java.use("java.util.HashMap");
                Java.choose("ms.bd.c.r4", {
                    onMatch: function(inst) {
                        r4Instance = inst;
                        run();
                    },
                    onComplete: function() {}
                });
            } catch(e) {}
        },
        onComplete: function() {}
    });
});

function sign(url) {
    var result = {};
    var headers = HashMapClass.$new();
    var r = r4Instance.onCallToAddSecurityFactor(url, headers);
    var map = Java.cast(r, HashMapClass);
    var it = map.keySet().iterator();
    while (it.hasNext()) {
        var key = it.next();
        result[key] = map.get(key).toString();
    }
    return result;
}

function run() {
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

    var sigs = sign(url);

    // Write as shell variables for immediate consumption
    send({
        type: "sigs",
        url: url,
        helios: sigs["X-Helios"],
        medusa: sigs["X-Medusa"],
        gorgon: sigs["X-Gorgon"],
        khronos: sigs["X-Khronos"],
        argus: sigs["X-Argus"],
        ladon: sigs["X-Ladon"],
        tsMs: tsMs.toString()
    });
}
