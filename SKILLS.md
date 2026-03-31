# 逆向 libmetasec_ml.so 签名算法

## 目标

将 `libmetasec_ml.so` 中的签名算法逆向并移植到 Rust，使 CLI 工具能独立生成有效的 API 签名。

## 前置条件

- macOS ARM64 (Apple Silicon) 或 ARM64 物理设备
- Android emulator with ARM64 system image (API 34)
- frida + frida-server (arm64)
- IDA Pro（可选，用 IDA MCP 辅助分析）
- APK: `test.apk` 已安装在模拟器上

## Step 1: 环境搭建

```bash
# 安装 ARM64 Android system image
sdkmanager "system-images;android-34;google_apis;arm64-v8a"
# 创建 AVD
avdmanager create avd -n fanqie_arm64 -k "system-images;android-34;google_apis;arm64-v8a"
# 启动
emulator -avd fanqie_arm64
# 安装 APK
adb install test.apk
# 推送 frida-server (arm64)
adb push frida-server-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb root && adb shell /data/local/tmp/frida-server -D &
```

## Step 2: 确认 .so 加载

```bash
frida -U -f com.dragon.read -e '
var m = Process.findModuleByName("libmetasec_ml.so");
console.log("Base: " + m.base + " Size: " + m.size);
m.enumerateExports().forEach(function(e) {
    console.log(e.type + " " + e.name + " @ " + e.address);
});
'
```

## Step 3: Hook JNI 签名函数

```javascript
// 找到 JNI_OnLoad 和签名相关的 JNI 方法
Java.perform(function() {
    var r4 = Java.use("ms.bd.c.r4");
    r4.onCallToAddSecurityFactor.implementation = function(url, headers) {
        console.log("INPUT URL: " + url);
        var result = this.onCallToAddSecurityFactor(url, headers);
        // 打印输出的签名 headers
        var Map = Java.use("java.util.Map");
        var m = Java.cast(result, Map);
        var it = m.entrySet().iterator();
        while (it.hasNext()) {
            var e = it.next();
            console.log("  " + e.getKey() + " = " + e.getValue());
        }
        return result;
    };
});
```

## Step 4: Hook native 函数

```javascript
// Hook libmetasec_ml.so 的导出函数
var metasec = Process.findModuleByName("libmetasec_ml.so");
var exports = metasec.enumerateExports();
// 找到签名相关函数 (通常包含 "sign", "encrypt", "init" 等关键字)
exports.forEach(function(e) {
    if (e.name.indexOf("sign") !== -1 || e.name.indexOf("ss_") !== -1) {
        Interceptor.attach(e.address, {
            onEnter: function(args) {
                console.log("CALL " + e.name);
                // dump args
            },
            onLeave: function(retval) {
                console.log("  RET " + retval);
            }
        });
    }
});
```

## Step 5: IDA 分析

1. 用 IDA 打开 `lib/arm64-v8a/libmetasec_ml.so`
2. 查找 JNI_OnLoad → RegisterNatives → 找到 Java native 方法对应的 C 函数
3. 分析签名函数的算法：
   - 输入: URL query string
   - 输出: Map<String, String> 包含 X-Gorgon, X-Argus, X-Ladon, X-Khronos, X-Helios, X-Medusa
4. 重点关注:
   - 哈希算法 (MD5, SM3, SHA256?)
   - 对称加密 (AES, Simon, Speck?)
   - 密钥来源 (硬编码? 动态生成?)

## Step 6: Rust 移植

将逆向出的算法替换 `src/signer/` 中的实现：
- `src/signer/gorgon.rs` — X-Gorgon (当前实现已验证正确)
- `src/signer/argus.rs` — X-Argus (需替换)
- `src/signer/ladon.rs` — X-Ladon (需替换)
- 新增 `src/signer/helios.rs` — X-Helios
- 新增 `src/signer/medusa.rs` — X-Medusa

## 关键提示

- X-Gorgon 当前 Rust 实现已通过验证（与 Python 输出一致），但可能版本过旧
- 服务端可能检查多个签名头的一致性（时间戳、随机数等需要关联）
- msssdk 有反调试，frida 可能需要用 -f spawn 模式或使用 frida-gadget
- .so 高度混淆，优先通过 frida 黑盒测试确定输入输出格式，再用 IDA 分析内部逻辑
