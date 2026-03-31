# 当前问题：需要逆向 X-Helios 和 X-Medusa 算法

## Frida 调查结论 (2026-03-31)

### 核心发现：只需要 X-Helios 和 X-Medusa

通过 Frida 生成真实签名 + curl 即时测试，**系统性排除**了每个签名头：

| 测试 | 结果 | 结论 |
|------|------|------|
| 全部6个签名头 | ✅ 22967 bytes | 基线 |
| 只有 Helios+Medusa | ✅ 22929 bytes | **只需要这两个** |
| 没有 Helios | ❌ 空响应 | Helios 必需 |
| 没有 Medusa | ❌ 空响应 | Medusa 必需 |
| 没有 Gorgon/Khronos/Argus/Ladon | ✅ 22937 bytes | **这4个都不需要** |
| 假 Helios + 真 Medusa | ❌ 空响应 | Helios 被验证 |
| 真 Helios + 假 Medusa | ❌ 空响应 | Medusa 被验证 |
| 不同 URL 复用相同签名 | ❌ 空响应 | **签名绑定 URL** |
| 无签名 | ❌ 空响应 | 需要签名 |

### 可以删除的代码

现有 `src/signer/` 中的以下模块**全部无用**，可以删除：
- `gorgon.rs` — X-Gorgon 不被验证
- `argus.rs` — X-Argus 只是 `base64(timestamp LE u32)`，不被验证
- `ladon.rs` — X-Ladon 4字节随机值，不被验证
- `simon.rs` — Simon 密码，不被使用
- `sm3.rs` — SM3 哈希，不被使用
- `protobuf.rs` — Protobuf 编码，不被使用

### X-Argus 真实算法（已破解，但无用）

```
X-Argus = base64(timestamp as u32 little-endian)
```

例：timestamp `1774936134` = `0x69CB6046` → LE bytes `[0x46, 0x60, 0xCB, 0x69]` → Base64 `RmDLaQ==`

## 需要 IDA 逆向的目标

### 目标1: X-Helios (优先)

- **大小**: 36 bytes (base64 ~48 chars)
- **特征**: 每次调用完全不同，即使相同 URL 和 timestamp
- **示例**:
  ```
  017f36184694cb86a4e82a029a731f18f24c7823935eca86eb4f47e7f107f39aae41b9f7
  f125112fd12e8e6ad684fa397fa7714b33f5a483992815a4fc8296a33eb96d0f1e097057
  2b1a8948c6add793b117133a9af115b38472f17ed504308db1d9d69b8099e429a09c1356
  ```
- **观察**: 36 bytes = 可能是 4 bytes 随机/nonce + 32 bytes hash (SHA-256?)

### 目标2: X-Medusa (优先)

- **大小**: ~966 bytes (base64 ~1288 chars)
- **结构**:
  ```
  前20字节 (固定头，同一 timestamp 内不变):
    bytes 0-3:  与 timestamp 相关 (不是直接 LE)
    bytes 4-19: 常量或设备相关
  bytes 20-21: 变化 (随机/计数器)
  bytes 22-23: 0x0001 (常量)
  bytes 24+:   加密内容 (~946 bytes)
  ```
- **示例** (前40字节 hex):
  ```
  7264cb695a2f84a33e11c62a48d165455509073f62eb0001...
  7264cb695a2f84a33e11c62a48d165455509073f063a0001...
  7264cb695a2f84a33e11c62a48d165455509073f40730001...
  ```
- **固定头分析** (ts=0x69CB6477):
  ```
  72 64 cb 69  — byte0 = 0x72, ts_byte0 = 0x77, 差值 0x05 或 XOR 0x05
  5a 2f 84 a3  — 可能是常量或与设备相关
  3e 11 c6 2a  — 可能是常量
  48 d1 65 45  — 可能是常量
  55 09 07 3f  — 可能是常量
  ```

### 调用链

```
Java 层:
  r4.onCallToAddSecurityFactor(String url, Map headers)
    → y2.a(50331649, 0, nativeHandle, url, headersArray)
      → libmetasec_ml.so JNI native

返回:
  String[] 键值对 → 包含 X-Helios, X-Medusa 等
```

### JNI 入口

- `y2.a` 是唯一 native 入口: `static native Object a(int tag, int type, long handle, String url, Object extra)`
- tag `50331649` = `0x3000001` — 对应签名功能
- tag `33554442` = `0x200000A` — 对应 frameSign
- 所有 native 方法通过 `JNI_OnLoad` → `RegisterNatives` 动态注册

### IDA 分析入口点

1. **JNI_OnLoad** @ offset `0x28741c` (从 export 表) — 找 RegisterNatives 调用
2. 从 RegisterNatives 找到 `y2.a` 的 native 实现函数
3. 根据 tag `0x3000001` 找到签名分发逻辑
4. 追踪到 X-Helios 和 X-Medusa 的生成代码

### 已知的 SO 信息

- 文件: `lib/arm64-v8a/libmetasec_ml.so` (~4MB)
- 唯一 export: `JNI_OnLoad`
- 架构: ARM64
- 混淆: 控制流平坦化 + 字符串加密 + 反调试
- 之前 IDA 分析发现: SHA-256 (sub_245354), AES-128-ECB (sub_243F10), AES-128-CBC

### 之前 IDA 发现的加密函数（可能用于 Helios/Medusa）

| 函数 | 算法 | 可能用途 |
|------|------|----------|
| sub_245354 | SHA-256 | Helios 的 hash 部分? |
| sub_243F10 | AES-128-ECB | Medusa 内部加密? |
| AES-128-CBC | 外层加密 | Medusa 外层? |

## App 设备信息（模拟器，用于测试）

```
device_id:  3722313718058683
iid:        3722313718062779
cdid:       e1f62191-7252-491d-a4ef-6936fee1c2f7
openudid:   9809e655-067c-47fe-a937-b150bfad0be9
device:     sdk_gphone64_arm64, google, Android 15, API 35
app:        com.dragon.read v7.1.3.32 (71332)
```

## 必需的 HTTP Headers（除签名外）

```
User-Agent: com.dragon.read/71332 (Linux; U; Android 15; zh_CN; sdk_gphone64_arm64; Build/AP3A.241105.008;tt-ok/3.12.13.20)
Accept: application/json
sdk-version: 2
lc: 101
passport-sdk-version: 5051451        (推荐)
x-tt-store-region: cn-gd             (推荐)
x-tt-store-region-src: did            (推荐)
X-SS-REQ-TICKET: {timestamp_ms}      (推荐)
x-reading-request: {timestamp_ms}-{random_hex}  (推荐)
```

## Frida 测试脚本

测试用的脚本在 `scripts/` 目录：
- `gen_sigs.js` — 生成签名并输出 JSON
- `investigate_algo.js` — 分析签名算法
- `analyze_helios_medusa.js` — 深入分析 Helios/Medusa 结构
- `capture_and_test.js` — 生成 curl 命令

用法（只能用 frida CLI）:
```bash
PID=$(adb shell "ps -A" | grep com.dragon.read | awk '{print $2}' | head -1)
timeout 10 frida -U -p $PID -l scripts/gen_sigs.js 2>&1 | grep "^SIGS_JSON:"
```
