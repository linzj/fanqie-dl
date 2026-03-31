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

## IDA 深度分析结果 (2026-03-31)

### SO 内部函数映射

| 地址 | 函数 | 大小 | 说明 |
|------|------|------|------|
| sub_245630 | SHA-256 full hash | 0x7C | `sha256(data, len, out32)` |
| sub_258A48 | SHA-256 struct wrapper | 0x64 | 从 struct(+12=len, +16=data_ptr) 读取并调用 sha256 |
| sub_258780 | SHA-1 wrapper | 0xB8 | 类似SHA-256但输出20字节 |
| sub_245354 | SHA-256 compression | - | 核心压缩函数 |
| sub_2451FC | SHA-1 init+hash | 0x7C | SHA-1初始值 0xC3D2E1F0 确认 |
| sub_243F10 | AES block encrypt | 4508 | 单block加密 |
| sub_243E50 | AES block wrapper | 0xC0 | 调用 sub_243F10 |
| sub_241E9C | AES key expansion | - | 支持 16/24/32 字节密钥 |
| sub_2450AC | SHA-1 finalize | 0x150 | padding + 20字节输出 |
| sub_243C34 | MD5 hash | - | 标准 MD5 |
| sub_167E54 | XOR string decrypt | - | `out[i] = enc[i] ^ key[i]` |

### 签名调用链

```
JNI_OnLoad (0x2873F4)
  → sub_168324 (初始化/注册)
    → callback sub_2884AC

签名请求:
  sub_29CCD4 (签名入口)
    → sub_29CF58 (签名分发器, CFF混淆)
      → sub_283748 (大签名函数, 5956字节, CFF混淆)
        ↑ 在vtable 0x35DCA0
```

### sub_283748 内部调用分析

这个函数是签名核心，但被 CFF 重度混淆。已确认的内部调用：

| 函数 | 调用次数 | 作用 |
|------|---------|------|
| sub_167E54 (XOR解密) | 7次 | 解密header名 (X-Helios, X-Medusa等) |
| sub_258A48 (SHA-256) | 1次 | 用于签名hash |
| sub_32A1F0 (malloc) | 11次 | 内存分配 |
| sub_15E1A8 (free) | 8次 | 内存释放 |
| sub_248344 | 6次 | 字符串/buffer操作 |
| sub_25BF3C | 5次 | map/dict操作(设置header键值对) |
| sub_2481FC | 4次 | 创建byte buffer |
| sub_26732C | 1次 | 在SHA-256之前调用 |
| sub_270020 | 1次 | 未知 |

### sub_29CF58 签名分发器发现

- 引用了字符串 `"X-BD-KMSV"` — ByteDance KMS版本header
- CFF switch-case 分发，多个状态处理不同签名头
- 调用 sub_28AEEC 获取某种单例/配置对象
- 最终通过 sub_296FD4 或内联代码组装结果

### 签名相关 vtable (0x35DC60)

```
[0]  sub_263C18
[1]  sub_263B98
[2]  sub_284F98
[3]  sub_263A10
[4]  sub_284FA4
[5]  sub_284FAC
[6]  sub_285054  — 调用 vtable[13](a1) 然后另一个方法
[7]  sub_28315C  — 调用 sub_285FC8(v1, 12)
[8]  sub_283748  — ★ 大签名函数 (SHA-256)
[9]  sub_28508C
[10] sub_285094
[11] sub_28509C
```

### 无法继续的原因

1. **CFF混淆**: sub_283748 的控制流完全被平坦化，switch变量驱动所有分支，IDA反编译不完整
2. **字符串加密**: 所有header名字符串通过XOR加密存储，运行时解密
3. **间接调用**: 关键函数通过vtable间接调用 (BLR)，静态分析无法追踪
4. **BSS数据**: 字符串指针表 (off_382FC0..FF0) 指向BSS段，运行时填充，IDB中全为0xFF
5. **密钥未知**: Medusa header中16字节常量 `5a2f84a33e11c62a48d165455509073f` 不是任何已知设备参数的简单hash

### Medusa header 16字节常量排查

已测试以下但都不匹配 `5a2f84a33e11c62a48d165455509073f`:
- MD5/SHA256(device_id), MD5/SHA256(iid), MD5/SHA256(cdid), MD5/SHA256(openudid)
- MD5(device_id+iid), MD5(device_id as LE i64)
- HMAC-MD5(各种key, 各种data)
- 可能是随机生成后服务端注册的密钥，或SO内部派生密钥

## 下一步：运行 Frida native crypto hook

### 目的

通过 hook SO内部的 SHA-256、AES、MD5 函数，在运行时捕获：
1. **X-Helios**: SHA-256 的输入数据 → 看hash的是什么（nonce+URL+key? HMAC?）
2. **X-Medusa**: AES 密钥 + 加密前的明文 → 看加密的是什么
3. **XOR解密字符串**: 确认所有被混淆的header名

### 运行方法

```bash
# 在有 Android 模拟器的机器上执行：
PID=$(adb shell "ps -A" | grep com.dragon.read | awk '{print $2}' | head -1)

# 方案1: 全面 crypto dump
timeout 30 frida -U -p $PID -l scripts/hook_crypto_native.js 2>&1 | tee crypto_dump.txt

# 方案2: 差分分析 (推荐，更清晰)
timeout 30 frida -U -p $PID -l scripts/hook_helios_medusa_deep.js 2>&1 | tee crypto_deep.txt
```

### hook 的 native 函数

| 函数地址 | 说明 | 捕获内容 |
|----------|------|----------|
| 0x245630 | SHA-256 hash | 输入数据(hex) + 输出hash |
| 0x258A48 | SHA-256 wrapper | struct解析后的输入 |
| 0x258780 | SHA-1 wrapper | 输入数据 |
| 0x241E9C | AES key expansion | 密钥(hex) + 密钥长度 |
| 0x243F10 | AES block encrypt | 加密计数 |
| 0x243C34 | MD5 | 调用标记 |
| 0x167E54 | XOR string decrypt | 解密后的明文字符串 |
| 0x283748 | 签名主函数 | 进入/退出标记 |
| 0x29CF58 | 签名分发器 | URL参数 |
| 0x26732C | SHA-256前的处理 | 参数 |

### hook 脚本输出格式

```
======== SIGNATURES ========
  X-Helios = AX82SNTs... (36 bytes)
    hex: 017f3618...
  X-Medusa = ....(966 bytes)
    first 48 bytes: 7264cb69...

======== CRYPTO OPERATIONS ========
  [0] XOR_DEC: "X-Helios"          ← header名解密
  [1] SHA256(len=XX): abcdef...     ← hash输入
      => 4694cb86a4e82a02...        ← hash输出(应该出现在Helios中)
  [2] AES_KEYGEN(keyLen=16): key=xx ← AES密钥
  ...

======== DIFFERENTIAL ANALYSIS ========
  SHA256[0]: DIFFERENT              ← URL相关
  AES[0]: SAME                     ← URL无关(固定key)
```

### 输出后的处理

把 `crypto_dump.txt` 或 `crypto_deep.txt` 的完整输出提交到 repo，或直接贴给 Claude。

从输出中可以提取：
1. **X-Helios 算法**: SHA-256 输入格式 (大概率是 `SHA256(random_4bytes + url_bytes + secret_key)`)
2. **X-Medusa 算法**: AES 密钥 + 加密格式 + 明文结构
3. **所有固定密钥**: 直接从 AES_KEYGEN 输出中获取

有了这些信息就可以在 Rust 中纯实现签名。

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
- **`hook_crypto_native.js`** — ★ hook native crypto函数，dump所有SHA-256/AES操作
- **`hook_helios_medusa_deep.js`** — ★ 差分分析版，用两个不同URL对比crypto操作

用法（只能用 frida CLI）:
```bash
PID=$(adb shell "ps -A" | grep com.dragon.read | awk '{print $2}' | head -1)

# 生成签名
timeout 10 frida -U -p $PID -l scripts/gen_sigs.js 2>&1 | grep "^SIGS_JSON:"

# ★ 深度crypto分析 (推荐)
timeout 30 frida -U -p $PID -l scripts/hook_helios_medusa_deep.js 2>&1 | tee crypto_deep.txt
```
