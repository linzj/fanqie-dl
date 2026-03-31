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

## IDA 深度分析修正 (2026-03-31, 第二轮)

### 重大发现：之前的 Frida hook 识别了错误的函数！

通过 IDA 反编译确认：
- **sub_243F10 = SHA-1 transform**（之前误认为 AES block encrypt）
  - 证据: 常量 `0x5A827999` (SHA-1 K0), ROTL5 (`EXTR W, W, #0x1B`), Ch 函数
- **sub_243E50 = SHA-1 update**（之前误认为 AES wrapper）
  - 处理 64 字节 block，内部调用 sub_243F10
- **sub_2422EC = 真正的 AES block encrypt**（之前从未被 hook！）
  - 使用 S-box 表 qword_93B78, qword_93698, qword_93EF0, qword_94320
- **sub_241E9C = AES key expansion**（这个是对的）

### MD5 Wrapper (0x258530) 分析完成 — 不变换输出

IDA 追踪 MD5 wrapper 的完整流程:
1. `sub_25BED4(16)` — 分配缓冲区
2. `sub_243C34(data, len, fp-0x18)` — 调用原始 MD5，输出到栈
3. `sub_32A1F0(24)` — malloc(24)
4. `sub_2481FC(ptr, fp-0x18, 16)` — 复制 16 字节 MD5 结果到堆
5. `sub_162944(obj, ptr)` — 存入对象
6. 返回

**结论: MD5 wrapper 不变换 MD5 输出，原样传递。** 任务3 完成。

### 完整的 Crypto 函数映射（IDA 确认）

| 地址 | 真实函数 | 之前误认为 | 说明 |
|------|---------|-----------|------|
| sub_243C34 | **MD5** | MD5 ✓ | `md5(data, len, out16)` |
| sub_242FAC | **MD5 update** | - | 调用 sub_24307C (MD5 transform) |
| sub_24307C | **MD5 transform** | - | MD5 核心压缩 |
| sub_243F10 | **SHA-1 transform** | ~~AES block~~ ❌ | 常量 0x5A827999, ROTL5 |
| sub_243E50 | **SHA-1 update** | ~~AES wrapper~~ ❌ | 64字节 block，调用 sub_243F10 |
| sub_2450AC | **SHA-1 finalize** | - | padding + 20字节输出 |
| sub_2451FC | **SHA-1 full** | - | init+update+finalize |
| sub_241E9C | **AES key expansion** | AES key expand ✓ | 支持 16/24/32 字节密钥 |
| sub_2422EC | **AES block encrypt** | **从未被 hook!** | 真正的 AES-128 加密 |
| sub_2429F8 | **AES keygen+encrypt** | - | key expand + block encrypt 一步完成 |
| sub_242A70 | **AES-CBC encrypt** | - | CBC 模式加密 |
| sub_242C98 | **AES-CTR encrypt** | - | CTR 模式: nonce(8)+counter(8) |
| sub_242DE0 | **XOR** | - | `out[i] = a[i] ^ b[i]`，CTR 模式用 |
| sub_259C1C | **AES setup** | - | 模式选择: 0=ECB, 1=CBC, 2=CTR, 3=CFB |
| sub_259CF0 | **AES dispatch** | - | 根据模式调用对应加密函数 |
| sub_258530 | **MD5 wrapper** | MD5 wrapper ✓ | 不变换输出，原样封装 |
| sub_258780 | **SHA-1 wrapper** | SHA-1 wrapper ✓ | |

### AES 加密系统（IDA 完整逆向）

```
sub_259C1C (setup) — 模式分发:
  case 0: ECB — 仅 key expansion (sub_241E9C)
  case 1: CBC — key expansion + IV setup (sub_2429F8)
  case 2: CTR — key expansion + nonce setup (sub_242C20)
  case 3: CFB — key expansion + IV setup (sub_242E40)

sub_259CF0 (encrypt) — 加密分发:
  case 0: ECB — 每 16 字节调用 sub_2422EC
  case 1: CBC — sub_242A70 (XOR前块 + encrypt)
  case 2: CTR — sub_242C98 (encrypt counter + XOR plaintext)
  case 3: CFB — sub_242EB8

sub_242C98 (AES-CTR) 算法:
  for each 16-byte block:
    counter_block = nonce(8 bytes) || bswap64(counter++)
    keystream = AES_ECB(key, counter_block)
    ciphertext = plaintext XOR keystream
```

### 修正后的签名操作顺序

```
[0]  sub_270020 (初始化)
[1]  MD5[0] (URL参数) → H0
[2]  MD5[1] (R+"1967") → H1
[3]  MD5[2] (session UUID) → H2
[4]  MD5[3] (AES key derivation) → H3 = AES key
[5]  AES key expansion (sub_241E9C)
[6]  SHA-1 (sub_258780/sub_2451FC)
[7-52] SHA-1 update × 46 (sub_243E50) — ★ 不是 AES！是 SHA-1！
[53] SHA-1 transform × 1 (sub_243F10) — ★ 不是 AES！是 SHA-1！
[??] AES block encrypt × N (sub_2422EC) — ★ 从未被 hook！Medusa 加密在这里
[54] MD5[4] (常量)
[55] MD5[5] (常量)
```

**关键**: 之前的 hook 完全漏掉了 AES 加密 (sub_2422EC)，并将 SHA-1 误认为 AES。
需要运行 `hook_crypto_v4.js` 来捕获真正的 AES 操作。

## Frida Crypto Hook 结果 (2026-03-31, 第一轮 — 部分错误)

### 核心发现：SHA-256 未被使用，签名用 MD5 + SHA-1 + AES-128

运行 native hook 后发现 IDA 静态分析的假设是错误的：
- **SHA-256 从未被调用** — 0次
- **MD5 被调用 6 次**（标准 MD5，已通过 Java MessageDigest 验证）
- **SHA-1 被调用 1 次** (通过 sub_258780 wrapper)
- **SHA-1 update × 46** (sub_243E50, ~~之前误认为 AES wrapper~~)
- **SHA-1 transform × 1** (sub_243F10, ~~之前误认为 AES block~~)
- **AES-128 密钥扩展 1 次** (sub_241E9C, 正确)
- **AES block encrypt × ?** (sub_2422EC, **从未被 hook!**)
- **XOR 解密 (sub_167E54) 0 次** — 说明 IDA 中 sub_283748 并非实际签名路径

### MD5 调用详情（完整输入输出）

| # | 输入 | 长度 | 输出 | 说明 |
|---|------|------|------|------|
| 0 | URL query string (从 `ac=wifi&aid=1967&...` 开始) | 380 | H0 (每次不同) | URL 参数哈希 |
| 1 | `R + "1967"` (R = Helios前4字节随机) | 8 | H1 (每次不同) | 随机数+aid 哈希 |
| 2 | `{session_uuid}0` (如 `7e8f14d8-3cc8-4350-bc26-2b9d48e98ebf0`) | 37 | H2 (每session不同) | 会话UUID哈希 |
| 3 | `"1967" + ab7cfe85 + "1967"` | 12 | `059874c397db2a6594024f0aa1c288c4` | **= AES-128 密钥！** |
| 4 | `abd3c178a46d39ad4fb312d3d23941c3` (固定16字节) | 16 | `7916c9e4604cf3e707159c25532f6fd3` | 固定常量 |
| 5 | `447c28b7a74153a038708f7aa92f9575` (固定16字节) | 16 | `d9c02b7a8cb156054008b36571298df6` | 固定常量 |

### AES-128 密钥

```
密钥 = MD5("1967" + 0xab7cfe85 + "1967") = 059874c397db2a6594024f0aa1c288c4
密钥来源: MD5(aid_str + magic_4bytes + aid_str)
magic_4bytes = ab 7c fe 85 (固定常量，嵌入 SO 中)
```

### SHA-1 调用

```
输入 (12 bytes): ad 9f 20 ff 31 39 36 37 ab 7c fe 85
               = magic_4bytes_2 + "1967" + magic_4bytes
输出: 未成功捕获 (outPtr 为 NULL)
```

### 签名操作顺序

```
[0]  sub_270020 (初始化)        ← 调用自 0x26fde0 (函数 0x26fc98)
[1]  MD5[0] (URL参数)           ← 调用自 0x286df8 → 0x258530(MD5 wrapper)
[2]  MD5[1] (R+"1967")         ← 调用自 0x288bd4 → 0x258530
[3]  MD5[2] (session UUID)     ← 调用自 0x2887e8 → 0x258530
[4]  MD5[3] (AES key)          ← 调用自 0x26351c → 0x258530
[5]  AES key expansion         ← 调用自 0x25a3f4 (函数 0x259dbc)
[6]  SHA-1                     ← 调用自 0x26351c
[7-51] AES_WRAP × 46           ← Medusa body 加密
[52] AES_BLOCK × 1             ← 单次 AES block 加密
[53] MD5[4] (常量)             ← 调用自 0x2887e8 → 0x258530
[54] MD5[5] (常量)             ← 调用自 0x2887e8 → 0x258530
```

### 函数调用链（Frida 发现 vs IDA 分析）

```
实际运行时路径 (Frida hook):
  JNI → r4.onCallToAddSecurityFactor()
    → y2.a(tag=0x3000001, ...)
      → [某 native 入口]
        → 0x26fc98 (初始化, 调用 sub_270020)         ← 调用自 0x17ba0c
        → 0x286df8 (调用 MD5 wrapper 哈希 URL)
        → 0x288bd4 (调用 MD5 wrapper 哈希 random+aid)
        → 0x2887e8 (调用 MD5 wrapper 哈希 UUID/常量)
        → 0x26351c (AES 密钥派生 + SHA-1)
          → 0x259dbc (AES 初始化)
        → [AES 加密 Medusa body]
        → 0x2887e8 (调用 MD5 wrapper 哈希固定常量)

IDA 静态分析推测的路径 (部分不准确):
  sub_29CCD4 → sub_29CF58 → sub_283748
  ↑ 这些函数在运行时从未被 hook 触发
```

### 关键函数地址（修正版）

见上方 "完整的 Crypto 函数映射" 表。

运行时调用点（Frida LR 确认）:
| 地址 | 调用点 | 说明 |
|------|--------|------|
| 0x258530 | MD5 wrapper | 所有 MD5 调用都经过此函数 |
| 0x286df8 | MD5(URL) 返回点 | 在函数 0x286b58 内 |
| 0x288bd4 | MD5(R+"1967") 返回点 | 在 thunk 0x288bbc 内 |
| 0x2887e8 | MD5(uuid/const) 返回点 | 在 thunk 0x2887d0 内 |
| 0x26351c | AES key + SHA-1 | 在 thunk 0x263504 内 |
| 0x25a3f4 | AES key expansion | 在函数 0x259dbc 内 |
| 0x26fc98 | 初始化 | 调用 sub_270020, 从 0x17ba0c 调用 |

### X-Helios 未解之谜

**已排除的假设** (用 Java MessageDigest/Cipher 在 Frida 中验证):

Helios = R(4 bytes) + part1(16 bytes) + part2(16 bytes)

以下都**不匹配** part1 或 part2:
- `MD5(H0 + H1)`, `MD5(H1 + H0)`, `MD5(H0 + R)`, `MD5(R + H0)`
- `H0 XOR H1`, `H0 XOR H4`, `H0 XOR H5`, `H1 XOR H4`, `H1 XOR H5`
- `AES_ECB(key, H0)`, `AES_ECB(key, H1)`
- `AES_ECB(key, H0) XOR H1`, `AES_ECB(key, H1) XOR H0`
- `AES_CBC(IV=0, H0||H1)`, `AES_CBC(IV=H2, H0||H1)`, etc.
- `AES_DEC(part1)`, `AES_DEC(part2)` 的结果也不匹配已知值
- `MD5(H0+H2+H1)`, `MD5(H1+H0+H2)`, `MD5(part1+H0)`, etc.
- HMAC-like: `MD5(H5 || MD5(H4 || H0))` etc.

**结论**: Helios 的 32 字节 hash 部分由 CFF 混淆的内联代码生成，不直接调用标准 crypto 函数。可能涉及:
1. 自定义字节变换/置换
2. 查表操作
3. 多步 XOR + rotate + add 组合
4. 或完全不同的算法路径

### X-Medusa 部分解析

```
结构: 24 bytes header + ~936 bytes encrypted body

Header:
  bytes 0-3:   timestamp-derived (非直接 LE, 有 XOR/偏移)
  bytes 4-19:  与 session/device 相关 (同一 session 内固定)
  bytes 20-21: random/counter (每次调用不同)
  bytes 22-23: 0x0001 (常量)

Body 加密 (IDA 确认):
  AES-128 key = 059874c397db2a6594024f0aa1c288c4
  模式: ECB/CBC/CTR 之一 (通过 sub_259CF0 分发，需要运行 hook_crypto_v4.js 确认)
  可能是 AES-CTR (sub_242C98): nonce(8 bytes) || counter_be64
  明文内容: 可能包含 SHA-1 hash 结果 (46 次 SHA-1 update 处理的数据)

关联的 SHA-1:
  46 次 SHA-1 update (sub_243E50) + 1 次 SHA-1 transform (sub_243F10)
  这些之前被误认为 AES 操作
  SHA-1 可能用于: Medusa 明文的完整性校验，或构建 Medusa 明文内容
```

## IDA 逆向任务

### 任务1: 逆向 X-Helios 的 32 字节 hash 构造 (最高优先)

**目标**: 搞清楚 Helios = R(4) + part1(16) + part2(16) 中 part1/part2 的生成算法

**已知**:
- 输入: H0=MD5(url_params), H1=MD5(R+"1967"), H2=MD5(session_uuid), H4/H5=固定常量
- 输出: part1(16 bytes) + part2(16 bytes)
- 不是 MD5/AES/SHA 的简单组合（已在 Frida 中穷举排除）
- 生成代码在 CFF 混淆的内联逻辑中

**IDA 分析入口**:
1. 去 **0x288bd0** (BL 到 MD5 wrapper 0x258530 的指令)
2. 这是一个 thunk: `str x30,[sp,#-0x10]!; bl md5_wrap; ldr x30,[sp],#0x10; ret`
3. 找到**调用这个 thunk 的父函数** — 那就是签名主函数
4. 在父函数中追踪: MD5 wrapper 返回后（x0=NULL），H1 结果从哪里取出、如何变成 part1/part2
5. 注意: 父函数使用 CFF 混淆，switch 变量驱动所有分支

**也可以从另一个方向**:
- 0x286df8 是 MD5(url_params) 的返回点
- 往上找调用 0x286df4 (BL指令) 的函数 — 同一个签名主函数
- 这个函数应该在 0x286xxx-0x288xxx 范围内

### 任务2: 逆向 X-Medusa 的明文结构

**目标**: 搞清楚 AES-128 加密前的明文是什么

**已知** (IDA 第二轮更新):
- AES-128 key = `059874c397db2a6594024f0aa1c288c4`
- AES 加密通过 sub_259CF0 分发，支持 ECB/CBC/CTR/CFB 四种模式
- 之前认为的 "46 次 AES" 实际是 SHA-1 update
- 真正的 AES encrypt (sub_2422EC) 从未被 hook

**Frida 验证** (最高优先):
1. 运行 **`hook_crypto_v4.js`** — 会 hook 真正的 AES block encrypt (sub_2422EC)
2. 观察 AES_DISPATCH 的 mode 值确认加密模式 (0=ECB, 1=CBC, 2=CTR, 3=CFB)
3. 如果是 CTR: 捕获 nonce 和 counter 初始值
4. 捕获 XOR 操作 (sub_242DE0) 来获取明文

**也可以用已知 key 解密**:
- 捕获完整 Medusa hex
- 根据确认的模式 + IV/nonce 解密 body 部分 (跳过前 24 字节 header)

### 任务3: ~~确认 MD5 wrapper 是否变换输出~~ ✅ 已完成

**结论**: MD5 wrapper (0x258530) **不变换输出**。
IDA 追踪完整流程: MD5 → malloc → 复制到堆 → 存入对象 → 返回。原样传递。

### 下一步 (优先级排序)

1. **运行 `hook_crypto_v4.js`** — 最高优先！这会揭示:
   - Medusa 用的 AES 模式 (ECB/CBC/CTR?)
   - AES block encrypt 的真实调用次数
   - CTR 的 nonce/counter (如果是 CTR 模式)
   - XOR 操作中的 Medusa 明文

2. **运行 `hook_helios_v3.js`** — 测试更多 Helios 组合:
   - 包括 H3 (AES key) 作为 XOR key
   - SHA-1 输出作为组件
   - 8 个样本的统计分析

3. 根据 v4 输出, 在 Rust 中实现 Medusa

### 验证方法

```bash
PID=$(adb shell "ps -A" | grep com.dragon.read | awk '{print $2}' | head -1)
timeout 30 frida -U -p $PID -l scripts/hook_crypto_v4.js
# 对比输出的 AES 操作和 Medusa 结构
timeout 45 frida -U -p $PID -l scripts/hook_helios_v3.js
# 分析 Helios 样本
```

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

### 签名生成
- `gen_sigs.js` — 生成签名并输出 JSON
- `gen_and_write.js` — 生成签名写入设备文件
- `gen_curl.js` — 生成签名输出 shell 变量

### Crypto Hook (核心)
- **`hook_crypto_v4.js`** — ★★★ 修正版! Hook 真正的 AES (sub_2422EC) + 正确标识 SHA-1
- **`hook_helios_v3.js`** — ★★ Helios 多样本 + 更多组合测试 (含 H3/SHA1)
- `hook_crypto_v3.js` — ⚠ 有错误: 把 SHA-1 当成 AES，漏掉真正的 AES
- **`hook_helios_multi.js`** — 固定 URL 多次签名收集 (R, H1, part1, part2) 样本
- **`hook_helios_verify.js`** — 用 Java MD5 测试 Helios 算法假设
- **`hook_helios_verify2.js`** — 用 Java AES 测试 Helios 算法假设
- `hook_crypto_v2.js` — crypto dump v2 (带差分分析)
- `hook_lr_only.js` — 捕获所有 crypto 函数的 LR (返回地址/调用者)
- `hook_find_parent.js` — 从 LR 找上层调用函数
- `hook_md5_wrapper.js` — 分析 0x258530 MD5 wrapper 的参数和返回值

### 分析工具
- `hook_disasm.js` — 反汇编 MD5 wrapper 和调用点代码
- `hook_find_crypto2.js` — 搜索 SO 中的 crypto 常量位置 + JNI 入口
- `investigate_algo.js` — 签名算法基本分析
- `analyze_helios_medusa.js` — Helios/Medusa 结构分析

### 测试
- `capture_and_test.js` — 生成 curl 命令
- `hook_crypto_native.js` — 原始 crypto hook (已被 v3 替代)
- `hook_helios_medusa_deep.js` — 差分分析版 (已被 v3 替代)

用法（只能用 frida CLI）:
```bash
PID=$(adb shell "ps -A" | grep com.dragon.read | awk '{print $2}' | head -1)

# 生成签名
timeout 10 frida -U -p $PID -l scripts/gen_sigs.js 2>&1 | grep "^SIGS_JSON:"

# ★★★ 修正版 crypto 分析 (hook 真正的 AES!)
timeout 30 frida -U -p $PID -l scripts/hook_crypto_v4.js

# ★★ Helios 多样本分析 (含更多组合测试)
timeout 45 frida -U -p $PID -l scripts/hook_helios_v3.js

# 旧版 (有错误，仅供参考)
# timeout 30 frida -U -p $PID -l scripts/hook_crypto_v3.js

# 调用链追踪
timeout 30 frida -U -p $PID -l scripts/hook_lr_only.js
```
