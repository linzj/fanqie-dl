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

### 签名调用链（2026-04-02 修正）

```
Java:
  r4.onCallToAddSecurityFactor(url, headersMap)
    → y2.a(tag=0x3000001, type=0, handle, url, headersArray)
      → SO+0x26e684 (JNI native 入口，通过 RegisterNatives 注册)

SO 内部:
  SO+0x26e684: JNI thunk — 重排参数 + CFF obfuscated dispatch
    rearranges: x0=tag, x1=JNIEnv, x2=type, x3=handle, x4=url, x5=extra
    → obfuscated dispatch (BR X0, based on tag)
      → ... → SO+0x2869f0 (CFF 签名函数，包含 0x286DF4)
        → 内部调用 MD5, SHA-1, AES, CREATE_BUF, MAP_SET 等

返回:
  String[] 键值对 → 包含 X-Helios, X-Medusa 等
```

**之前 IDA 分析的调用链 (sub_29CCD4 → sub_29CF58 → sub_283748) 未被实际调用！**
Frida hook 验证：sub_29CCD4, sub_283748, sub_29CF58 在签名过程中 0 次命中。

### y2.a JNI 函数签名

```java
public static native Object y2.a(int tag, int type, long handle, String url, Object extra)
```

| 参数 | JNI 寄存器 | 重排后 | 含义 |
|------|-----------|--------|------|
| JNIEnv* | x0 | x1 | JNI 环境指针 |
| jclass | x1 | (dropped) | 类引用 |
| tag | x2 | x0 | `0x3000001` = 签名 |
| type | x3 | x2 | `0` |
| handle | x4 | x3 | MetaSec native handle |
| url | x5 | x4 | 请求 URL (jstring) |
| extra | x6 | x5 | headers 数组 (jobject) |

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
| sub_2422EC | **AES block encrypt (标准入口)** | **CFF 代码不用此入口!** | 真正的 AES-128 加密 |
| 0x242640 | **AES block encrypt (替代入口)** | **★ 实际被调用!** | CFF 代码用此入口，跳过标准序言，从 [ctx+0xF0] 读 round key |
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

## Frida 第三轮结果 (2026-03-31) — AES 替代入口发现

### 重大突破：AES block encrypt 有两个入口！

通过 simpleperf 采样发现 AES block encrypt 函数内部有执行（28 个采样），但 Frida hook 入口 0x2422EC 显示 0 次调用。反汇编确认：

```
sub_2422EC (标准入口): STP x26,x25,[sp,#-0x40]!  — 从 [ctx+0x00] 读 round key
sub_242640 (替代入口): STP x24,x23,[sp,#-0x30]!  — 从 [ctx+0xF0] 读 round key
```

CFF 混淆代码调用 **0x242640 (替代入口)**，绕过标准入口！Hook 0x242640 后成功捕获：

### AES-ECB 加密：17 次调用

```
调用者: 0x25AB84 (在 sub_259DBC AES setup 函数内部)
所有调用都是 AES-ECB (单 block 加密)

#   输入 (plaintext)                      输出 (ciphertext)
1   98b7e200553b0e2bbff78bfa31499be4      ad9f20ff6a5d228c085f342a23325a2f
2   3ecc4dccbc9a24b6d7bbf244bdd1b763      4a97e5543ce59500f3006aa27c0bf902
3   b09d7d3bb048971eeb65a783b352324f      efc4a33faf945825656a0b9bf59ee660
4   3bf9396254b33fad8b90700f1952638d      8692ffd5250368320bbf22b8407d5675
5   08bea339160da1881ca914fb71e358ff      6ddcc0e774454774bca6c049aa9637d6
6   f6145398c1c399144e3b96f3682dd59d      76270db7cd3bbdc5336896a2c0c4d160
7   0e209a874f668a19114465c1b0fe4ba2      47133eb87d193afbe35294a46b494cdc
8   551d63a051ba944726aaa30397fab2e6      d40dab53e89286c72448194293c94dee
9   1778d35426196e62800b2831ea30ebd3      83f6fa82011b7339f21531b07d9c89d3
10  82650f33fbe7d1c7ab925cfea027bbb3      08164a6836b5a3155c00d8d03f4d07ce
11  b4055c36e66da379766ce917c9207429      873b1dc2f453910ea2140760314dba8f
12  be2abaac47ba9f8ebc7a6c3452e8dd6c      663ce9ab0c70862e432eb4e50006f4d8
13  f875bead24d939c08604f7a71ddb6787      828a0e21e6e54213930cde448f9e5683
14  0f9adac992a23304ca76d2678c33ad07      210b45ffb47fabdb6b9225d524377ebf
15  fac430ccd1f5f522f060ddf05ae0855e      6dd1763b5a4e4146d65b0de78fda1187
16  6b714b66a8b02da97f18e71c74493579      6ed01f2953415511b8701c8e34c4788e
17  8bc43c46fb6c51a28af469749346b436      20a02f5565822650198ce14452775801
```

### 关键观察

1. **17 blocks × 16 bytes = 272 bytes AES**，但 Medusa body = 936 bytes
   → AES 只加密了一部分，剩下 ~664 bytes 用其他方式生成
2. **输出 #1 前 4 字节 `ad9f20ff` = SHA-1 输入的前 4 字节！**
   → SHA-1 的 12 字节输入 `ad9f20ff 31393637 ab7cfe85` 来自 AES 输出
   → magic_4bytes_2 = AES_ECB(key, counter_block)[0:4] ← 不是固定常量！
3. **输入是递增的计数器块** — 这是 AES-CTR 模式的 keystream 生成
   → 17 个 counter blocks 经 AES-ECB 加密产生 272 bytes keystream
   → keystream XOR 明文 = Medusa body 的前 272 bytes
4. 操作顺序: MD5×4 → AES key expand → **AES-ECB×17** → SHA-1 → MD5×2
5. 调用者 0x25AB84 在 sub_259DBC (AES setup) 内部 — AES-CTR 加密是在 setup 函数中完成的

### AES-CTR 计数器分析

```
Counter block 1: 98b7e200 553b0e2b bff78bfa 31499be4
Counter block 2: 3ecc4dcc bc9a24b6 d7bbf244 bdd1b763
Counter block 3: b09d7d3b b048971e eb65a783 b352324f
...
```

这些计数器块看起来不是简单的递增整数 — 可能是加密后的计数器或者用某种方式派生的。需要在 IDA 中分析 0x25AB84 周围的代码来确认计数器生成逻辑。

### SHA-1 的 46 次 update = 手动 padding

```
Update 1: 12 bytes → ad9f20ff 31393637 ab7cfe85
Update 2: 1 byte  → 80 (SHA-1 padding start)
Update 3-45: 1 byte → 00 each (43 zero bytes)
Update 46: 8 bytes → 0000000000000060 (length in bits = 96)
Total: 64 bytes = one SHA-1 block
```

SHA-1 输入 = `AES_output[0:4] + "1967" + magic_bytes`
SHA-1 输出 = `1509be656b6620abd6cc6c48e8156dbe5927c8f8` (固定，因为输入常量)

### Helios 仍未解决

8 个样本测试了所有已知组合 (XOR, MD5, SHA-1, H3 等)，无一匹配。
- part1 XOR H1 不是常量
- part2 XOR H1 不是常量
- part1 XOR part2 不是常量
- 任何 MD5(Hx+Hy) 组合都不匹配

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

### 任务2: 逆向 X-Medusa 的完整加密流程

**目标**: 搞清楚 Medusa 936 字节 body 的完整生成算法

**已知** (Frida 第三轮):
- AES-128 key = `059874c397db2a6594024f0aa1c288c4`
- AES block encrypt 通过**替代入口 0x242640** 调用（标准入口 0x2422EC 被绕过）
- 调用 **17 次** AES-ECB，产生 272 bytes (17×16)
- 调用者: 0x25AB84 (在 sub_259DBC 内部)
- 但 Medusa body = 936 bytes，远超 272 bytes
- SHA-1 的 46 次 update 只是手动 padding 一个 12 字节输入，不参与加密

**IDA 分析入口**:
1. 去 **0x25AB84** (AES block encrypt 的调用点)
2. 往上分析: 17 个 counter block 是怎么生成的 (不是简单递增)
3. 分析 AES 之后的代码: 272 bytes keystream 如何 XOR 明文
4. 搞清楚剩余 ~664 bytes (936-272) 怎么生成 — 可能是明文直接拼接，或另一种加密
5. Medusa header (24 bytes) 的构造逻辑

**关键线索**:
- AES 输出 #1 前 4 字节 `ad9f20ff` = SHA-1 输入的前 4 字节
- 所有 17 次 AES 调用都来自同一个 LR (0x25AB84)
- sub_259DBC 是一个 CFF 混淆的大函数

### 任务3: ~~确认 MD5 wrapper 是否变换输出~~ ✅ 已完成

**结论**: MD5 wrapper (0x258530) **不变换输出**。
IDA 追踪完整流程: MD5 → malloc → 复制到堆 → 存入对象 → 返回。原样传递。

### IDA 深度分析结果 (2026-03-31, 第三轮)

#### AES 加密分发系统（两个并行实现）

IDA 确认存在**两个**加密分发函数:
- `sub_259CF0`: 使用标准入口 `sub_2422EC` (从 [ctx+0x00] 读 round key)
- `sub_25AB1C`: 使用替代入口 `sub_242640` (从 [ctx+0xF0] 读 round key) — **实际被调用的版本**

`sub_25AB1C` 的完整反编译（未被 CFF 混淆!）:
```c
int64 sub_25AB1C(int **a1, int64 a2, int64 a3, int64 a4, uint a5) {
    switch (**a1) {
        case 0: // ECB
            for (uint i = 0; i < a5; i += 16)
                sub_242640(a2, a3 + i, a4 + i);  // AES block encrypt
            return 0;
        case 1: return sub_242B18(a2, a3, a4, a5);  // CBC
        case 2: sub_242C98(a2, a3, a4, a5); return 0; // CTR
        case 3: sub_242EB8(a2, a3, a4, a5); return 0; // CFB
    }
}
```

Frida 确认 mode=0 (ECB)，17 次循环每次加密 16 字节。

#### sub_259DBC (AES setup, 0xBB4 字节 CFF) 加密调用流程

从反汇编追踪:
```
0x25A3E0: arg0 = mode_context (栈上)
0x25A3E4: LDR X8, [vtable]         ; 加载 key expansion 函数指针
0x25A3F0: BLR X9                    ; 调用 key expansion

0x25A3FC: LDRSW X24, [struct+0xC]   ; data_len = struct.len
0x25A404: BL malloc(data_len)        ; 分配输出缓冲区
0x25A408: LDR X1, [struct+0x10]      ; src_data = struct.data_ptr
0x25A414: BL memcpy(out, src, len)   ; 复制明文到输出缓冲区
0x25A444: BLR X8                     ; AES_ECB_encrypt(ctx, key, data, data, len) — in-place!
```

**关键**: AES 加密是 **in-place** 操作，输入=输出缓冲区 (X2==X3)。
明文长度来自 `[struct+0xC]`，明文数据来自 `[struct+0x10]`。

#### Base64 编码链

- `sub_2456AC` — 标准 base64 编码器，字符表在 `0x95C80` (标准 A-Za-z0-9+/)
- `sub_258C84` — wrapper: 先算大小，malloc，再编码
- `sub_258C14` — 高层入口，被 CFF 代码块调用
- 输入: 对象 `[obj+0x10]` = data ptr, `[obj+0xC]` = data len

#### 签名编排函数

- `sub_17B96C` (348字节): 顶层编排函数
  1. 调用 `sub_26FE2C` — 某种初始化
  2. 调用 `sub_26FC94` — 键值对构建器 (遍历签名请求的参数对)
  3. 通过 vtable[4] 调用签名核心 (arg=312)
  4. 调用 `sub_271384` — 最终结果处理

- `sub_26FC94` (408字节): 参数对处理
  1. 通过 vtable 获取参数数量和每对参数
  2. 对每对参数调用 `sub_26FE2C` 转换
  3. 创建缓冲区并通过 `sub_25BF3C` 添加到 map
  4. 最后调用 `sub_270020` 初始化

#### D-810 反混淆结果: 对此 CFF 无效

已安装 D-810 (OLLVM unflattening 配置, 177 条指令规则 + 2 条块规则)。
**结论**: D-810 的 Unflattener 无法处理此 CFF 变种。

此二进制的 CFF 特征:
- 使用 **计算型分支跳转** (ADRP+ADD+arithmetic+BR), 不是标准 switch-variable
- 多层间接寻址 + 常量混淆
- IDA 无法解析 BR 目标，导致 JUMPOUT

## hook_correlate.js 结果 (2026-03-31, 第四轮)

### 关联分析结论：所有已知组合均不匹配 Helios

运行 5 个样本的全面关联分析，测试了以下所有组合，**无一匹配** part1 或 part2：

| 测试类型 | 测试内容 | 结果 |
|---------|---------|------|
| 直接匹配 | AES[0..16].output == part1/part2 | ❌ |
| 直接匹配 | AES[0..16].input == part1/part2 | ❌ |
| XOR | AES[j].out XOR H0/H1/H2/H3/H4/H5/SHA1 == part1/part2 | ❌ |
| XOR | AES[j].in XOR H0/H1/H2/H3/H4/H5/SHA1 == part1/part2 | ❌ |
| AES-ECB | AES(H0^H1), AES(H0^H2), AES(H1^H2), etc. == part1/part2 | ❌ |
| AES-ECB+XOR | AES(combo) XOR Hx == part1/part2 | ❌ |
| MD5 | MD5(H1+AES0out), MD5(AES0out+H1), MD5(H0+AES0out), etc. == part1/part2 | ❌ |

### 重要发现：AES 块在相同 URL 下完全恒定

```
Cross-sample analysis:
  AES[0..16] same_input = true (全部)
  All AES inputs constant: true
```

**所有 17 个 AES-ECB 块输入输出完全相同**（因为是相同 URL → 相同 Medusa 明文 → 相同 AES 加密结果）。
这意味着 AES 输出不参与 Helios 生成（Helios 每次都变，但 AES 输出是常量）。

### 确认的数据

```
5 samples, each: 17 AES blocks, 6 MD5 calls
Constants: H0, H2, H3, H4, H5, SHA1 (不变)
Variable:  R (random 4 bytes), H1=MD5(R+"1967"), part1, part2
Medusa body: 960 bytes total, 272 from AES, 664 unaccounted
```

### Helios 算法排除总结

至此，已系统排除的所有假设：
1. ❌ 标准 crypto 函数输出的简单组合（MD5/AES/SHA1/XOR）
2. ❌ AES 块输出与 Helios 无关（AES 是常量，Helios 是变量）
3. ❌ 任何两个 hash 的 XOR
4. ❌ AES-ECB 加密任何 hash 组合
5. ❌ AES-ECB 加密后再 XOR 任何 hash
6. ❌ MD5 链（concat 后再 hash）

**结论**：Helios part1/part2 由 CFF 内联代码生成，不经过任何已 hook 的标准 crypto 函数。
需要 IDA 逆向 CFF 混淆代码才能找到算法。

## ARM64 模拟器方案

### 方案演进

1. **Unicorn** (2026-03-31): MD5 验证成功，但 CFF 混淆代码执行太慢（10+ 分钟），不可行
2. **dynarmic JIT** (2026-04-01): ARM64 JIT 重编译器，10-100x 快于 Unicorn，当前方案

### dynarmic 模拟器进展 (2026-04-01)

#### 已解决的技术问题

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| 40-bit 地址空间 | dynarmic page table 只支持 1TB，Android 地址 >43-bit | Rust 端传 null page_table，禁用 page table 快速路径，纯 hash map |
| macOS PROT_EXEC | `mmap(RWX)` 返回 EACCES | mem_map 用 prot=3 (RW only)，dynarmic 不需要 host EXEC 权限 |
| LSE 原子指令 | dynarmic 不支持 CAS/LDADD/LDSET/SWP 等 LSE atomics | 扫描非 SO 范围代码，替换为 SVC #0x500，在回调中模拟全部 opc 变体 |
| MemoryReadCode 不触发 callback | C 代码 MemoryRead32 没有 unmapped callback | 修改 dynarmic.cpp，MemoryRead32 和 MemoryReadCode 加 callback + HaltExecution |
| ClearHalt 不完整 | emu_start 只清 UserDefined halt，不清 MemoryAbort | 在 emu_start 加 ClearHalt(MemoryAbort) + ClearHalt(CacheInvalidation) |
| 缺页检测慢 | unmapped callback 映射零页导致死循环 | 不映射，设 miss_flag atomic，main loop 检查后立刻 break |
| futex 死锁 | pthread_mutex_lock 在单线程中等待永远不会释放的锁 | futex WAIT 时强制写 0 到 futex 地址（解锁）+ 返回 -ETIMEDOUT |
| range 映射重叠 | dynarmic_mmap 遇到已存在 page 返回 4 | 合并 page-aligned 范围后统一映射 |
| SVC patch 破坏 CFF | CFF 使用指令地址作为 dispatch 常量 | **完全不 patch SO 代码**，外部函数通过 dump 的 libc 原生执行 |

#### 迭代缺页 dump 框架

核心思路：只 dump SO + 栈，emulator 执行时遇到缺页 → 记录 → 从设备补 dump → 重跑。

1. `scripts/dump_so_only.py` — 通过 `/proc/pid/mem` dump SO + 栈（0.5 秒）
2. `scripts/dump_pages.py` — 按缺页地址查找模块，dump 整个模块所有 range
3. Emulator 的 unmapped callback 记录缺页，设 miss_flag 停止执行
4. 典型 8 次迭代完成所有缺页补 dump（libc、libc++、liblog 等）

#### 当前状态 (2026-04-02 更新)

##### 已解决 (全流程模拟器)
- ✅ dynarmic JIT 全链路通：加载 memdump → patch LSE → 执行 → syscall 处理 → 缺页迭代
- ✅ Hook RegisterNatives → 找到 `y2.a` native 入口 = **SO+0x26e684**
- ✅ 解码 JNI thunk 参数重排逻辑（x0=tag, x1=JNIEnv, x2=type, x3=handle, x4=url, x5=extra）
- ✅ TPIDR_EL0 = `stack_and_tls_rw_end - 0x3580`（偏移固定，已验证）
- ✅ Fake JNIEnv 框架：232 个 SVC stub，15 个 JNI 函数已实现
- ✅ JNI 调用正常：NewStringUTF("utf-8") → getBytes → GetByteArrayRegion → 获取 URL 字节
- ✅ MTE/TBI 支持：dynarmic.cpp 的所有内存回调加了 `strip_tag` 去掉 top byte
- ✅ `emu_step` 单步 API 用于调试 trace
- ✅ 迭代缺页 dump 框架稳定（dump_clean.py + dump_pages.py）
- ✅ Frida spawn 获取 handle 值可用

##### 核心阻塞：handle 数据的进程一致性问题

**根本矛盾：handle 必须来自 Frida 进程，但 Frida 会污染进程内存。**

MetaSec native handle 是一个 C++ 对象（~4KB），内部包含：
- SO 代码指针（vtable 等）→ 可以重定位
- **堆对象指针**（session state, crypto context 等）→ **无法在不同进程间重用**
- **其他库指针**（libc++ std::string 等）→ **无法重定位**

已尝试的方案及失败原因：

| 方案 | 结果 | 失败原因 |
|------|------|----------|
| handle=0（fake） | 函数 7612 步后返回 NULL | CFF dispatch 检查 handle 有效性 |
| handle=全零 4KB | 同上 | 同上 |
| Frida 进程 dump + Frida 范围填 RET | Scudo ERROR: internal map failure | bytehook 修改了 libc 函数入口，RET 跳过了 malloc 等关键函数 |
| 干净进程 dump + Frida 进程 handle（重定位 SO 指针） | 函数执行但 code fetch miss 不断增长 | handle 内的非 SO 指针（堆/库）全部无效 |
| 替换 libc 代码段为干净版本 | SP 无限下降（栈溢出） | libc GOT 仍指向 Frida agent，内部调用走错路径 |

##### 错误的尝试（教训）

1. **"完全离线 emulator" 方案过于理想化** — handle 对象不是简单的配置数据，它包含运行时分配的堆指针、动态链接的 vtable 等，**必须来自同一个活着的进程**
2. **跨进程重用 handle 数据不可行** — 即使重定位了 SO 指针，堆指针、libc++ 对象指针、其他库 vtable 全部无效
3. **Frida 代码段 + 干净数据段 != 干净进程** — bytehook 不仅修改代码段（函数入口），还修改 GOT 表（数据段中的函数指针）
4. **Frida 页面填 RET 太粗暴** — 被 hook 的是 malloc/free/pthread 等关键函数，跳过它们会导致内存分配器崩溃

##### 正确的方向

**必须从同一个进程获取所有数据**：内存 dump + handle + 系统库，全部来自同一 PID。

可行方案：
1. **`frida -f` spawn + 同进程完整 dump** — 用 Frida spawn app，在同一进程中读取 handle 并 dump 全部内存。然后用 `/apex/.../libc.so` 的干净代码替换 libc 代码段 **和** GOT 表
2. **构造最小化 handle** — 逆向 handle 结构，只填入签名需要的字段（session UUID, device ID, crypto keys），不需要真实堆指针
3. **on-device 执行** — 放弃 emulator，在设备上直接 `dlopen` SO 并调用签名函数

##### 当前进程环境

- App: `com.dragon.read` v7.1.3.32
- 反调试：ptrace/lldb 会被检测，进程挂起
- 反 Frida：`frida -U -p PID` attach 后进程很快崩溃（杀 frida-server 时连带崩）
- `frida -f` spawn 可用，但进程内有 bytehook trampolines
- bytehook (libbytehook.so) 修改 libc 函数入口跳转到 Frida agent

#### 文件

```
src/signer/emulator.rs      — dynarmic JIT 模拟器 (~1600 行)，含 fake JNIEnv + MTE + handle 加载
dynarmic-sys-local/
  vendor/dynarmic/dynarmic.cpp — MTE strip_tag + emu_step + MemoryReadCode callback
  src/lib.rs                   — emu_step Rust wrapper
scripts/
  dump_clean.py              — /proc/pid/mem 快速 dump（SO + libc + libc++ 等）
  dump_pages.py              — 迭代缺页 dump（按模块，过滤 Frida）
  get_handle.js              — Frida hook y2.a 获取 handle + dump 内存
  get_handle_save.js         — Frida hook 保存 handle 到设备文件
  parse_handle_dump.py       — 解析 Frida 输出的 handle hex dump
  hook_register_natives.js   — Hook RegisterNatives 找 JNI native 入口
  dump_regs_wait.js          — Frida hook 等待自然触发签名
lib/
  memdump.bin                — 进程内存 dump（当前是干净进程但 handle 不匹配）
  handle_dump.bin            — MetaSec native handle dump（来自不同进程，指针无效）
  regs_only.txt              — TPIDR_EL0
  frida_ranges.txt           — Frida agent 地址范围
```

## Helios 生成流程破解 (2026-03-31, 第五轮)

### 完整的 Helios 生成链路（Frida 确认）

```
1. MD5(URL_params) → H0                              [已知]
2. R = random 4 bytes                                 [已知]
3. MD5(R + "1967") → H1                               [已知]
4. CREATE_BUF(4)  at LR=0x16aa4c → R (4 bytes)       [已知]
5. CREATE_BUF(32) at LR=0x287b44 → H1 ASCII hex       "bb7a9a17c05b0a773849723adc3bc5af"
6. CREATE_BUF(26) at LR=0x287b80 → "{ts}-{dev_id}-1967"  "1774952267-1394812046-1967"
7. B64_ENCODE     at LR=0x288c20 → base64(36 bytes)   [调用 sub_258C14]
8. CREATE_BUF(48) at LR=0x258d20 → Helios base64 str  [最终结果]
9. MAP_SET("X-Helios", base64_str) at LR=0x16aa4c
```

### 关键中间值

- **H1 hex 字符串** (32 bytes): MD5(R+"1967") 的十六进制文本表示
- **Timestamp 字符串** (26 bytes): `"{unix_ts}-{device_reg_id}-1967"`
  - `unix_ts`: 当前 unix 时间戳（秒）
  - `device_reg_id`: 固定值 `1394812046`（设备注册时分配的 ID，同一设备不变）
  - `1967`: aid 常量

### Helios = R(4) + part1(16) + part2(16) — 算法仍未知

输入: H0(16b), H1_hex(32B ASCII), timestamp_str(26B ASCII)
输出: part1(16b), part2(16b)

**不是任何简单 MD5 组合**（已穷举测试 MD5(H0+H1), MD5(H1+ts), MD5(ts+H0) 等数十种组合）。
part1/part2 由 CFF 内联代码在 0x287b44→0x288c20 之间生成。

### 关键地址

| 地址 | 操作 | 说明 |
|------|------|------|
| 0x287b44 | CREATE_BUF(H1_hex) | Helios 中间值: H1 的 hex 字符串 |
| 0x287b80 | CREATE_BUF(ts_str) | Helios 中间值: timestamp 字符串 |
| 0x288c20 | B64_ENCODE(36bytes) | Helios base64 编码 |
| 0x258d20 | CREATE_BUF(b64_str) | Helios base64 结果 |

### 下一步

1. **★★★★★ 用 Unicorn 模拟 0x287b44→0x288c20 之间的代码** — 输入 H0/H1/ts，输出 part1/part2
2. 或: Frida 内存写入 hook — 在 B64_ENCODE 之前对输入 buffer 设置 watchpoint，找到写入 part1/part2 的指令地址
3. `device_reg_id` = 1394812046 — 需要确认来源（可能是设备注册返回的 ID）

### 验证方法

```bash
PID=$(adb shell "ps -A" | grep com.dragon.read | awk '{print $2}' | head -1)

# ★★★ 最重要: hook AES 替代入口 (0x242640) — 之前的 v4 hook 0x2422EC 抓不到！
timeout 30 frida -U -p $PID -l scripts/hook_aes_alt_entry.js

# Helios 多样本分析
timeout 45 frida -U -p $PID -l scripts/hook_helios_v3.js

# simpleperf 采样 (需要大量重复)
adb shell "simpleperf record -e cpu-clock -p $PID -o /data/local/tmp/perf.data --duration 300 -f 10000" &
timeout 290 frida -U -p $PID -l scripts/hook_perf_loop.js
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
- **`hook_correlate.js`** — ★★★★★ 全面关联分析: 同时捕获 MD5+AES(0x242640)+SHA1+Helios+Medusa, 自动测试所有已知组合
- **`hook_aes_alt_entry.js`** — ★★★★ Hook AES 替代入口 0x242640! 捕获 17 次 AES-ECB
- **`hook_helios_v3.js`** — ★★ Helios 多样本 + 更多组合测试 (含 H3/SHA1, 但缺少 AES 关联!)
- `hook_crypto_v4.js` — ⚠ hook 0x2422EC 但 CFF 代码调用 0x242640 绕过！实际抓不到 AES
- `hook_crypto_v3.js` — ⚠ 有错误: 把 SHA-1 当成 AES，漏掉真正的 AES
- **`hook_helios_multi.js`** — 固定 URL 多次签名收集 (R, H1, part1, part2) 样本
- **`hook_helios_verify.js`** — 用 Java MD5 测试 Helios 算法假设
- **`hook_helios_verify2.js`** — 用 Java AES 测试 Helios 算法假设
- `hook_crypto_v2.js` — crypto dump v2 (带差分分析)
- `hook_lr_only.js` — 捕获所有 crypto 函数的 LR (返回地址/调用者)
- `hook_find_parent.js` — 从 LR 找上层调用函数
- `hook_md5_wrapper.js` — 分析 0x258530 MD5 wrapper 的参数和返回值

### Medusa 分析
- `hook_medusa_trace.js` — 追踪 AES setup 后的函数调用序列
- `hook_medusa_decrypt.js` — 用 Java Cipher 尝试解密 Medusa body
- `hook_medusa_decrypt2.js` — 更多解密尝试 (RC4, XOR, CTR 变体)
- `hook_medusa_keystream.js` — 捕获 AES 扩展密钥 + 函数调用序列
- `hook_perf_loop.js` — 5000 次签名循环，配合 simpleperf 采样
- `hook_func_scan.js` — 扫描函数序言批量 hook

### 分析工具
- `hook_disasm.js` — 反汇编 MD5 wrapper 和调用点代码
- `hook_disasm_full.js` — 反汇编签名核心函数区域
- `hook_aes_deep.js` — 尝试 hook AES 内部地址 (会崩溃，仅参考)
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

# ★★★★★ 全面关联分析 (同时捕获 AES+MD5+SHA1+Helios, 测试所有组合!)
timeout 60 frida -U -p $PID -l scripts/hook_correlate.js

# 生成签名
timeout 10 frida -U -p $PID -l scripts/gen_sigs.js 2>&1 | grep "^SIGS_JSON:"

# ★★★★ AES 替代入口 hook (捕获 17 次 AES-ECB!)
timeout 30 frida -U -p $PID -l scripts/hook_aes_alt_entry.js

# ★★ Helios 多样本分析 (含更多组合测试, 但缺少 AES 关联)
timeout 45 frida -U -p $PID -l scripts/hook_helios_v3.js
```

## Custom VM 发现 + Mini-Emulator (2026-04-02)

### 重大突破：Helios 算法是自定义字节码虚拟机

通过 IDA Pro MCP 深入分析 CFF 混淆代码，发现 Helios part1/part2 的计算不是 CFF 内联代码，而是一个**自定义字节码 VM 解释器**。

### VM 架构

| 组件 | 地址 | 说明 |
|------|------|------|
| VM dispatcher | SO+0x168324 | 初始化 VM state + dispatch first opcode |
| 字节码 | SO+0x118F50 | ~48 条 32-bit 指令，嵌入 .rodata |
| Dispatch table | SO data section 0x34CF68 | 64 entries，通过 `*(off_3798D8) + CFF_offset` 间接寻址 |
| Handler 代码 | SO+0x168324 ~ SO+0x172940 | 48 unique handlers，纯计算 (0 外部 BL 调用) |

### 指令编码

```
bits[0:5]  = opcode (6 bits, 0-63)
bits[6:31] = operands (26 bits, format varies per opcode)
```

### VM 寄存器

- **X28** = register file base (栈上分配, 32 个 64-bit 寄存器, [X28 + idx*8])
- **X19** = pointer to bytecode pointer (double indirect)
- **X20** = ADRP page of dispatch table pointer
- **X4**  = `0xFF5F9EBBF5FE033C` (CFF magic XOR constant)
- **X5**  = `0x00A061440A061440` (CFF intermediate value)
- **[X29-8]** = `0x33DC5` (handler address adjustment)

### CFF 地址计算公式 (已验证)

```
func_addr = address of sub_168324
mask = 0x10400040400
base = 0xA060400A021040
X5 = ((~func_addr & mask | base) + (func_addr & mask))
cff_offset = (X5 | 0x1010104) ^ 0xFF5F9EBBF5FE033C
dispatch_table_base = *(off_3798D8) + cff_offset
handler = dispatch_table_base[opcode * 8] - 0x33DC5
```

### 字节码内容 (SO+0x118F50, 64 dwords)

```
11000418 19000018 09000218 30400218 20400018 000002BB 1DDF5035 082070B7
004B002D 09901851 01021391 31FE02C4 00CC65D1 018C3391 31800018 300C1751
0903D991 200C1751 002A02BB 0000300D 3088001A 2080001A 07C00791 00000000
03307BEC 9B83BD86 4358D4F2 7F2353A5 561A4BB4 D000993D D37C6983 72784A5E
77968400 0B15D49D BC6DDBF8 E961D7B6 2B04B53E 5D5BBBBA EEBAE1AF 1621DAE3
1F4B9206 31177B0E 8CA7BB11 6DA0C0FE 26F8856C 6A0E29E1 2002F3D4 F27FC5AA
000000FD 00000000 00000000 00000000 62081EDE A9B18CE4 7468B0C1 1E15609D
357C7FD0 B366AC0B B14D51B6 4A48726A 00000000 00000000 00000000 00000000
```

Opcode 序列: 24×5, 59, 53, 55, 45, 17×2, 4, 17×2, 24, 17×2, 59, 13, 26×2, 17, 0, ...

### Handler 分类

| Opcode | Handler offset | 大小 | 核心操作 |
|--------|---------------|------|---------|
| 0  | 0x16F9B8 | 244B | 1 RF read + 1 RF write (register op) |
| 1  | 0x170270 | 216B | 1 RF read + 1 RF write |
| 17 | 0x16855C | **13KB** | 205 RF ops, 50 BR jumps (★ 核心计算) |
| 24 | 0x16F8E0 | 216B | LOAD: `reg[dst] = *(reg[src] + imm16)` |
| 5  | 0x172440 | 512B | 17 opcodes 共用 (unused/exit handler) |

OP 17 (13KB, 3074 条指令) 是核心计算 handler，在字节码中出现 8 次。**纯计算，0 个外部 BL 调用。**

### Mini-Emulator 方案 ✅ 已验证

由于 VM handler 是纯计算（不调用外部函数），可以单独运行，不需要 libc/JNI/handle：

1. 加载 SO code+data 段到 dynarmic（映射在原始运行时地址）
2. 调用 `sub_168324(bytecode, packed_args, 0, 0, callback_ctx)`
3. VM 自行执行 37368 步后正常返回（78ms）

```
test_vm_helios() 在 emulator.rs 中：
  - 加载 lib/so_code.bin (3.3MB) + so_data1.bin + so_data2.bin
  - 映射在运行时地址 0x6d8801b000
  - 设置栈 + TPIDR_EL0 + 输入数据
  - sub_168324 入口执行
  - 37368 步 / 78ms 正常返回到 HALT 地址 ✅
```

### Windows 构建修复

- `build.rs`: macOS-only 代码加 `#[cfg(target_os = "macos")]` 条件编译
- `dynarmic-sys-local/build.rs`: 自动检测 vcpkg Boost 路径 (`Boost_INCLUDE_DIR`)
- `dynarmic-sys-local/build.rs`: MSVC 需要链接 fmt/mcl/Zycore/Zydis 静态库
- `mman.h`: 添加 `MAP_NORESERVE` 定义 + `madvise` stub

### 下一步

1. **填入真实 Helios 输入数据** — 需要一组完整 Frida 样本 (R, H1_hex, ts_str, part1, part2)
2. **验证 VM 输出** — 对比 emulator 输出与 Frida 捕获的 part1/part2
3. **集成到签名流程** — 把 VM emulator 集成到 `sign()` 函数中

### 导出文件 (lib/)

```
so_code.bin    — SO code section (3.3MB, 从运行时 dump 的 IDB 导出)
so_data1.bin   — data segment 1 (164KB)
so_data2.bin   — data segment 2 (425KB)
vm_meta.txt    — VM 元数据 (地址偏移等)
```

## VM 指令集完整逆向 (2026-04-02)

详细文档见 `docs/vm_architecture.md`。

### 指令集概要

| 类型 | 指令 | 操作 |
|------|------|------|
| 加载 | OP24 | `r[d] = *(u64)(r[s] + imm16)` |
| 存储 | OP26 | `*(u64)(r[b] + imm16) = r[v]` |
| 32位存储 | OP22 | `*(u32)(r[b] + imm16) = r[v]` |
| 32位加载 | OP59 | `r[d] = sext32(*(i32)(r[s] + imm16))` |
| 指针偏移 | OP15 | `r[d] = r[s] + imm16` |
| 高16位立即数 | OP52 | `r[d] = sext32(imm16 << 16)` |
| 低16位OR | OP48 | `r[d] \|= imm16` |
| 符号扩展 | OP1 | `r[d] = sext16(r[s])` |
| 条件跳转 | OP45 | `if r[a]==r[b]: PC += N*4` |
| 位域提取 | OP4.11 | `r[d] = (r[s] >> shift) & ((1<<w)-1)` |

#### OP17 子指令集 (ALU，47个子handler)

| sub-op | 操作 | Medusa中出现 |
|--------|------|-------------|
| 14 | `r[d] = r[a] + r[b]` (ADD) | 10次 |
| 44 | `r[d] = r[a] \| r[b]` (OR) | 6次 |
| 51 | `r[d] = sext32(r[a] + r[b])` (ADDW) | 7次 |
| 50 | SPLIT: 分割值到两个寄存器 | 4次 |
| 29 | `r[d] = (r[a] & mask) ^ r[b]` (XOR) | 4次 |
| 23 | `r[d] = r[a] << imm` (SHL) | 4次 |
| 16 | `r[d] = r[a] - r[b]` (SUB) | 1次 |
| 3 | `r[d] = sext32(r[a] << imm)` (SHLW) | 1次 |
| 7 | `r[d] = sext32(r[a] >> imm)` (SHRW) | 1次 |
| 54 | `r[d] = r[a] & r[b]` (AND) | 1次 |
| 10 | `r[d] = r[a] & r[b] & mask` (AND2) | 2次 |
| 46 | `r[d] = sext32(r[a] - r[b])` (SUBW) | 1次 |
| 13 | NOP | 2次 |

### 4个VM字节码

| 偏移 | 大小 | 用途 | 调用者 |
|------|------|------|--------|
| SO+0x118F50 | 64 dwords | **Helios part1/part2** | sub_2A31CC |
| SO+0x119050 | 256 dwords | **Medusa 明文组装** | sub_2A3C5C |
| SO+0x0A46A0 | ? | 未知功能 | sub_2848F0 |
| SO+0x0F1FB0 | ? | 未知功能 | sub_29C36C |

### Medusa VM 反汇编 (256 条指令) 数据流

```
Phase 1 [0-12]:    初始化栈帧 + 保存 r16-r31
Phase 2 [13-67]:   从 TABLE_A/B 加载 30 个 handle 数据指针到寄存器/栈
Phase 3 [68-74]:   指针 + r12 基址偏移 (r12 = ASLR 重定位 delta)
Phase 4 [75-135]:  读取 packed_args + handle 字段, OR/SPLIT 处理
Phase 5 [136-186]: 位操作 + 数据变换 (SHL/ADDW/SUBW/UBFX)
Phase 6 [187-226]: 18×MOVI_HI + 19×ORI_LO = 构建常量表 (bytecode 嵌入)
Phase 7 [235-255]: XOR + AND + ADDW + SHRW = 最终 hash/checksum
```

### Handle 数据结构 (三级指针)

```
TABLE_A/B (SO data section)
  └─ 指针 ──→ Cluster H (handle 对象, 460B) ──→ 第三级堆对象
  └─ 指针 ──→ Cluster B (config 对象, 300+B) ──→ 第三级堆对象 (device_id, uuid, keys...)
```

- r12 = `0xffffffffff5011e8` (ASLR 重定位偏移，bytecode 嵌入常量)
- Cluster H: handle 内部 0x40 字节条目数组 (entries 1/5/6/7)
- Cluster B: C++ config 对象，8字节对齐指针成员
- 第三级: 实际数据 (device_id string, session UUID, crypto keys)
- **纯静态无法获取第三级数据**——依赖运行时堆内存

## 重大发现: VM 是代码虚拟化保护 (2026-04-02)

### 结论: 字节码 VM = ARM64 代码翻译

通过 dynarmic JIT 逐条追踪 Medusa 256 条字节码指令，发现 VM 不是"自定义算法"——而是 **ARM64 代码虚拟化保护 (Code Virtualization)**。原始签名函数的 ARM64 代码被翻译成了自定义字节码。

| VM 字节码 | 原始 ARM64 等价 | 说明 |
|-----------|---------------|------|
| LOAD64 (OP24) | LDR X, [X, #imm] | 64位内存读 |
| STORE64 (OP26) | STR X, [X, #imm] | 64位内存写 |
| STORE32 (OP22) | STR W, [X, #imm] | 32位内存写 |
| LOAD32S (OP59) | LDRSW X, [X, #imm] | 带符号32位读 |
| ADD_PTR (OP15) | ADD X, X, #imm | 指针偏移 |
| MOVI_HI (OP52) | MOVZ W, #imm, LSL#16 + SXTW | 高16位常量 |
| ORI_LO (OP48) | ORR X, X, #imm | 低16位OR |
| SEXT (OP1) | SXTH / SXTW | 符号扩展 |
| BEQ (OP45) | B.EQ | 条件跳转 |
| OP17.ADD | ADD X, X, X | 64位加法 |
| OP17.ADDW | ADD W,W,W + SXTW | 32位加法 |
| OP17.OR | ORR X, X, X | 按位或 |
| OP17.AND | AND X, X, X | 按位与 |
| OP17.SHL | LSL X, X, #imm | 左移 |
| OP17.SHRW | LSR W, W, #imm | 32位右移 |
| **OP17.SPLIT (sub50)** | **BLR X (函数调用!)** | **间接调用** |
| OP4.11 | UBFX | 位域提取 |
| OP20 | B.NE / CBNZ | 条件跳转 |

**关键证据**: OP17.SPLIT handler (SO+0x16A8E4) 内部做了 BLR 跳转，LR=SO+0x16AA4C 确认。每次 OR+SPLIT 模式 = 加载函数地址 + 调用外部函数。

### Medusa VM 逐条追踪结果 (指令 0-94)

通过 dynarmic step + bytecode pointer 监控，完成了前 94 条指令的精确追踪：

#### Phase 1 [0-10]: 栈帧设置
```
[0]  r29 -= 1280              (SP = frame pointer - 1280)
[1-10] STORE r31..r16 → stack  (保存 callee-saved 寄存器)
```

#### Phase 2 [11-67]: TABLE 加载 (48 个 handle 入口指针)
```
r12 构建: [12] MOVI_HI 0xFF50_0000 + [33] ORI_LO 0x11E8
→ r12 = 0xFFFFFFFFFF5011E8 (-0xAFEE18)

寄存器赋值 (从 TABLE_A r5 和 TABLE_B r6 加载):
  r7  = TA[0]  = 0x6d8892e690  (ClusterH+200)
  r8  = TA[3]  = 0x6d885db208  (ClusterB+ 68)
  r1  = TA[4]  = 0x6d885db350  (ClusterB+396)
  r2  = TA[5]  = 0x6d8892e658  (ClusterH+144)
  r3  = TA[6]  = 0x6d885db20c  (ClusterB+ 72)
  r5  = TB[0]  = 0x6d885db220  (ClusterB+ 92)
  r9  = TB[1]  = 0x6d885db330  (ClusterB+364)
  r10 = TB[2]  = 0x6d8892e6ac  (ClusterH+228)
  r11 = TB[3]  = 0x6d885db240  (ClusterB+124)
  r20 = TB[4]  = 0x6d885db310  (ClusterB+332)

保存到栈: TA[1,2,5,7-11], TB[5-13,19] (共 23 个)
```

#### Phase 3 [68-74]: r12 重定位 → handle 数据访问指针
```
r23 = TA[0] + r12 = 0x6d87e2f878  ← 主数据指针 (ClusterH)
r21 = TA[4] + r12 = 0x6d87adc538  (ClusterB)
r17 = TB[3] + r12 = 0x6d87adc428  (ClusterB)
r18 = TB[2] + r12 = 0x6d87e2f894  (ClusterH)
r19 = TB[1] + r12 = 0x6d87adc518  (ClusterB)
r6  = TA[3] + r12 = 0x6d87adc3f0  (ClusterB)
```

r12 将 TABLE 指针（指向 handle C++ 对象）转换为指向**相关联数据区域**的指针。这些数据区域包含 vtable、函数指针、配置数据。

#### Phase 4 [75-94]: packed_args + handle 数据 + 函数调用
```
[75]  OP40: r1 = 0 (初始化)
[77]  r16 = packed_args[1] = output_buf (0x70000400)
[78]  r1  = packed_args[0] = struct_ptr
[80]  r1  = sext(r1)
[83]  OP20 条件跳转: struct=0 → 跳过 16 条 (83→99)
[84-86] 更多 r12 调整: r4, r1, r2
[87]  ★ r3 = *(r23+offset) — 第一次 handle 数据读取
[93]  r5 = r29 + offset (stack addr)
[94]  r25 = r22 = callback_stub_addr
```

**指令 83 (OP20)**: 根据 struct_ptr 是否为零决定跳转，有两条执行路径。

**指令 87**: 第一次通过 r23 (r12-adjusted ClusterH) 读取 handle 数据。

**指令 94-95 (OR+SPLIT)**: 加载函数地址 + BLR 调用。**VM 卡在这里** — SPLIT 跳转到 r12-adjusted 地址（应该是 SO 函数的 vtable 入口），但 emulator 中没有有效代码。

#### 阻塞点: SPLIT = BLR

VM 在 Phase 4 中需要通过 handle vtable 调用外部 SO 函数。追踪确认:
- PC 跳转到 r12-adjusted 地址 (handle 数据区)
- LR = SO+0x16AA4C (SPLIT handler 内部的 BLR 返回地址)
- 后续每个 OR+SPLIT 都是同样的 BLR 调用模式

**要跑完 Medusa 字节码，必须:**
1. 知道每个 SPLIT 调用的目标函数 (从 handle vtable 读出)
2. 在 emulator 中实现这些函数，或提供正确的函数指针
3. 这些函数可能包括: hash (MD5/SHA-1), 内存分配, 字符串操作等

### TABLE_A/TABLE_B 完整映射

```
TABLE_A (SO+0x37A6D0, 24 entries) 和 TABLE_B (SO+0x37A730, 24 entries)
指向两个堆对象集群:

Cluster H (handle 对象): 0x6d8892e5c8 - 0x6d8892e6bc (252 bytes)
  10 个 TABLE 入口指向此区域，间距不均匀

Cluster B (config 对象): 0x6d885db1c4 - 0x6d885db390 (468 bytes)
  14 个 TABLE 入口指向此区域

其他:
  TB[12] = 0x0100000001000000 (packed flags, 非指针)
  TB[13] = SO+0x6ef26 (SO code section 内的地址!)
  TB[14-23] = 0x6d890e92a4... (12字节间距的结构体数组)
```

### 下一步

1. **IDA 分析 SPLIT handler (SO+0x16A8E4)**: BLR 目标地址如何从寄存器计算
2. **IDA 分析 SO+0x16AA4C 附近**: BLR 调用上下文，参数传递方式
3. **识别被调用函数**: handle vtable 中的函数指针对应哪些 SO 函数
4. **在 emulator 中 stub 这些函数**: 让 VM 能跑完所有 256 条指令

## 当前实现状态 (2026-04-02)

### X-Helios ✅ 完成

```
sign() → vm_compute_helios() → 4 blocks × 37K steps = 89ms
输出: base64(R(4) + part1(16) + part2(16)) = 48 chars
```

### X-Medusa 🔶 格式正确，内容猜测

```
sign() → AES-128-ECB encrypt + SHA-1 + header 构造
输出: base64(header(24) + body(936)) = 1280 chars
问题: 明文是猜测的（MD5 hash 拼凑），服务器不接受
```

### 测试结果

```
请求到达服务器 ✅ (有 x-tt-logid, x-tt-trace-id 等响应 header)
HTTP 200 但 body 为空 ❌ (签名验证不通过 — 服务器静默拒绝)
新设备注册成功 ✅ (device_id=1751989655468474)
```

### 阻塞点

Medusa 明文由 Medusa VM 从 handle 数据（三级指针 → 运行时堆内存）组装。
无法纯静态获取。需要一次运行时捕获：

```bash
# 方案1: Frida hook native 入口 (y2.a 被调用时 handle 已初始化)
frida -f com.dragon.read -l scripts/dump_vm_data.js

# 方案2: 如果 Frida 被检测，用 /proc/pid/mem 直接读
adb shell "cat /proc/PID/mem" | extract_regions.py
```

### 代码结构

```
src/signer/emulator.rs:
  vm_compute_helios()      — Helios VM runner (dynarmic JIT, 4 blocks)
  sign()                   — 生成 X-Helios + X-Medusa headers
  test_vm_helios()         — Helios VM 单元测试
  test_vm_medusa_regs()    — Medusa VM 寄存器 dump (发现 r12)
  test_vm_medusa_probe()   — Medusa VM 探测 (缺页迭代)
  test_vm_medusa_trace()   — ★ Medusa VM 逐条追踪 (bytecode ptr 监控)
  test_download_chapter()  — 实际下载测试

src/signer/mod.rs:
  sign_request()           — 签名入口 (调用 emulator::sign)

src/api/client.rs:
  get()                    — GET 请求 (自动签名)
  register_encryption_key() — registerkey POST (自动签名)

docs/vm_architecture.md   — VM 架构文档 (指令集 + 反汇编)
scripts/dump_vm_data.js   — Frida 一次性 dump handle 数据
```
