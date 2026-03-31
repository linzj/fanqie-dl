# fanqie-dl

番茄小说命令行下载器，纯 Rust 实现。通过逆向 APK 和 native SO 库还原 API 签名算法，实现小说搜索与章节下载。

## 功能

- 搜索小说（按书名关键词）
- 通过 book_id 或 URL 直接下载
- 自动获取章节列表并批量下载为 TXT
- 内容解密（AES + 自定义密钥协商）
- 纯 Rust 签名算法，无外部依赖

## 签名算法逆向

本项目的核心挑战是还原番茄小说 APP (`com.dragon.read`) 的 API 请求签名。

APP 使用 ByteDance msssdk (`libmetasec_ml.so`) 生成 6 个签名头：

| Header | 算法 |
|--------|------|
| `X-Gorgon` | MD5 + 自定义 S-box 变换 |
| `X-Argus` | Protobuf → AES-128-ECB → XOR 混淆 → AES-128-CBC → Base64 |
| `X-Ladon` | Speck-128/128 块加密 + Base64 |
| `X-Khronos` | Unix 时间戳 |
| `X-Helios` | 待逆向 |
| `X-Medusa` | 待逆向 |

### IDA 逆向发现

通过 IDA Pro 对 `libmetasec_ml.so` (ARM64) 的静态分析，确认番茄小说 v7.1.3.32 的算法与 TikTok 社区公开版本存在关键差异：

| 组件 | TikTok 社区版 | 番茄小说 (本项目) |
|------|-------------|-----------------|
| 哈希算法 | SM3 | **SHA-256** |
| 内层加密 | Simon-128/256 | **AES-128-ECB** |
| 外层加密 | AES-128-CBC | AES-128-CBC |
| 密钥派生 | SM3(key+salt+key) | SHA-256(key+salt+key) |

详细逆向分析记录见 [REVERSE_ENGINEERING_NOTES.md](REVERSE_ENGINEERING_NOTES.md)。

## 项目结构

```
src/
├── main.rs              # CLI 入口，搜索/下载交互
├── api/
│   ├── client.rs        # HTTP 客户端，签名注入，设备注册
│   ├── book.rs          # 书籍详情 & 章节列表 API
│   ├── reader.rs        # 章节内容获取 & 解密
│   └── search.rs        # 搜索 API
├── signer/
│   ├── mod.rs           # 签名入口，组装所有 X-* headers
│   ├── gorgon.rs        # X-Gorgon (MD5 + S-box)
│   ├── argus.rs         # X-Argus (SHA-256 + AES)
│   ├── ladon.rs         # X-Ladon (Speck cipher)
│   ├── protobuf.rs      # 轻量 protobuf 编码器
│   ├── simon.rs         # Simon-128/256 (legacy, 已替换为 AES)
│   └── sm3.rs           # SM3 hash (legacy, 已替换为 SHA-256)
├── crypto.rs            # 内容解密（AES + DH 密钥交换）
├── device.rs            # 设备指纹管理
└── model.rs             # API 响应数据结构
```

## 构建

```bash
cargo build --release
```

## 使用

```bash
cargo run

# 交互式：输入书名搜索或直接输入 book_id
> 输入书名搜索 或 book_id (q退出): 7373660003258862617
```

支持的输入格式：
- 纯数字 book_id: `7373660003258862617`
- 完整 URL: `https://fanqienovel.com/page/7373660003258862617`
- 关键词搜索: `停尸房兼职`

下载文件保存在 `downloads/<书名>/` 目录。

## 当前状态

> **WIP** — 签名算法框架已就绪，但 sign key 需要通过 Frida 动态分析提取。

- [x] 设备注册（无需签名）
- [x] X-Gorgon 算法
- [x] X-Argus 算法框架 (SHA-256 + AES)
- [x] X-Ladon 算法 (Speck)
- [x] 内容解密
- [ ] 提取正确的 sign key（需 ARM64 设备 + Frida）
- [ ] X-Helios / X-Medusa

## 技术栈

- **Rust** — 主语言
- **reqwest** — HTTP 客户端
- **aes / cbc** — AES 加密
- **sha2** — SHA-256 哈希
- **md5** — MD5 哈希
- **base64** — 编码

## 免责声明

本项目仅用于技术研究和学习目的。请遵守相关服务条款和法律法规。

## License

MIT
