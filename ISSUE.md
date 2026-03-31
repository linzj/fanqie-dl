# 当前问题：搜索API签名验证失败

## 问题描述

搜索API `/reading/bookapi/search/tab/v` 返回空响应（200 OK, Content-Length: 0），
原因是缺少有效的 msssdk 签名头（X-Gorgon, X-Argus, X-Ladon, X-Khronos, X-Helios, X-Medusa）。

当前 Rust 中移植的社区签名算法（来自 TikTok-Encryption 项目）不被服务端接受：
- 无签名 → 空响应
- 社区签名 → `verify fail` (code 500002) 或空响应
- 真实签名（app 内 native .so 生成）→ 正常返回数据

## 根因

签名由 `libmetasec_ml.so`（ByteDance msssdk）生成，该库：
- 只有 arm64-v8a 版本，x86_64 模拟器无法加载
- 高度混淆（控制流平坦化、字符串加密、反调试）
- 社区逆向的算法已过期，服务端已更新验证逻辑

## 已确认的技术细节

### 签名调用链
```
OkHttp3SecurityFactorInterceptor.intercept()
  → ms.bd.c.r4.onCallToAddSecurityFactor(String url, Map headers) → Map
    → MSManager.frameSign(String, int) → Map  (或直接调 JNI)
      → libmetasec_ml.so (native, arm64 only)
```

### 搜索API完整请求格式（frida抓包确认）
- **端点**: `GET /reading/bookapi/search/tab/v`
- **Base URL**: `api5-normal-sinfonlinec.fqnovel.com`
- **必需参数**: `query`, `offset`, `count`, `search_source=1`, `aid=1967`, `device_id`, `iid`, 以及几十个公共参数
- **必需 Headers**:
  - `Accept: application/json; charset=utf-8,application/x-protobuf`
  - `X-SS-REQ-TICKET: {timestamp_ms}`
  - `x-reading-request: {timestamp_ms}-{random}`
  - `lc: 101`
  - `sdk-version: 2`
  - `passport-sdk-version: 5051451`
  - `x-tt-store-region: cn-gd`
  - `x-tt-store-region-src: did`
  - `X-Gorgon: ...` (签名)
  - `X-Argus: ...` (签名)
  - `X-Ladon: ...` (签名)
  - `X-Khronos: {timestamp}` (签名)
  - `X-Helios: ...` (签名)
  - `X-Medusa: ...` (签名)
- **User-Agent**: `com.dragon.read/71332 (Linux; U; Android {ver}; {lang}; {device}; Build/{build};tt-ok/3.12.13.20)`

### X-Gorgon 算法（已验证正确）
Python 和 Rust 输出完全一致，格式 `0404d0e40001...`，但服务端仍拒绝——说明问题在 X-Argus/X-Ladon 或其他签名头。

## 解决方案

在 ARM64 环境中逆向 `libmetasec_ml.so`：

1. macOS ARM64 模拟器可直接运行 arm64 .so
2. 用 frida hook native JNI 函数，观察签名算法的输入/输出
3. 用 IDA 分析算法细节
4. 将正确算法移植到 Rust

## 相关文件

- APK: `test.apk` (com.dragon.read v7.1.3.32)
- Native .so: `lib/arm64-v8a/libmetasec_ml.so`
- Java 入口: `ms.bd.c.r4.onCallToAddSecurityFactor`
- 当前 Rust 签名: `src/signer/` (X-Gorgon正确, X-Argus/X-Ladon 需替换)
- Decompiled: `decompiled/sources/ms/bd/c/r4.java`
