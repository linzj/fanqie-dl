# 逆向辅助脚本使用指南

## 目标
通过 Frida 动态hook native crypto函数，捕获 X-Helios 和 X-Medusa 签名算法的完整数据流，
然后在 Rust 中纯实现。

## 前置条件
- Android 模拟器/设备（ARM64）运行番茄小说 v7.1.3.32
- Frida (pip install frida-tools)
- USB 调试已开启

## 步骤

### 1. 运行深度crypto hook脚本
```bash
# 获取PID
PID=$(adb shell "ps -A" | grep com.dragon.read | awk '{print $2}' | head -1)

# 运行hook（输出重定向到文件）
timeout 30 frida -U -p $PID -l scripts/hook_helios_medusa_deep.js 2>&1 | tee crypto_dump.txt
```

### 2. 分析输出
输出包含：
- **SHA-256 输入/输出**: 所有hash操作的完整数据
- **AES 密钥**: 所有AES key expansion操作中的密钥
- **XOR解密字符串**: 被混淆的header名和其他字符串
- **差分分析**: 不同URL输入时，哪些crypto操作变化

### 3. 关键信息
从输出中提取：
- X-Helios 的 SHA-256 输入格式（nonce + URL + key?）
- X-Medusa 的 AES 加密密钥
- 任何固定的签名密钥

### 4. 将输出交给 Claude
```
把 crypto_dump.txt 的内容贴给 Claude，它会分析数据流并实现纯 Rust 签名。
```
