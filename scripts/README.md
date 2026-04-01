# Scripts

## 模拟器工作流（当前方案）

```bash
PID=$(adb shell pidof com.dragon.read)

# 1. 抓寄存器（需要触发签名，用 frida CLI）
timeout 30 frida -U -p $PID -l scripts/dump_regs_and_stack.js
# 手动保存输出到 lib/regs_only.txt

# 2. dump SO + 栈（/proc/pid/mem，0.5 秒）
python3 scripts/dump_so_only.py $PID

# 3. 迭代缺页 dump
bash scripts/iterate.sh $PID

# 4. 跑模拟器测试
cargo test test_signing -- --nocapture
```

## 脚本索引

### Dump（模拟器数据准备）
| 脚本 | 用途 |
|------|------|
| `dump_regs_and_stack.js` | Frida CLI：hook SO+0x286DF4 抓寄存器，触发 Java 签名 |
| `dump_so_only.py` | `/proc/pid/mem` 快速 dump SO 全部 segment + 栈（128KB） |
| `dump_pages.py` | 按缺页地址补 dump，自动识别模块并 dump 整个模块 |
| `iterate.sh` | 自动化迭代循环：run emulator → collect missing → dump → repeat |

### Frida Hooks（逆向分析）
| 脚本 | 用途 |
|------|------|
| `hook_correlate.js` | ★ 全面关联分析：同时捕获 MD5+AES(0x242640)+SHA1+Helios+Medusa |
| `hook_aes_alt_entry.js` | ★ Hook AES 替代入口 0x242640（CFF 代码绕过标准入口 0x2422EC） |

### 签名生成与测试
| 脚本 | 用途 |
|------|------|
| `gen_sigs.js` | Frida CLI：生成签名输出 JSON |
| `gen_curl.js` | Frida CLI：生成签名输出 shell 变量（配合 curl 测试） |
| `sign_proxy.js` | Frida RPC：暴露 r4.onCallToAddSecurityFactor 供外部调用 |
| `sign_server.py` | HTTP 代理服务器：接收 URL → Frida 签名 → 返回 headers |

## 用法

所有 Frida 脚本只能用 CLI（python frida 的 Java API 不可用）：
```bash
PID=$(adb shell pidof com.dragon.read)
timeout 30 frida -U -p $PID -l scripts/<script>.js
```

Python dump 脚本使用 `/proc/pid/mem`，不依赖 frida：
```bash
python3 scripts/dump_so_only.py $PID
python3 scripts/dump_pages.py $PID lib/missing_pages.txt
```
