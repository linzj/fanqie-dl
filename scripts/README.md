# Scripts

## 完整 dump + 签名采集工作流

```bash
# 0. 清理环境
adb shell "killall frida-server; am force-stop com.dragon.read"

# 1. 启动 app，等待初始化
adb shell "am start -n com.dragon.read/.pages.splash.SplashActivity"
sleep 15
PID=$(adb shell "ps -A | grep com.dragon.read" | awk '{print $2}')

# 2. 干净 dump（无 Frida，先于一切 hook）
adb root
python3 scripts/dump_full_memory.py $PID
# 输出: lib/full_dump/ (maps.txt, manifest.txt, regions/*.bin)

# 3. Frida hook：TPIDR + handle + VM 输入 + 签名结果
adb shell "/data/local/tmp/frida-server -D &"
sleep 3
timeout 120 frida -U -p $PID -l scripts/dump_all_in_one.js 2>&1 | tee lib/full_dump/frida_dump.txt

# 4. 打包
cd lib && 7z a full_dump.7z full_dump/
```

**关键：Step 2 必须在 Step 3 之前，否则 Frida agent 污染 libc 代码段。**

## 脚本索引

### 核心（dump + 签名采集）
| 脚本 | 用途 |
|------|------|
| `dump_full_memory.py` | `/proc/pid/mem` 全量 dump 所有可读区域，输出 regions/*.bin + manifest |
| `dump_all_in_one.js` | ★ 一次性采集：TPIDR + handle(4KB) + 10次VM完整输入 + 签名headers |
| `capture_and_curl.js` | 拦截完整签名 headers，输出可直接执行的 curl 命令 |
| `capture_medusa.js` | 连续拦截多个 Medusa 样本（base64 解码） |

### 签名流程分析
| 脚本 | 用途 |
|------|------|
| `hook_sign_flow.js` | Hook JNI 入口(SO+0x26e684) + VM dispatcher(SO+0x168324) 完整调用链 |
| `hook_medusa_vm.js` | 监控所有 VM 调用，识别 Medusa 计算路径，捕获 TABLE_A/B 可读数据 |
| `hook_correlate.js` | 全面关联分析：MD5 + AES(0x242640) + SHA1 + Helios + Medusa |
| `hook_aes_alt_entry.js` | Hook AES 替代入口 0x242640（CFF 绕过标准 AES 入口） |

### 辅助 dump
| 脚本 | 用途 |
|------|------|
| `dump_so_segments.py` | dump SO code/data/bss 段（被 dump_full_memory.py 取代） |
| `dump_handle.js` | 递归 dump handle 对象指针链（3层，更详细但慢） |
| `dump_medusa_input.js` | dump 每次 VM 调用的完整输入（TABLE_A/B 512B） |
| `dump_clean.py` | dump SO + libc + TLS（旧版，被 dump_full_memory.py 取代） |
| `dump_pages.py` | 迭代缺页 dump（按 missing_pages.txt 补页） |
| `dump_so_only.py` | 快速 dump SO segment + 栈 |

### 暗区调查（参考）
| 脚本 | 用途 |
|------|------|
| `hook_mprotect_sign.js` | 证明签名期间零次 mprotect 调用 — 暗区不会被动态解锁 |

### Handle / 寄存器
| 脚本 | 用途 |
|------|------|
| `get_handle.js` | Frida hook y2.a 获取 Java 层 handle |
| `get_handle_save.js` | 获取 handle 并保存到文件 |
| `dump_regs_and_stack.js` | Hook 签名入口抓寄存器 + 栈 |
| `dump_regs_deadlock.js` | 寄存器 dump（死锁调试版） |
| `dump_regs_wait.js` | 寄存器 dump（等待版） |
| `parse_handle_dump.py` | 解析 handle dump 输出 |

### 签名生成与测试
| 脚本 | 用途 |
|------|------|
| `gen_sigs.js` | 生成签名输出 JSON |
| `gen_curl.js` | 生成签名输出 shell 变量 |
| `sign_proxy.js` | Frida RPC 签名代理 |
| `sign_server.py` | HTTP 签名代理服务器 |

### 其他
| 脚本 | 用途 |
|------|------|
| `hook_register_natives.js` | Hook RegisterNatives 找 JNI native 入口地址 |
| `dump_vm_data.js` | Frida dump VM handle 数据（Medusa VM 输入） |
| `iterate.sh` | 自动化迭代缺页 dump 循环 |

## 关键发现

- **暗区 (---p)** 不含有效数据，SO 内无 mprotect syscall，VM 不依赖 dispatch table
- **Medusa** 不是单独 VM 调用 (SO+0x119050)，而是通过 VM#1→#10 嵌套调用链组合计算
- **VM#8 (SO+0x8a4f0)** 的 TABLE_B[3:11] 可读 — system properties 字符串在 SO data 段
- **Handle** (~4KB) 包含设备信息、session 数据，地址在堆中可通过 `/proc/pid/mem` 读取
- **签名线程**：VM 调用在同一线程同步执行，但 JNI 全流程会 clone 后台线程

## 注意事项

- Frida 脚本只能用 CLI (`frida -U -p PID -l script.js`)，QJS runtime 无 Java bridge
- `setTimeout` 在 QJS 不可靠，用 `setInterval` 或同步执行
- `Module.findBaseAddress` 不可用，用 `Process.findModuleByName(name).base`
- dump 必须在 Frida attach 之前完成，否则 libc 代码段被 Frida agent 污染
