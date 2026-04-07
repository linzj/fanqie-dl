# Scripts

## 一键 dump 工作流

```bash
adb root
scripts/dump_all.sh
```

`dump_all.sh` 强制执行正确的顺序：

1. 杀掉 frida-server，force-stop `com.dragon.read`，确认无 frida 残留
2. 重新 spawn app，等待 `libmetasec_ml.so` 加载
3. 校验 `/proc/$PID/maps` **不含 frida**
4. 运行 `dump_full_memory.py` 做干净的 `/proc/pid/mem` 全量 dump
5. 再次校验 maps（确认 dump 期间无 frida attach）
6. 启动 frida-server，运行 `dump_all_in_one.js` 采集 handle / VM 输入 / 签名

**关键约束**：内存 dump 必须先于 Frida attach，否则 libbytehook 会污染 libc 代码段和 GOT。`dump_all.sh` 的前后两次校验保证了这一点。

## 脚本索引

### 入口
| 脚本 | 用途 |
|------|------|
| `dump_all.sh` | ★ 完整 dump 工作流编排器（顺序保证 + 污染检测） |

### 内存 dump（无 Frida）
| 脚本 | 用途 |
|------|------|
| `dump_full_memory.py` | `/proc/pid/mem` 全量 dump 所有可读区域，输出 `lib/full_dump/{maps.txt, manifest.txt, regions/*.bin}` |

### Frida 采集（dump 之后）
| 脚本 | 用途 |
|------|------|
| `dump_all_in_one.js` | ★ 一次性采集 TPIDR + handle (4KB) + 多次 VM 完整输入 + 签名 headers |
| `capture_and_curl.js` | 拦截完整签名 headers，输出可直接执行的 curl 命令 |
| `get_handle.js` | Hook `y2.a` 获取 Java 层 handle 指针 |

### 分析 / 探索（按需）
| 脚本 | 用途 |
|------|------|
| `hook_sign_flow.js` | Hook JNI 入口 (SO+0x26e684) + VM dispatcher (SO+0x168324) 调用链 |
| `hook_correlate.js` | 关联分析：MD5 + AES (0x242640) + SHA1 + Helios + Medusa |
| `hook_register_natives.js` | Hook `RegisterNatives` 找 JNI native 入口地址 |

### 解析
| 脚本 | 用途 |
|------|------|
| `parse_handle_dump.py` | 解析 handle dump 输出 |

## 注意事项

- Frida 脚本只能用 CLI (`frida -U -p PID -l script.js`)，QJS runtime 无 Java bridge
- `setTimeout` 在 QJS 不可靠，用 `setInterval` 或同步执行
- `Module.findBaseAddress` 不可用，用 `Process.findModuleByName(name).base`
- 永远不要在 dump 之前 attach Frida —— 用 `dump_all.sh` 而不是手工执行步骤
