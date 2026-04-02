# dynarmic 模拟器开发必知

## dynarmic 限制与绕过

### 地址空间
- `PAGE_TABLE_ADDRESS_SPACE_BITS=40` — page table 只支持 1TB（`2^40`）
- Android 进程地址在 0x79... 范围（需要 43-bit），**超出 page table**
- **解决**: Rust 端传 `null_mut()` 作为 page_table，dynarmic 退化到纯 hash map（`kh_get/kh_put`），无地址限制
- 注意：不能改成 48-bit，因为 page table 需要 `2^36 × 8 = 512TB` 虚拟内存，macOS 会拒绝

### macOS PROT_EXEC
- macOS Hardened Runtime 禁止 `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)`，返回 `EACCES (errno=13)`
- **解决**: `mem_map` 用 `prot=3` (RW only)，dynarmic JIT 不需要 host 端 EXEC 权限（JIT 代码在 dynarmic 自己的 code cache 里）

### LSE 原子指令
- dynarmic 不支持 ARMv8.1 LSE atomics：CAS、CASAL、LDADD、LDADDH、LDSET、LDCLR、SWP 等
- 遇到时 JIT 编译失败，emit `Interpret` terminal → `ReturnFromRunCode`
- **不能在 SO 代码里 patch**（CFF 用指令地址作 dispatch 常量）
- **解决**: 扫描非 SO 范围（libc 等）的代码页，替换为 `SVC #0x500`，在 SVC 回调中根据原始指令编码模拟
- LSE 检测 mask:
  - CAS 家族: `(insn & 0x3F207C00) == 0x08207C00`
  - LDADD/LDSET/LDCLR/SWP 家族: `(insn & 0x3F200C00) == 0x38200000`
  - 注意 opc 字段 [14:12] 和 o3 [15] 决定具体操作（ADD/CLR/EOR/SET/SMAX/SMIN/UMAX/UMIN/SWP）

### MemoryReadCode 回调
- dynarmic 原始代码中 `MemoryReadCode` 直接调用 `MemoryRead32`
- `MemoryRead32` **没有** unmapped callback，未映射页面直接返回 0
- 0x00000000 被当作 NOP/UDF 执行，导致无限循环
- **解决**: 修改 `dynarmic.cpp` 的 `MemoryReadCode` 和 `MemoryRead32`，加入 unmapped callback + `HaltExecution(MemoryAbort)`

### ClearHalt
- `emu_start` 必须清除 **所有** halt reason，包括 `MemoryAbort` 和 `CacheInvalidation`
- 原始代码只清 `UserDefined1-8`，遗漏 MemoryAbort 导致后续 Run() 立刻返回（single-step 模式）

### JIT Cache Invalidation
- 提供了 `dynarmic_invalidate_cache(addr, size)` API
- 在处理 unsupported instruction 后可用，但实际效果有限（block 重编译仍会遇到同一指令）

## CFF 混淆约束

- **绝对不能 patch SO 代码的任何字节** — CFF dispatch 使用指令地址（ADRP+ADD 的立即数）作为状态常量
- 即使 patch 不在 CFF dispatch 路径上的函数入口（如 MAP_SET），也可能破坏 CFF（因为 CFF block 可能跨函数引用地址）
- 外部函数调用通过 GOT/PLT，不经过 CFF，可以安全地由 libc dump 原生执行

## 迭代缺页 dump

### 原理
只 dump SO + 栈（4MB），emulator 执行时遇到未映射内存 → 记录页地址 → 从设备补 dump → 重跑

### 关键实现
1. `/proc/pid/mem` 比 frida python API 快 100 倍（0.5s vs 15s+）
2. 缺页属于某个模块时，dump 该模块所有 range（避免 GOT/data 段缺失）
3. 跳过 >10MB 的大模块，只 dump 单页
4. 过滤垃圾地址（`< 0x1000` 或 `> 0x800000000000`）
5. unmapped callback 中设 `miss_flag` atomic + `emu_stop()`，**不映射**页面（让 MemoryReadCode HaltExecution）

### Android 特性
- Android 不支持 lazy binding（`BIND_NOW` + full RELRO），GOT 在 dlopen 时全部解析
- 从运行进程 dump 的 SO 数据段已包含正确的 GOT 值（指向 libc 等真实函数地址）
- Frida python API 的 Java bridge 不可用（QJS runtime 不支持 Java），**只能用 frida CLI** 做需要 Java 的操作

## Syscall 处理

在 emulator 中，libc 代码执行真实 Linux ARM64 syscall（SVC #0，syscall number in X8）：

| nr | syscall | 处理方式 |
|----|---------|----------|
| 98 | futex | WAIT: 写 0 到 futex 地址（强制解锁）+ 返回 -ETIMEDOUT；WAKE: 返回 0 |
| 113/114 | clock_gettime | 写固定 timespec 到 [x1]，返回 0 |
| 222 | mmap | 从 emulator heap (0x5000_0000) 分配，返回指针 |
| 226 | mprotect | 返回 0 |
| 56 | openat | 返回 -1 (ENOENT) |
| 63 | read | 返回 0 (EOF) |
| 64 | write | 返回 count |
| 167 | prctl | 返回 0 |
| 198 | socket | 返回 -1 |
| 其他 | — | 返回 0 |

## 文件结构

```
src/signer/emulator.rs     — dynarmic 模拟器主代码 (~1600 行)
  - fake JNIEnv (232 SVC stub)
  - JNI 函数实现 (NewStringUTF, getBytes, GetByteArrayRegion 等)
  - MTE tagged pointer 处理（unmapped callback 中 strip top byte）
  - handle_dump.bin 加载 + 自动缺页处理
  - 迭代执行框架
dynarmic-sys-local/         — patched dynarmic FFI
  vendor/dynarmic/dynarmic.cpp  — 修改:
    - null page_table (hash map 模式)
    - MemoryReadCode/MemoryRead32 unmapped callback + HaltExecution
    - ClearHalt (MemoryAbort + CacheInvalidation)
    - MTE strip_tag (所有 MemoryRead/Write 函数)
    - emu_step (单步执行 API)
  vendor/dynarmic/dynarmic.h    — PAGE_TABLE_ADDRESS_SPACE_BITS=40, emu_step 声明
  src/lib.rs                    — Rust wrapper (null page_table, invalidate_cache, emu_step)
  src/ffi.rs                    — FFI 声明
scripts/
  dump_clean.py             — /proc/pid/mem 快速 dump (SO + libc + libc++ 等)
  dump_pages.py             — 迭代缺页 dump（按模块级别，自动过滤 Frida 页面）
  get_handle.js             — Frida hook y2.a 获取 handle 地址 + hex dump
  parse_handle_dump.py      — 解析 get_handle.js 输出，生成 handle_dump.bin
  hook_register_natives.js  — Hook RegisterNatives 找 JNI native 入口
lib/
  memdump.bin               — 进程内存 dump
  handle_dump.bin           — MetaSec handle 对象 (addr + data)
  regs_only.txt             — TPIDR_EL0
  frida_ranges.txt          — Frida agent 地址范围（空文件 = 干净进程）
```

## 签名函数入口

- **JNI native 入口**: `SO+0x26e684` — `y2.a(int tag, int type, long handle, String url, Object extra)`
- tag=`0x3000001` 对应签名功能
- 之前 IDA 分析的 sub_29CCD4 → sub_283748 调用链**未被实际调用**

### SO+0x26e684 内部流程（已 trace 确认）

```
0x26e684: 参数重排 (x0=JNIEnv→x1, x2=tag→x0, x3=type→x2, x4=handle→x3, x5=url→x4, x6=extra→x5)
0x26e69c: SUB SP, SP, #0x50; 保存所有参数到栈
0x26e6b4: BL thunk → 获取 PC 值（反分析技巧）
0x26e6c0: BR X1 → 跳转到 0x26e6f0
0x26e6f0: 恢复参数; B 0x1734f8 (CFF dispatcher)
```

### CFF Dispatcher (0x1734f8)

- 大函数 (~3KB CFF code)
- 初始状态 0xFE，通过 MADD 计算 hash 做 switch-case
- 保存参数到 callee-saved 寄存器: X25=tag, X24=JNIEnv, X22=handle, X21=url, X20=extra
- 读取 TPIDR_EL0 + 0x28 设置 stack canary
- 调用 sub_17B96C (顶层编排)
- sub_17B96C 通过 vtable 调用签名核心

### handle 对象结构

handle 是 MetaSec C++ 对象 (~4KB)，内部有 0x40 字节为一组的条目数组，每组含：
- +0x00: 指针（vtable 或堆对象）
- +0x08: 数据/指针
- +0x30: 类型标记（0x03010300 或 0x03810200）
- +0x34: 某种 ID/hash（每个条目不同）
- +0x38: SO 数据段指针（如 SO+0x34c738）
- +0x3C: 常量 0x4000

**关键约束**: handle 的所有指针必须来自同一个活着的进程，不能跨进程重用。

## TPIDR_EL0 计算

从 `/proc/pid/maps` 找到线程的 `[anon:stack_and_tls:TID]` rw 区域结束地址：
```
TPIDR_EL0 = stack_and_tls_rw_end - 0x3580
```
偏移 0x3580 在 Android 15 上固定（已多次验证）。

## MTE / Tagged Pointers

- Android 15 使用 MTE (Memory Tagging Extension)，指针 top byte 携带 tag（如 `0xb400007cdb88bd08`）
- dynarmic 不自动处理 TBI (Top Byte Ignore)
- **解决**: `dynarmic.cpp` 所有 `MemoryRead*` 和 `MemoryWrite*` 函数开头加 `vaddr = strip_tag(vaddr)`
- `strip_tag` = `vaddr & 0x00FFFFFFFFFFFFFF`
- Rust 端 unmapped callback 也要 strip

## Frida 注意事项

- Frida attach 后进程残留 `memfd:frida-agent-64.so` 映射，杀 frida-server 不会卸载
- `frida -U -p PID` attach 模式：app 有反 Frida 检测，进程很快崩溃
- `frida -f com.dragon.read` spawn 模式：可用，但 bytehook 会修改 libc 函数入口
- **不能用 Frida 触发签名**——调用链经过 Frida 代码，栈上残留 Frida 指针污染 emulator
- lldb/ptrace 会被 app 反调试检测到，进程挂起

### bytehook 污染详情

- libbytehook.so 随 SO 加载，hook libc 函数入口（替换前几条指令为 branch 到 trampoline）
- trampoline 跳转到 Frida agent 代码（当 Frida attach 时）
- 影响范围：libc 代码段（函数入口字节）+ libc GOT（函数指针）
- **替换 libc 代码段不够** — GOT 表也被修改了
- 被 hook 的函数包括 malloc/free/pthread 等关键函数，跳过它们导致 Scudo 分配器崩溃

## 已验证的错误方向（不要重复）

1. **跨进程 handle 重用** — handle 内的堆指针/库指针在不同进程中无效，即使重定位了 SO 指针
2. **Frida 页面填 RET** — 被 hook 的是 malloc/free 等关键函数，跳过导致 Scudo 崩溃
3. **只替换 libc 代码段** — GOT 仍指向 Frida agent，内部间接调用走错路径
4. **code fetch 时分配堆返回** — 不是所有被跳过的函数都是 malloc，错误地给非分配函数返回堆指针
5. **handle=0 或全零** — CFF dispatch 检查 handle 有效性，直接返回 NULL

## Fake JNIEnv

emulator.rs 构造了完整的 JNI 环境：

- 232 个函数 stub（`SVC #(0x600+index); RET`），每个 JNI 函数一个
- JNIEnv 结构在 0x4000_0000，function table 在 0x4000_0100，stub 代码在 0x4000_1000
- JNI stack 在 0x4800_0000 (8MB)
- JNI 对象用 HashMap 跟踪（handle → JniObject enum）

已实现的 JNI 函数：
- NewStringUTF, GetStringUTFChars, ReleaseStringUTFChars, GetStringUTFLength
- FindClass, GetMethodID, GetStaticMethodID, GetFieldID
- CallObjectMethod/V/A, CallStaticObjectMethod（对 String 自动返回 getBytes 结果）
- GetObjectClass, ExceptionCheck, EnsureLocalCapacity, DeleteLocalRef
- NewObjectArray, Get/SetObjectArrayElement, GetArrayLength
- NewByteArray, GetByteArrayElements, GetByteArrayRegion, SetByteArrayRegion

签名函数的 JNI 调用序列（已验证）：
```
NewStringUTF("utf-8") → EnsureLocalCapacity → GetObjectClass(url)
→ GetMethodID("getBytes", "(Ljava/lang/String;)[B")
→ CallObjectMethodV(url, getBytes, "utf-8") → 返回 byte[]
→ GetArrayLength → GetByteArrayRegion(byte[], 0, len, buf)
→ ... 后续 SO 内部处理 ...
```

## 重新编译 dynarmic C 代码

修改 `dynarmic.cpp` / `dynarmic.h` 后：
```bash
cargo clean -p dynarmic-sys   # 必须 clean，cargo 不追踪 C 文件变化
cargo build --tests           # cmake 会自动重新编译
```
`touch` Cargo.toml 或 build.rs **不够**，必须 `cargo clean -p dynarmic-sys`。
