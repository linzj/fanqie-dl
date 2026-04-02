# MetaSec Custom VM Architecture

## Overview

libmetasec_ml.so 内嵌了一个**代码虚拟化保护层 (Code Virtualization)**。
原始 ARM64 签名函数被翻译/编译成自定义字节码，运行在 SO 内嵌的 VM 解释器上。
VM dispatcher 在 SO+0x168324 (sub_168324)，handler 代码在 SO+0x168324~0x172940 范围。

**关键发现 (2026-04-02)**: 每条 VM 字节码指令对应一条 ARM64 指令。
OP17.SPLIT (sub50) = BLR (间接函数调用)，不是值拆分操作。

## VM 架构

### 寄存器文件
- 32 个 64-bit 寄存器 (r0-r31)
- 通过 ARM64 X28 寄存器作为基址访问: `reg[i] = *(X28 + i*8)`
- 栈上分配，每次 VM 调用独立

### 字节码格式
- 每条指令 32 bits (4 bytes)
- `bits[0:5]` = 主 opcode (6 bits, 0-63)
- `bits[6:31]` = 操作数 (26 bits, 编码方式因 opcode 不同)

### 持久 ARM64 寄存器 (handler 之间保持)
| ARM64 寄存器 | 用途 | 值 |
|-------------|------|-----|
| X19 | 指向字节码指针的指针 (double indirect) | 栈地址 |
| X20 | dispatch table 页基址 (ADRP) | SO data section page |
| X28 | 寄存器文件基址 | 栈地址 |
| X4  | CFF magic XOR | `0xFF5F9EBBF5FE033C` |
| X5  | CFF 中间值 | `0x00A061440A061440` |
| [X29-8] | handler 地址调整量 | `0x33DC5` |

### Dispatch 机制
每个 handler 执行完后:
1. 读取下一条指令 dword: `W9 = *([X19] + 4); [X19] += 4`
2. 提取 opcode: `X9 = W9 & 0x3F`
3. CFF 地址计算: `offset = (X5 | 0x1010104) ^ X4`
4. 查表: `handler = *(dispatch_table_ptr + offset + opcode*8) - 0x33DC5`
5. `BR handler`

### 初始寄存器 (sub_168324 设置)
对于 Helios VM:
- r4 = packed_args 指针 → [workspace, input_block, output_block]
- r5 = 0 (a3)
- r6 = 0 (a4)
- r0 = 0

对于 Medusa VM:
- r4 = packed_args 指针 → [struct, output, flags]
- r5 = TABLE_A 基址 (SO+0x37A6D0, 指向 handle 数据的指针数组)
- r6 = TABLE_B 基址 (SO+0x37A730, 指向 handle 数据的指针数组)

---

## 指令集

### LOAD/STORE 类

#### OP24: LOAD64 — 64 位内存读取
```
reg[dst] = *(u64*)(reg[src] + sign_extend_16(offset))
```
- Handler: SO+0x16F8E0 (216 bytes)
- 编码: src=bits[22:26]+bit27→bit4, dst=bits[27:30]+bit17→bit4, offset=scrambled 16 bits
- 操作数解码:
  ```python
  src_reg = ((insn >> 27) & 0x10) | ((insn >> 22) & 0xF)
  dst_reg = ((insn >> 17) & 0x10) | ((insn >> 27) & 0xF)
  # offset: complex bit permutation from bits[6:26]
  ```

#### OP26: STORE64 — 64 位内存写入
```
*(u64*)(reg[base] + sign_extend_16(offset)) = reg[value]
```
- Handler: SO+0x171138 (584 bytes)
- 编码: base_reg 和 value_reg 同 OP24, offset 有不同的 bit 置换

#### OP22: STORE32 — 32 位内存写入
```
*(u32*)(reg[base] + sign_extend_16(offset)) = (u32)reg[value]
```
- Handler: SO+0x171F70 (564 bytes)
- 读两个寄存器: base (指针) 和 value (数据)
- 写入低 32 位到目标内存

#### OP59: LOAD32_SEXT — 32 位带符号读取
```
reg[dst] = sign_extend_64(*(i32*)(reg[src] + sign_extend_16(offset)))
```
- Handler: SO+0x16DA60 (512 bytes)
- 使用 LDRSW (带符号扩展的 32 位读取)

#### OP15: ADD_PTR — 指针偏移计算
```
reg[dst] = reg[src] + sign_extend_16(offset)
```
- Handler: SO+0x16D7D0 (452 bytes)
- 1 RF read, 1 RF write
- 核心: `ADD X15, X15, W12, SXTH` — 寄存器值加 16 位有符号立即数
- 用途: 计算内存地址偏移

### 立即数加载类

#### OP52: MOVI_HI — 加载高 16 位
```
reg[dst] = sign_extend_32(imm16 << 16)
```
- Handler: SO+0x16E158 (468 bytes)
- 0 RF read, 1 RF write
- 核心: `LSL W15, W11, #0x10; SXTW X15, W15` — 左移 16 位并符号扩展到 64 位
- 用途: 与 OP48 配对，构建 32 位常量

#### OP48: ORI_LO — OR 低 16 位
```
reg[dst] |= imm16
```
- Handler: SO+0x16E32C (492 bytes)
- 1 RF read, 1 RF write (同一个寄存器: 读→OR→写回)
- 核心: `ORR X14, X14, X15` — 将 16 位立即数 OR 到寄存器低位
- 用途: 与 OP52 配对: `OP52 r, hi16; OP48 r, lo16` → r = full 32-bit constant

### ALU 类 (OP17 子指令)

OP17 是一个多操作 handler (13KB, SO+0x16855C)，通过 `bits[6:11]` (6-bit sub-opcode) 分发到 47 个子 handler。

#### OP17 操作数编码 (所有子指令通用)
```python
sub_opcode = (insn >> 6) & 0x3F
reg_a = (insn >> 12) & 0x1F      # 源寄存器 1
reg_d = (insn >> 17) & 0x1F      # 目标寄存器
reg_b = (insn >> 22) & 0x1F      # 源寄存器 2
extra = (insn >> 27) & 0x1F      # 额外参数 (shift amount 等)
```

#### sub14: ADD — 64 位加法
```
reg[d] = reg[a] + reg[b]
```
- Sub-handler: SO+0x1692CC (108 bytes)
- 2 RF reads, 1 RF write
- **Medusa 中出现 10 次** (最高频)

#### sub16: SUB — 64 位减法
```
reg[d] = reg[a] - reg[b]
```
- Sub-handler: SO+0x16949C

#### sub44: OR — 64 位按位或
```
reg[d] = reg[a] | reg[b]
```
- Sub-handler: SO+0x16A5A8
- Medusa 中出现 6 次

#### sub54: AND — 64 位按位与
```
reg[d] = reg[a] & reg[b]
```
- Sub-handler: SO+0x16A2D8

#### sub29: XOR_MASKED — 带掩码异或
```
reg[d] = (reg[a] & mask) ^ reg[b]
```
- Sub-handler: SO+0x16A780
- mask 来自 `extra` 字段
- Medusa 中出现 4 次

#### sub10: AND2 — 双重与
```
reg[d] = reg[a] & reg[b] & mask
```
- Sub-handler: SO+0x16A444

#### sub51: ADDW — 32 位带符号加法
```
reg[d] = sign_extend_32((reg[a] & 0xFFFFFFFF) + (reg[b] & 0xFFFFFFFF))
```
- Sub-handler: SO+0x1696A0
- 核心: AND + ADD + SXTW
- Medusa 中出现 7 次

#### sub46: SUBW — 32 位带符号减法
```
reg[d] = sign_extend_32((reg[a] & mask) - reg[b])
```
- Sub-handler: SO+0x1699D4

#### sub23: SHL — 左移
```
reg[d] = (reg[a] & mask) << extra
```
- Sub-handler: SO+0x168598
- `extra` = shift amount (from bits[27:31])

#### sub3: SHLW — 32 位左移
```
reg[d] = sign_extend_32(reg[a] << extra)
```
- Sub-handler: SO+0x16917C

#### sub7: SHRW — 32 位右移
```
reg[d] = sign_extend_32((reg[a] & mask) >> extra)
```
- Sub-handler: SO+0x168DF0

#### sub50: SPLIT — 分割值
```
reg[d1] = part1(reg[a])
reg[d2] = part2(reg[a])
```
- Sub-handler: SO+0x16A8E4
- 1 RF read, 2 RF writes
- 用途: 将一个 64 位值分成两部分

#### sub13: NOP
- Sub-handler: SO+0x16AA88
- 无寄存器访问

### 控制流类

#### OP1: SIGN_EXTEND — 符号扩展 / 类型转换
```
reg[dst] = sign_extend_16(reg[src])  ; 或其他宽度
```
- Handler: SO+0x170270 (216 bytes)
- 1 RF read, 1 RF write
- 核心: SXTH (16 位有符号扩展到 64 位)

#### OP45: BEQ — 条件跳转 (相等则跳)
```
if reg[a] == reg[b]:
    PC += imm16 * 4  ; 跳过 imm16 条指令
```
- Handler: SO+0x16ECEC (140 bytes)
- 2 RF reads, 0 RF writes
- 核心: `CMP X9, X11; CSEL X9, X10, XZR, EQ; ADD X8, X8, X9, LSL#2`
- 条件成立时修改字节码指针，跳过后续指令

#### OP4: 多操作 handler (内部 dispatch)
- Handler: SO+0x16C368 (3088 bytes)
- 有自己的内部 dispatch table (off_3948F0)
- 使用 `bits[6:11]` 作为 sub-opcode
- Medusa 使用 sub_op 11 — 可能是函数调用或特殊操作

#### OP20: 条件/比较操作
- Handler: SO+0x16EF24 (80 bytes)  
- 2 RF reads, 0 RF writes
- 可能是 BNE (不等则跳) 或其他条件操作

#### OP40: 初始化/设置
- Handler: SO+0x1708E8 (528 bytes)
- 1 RF read, 1 RF write
- 核心: SXTH + MOV + AND — 带条件的初始化操作

### 未完全解码

#### OP0: 复合 ALU
- Handler: SO+0x16F9B8 (244 bytes)
- 1 RF read, 1 RF write
- 核心: AND + AND + ORR + ORR + ADD + SXTW
- Helios 专用

#### OP53: 未知 (1 次)
#### OP16: 未知 (1 次)

---

## 字节码位置

| 用途 | SO 偏移 | 大小 | 说明 |
|------|---------|------|------|
| Helios part1/part2 | SO+0x118F50 | 256 bytes (64 dwords) | ~48 有效指令 |
| Medusa 明文组装 | SO+0x119050 | 1024 bytes (256 dwords) | 256 有效指令 |
| 未知功能 1 | SO+0x0A46A0 | ? | 被 sub_2848F0 调用 |
| 未知功能 2 | SO+0x0F1FB0 | ? | 被 sub_2813C0 调用 |

---

## Dispatch Table

### 主 dispatch table (64 entries)
- 指针存储位置: SO+0x3798D8 (data section)
- 运行时值: `0x6d893d68f0` (外部分配)
- CFF 偏移: `0xfffffffffef91678`
- 实际表基址: `ptr_value + cff_offset`
- Handler 计算: `handler = table[opcode*8] - 0x33DC5`

### OP17 内部 dispatch table (64 entries)
- 指针存储位置: SO+0x3798E0
- 47 unique sub-handlers + 18 unused (指向同一个 exit handler)

### OP4 内部 dispatch table
- 指针存储位置: SO+0x3798F0

---

## Medusa VM 完整反汇编 (256 条指令)

### Phase 1: 初始化 [0-12]
```
[  0] OP15    init (设置栈帧?)
[  1] STORE64 *(r29+1272) = r31    ; 保存 callee-saved 寄存器
[  2] STORE64 *(r29+1264) = r30
[  3] STORE64 *(r29+1256) = r23
[  4] STORE64 *(r29+1248) = r22
[  5] STORE64 *(r29+1240) = r21
[  6] STORE64 *(r29+1232) = r20
[  7] STORE64 *(r29+1224) = r19
[  8] STORE64 *(r29+1216) = r18
[  9] STORE64 *(r29+1208) = r17
[ 10] STORE64 *(r29+1200) = r16
[ 11] OR      r0 = r22 | r7        ; 初始计算
[ 12] OP52    (设置常量?)
```

### Phase 2: 加载 handle 数据表 [13-67]
从 TABLE_A (r5) 和 TABLE_B (r6) 加载 30 个指针到栈和寄存器:
```
[ 13] LOAD64  r2 = *(r5+88)        ; TABLE_A[11] → r2 (handle 数据指针)
[ 14] STORE64 *(r29+24) = r2       ; 保存到栈
[ 15] LOAD64  r2 = *(r5+80)        ; TABLE_A[10]
[ 16] STORE64 *(r29+136) = r2
     ... (类似模式，共 28 对 LOAD+STORE) ...
[ 66] LOAD64  r6 = *(r6+152)       ; TABLE_B[19] (最后一个)
[ 67] STORE64 *(r29+64) = r6
```

### Phase 3: 指针基址偏移 [68-74]
```
[ 68] ADD     r17 = r11 + r12      ; r12 可能是 handle base offset
[ 69] ADD     r18 = r10 + r12
[ 70] ADD     r19 = r9 + r12
[ 71] ADD     r6 = r8 + r12
[ 72] STORE64 *(r29+168) = r6
[ 73] ADD     r23 = r7 + r12
[ 74] ADD     r21 = r1 + r12
```

### Phase 4: 读取 packed_args + handle 字段 [75-135]
```
[ 77] LOAD64  r16 = *(r4+8)        ; packed_args[1] = output/input pointer
[ 78] LOAD64  r1 = *(r4+0)         ; packed_args[0] = struct pointer
     ... (交替 LOAD 和处理操作) ...
[ 87] LOAD64  r3 = *(r23+8)        ; 从 handle 数据读取字段
[102] LOAD64  r1 = *(r23+0)        ; 读取另一个字段
[114] LOAD64  r1 = *(r23+48)       ; 读取更多字段
[123] LOAD64  r18 = *(r16+16)      ; 从输出指针读取
[126] LOAD64  r2 = *(r23+96)       ; 读取 handle 字段
```

### Phase 5: 位操作和数据变换 [136-186]
```
[136] OP52    (设置常量)
[138] SHL     r1 = r1 << 0          ; 移位操作
[140] SHL     r1 = r1 << 0
[141] OP52    (设置常量)
[144] SHL     r2 = r2 << 0
[151] SHLW    r17 = r0 << 16        ; 32 位左移 16
[154] ADDW    r0 = r2 + r1 (32bit)  ; 32 位加法
[156] AND     r2 = r2 & r0
[164] SUBW    r1 = r3 - r1 (32bit)  ; 32 位减法
[166] AND     r1 = r17 & r0
[176] ADD     r1 = r2 + r1          ; 地址计算
[183] SUB     r17 = r17 - r0        ; 减法
[184] ADD     r18 = r18 + r16       ; 地址计算
```

### Phase 6: OP52 数据块 + OP48 常量表 [187-226]
```
[187-204] 18× OP52  — 加载 18 个 16-bit 高半字常量到寄存器
[208-226] 19× OP48  — OR 19 个 16-bit 低半字到寄存器
```
**OP52+OP48 配对构建完整的 32 位常量值** — 这可能是 Medusa 头部或 AES 相关的固定常量。

### Phase 7: 最终 hash/checksum [227-255]
```
[235] AND2    r0 = r7 & r22         ; 按位与
[236] XOR     r7 = r30 ^ r0         ; 异或
[238] ADDW    r0 = r7 + r7 (32bit)  ; 自加 (=左移1)
[242] ADDW    r0 = r7 + r7 (32bit)  ; 再次自加
[243] XOR     r31 = r23 ^ r0        ; 异或
[244] ADDW    r0 = r1 + r7 (32bit)  ; 累加
[245] SHRW    r1 = r1 >> 1          ; 右移 1
[246] ADDW    r0 = r1 + r1 (32bit)  ; 自加
[247] AND2    r0 = r7 & r22         ; 按位与
[248] XOR     r7 = r31 ^ r0         ; 异或
[251] ADDW    r0 = r7 + r7 (32bit)  ; 自加
[252] ADDW    r0 = r7 + r7 (32bit)  ; 自加
[253] ADDW    r0 = r2 + r7 (32bit)  ; 累加
[254] SHRW    r2 = r0 >> 3          ; 右移 3
[255] ADDW    r0 = r2 + r2 (32bit)  ; 自加
```

---

## Helios VM 反汇编 (64 条指令)

### 初始加载 [0-4]
```
[  0] LOAD64  r2 = *(r4+16)        ; packed_args[2] = output accumulator ptr
[  1] LOAD64  r3 = *(r4+0)         ; packed_args[0] = workspace ptr
[  2] LOAD64  r1 = *(r4+8)         ; packed_args[1] = input block ptr
[  3] LOAD64  r6 = *(r1+8)         ; input bytes [8:15] as u64
[  4] LOAD64  r4 = *(r1+0)         ; input bytes [0:7] as u64
```

### 计算 + 数据块 [5-48]
```
[  5] OP59    (32-bit load)
     ... (交替 OP17 计算 + LOAD/STORE) ...
[ 23] NOP
[ 24-47] 大量 OP52/OP48/OP17 — 常量 + 自定义 hash 计算
[ 48] OP52
```

输入: 16 bytes (两个 u64: r4, r6)
输出: 写回到 output accumulator (通过 r2 指针)

---

## 数据依赖

### Helios VM 输入
- H1_hex (32 bytes ASCII hex) + ts_str (26 bytes) → PKCS#7 填充到 64 bytes
- 分 4 个 16-byte block 调用 VM，每次处理一个 block
- 输出 32 bytes = part1(16) + part2(16)
- **不依赖 handle** — 纯计算

### Medusa VM 输入
- TABLE_A (SO+0x37A6D0): 12+ 个指针，指向 handle 对象内部数据
- TABLE_B (SO+0x37A730): 12+ 个指针，指向 handle 对象和堆数据
- packed_args: [struct_ptr, output_ptr, flags]
- **依赖 handle 数据** — 需要运行进程的堆内存

### 已知的固定数据
- AES-128 key: `059874c397db2a6594024f0aa1c288c4` = MD5("1967" + 0xab7cfe85 + "1967")
- Device reg ID: `1394812046`
- Aid: `1967`
- Magic bytes: `0xab7cfe85`
