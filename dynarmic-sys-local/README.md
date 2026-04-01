# dynarmic-sys

[English](#english) | [中文](#中文)

## English

Rust bindings for the [Dynarmic](https://github.com/lioncash/dynarmic) ARM dynamic recompiler.

### Credits

- **Original Project**: [Dynarmic](https://github.com/lioncash/dynarmic) by [lioncash](https://github.com/lioncash)
- **Initial Implementation Reference**: [rnidbg](https://github.com/fuqiuluo/rnidbg) by [fuqiuluo](https://github.com/fuqiuluo)
- **Maintainer**: [wyourname](https://github.com/wyourname/dynarmic-sys)

### Features

- High-level safe(r) wrapper for ARM32 and ARM64 emulation.
- Integrated C++ source (vendored) for easier building.
- Support for custom memory mapping and protection.
- Support for SVC and Unmapped memory callbacks.

### Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
dynarmic-sys = { version = "0.1.0" }
```

---

## 中文

[Dynarmic](https://github.com/lioncash/dynarmic) ARM 动态重编译器的 Rust 绑定。

### 致谢与出处

- **原始项目**: [Dynarmic](https://github.com/lioncash/dynarmic) - 作者 [lioncash](https://github.com/lioncash)
- **初始实现参考**: [rnidbg](https://github.com/fuqiuluo/rnidbg) - 作者 [fuqiuluo](https://github.com/fuqiuluo)
- **维护者**: [wyourname](https://github.com/wyourname/dynarmic-sys)

### 特性

- 针对 ARM32 和 ARM64 模拟的高层安全封装。
- 集成 C++ 源码（内置），简化编译流程。
- 支持自定义内存映射与保护。
- 支持 SVC 指令和未映射内存访问回调。

### 使用方法

在 `Cargo.toml` 中添加：

```toml
[dependencies]
dynarmic-sys = { version = "0.1.0" }
```

---

## Example / 示例

Check the `examples/` directory for a basic ARM64 emulation demo.
查看 `examples/` 目录获取基础的 ARM64 模拟示例。

```rust
use dynarmic_sys::Dynarmic;

fn main() -> anyhow::Result<()> {
    let emu: Dynarmic<()> = Dynarmic::new();
    // ... see examples/basic_a64.rs for full code
    Ok(())
}
```

## Configuration / 配置

- `DYNARMIC_JIT_SIZE`: Set JIT cache size in MB (default: 64). / 设置 JIT 缓存大小（单位 MB，默认 64）。

## License / 许可证

This project is licensed under the 0BSD license, matching the original Dynarmic project.
本项目采用 0BSD 许可证，与原始 Dynarmic 项目保持一致。
