use dynarmic_sys::Dynarmic;

fn main() -> anyhow::Result<()> {
    // Initialize Dynarmic for ARM64 with a dummy user data type
    let emu: Dynarmic<()> = Dynarmic::new();

    // Map 2MB of memory at 0x1000000
    let code_addr = 0x1000000;
    emu.mem_map(code_addr, 2 * 1024 * 1024, 7)?; // Read/Write/Execute

    // ARM64 code:
    // mov x0, #42
    // add x0, x0, #1
    // brk #0
    let code: [u8; 12] = [
        0x40, 0x05, 0x80, 0xd2, // mov x0, #42
        0x00, 0x04, 0x00, 0x91, // add x0, x0, #1
        0x00, 0x00, 0x20, 0xd4, // brk #0
    ];

    emu.mem_write(code_addr, &code)?;

    println!("Starting emulation at 0x{:x}...", code_addr);

    // Run until the end of the code block
    emu.emu_start(code_addr, code_addr + code.len() as u64)?;

    let x0 = emu.reg_read(0)?;
    println!("Emulation finished. X0 = {}", x0);

    assert_eq!(x0, 43);
    println!("Success!");

    Ok(())
}
