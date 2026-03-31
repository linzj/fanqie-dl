//! ARM64 emulator for libmetasec_ml.so signing functions.
//! Uses Unicorn Engine to execute native code from the dumped SO.

use std::collections::HashMap;
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Prot};
use unicorn_engine::{RegisterARM64, Unicorn};

// Use the same base as the Frida dump to preserve ADRP calculations
const SO_BASE: u64 = 0x7623e02000;
const SO_SIZE: u64 = 0x3E4000;
const SO_END: u64 = SO_BASE + SO_SIZE;

const STACK_BASE: u64 = 0x7F000000;
const STACK_SIZE: u64 = 0x100000;
const HEAP_BASE: u64 = 0x80000000;
const HEAP_SIZE: u64 = 0x1000000;
const DATA_BASE: u64 = 0x90000000;
const DATA_SIZE: u64 = 0x100000;
const HALT_ADDR: u64 = 0xDEAD0000;
const STUB_BASE: u64 = 0xA0000000;
const STUB_SIZE: u64 = 0x10000;

// Function offsets (past PLT stubs — actual function body addresses)
const OFF_MD5: u64 = 0x243C44;
#[allow(dead_code)]
const OFF_AES_KEY_EXPAND: u64 = 0x241E9C;
#[allow(dead_code)]
const OFF_AES_ECB_ALT: u64 = 0x242640;
#[allow(dead_code)]
const OFF_ORCHESTRATOR: u64 = 0x17B96C;

struct EmuState {
    heap_next: u64,
}

fn load_so_memdump() -> Vec<u8> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dump_path = format!("{}/lib/so_memdump.bin", manifest_dir);
    std::fs::read(&dump_path).expect("failed to read so_memdump.bin")
}

/// Patch GOT entries that point outside the SO to redirect to unique stubs
/// Returns a map: stub_offset → (original_addr, got_offset)
fn patch_external_got(so_data: &mut [u8]) -> HashMap<u64, (u64, usize)> {
    let mut stub_map: HashMap<u64, (u64, usize)> = HashMap::new();
    // Map original external address → stub offset (dedup)
    let mut addr_to_stub: HashMap<u64, u64> = HashMap::new();
    let mut next_stub: u64 = 0;

    let scan_ranges: &[(usize, usize)] = &[
        (0x17b000, 0x17c000),
        (0x241000, 0x246000),
        (0x24b000, 0x24c000),
        (0x25b000, 0x25d000),
        (0x347000, 0x349000),
        (0x34c000, 0x376000),
        (0x379000, 0x3D2000),
    ];

    for (start, end) in scan_ranges {
        let s = (*start).min(so_data.len());
        let e = (*end).min(so_data.len());
        let mut off = s;
        while off + 8 <= e {
            let val = u64::from_le_bytes(so_data[off..off + 8].try_into().unwrap());
            if val > 0x10000 && (val < SO_BASE || val >= SO_END) {
                if val > 0x7000000000 && val < 0x8000000000 {
                    let stub_off = *addr_to_stub.entry(val).or_insert_with(|| {
                        let s = next_stub;
                        next_stub += 4; // one RET per stub
                        s
                    });
                    let stub_addr = STUB_BASE + stub_off;
                    so_data[off..off + 8].copy_from_slice(&stub_addr.to_le_bytes());
                    stub_map.entry(stub_off).or_insert((val, off));
                }
            }
            off += 8;
        }
    }

    eprintln!("[emu] Patched {} GOT entries, {} unique external functions",
        addr_to_stub.len(), stub_map.len());
    stub_map
}

pub fn test_md5() -> String {
    let mut so_data = load_so_memdump();

    // Patch external GOT entries
    let _stub_map = patch_external_got(&mut so_data);

    let mut emu = Unicorn::new_with_data(Arch::ARM64, Mode::LITTLE_ENDIAN, EmuState {
        heap_next: HEAP_BASE,
    })
    .expect("failed to create unicorn");

    // Map SO
    let so_aligned = (so_data.len() as u64 + 0xFFF) & !0xFFF;
    emu.mem_map(SO_BASE, so_aligned, Prot::ALL).unwrap();
    emu.mem_write(SO_BASE, &so_data).unwrap();

    // Map other regions
    emu.mem_map(STACK_BASE, STACK_SIZE, Prot::ALL).unwrap();
    emu.mem_map(HEAP_BASE, HEAP_SIZE, Prot::ALL).unwrap();
    emu.mem_map(DATA_BASE, DATA_SIZE, Prot::ALL).unwrap();
    emu.mem_map(HALT_ADDR & !0xFFF, 0x1000, Prot::ALL).unwrap();
    emu.mem_map(STUB_BASE, STUB_SIZE, Prot::ALL).unwrap();

    // Write RET at halt address and all stub locations
    let ret_insn = 0xD65F03C0u32.to_le_bytes();
    emu.mem_write(HALT_ADDR, &ret_insn).unwrap();
    // Fill stub area with RET instructions
    let ret_page: Vec<u8> = (0..STUB_SIZE / 4)
        .flat_map(|_| ret_insn.to_vec())
        .collect();
    emu.mem_write(STUB_BASE, &ret_page).unwrap();

    // Set up TLS
    let tls_base = DATA_BASE + 0x80000;
    let stack_guard: u64 = 0xDEADBEEFCAFEBABE;
    emu.mem_write(tls_base + 0x28, &stack_guard.to_le_bytes())
        .unwrap();
    emu.reg_write(RegisterARM64::TPIDR_EL0, tls_base).unwrap();

    // Write test input
    let input: &[u8] = &[
        0x31, 0x39, 0x36, 0x37, 0xab, 0x7c, 0xfe, 0x85, 0x31, 0x39, 0x36, 0x37,
    ];
    emu.mem_write(DATA_BASE, input).unwrap();
    let out_addr = DATA_BASE + 0x1000;

    // Set registers
    let sp = STACK_BASE + STACK_SIZE - 0x10000;
    emu.reg_write(RegisterARM64::SP, sp).unwrap();
    emu.reg_write(RegisterARM64::X29, sp).unwrap();
    emu.reg_write(RegisterARM64::X0, DATA_BASE).unwrap();
    emu.reg_write(RegisterARM64::X1, input.len() as u64).unwrap();
    emu.reg_write(RegisterARM64::X2, out_addr).unwrap();
    emu.reg_write(RegisterARM64::LR, HALT_ADDR).unwrap();

    // Hook stub calls - implement malloc/memcpy/etc.
    emu.add_code_hook(STUB_BASE, STUB_BASE + STUB_SIZE, |emu: &mut Unicorn<EmuState>, addr: u64, _size: u32| {
        let lr = emu.reg_read(RegisterARM64::LR).unwrap_or(0);
        let x0 = emu.reg_read(RegisterARM64::X0).unwrap_or(0);
        let x1 = emu.reg_read(RegisterARM64::X1).unwrap_or(0);
        let x2 = emu.reg_read(RegisterARM64::X2).unwrap_or(0);

        let stub_off = addr - STUB_BASE;

        // Identify by argument patterns:
        if x2 > 0 && x2 < 0x100000 && x0 >= 0x10000 && x1 >= 0x10000 {
            // memcpy(dst, src, len) or memmove
            let len = x2 as usize;
            if let Ok(buf) = emu.mem_read_as_vec(x1, len) {
                let _ = emu.mem_write(x0, &buf);
            }
            // return dst (x0 unchanged)
        } else if x2 > 0 && x2 < 0x100000 && x0 >= 0x10000 && x1 < 256 {
            // memset(dst, val, len)
            let buf = vec![x1 as u8; x2 as usize];
            let _ = emu.mem_write(x0, &buf);
        } else if x0 > 0 && x0 < 0x1000000 {
            // malloc(size) or similar allocator
            let state = emu.get_data_mut();
            let ptr = state.heap_next;
            state.heap_next += (x0 + 15) & !15;
            emu.reg_write(RegisterARM64::X0, ptr).unwrap();
        } else if x0 >= HEAP_BASE && x0 < HEAP_BASE + HEAP_SIZE {
            // free(ptr) - no-op
            emu.reg_write(RegisterARM64::X0, 0).unwrap();
        } else {
            // Unknown function - allocate a small buffer and return it
            // Many functions return a pointer to something
            let state = emu.get_data_mut();
            let ptr = state.heap_next;
            state.heap_next += 256;
            emu.reg_write(RegisterARM64::X0, ptr).unwrap();
            eprintln!(
                "[STUB#{}] LR=SO+0x{:x} x0=0x{:x} x1=0x{:x} x2=0x{:x} → heap 0x{:x}",
                stub_off/4, lr.wrapping_sub(SO_BASE), x0, x1, x2, ptr,
            );
        }
    }).unwrap();

    // Hook unmapped data access for debugging
    emu.add_mem_hook(
        HookType::MEM_READ_UNMAPPED | HookType::MEM_WRITE_UNMAPPED,
        0,
        u64::MAX,
        |emu: &mut Unicorn<EmuState>, mem_type: MemType, addr: u64, size: usize, _value: i64| -> bool {
            let pc = emu.reg_read(RegisterARM64::PC).unwrap_or(0);
            eprintln!(
                "[UNMAPPED] {:?} addr=0x{:x} size={} PC=SO+0x{:x}",
                mem_type, addr, size, pc.wrapping_sub(SO_BASE),
            );
            false
        },
    ).unwrap();

    // Execute MD5
    let md5_addr = SO_BASE + OFF_MD5;
    match emu.emu_start(md5_addr, HALT_ADDR, 10_000_000, 0) {
        Ok(()) => {}
        Err(e) => {
            let pc = emu.reg_read(RegisterARM64::PC).unwrap();
            eprintln!(
                "MD5 error: {:?} at PC=0x{:x} (SO+0x{:x})",
                e, pc, pc.wrapping_sub(SO_BASE)
            );
            return format!("error: {:?}", e);
        }
    }

    let mut md5_out = [0u8; 16];
    emu.mem_read(out_addr, &mut md5_out).unwrap();
    hex::encode(md5_out)
}

pub fn sign(_url: &str) -> HashMap<String, String> {
    HashMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulated_md5() {
        let result = test_md5();
        println!("Emulated MD5: {}", result);
        assert_eq!(result, "059874c397db2a6594024f0aa1c288c4");
    }
}
