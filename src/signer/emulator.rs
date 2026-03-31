//! ARM64 emulator for libmetasec_ml.so signing functions.
//! Loads the SO memory dump + captured heap state, then executes the orchestrator.

use std::collections::HashMap;
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Prot};
use unicorn_engine::{RegisterARM64, Unicorn};

const SO_SIZE: u64 = 0x3E4000;

fn read_so_base() -> u64 {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let data = std::fs::read(format!("{}/lib/emu_state.bin", manifest_dir))
        .expect("failed to read emu_state.bin");
    u64::from_le_bytes(data[0..8].try_into().unwrap())
}

const STACK_SIZE: u64 = 0x100000;
const HEAP_BASE: u64 = 0x80000000;
const HEAP_SIZE: u64 = 0x1000000;
const HALT_ADDR: u64 = 0xDEAD0000;
const STUB_BASE: u64 = 0xA0000000;
const STUB_SIZE: u64 = 0x100000; // 1MB for stubs

const OFF_MD5: u64 = 0x243C44;
const OFF_ORCHESTRATOR: u64 = 0x17B8F8; // real function body (not the PLT trampoline at 0x17B96C)

struct EmuState {
    heap_next: u64,
    so_base: u64,
}

fn load_so_memdump() -> Vec<u8> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut data = std::fs::read(format!("{}/lib/so_memdump.bin", manifest_dir))
        .expect("failed to read so_memdump.bin");

    // NOP all stack guard checks in the SO code BEFORE loading into Unicorn
    // Pattern: LDR x?, [x?, #0x28]; LDUR x?, [x29, #-8]; CMP x?, x?; B.NE
    let nop = 0xD503201Fu32.to_le_bytes();
    let mut nop_count = 0u32;
    let len = data.len();
    for off in (0..len.saturating_sub(16)).step_by(4) {
        let w0 = u32::from_le_bytes(data[off..off+4].try_into().unwrap());
        // LDR (unsigned offset) with imm12=5 → offset #0x28
        if (w0 & 0xFFC00000) == 0xF9400000 && ((w0 >> 10) & 0xFFF) == 5 {
            let w1 = u32::from_le_bytes(data[off+4..off+8].try_into().unwrap());
            let w2 = u32::from_le_bytes(data[off+8..off+12].try_into().unwrap());
            let w3 = u32::from_le_bytes(data[off+12..off+16].try_into().unwrap());
            // LDUR x?, [x29, #-8]: check opcode, simm9=-8, Rn=29
            let is_ldur = (w1 >> 21) == 0x7C2
                && ((w1 >> 12) & 0x1FF) == 0x1F8
                && ((w1 >> 5) & 0x1F) == 29;
            let is_cmp = (w2 & 0xFFE0FC1F) == 0xEB00001F;
            let is_bne = (w3 & 0xFF00001F) == 0x54000001;
            if is_ldur && is_cmp && is_bne {
                for i in 0..4 {
                    data[off + i * 4..off + i * 4 + 4].copy_from_slice(&nop);
                }
                nop_count += 4;
            }
        }
    }
    eprintln!("[emu] NOP'd {} stack guard instructions in SO data", nop_count);

    // Also NOP all ADRP+BR x16 trampolines that jump outside SO
    // These are PLT-like stubs to external functions (__cxa_guard, etc.)
    // Pattern: ADRP x16, #page; BR x16
    let mut tramp_count = 0u32;
    for off in (0..len.saturating_sub(8)).step_by(4) {
        let w0 = u32::from_le_bytes(data[off..off+4].try_into().unwrap());
        let w1 = u32::from_le_bytes(data[off+4..off+8].try_into().unwrap());
        // ADRP x16: bit[31]=1, bits[28:24]=10000, Rd=16(10000)
        let is_adrp_x16 = (w0 & 0x9F00001F) == 0x90000010;
        // BR x16: 0xD61F0200
        let is_br_x16 = w1 == 0xD61F0200;
        if is_adrp_x16 && is_br_x16 {
            data[off..off+4].copy_from_slice(&nop);
            data[off+4..off+8].copy_from_slice(&nop);
            tramp_count += 1;
        }
    }
    eprintln!("[emu] NOP'd {} ADRP+BR x16 trampolines", tramp_count);

    data
}

/// Patch GOT: redirect external pointers to unique stubs
fn patch_external_got(so_data: &mut [u8], so_base: u64) -> u32 {
    let so_end = so_base + SO_SIZE;
    let mut addr_to_stub: HashMap<u64, u64> = HashMap::new();
    let mut next_stub: u64 = 0;
    let scan_ranges: &[(usize, usize)] = &[
        (0x17b000, 0x17c000), (0x241000, 0x246000), (0x24b000, 0x24c000),
        (0x25b000, 0x25d000), (0x347000, 0x349000), (0x34c000, 0x376000),
        (0x379000, 0x3D2000),
    ];
    for (start, end) in scan_ranges {
        let s = (*start).min(so_data.len());
        let e = (*end).min(so_data.len());
        let mut off = s;
        while off + 8 <= e {
            let val = u64::from_le_bytes(so_data[off..off + 8].try_into().unwrap());
            if val > 0x10000 && (val < so_base || val >= so_end) && val > 0x7000000000 && val < 0x8000000000 {
                let stub_off = *addr_to_stub.entry(val).or_insert_with(|| { let s = next_stub; next_stub += 4; s });
                so_data[off..off + 8].copy_from_slice(&(STUB_BASE + stub_off).to_le_bytes());
            }
            off += 8;
        }
    }
    addr_to_stub.len() as u32
}

/// Parse emu_state.bin and load all memory regions into the emulator
/// Returns (registers, so_base)
fn load_emu_state(emu: &mut Unicorn<EmuState>, so_base: u64) -> HashMap<String, u64> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let data = std::fs::read(format!("{}/lib/emu_state.bin", manifest_dir))
        .expect("failed to read emu_state.bin");

    let mut pos = 0usize;
    // Read SO_BASE from header
    let _saved_so_base = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()); pos += 8;
    let num_regs = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize; pos += 4;
    let num_regions = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize; pos += 4;

    // Read registers
    let mut regs = HashMap::new();
    for _ in 0..num_regs {
        let name = std::str::from_utf8(&data[pos..pos+16]).unwrap().trim_end_matches('\0').to_string();
        pos += 16;
        let val = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()); pos += 8;
        regs.insert(name, val);
    }

    // Collect all pages needed
    let mut pages: HashMap<u64, Vec<u8>> = HashMap::new();
    for _ in 0..num_regions {
        let addr = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()); pos += 8;
        let size = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize; pos += 4;
        let region_data = &data[pos..pos+size]; pos += size;

        // Write into pages (skip SO range — SO was already loaded with patches)
        let so_end = so_base + SO_SIZE;
        let mut off = 0usize;
        while off < size {
            let cur_addr = addr + off as u64;
            if cur_addr >= so_base && cur_addr < so_end {
                off += 1;
                continue;
            }
            let page = cur_addr & !0xFFF;
            let page_off = (cur_addr - page) as usize;
            let chunk_len = (0x1000 - page_off).min(size - off);

            let page_data = pages.entry(page).or_insert_with(|| vec![0u8; 0x1000]);
            page_data[page_off..page_off + chunk_len].copy_from_slice(&region_data[off..off + chunk_len]);
            off += chunk_len;
        }
    }

    // Map pages in large chunks to avoid Unicorn's section limit
    // Group all pages into mega-regions (round to 1MB boundaries)
    let mut mega_regions: HashMap<u64, Vec<u64>> = HashMap::new();
    for &page in pages.keys() {
        if page >= so_base && page < so_base + SO_SIZE { continue; } // skip SO range
        let mega = page & !0xFFFFF; // 1MB aligned
        mega_regions.entry(mega).or_default().push(page);
    }

    let mut mapped = 0u32;
    for (mega_start, page_list) in &mega_regions {
        // Find the range within this mega region
        let min_page = *page_list.iter().min().unwrap();
        let max_page = *page_list.iter().max().unwrap() + 0x1000;
        // Align to page boundary
        let start = min_page;
        let end = max_page;
        let size = end - start;
        if emu.mem_map(start, size, Prot::ALL).is_ok() {
            for &page in page_list {
                if let Some(page_data) = pages.get(&page) {
                    let _ = emu.mem_write(page, page_data);
                }
            }
            mapped += page_list.len() as u32;
        }
    }
    // Also write SO-range pages directly
    for (&page, page_data) in &pages {
        if page >= so_base && page < so_base + SO_SIZE {
            let _ = emu.mem_write(page, page_data);
        }
    }
    eprintln!("[emu] Loaded {} heap pages in {} mega-regions", mapped, mega_regions.len());

    regs
}

fn name_to_reg(name: &str) -> Option<RegisterARM64> {
    match name {
        "x0" => Some(RegisterARM64::X0), "x1" => Some(RegisterARM64::X1),
        "x2" => Some(RegisterARM64::X2), "x3" => Some(RegisterARM64::X3),
        "x4" => Some(RegisterARM64::X4), "x5" => Some(RegisterARM64::X5),
        "x6" => Some(RegisterARM64::X6), "x7" => Some(RegisterARM64::X7),
        "x8" => Some(RegisterARM64::X8), "x9" => Some(RegisterARM64::X9),
        "x10" => Some(RegisterARM64::X10), "x11" => Some(RegisterARM64::X11),
        "x12" => Some(RegisterARM64::X12), "x13" => Some(RegisterARM64::X13),
        "x14" => Some(RegisterARM64::X14), "x15" => Some(RegisterARM64::X15),
        "x16" => Some(RegisterARM64::X16), "x17" => Some(RegisterARM64::X17),
        "x19" => Some(RegisterARM64::X19), "x20" => Some(RegisterARM64::X20),
        "x21" => Some(RegisterARM64::X21), "x22" => Some(RegisterARM64::X22),
        "x23" => Some(RegisterARM64::X23), "x24" => Some(RegisterARM64::X24),
        "x25" => Some(RegisterARM64::X25), "x26" => Some(RegisterARM64::X26),
        "x27" => Some(RegisterARM64::X27), "x28" => Some(RegisterARM64::X28),
        "fp" => Some(RegisterARM64::X29), "lr" => Some(RegisterARM64::LR),
        "sp" => Some(RegisterARM64::SP),
        _ => None,
    }
}

fn setup_emu<'a>() -> (Unicorn<'a, EmuState>, u64) {
    let so_base = read_so_base();
    let so_end = so_base + SO_SIZE;
    eprintln!("[emu] SO_BASE=0x{:x}", so_base);

    let mut so_data = load_so_memdump();
    let ext_count = patch_external_got(&mut so_data, so_base);
    eprintln!("[emu] Patched {} external GOT entries", ext_count);

    let mut emu = Unicorn::new_with_data(Arch::ARM64, Mode::LITTLE_ENDIAN, EmuState {
        heap_next: HEAP_BASE,
        so_base,
    }).expect("failed to create unicorn");

    // Map SO
    let so_aligned = (so_data.len() as u64 + 0xFFF) & !0xFFF;
    emu.mem_map(so_base, so_aligned, Prot::ALL).unwrap();
    emu.mem_write(so_base, &so_data).unwrap();

    // Map heap, halt, stubs
    emu.mem_map(HEAP_BASE, HEAP_SIZE, Prot::ALL).unwrap();
    emu.mem_map(HALT_ADDR & !0xFFF, 0x1000, Prot::ALL).unwrap();
    emu.mem_map(STUB_BASE, STUB_SIZE, Prot::ALL).unwrap();

    // Fill stubs with RET
    let ret_insn = 0xD65F03C0u32.to_le_bytes();
    let ret_page: Vec<u8> = (0..STUB_SIZE / 4).flat_map(|_| ret_insn.to_vec()).collect();
    emu.mem_write(STUB_BASE, &ret_page).unwrap();
    emu.mem_write(HALT_ADDR, &ret_insn).unwrap();

    // TLS setup
    let tls_base = HEAP_BASE + HEAP_SIZE - 0x10000;
    emu.mem_write(tls_base + 0x28, &0xDEADBEEFCAFEBABEu64.to_le_bytes()).unwrap();
    emu.reg_write(RegisterARM64::TPIDR_EL0, tls_base).unwrap();

    // Load captured heap state
    let regs = load_emu_state(&mut emu, so_base);

    // Set registers from captured state
    for (name, val) in &regs {
        if let Some(reg) = name_to_reg(name) {
            emu.reg_write(reg, *val).unwrap();
        }
    }
    // Override LR to halt after orchestrator returns
    emu.reg_write(RegisterARM64::LR, HALT_ADDR).unwrap();

    // Fix vtable pointer in x1 object (it's 0 in the dump, should point to SO vtable)
    if let Some(&x1) = regs.get("x1") {
        let vtable_addr = so_base + 0x35DC60;
        emu.mem_write(x1, &vtable_addr.to_le_bytes()).unwrap();
        eprintln!("[emu] Set x1 vtable to SO+0x35DC60 (0x{:x})", vtable_addr);
    }

    // Also patch the saved LR on the stack (orchestrator saves LR at [SP+offset])
    // The function prologue does: sub sp, #0xB0; stp x29, x30, [sp, #0x70]
    // So saved LR is at SP + 0x78 (after sp adjustment)
    // But SP hasn't been adjusted yet at entry. Let's compute:
    // At entry, SP = regs["sp"]. After sub sp, #0xB0: new_sp = sp - 0xB0
    // STP x29, x30, [sp, #0x70] → stores LR at new_sp + 0x78 = sp - 0xB0 + 0x78 = sp - 0x38
    if let (Some(&sp_val), Some(&lr_orig)) = (regs.get("sp"), regs.get("lr")) {
        // Write HALT_ADDR where LR will be saved by the prologue
        let saved_lr_addr = sp_val - 0x38;
        let _ = emu.mem_write(saved_lr_addr, &HALT_ADDR.to_le_bytes());
        eprintln!("[emu] Patched saved LR at stack 0x{:x}", saved_lr_addr);
    }

    // Hook stubs for external calls
    emu.add_code_hook(STUB_BASE, STUB_BASE + STUB_SIZE, |emu: &mut Unicorn<EmuState>, addr: u64, _size: u32| {
        let x0 = emu.reg_read(RegisterARM64::X0).unwrap_or(0);
        let x1 = emu.reg_read(RegisterARM64::X1).unwrap_or(0);
        let x2 = emu.reg_read(RegisterARM64::X2).unwrap_or(0);

        if x2 > 0 && x2 < 0x100000 && x0 >= 0x10000 && x1 >= 0x10000 {
            // memcpy
            if let Ok(buf) = emu.mem_read_as_vec(x1, x2 as usize) { let _ = emu.mem_write(x0, &buf); }
        } else if x2 > 0 && x2 < 0x100000 && x0 >= 0x10000 && x1 < 256 {
            // memset
            let buf = vec![x1 as u8; x2 as usize];
            let _ = emu.mem_write(x0, &buf);
        } else if x0 > 0 && x0 < 0x1000000 {
            // malloc
            let state = emu.get_data_mut();
            let ptr = state.heap_next;
            state.heap_next += (x0 + 15) & !15;
            emu.reg_write(RegisterARM64::X0, ptr).unwrap();
        } else if x0 >= HEAP_BASE && x0 < HEAP_BASE + HEAP_SIZE {
            // free
            emu.reg_write(RegisterARM64::X0, 0).unwrap();
        } else {
            let state = emu.get_data_mut();
            let ptr = state.heap_next;
            state.heap_next += 256;
            emu.reg_write(RegisterARM64::X0, ptr).unwrap();
        }
    }).unwrap();

    // Pre-map page 0 with RETs (BLR to NULL pointers)
    emu.mem_map(0x0, 0x10000, Prot::ALL).unwrap();
    {
        let ret_page: Vec<u8> = (0..0x10000/4).flat_map(|_| 0xD65F03C0u32.to_le_bytes().to_vec()).collect();
        emu.mem_write(0x0, &ret_page).unwrap();
    }

    // Hook unmapped memory — auto-map pages with RET for code, zeros for data
    emu.add_mem_hook(
        HookType::MEM_UNMAPPED,
        0, u64::MAX,
        |emu: &mut Unicorn<EmuState>, mem_type: MemType, addr: u64, _size: usize, _value: i64| -> bool {
            let page = addr & !0xFFF;
            if page == 0 { return false; } // already mapped
            if emu.mem_map(page, 0x1000, Prot::ALL).is_ok() {
                if matches!(mem_type, MemType::FETCH_UNMAPPED) {
                    let ret_page: Vec<u8> = (0..0x1000/4).flat_map(|_| 0xD65F03C0u32.to_le_bytes().to_vec()).collect();
                    let _ = emu.mem_write(page, &ret_page);
                }
                return true;
            }
            false
        },
    ).unwrap();

    (emu, so_base)
}

pub fn test_md5() -> String {
    let (mut emu, so_base) = setup_emu();

    let input: &[u8] = &[0x31, 0x39, 0x36, 0x37, 0xab, 0x7c, 0xfe, 0x85, 0x31, 0x39, 0x36, 0x37];
    let data_addr = HEAP_BASE + HEAP_SIZE - 0x20000;
    let out_addr = data_addr + 0x1000;

    emu.mem_write(data_addr, input).unwrap();
    emu.reg_write(RegisterARM64::X0, data_addr).unwrap();
    emu.reg_write(RegisterARM64::X1, input.len() as u64).unwrap();
    emu.reg_write(RegisterARM64::X2, out_addr).unwrap();
    emu.reg_write(RegisterARM64::LR, HALT_ADDR).unwrap();
    let sp = emu.reg_read(RegisterARM64::SP).unwrap();
    emu.reg_write(RegisterARM64::X29, sp).unwrap();

    let md5_addr = so_base + OFF_MD5;
    match emu.emu_start(md5_addr, HALT_ADDR, 10_000_000, 0) {
        Ok(()) => {}
        Err(e) => {
            let pc = emu.reg_read(RegisterARM64::PC).unwrap();
            return format!("error: {:?} PC=SO+0x{:x}", e, pc.wrapping_sub(so_base));
        }
    }
    let mut out = [0u8; 16];
    emu.mem_read(out_addr, &mut out).unwrap();
    hex::encode(out)
}

pub fn test_orchestrator() -> String {
    let (mut emu, so_base) = setup_emu();
    let so_end = so_base + SO_SIZE;

    let orch_addr = so_base + OFF_ORCHESTRATOR;
    eprintln!("[emu] Starting orchestrator at SO+0x{:x}", OFF_ORCHESTRATOR);

    // Instruction counter
    {
        let count = std::cell::Cell::new(0u64);
        emu.add_code_hook(so_base, so_end, move |_emu: &mut Unicorn<EmuState>, _addr: u64, _size: u32| {
            count.set(count.get() + 1);
            if count.get() % 100_000_000 == 0 {
                eprintln!("[INSN] {} million", count.get() / 1_000_000);
            }
        }).unwrap();
    }

    // Also hook STUB calls to see what external functions are called
    emu.add_code_hook(STUB_BASE, STUB_BASE + STUB_SIZE,
        |emu: &mut Unicorn<EmuState>, addr: u64, _size: u32| {
            let lr = emu.reg_read(RegisterARM64::LR).unwrap_or(0);
            let sb = emu.get_data().so_base;
            let x0 = emu.reg_read(RegisterARM64::X0).unwrap_or(0);
            eprintln!("[STUB] LR=SO+0x{:x} x0=0x{:x} stub_id={}", lr.wrapping_sub(sb), x0, (addr - STUB_BASE)/4);
        },
    ).unwrap();

    // Probe key functions to see if they're reached
    for (off, name) in [(OFF_MD5, "MD5"), (0x25BF3C, "MAP_SET"), (0x241E9C, "AES_KEY"),
                         (0x242640, "AES_ECB"), (0x258530, "MD5_WRAP"), (0x2456AC, "B64"),
                         (0x17B974, "ORCH_POST_GUARD")] {
        let name = name.to_string();
        emu.add_code_hook(so_base + off, so_base + off + 4, move |_emu: &mut Unicorn<EmuState>, _addr: u64, _size: u32| {
            eprintln!("[PROBE] {}", name);
        }).unwrap();
    }

    // Hook MAP_SET (sub_25BF3C) to capture signature headers
    // MAP_SET(map, key_obj, val_obj, ...) where obj has [vtable, ?, ?, len@+0xC, data@+0x10]
    emu.add_code_hook(so_base + 0x25BF3C, so_base + 0x25BF40,
        |emu: &mut Unicorn<EmuState>, _addr: u64, _size: u32| {
            let x1 = emu.reg_read(RegisterARM64::X1).unwrap_or(0);
            let x2 = emu.reg_read(RegisterARM64::X2).unwrap_or(0);
            // Read key
            if let (Ok(key_len_bytes), Ok(key_ptr_bytes)) = (
                emu.mem_read_as_vec(x1 + 0xC, 4),
                emu.mem_read_as_vec(x1 + 0x10, 8),
            ) {
                let key_len = u32::from_le_bytes(key_len_bytes.try_into().unwrap()) as usize;
                let key_ptr = u64::from_le_bytes(key_ptr_bytes.try_into().unwrap());
                if key_len > 0 && key_len < 100 {
                    if let Ok(key_data) = emu.mem_read_as_vec(key_ptr, key_len) {
                        let key = String::from_utf8_lossy(&key_data);
                        // Read value
                        if let (Ok(val_len_bytes), Ok(val_ptr_bytes)) = (
                            emu.mem_read_as_vec(x2 + 0xC, 4),
                            emu.mem_read_as_vec(x2 + 0x10, 8),
                        ) {
                            let val_len = u32::from_le_bytes(val_len_bytes.try_into().unwrap()) as usize;
                            let val_ptr = u64::from_le_bytes(val_ptr_bytes.try_into().unwrap());
                            if val_len > 0 && val_len < 10000 {
                                if let Ok(val_data) = emu.mem_read_as_vec(val_ptr, val_len.min(200)) {
                                    let val = String::from_utf8_lossy(&val_data);
                                    eprintln!("[MAP_SET] {}={}", key, &val[..val.len().min(80)]);
                                }
                            }
                        }
                    }
                }
            }
        },
    ).unwrap();

    // Skip PAC instructions
    emu.add_insn_invalid_hook(|emu: &mut Unicorn<EmuState>| -> bool {
        let pc = emu.reg_read(RegisterARM64::PC).unwrap_or(0);
        if let Ok(insn_bytes) = emu.mem_read_as_vec(pc, 4) {
            let w = u32::from_le_bytes(insn_bytes.try_into().unwrap());
            if w == 0xd503233f || w == 0xd50323bf
                || (w & 0xFFFFFC00) == 0xDAC10000 || (w & 0xFFFFFC00) == 0xDAC10800
                || (w & 0xFFFFFC00) == 0xDAC11000 || (w & 0xFFFFFC00) == 0xDAC11800 {
                emu.reg_write(RegisterARM64::PC, pc + 4).unwrap();
                return true;
            }
            let sb = emu.get_data().so_base;
            eprintln!("[INVALID_INSN] PC=SO+0x{:x} insn=0x{:08x}", pc.wrapping_sub(sb), w);
        }
        false
    }).unwrap();

    // Write external stub at 0x7600001000 (the __cxa_guard_acquire trampoline target)
    // Must return to SO+0x17B974 after the trampoline
    {
        let ret_addr = so_base + 0x17B974;
        let stub_code: [u32; 5] = [
            0xF94007E9, // LDR x9, [sp, #8]  (restore saved value)
            0x910043FF, // ADD sp, sp, #0x10  (pop CFF's saved frame)
            0xD2800000 | (((ret_addr & 0xFFFF) as u32) << 5) | 30, // MOVZ x30, #lo16
            0xF2A00000 | ((((ret_addr >> 16) & 0xFFFF) as u32) << 5) | 30, // MOVK x30, #mid16, LSL#16
            0xF2C00000 | ((((ret_addr >> 32) & 0xFFFF) as u32) << 5) | 30, // MOVK x30, #hi16, LSL#32
        ];
        let page = 0x7600001000u64 & !0xFFF;
        let _ = emu.mem_map(page, 0x1000, Prot::ALL); // may already be mapped
        // Fill with RET then overwrite stub location
        let mut page_data = vec![0u8; 0x1000];
        for i in (0..0x1000).step_by(4) { page_data[i..i+4].copy_from_slice(&0xD65F03C0u32.to_le_bytes()); }
        let stub_off = (0x7600001000u64 - page) as usize;
        for (i, insn) in stub_code.iter().enumerate() {
            page_data[stub_off + i*4..stub_off + i*4+4].copy_from_slice(&insn.to_le_bytes());
        }
        // Add RET after stub
        page_data[stub_off + stub_code.len()*4..stub_off + stub_code.len()*4+4]
            .copy_from_slice(&0xD65F03C0u32.to_le_bytes());
        emu.mem_write(page, &page_data).unwrap();
        eprintln!("[emu] External stub at 0x7600001000 → returns to SO+0x17B974");
    }

    // Limit to 10M instructions to avoid long waits
    match emu.emu_start(orch_addr, HALT_ADDR, 60_000_000, 10_000_000) {
        Ok(()) => "orchestrator completed".to_string(),
        Err(e) => {
            let pc = emu.reg_read(RegisterARM64::PC).unwrap();
            format!("error: {:?} PC=SO+0x{:x}", e, pc.wrapping_sub(so_base))
        }
    }
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

    #[test]
    fn test_emulated_orchestrator() {
        let result = test_orchestrator();
        println!("Orchestrator result: {}", result);
        assert!(result.contains("completed"), "Orchestrator failed: {}", result);
    }
}
