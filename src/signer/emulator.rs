//! ARM64 emulator: loads full process memory dump, replays from signing entry.

use std::collections::HashMap;
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Prot};
use unicorn_engine::{RegisterARM64, Unicorn};

const HALT_ADDR: u64 = 0xDEAD0000;
const OFF_MAP_SET: u64 = 0x25BF3C;
const OFF_MD5_WRAPPER: u64 = 0x258530;

struct EmuState {
    so_base: u64,
    signatures: Vec<(String, String)>,
}

fn name_to_reg(n: &str) -> Option<RegisterARM64> {
    match n {
        "x0"=>Some(RegisterARM64::X0),"x1"=>Some(RegisterARM64::X1),"x2"=>Some(RegisterARM64::X2),
        "x3"=>Some(RegisterARM64::X3),"x4"=>Some(RegisterARM64::X4),"x5"=>Some(RegisterARM64::X5),
        "x6"=>Some(RegisterARM64::X6),"x7"=>Some(RegisterARM64::X7),"x8"=>Some(RegisterARM64::X8),
        "x9"=>Some(RegisterARM64::X9),"x10"=>Some(RegisterARM64::X10),"x11"=>Some(RegisterARM64::X11),
        "x12"=>Some(RegisterARM64::X12),"x13"=>Some(RegisterARM64::X13),"x14"=>Some(RegisterARM64::X14),
        "x15"=>Some(RegisterARM64::X15),"x16"=>Some(RegisterARM64::X16),"x17"=>Some(RegisterARM64::X17),
        "x19"=>Some(RegisterARM64::X19),"x20"=>Some(RegisterARM64::X20),"x21"=>Some(RegisterARM64::X21),
        "x22"=>Some(RegisterARM64::X22),"x23"=>Some(RegisterARM64::X23),"x24"=>Some(RegisterARM64::X24),
        "x25"=>Some(RegisterARM64::X25),"x26"=>Some(RegisterARM64::X26),"x27"=>Some(RegisterARM64::X27),
        "x28"=>Some(RegisterARM64::X28),"fp"=>Some(RegisterARM64::X29),"lr"=>Some(RegisterARM64::LR),
        "sp"=>Some(RegisterARM64::SP), _ => None,
    }
}

/// Collect all memory ranges from memdump.bin + anon_pages.bin
/// Returns: (so_base, Vec<(base_addr, data)>)
fn collect_ranges() -> (u64, Vec<(u64, Vec<u8>)>) {
    let dir = env!("CARGO_MANIFEST_DIR");
    let memdump = std::fs::read(format!("{}/lib/memdump.bin", dir)).unwrap();
    let mut pos = 0;
    let so_base = u64::from_le_bytes(memdump[pos..pos+8].try_into().unwrap()); pos += 8;
    let count = u32::from_le_bytes(memdump[pos..pos+4].try_into().unwrap()) as usize; pos += 4;

    let mut all_ranges = Vec::with_capacity(count + 500);
    for _ in 0..count {
        let base = u64::from_le_bytes(memdump[pos..pos+8].try_into().unwrap()); pos += 8;
        let size = u64::from_le_bytes(memdump[pos..pos+8].try_into().unwrap()) as usize; pos += 8;
        all_ranges.push((base, memdump[pos..pos+size].to_vec()));
        pos += size;
    }

    // Add anon executable pages
    if let Ok(anon) = std::fs::read(format!("{}/lib/anon_pages.bin", dir)) {
        let mut ap = 0;
        let ac = u32::from_le_bytes(anon[ap..ap+4].try_into().unwrap()) as usize; ap += 4;
        for _ in 0..ac {
            let base = u64::from_le_bytes(anon[ap..ap+8].try_into().unwrap()); ap += 8;
            let size = u64::from_le_bytes(anon[ap..ap+8].try_into().unwrap()) as usize; ap += 8;
            all_ranges.push((base, anon[ap..ap+size].to_vec()));
            ap += size;
        }
        eprintln!("[emu] +{} anon ranges", ac);
    }

    (so_base, all_ranges)
}

/// Map all collected ranges into Unicorn, merging into large contiguous blocks
fn map_ranges(emu: &mut Unicorn<EmuState>, ranges: &[(u64, Vec<u8>)]) {
    // Group pages by 256MB super-region
    let mut supers: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, (base, _)) in ranges.iter().enumerate() {
        supers.entry(base & !0xFFFFFFF).or_default().push(i); // 256MB aligned
    }

    let mut total_mapped = 0u64;
    for (_, indices) in &supers {
        let min_page = indices.iter().map(|&i| ranges[i].0 & !0xFFF).min().unwrap();
        let max_end = indices.iter().map(|&i| ranges[i].0 + ranges[i].1.len() as u64).max().unwrap();
        let map_end = (max_end + 0xFFF) & !0xFFF;
        let map_size = map_end - min_page;

        if emu.mem_map(min_page, map_size, Prot::ALL).is_ok() {
            for &i in indices {
                let _ = emu.mem_write(ranges[i].0, &ranges[i].1);
            }
            total_mapped += map_size;
        }
    }
    eprintln!("[emu] Mapped {} super-regions, {} MB total", supers.len(), total_mapped / 1048576);
}

pub fn test_signing() -> Vec<(String, String)> {
    let (so_base, ranges) = collect_ranges();
    eprintln!("[emu] SO_BASE=0x{:x}, {} ranges", so_base, ranges.len());

    let mut emu = Unicorn::new_with_data(Arch::ARM64, Mode::LITTLE_ENDIAN, EmuState {
        so_base, signatures: Vec::new(),
    }).unwrap();

    map_ranges(&mut emu, &ranges);

    // Map halt page + null page (for NULL function pointer calls)
    let _ = emu.mem_map(HALT_ADDR & !0xFFF, 0x1000, Prot::ALL);
    emu.mem_write(HALT_ADDR, &0xD65F03C0u32.to_le_bytes()).unwrap();
    let _ = emu.mem_map(0, 0x10000, Prot::ALL);
    let ret_page: Vec<u8> = (0..0x10000/4).flat_map(|_| 0xD65F03C0u32.to_le_bytes().to_vec()).collect();
    emu.mem_write(0, &ret_page).unwrap();

    // Load registers
    let regs_content = std::fs::read_to_string("/tmp/regs_only.txt").unwrap();
    for line in regs_content.lines() {
        if let Some(rest) = line.strip_prefix("REG:") {
            let parts: Vec<&str> = rest.split(':').collect();
            if parts.len() == 2 {
                if let (Some(reg), Ok(val)) = (name_to_reg(parts[0]), u64::from_str_radix(parts[1].trim_start_matches("0x"), 16)) {
                    emu.reg_write(reg, val).unwrap();
                }
            }
        }
    }

    // Check if 0x7a6c9dc000 is in ranges
    let target = 0x7a6c9dc000u64;
    for (base, data) in &ranges {
        if *base <= target && target < *base + data.len() as u64 {
            eprintln!("[emu] Found 0x7a6c9dc000 in range 0x{:x}+0x{:x}", base, data.len());
        }
    }
    // Check what super-region 0x7a6c9dc000 is in
    let super_key = target & !0xFFFFFFF;
    eprintln!("[emu] Target super-region: 0x{:x}", super_key);

    // Verify critical page
    match emu.mem_read_as_vec(0x7a6c9dc500, 4) {
        Ok(v) => eprintln!("[emu] Trampoline OK: {:02x}{:02x}{:02x}{:02x}", v[0], v[1], v[2], v[3]),
        Err(e) => eprintln!("[emu] Trampoline FAIL: {:?}", e),
    }

    // Hook MAP_SET
    emu.add_code_hook(so_base + OFF_MAP_SET, so_base + OFF_MAP_SET + 4,
        |emu: &mut Unicorn<EmuState>, _, _| {
            let (x1, x2) = (emu.reg_read(RegisterARM64::X1).unwrap_or(0),
                            emu.reg_read(RegisterARM64::X2).unwrap_or(0));
            let read_obj = |emu: &Unicorn<EmuState>, p: u64| -> Option<String> {
                let len = u32::from_le_bytes(emu.mem_read_as_vec(p + 0xC, 4).ok()?.try_into().ok()?) as usize;
                let dp = u64::from_le_bytes(emu.mem_read_as_vec(p + 0x10, 8).ok()?.try_into().ok()?);
                if len == 0 || len > 10000 { return None; }
                String::from_utf8(emu.mem_read_as_vec(dp, len.min(2000)).ok()?).ok()
            };
            if let (Some(k), Some(v)) = (read_obj(emu, x1), read_obj(emu, x2)) {
                eprintln!("[SIG] {}={}", k, &v[..v.len().min(60)]);
                emu.get_data_mut().signatures.push((k, v));
            }
        },
    ).unwrap();

    // Skip invalid/unsupported instructions (PAC, BTI, LSE atomics)
    emu.add_insn_invalid_hook(|emu: &mut Unicorn<EmuState>| -> bool {
        let pc = emu.reg_read(RegisterARM64::PC).unwrap_or(0);
        emu.reg_write(RegisterARM64::PC, pc + 4).unwrap();
        true
    }).unwrap();

    // Handle CPU exceptions — implement unsupported LSE atomic instructions
    emu.add_intr_hook(|emu: &mut Unicorn<EmuState>, _intno: u32| {
        let pc = emu.reg_read(RegisterARM64::PC).unwrap_or(0);
        if let Ok(insn_bytes) = emu.mem_read_as_vec(pc, 4) {
            let w = u32::from_le_bytes(insn_bytes.try_into().unwrap());

            // LDADDH (LSE atomic): 0x38200020 family
            // Format: size=01 111 000 001 Rs 0 000 00 Rn Rt
            // LDADD*: 0x38/78/B8/F8 20xxxx
            if (w & 0x3F20FC00) == 0x38200000 {
                let rt = (w & 0x1F) as i32;
                let rn = ((w >> 5) & 0x1F) as i32;
                let rs = ((w >> 16) & 0x1F) as i32;
                let size = (w >> 30) & 3; // 0=byte, 1=half, 2=word, 3=dword

                let addr_val = emu.reg_read(rn + RegisterARM64::X0 as i32).unwrap_or(0);
                let rs_val = emu.reg_read(rs + RegisterARM64::X0 as i32).unwrap_or(0);

                // Read old value
                let old = match size {
                    0 => { let mut b = [0u8;1]; let _ = emu.mem_read(addr_val, &mut b); b[0] as u64 }
                    1 => { let mut b = [0u8;2]; let _ = emu.mem_read(addr_val, &mut b); u16::from_le_bytes(b) as u64 }
                    2 => { let mut b = [0u8;4]; let _ = emu.mem_read(addr_val, &mut b); u32::from_le_bytes(b) as u64 }
                    _ => { let mut b = [0u8;8]; let _ = emu.mem_read(addr_val, &mut b); u64::from_le_bytes(b) }
                };

                // Write new value = old + rs
                let new_val = old.wrapping_add(rs_val);
                match size {
                    0 => { let _ = emu.mem_write(addr_val, &(new_val as u8).to_le_bytes()); }
                    1 => { let _ = emu.mem_write(addr_val, &(new_val as u16).to_le_bytes()); }
                    2 => { let _ = emu.mem_write(addr_val, &(new_val as u32).to_le_bytes()); }
                    _ => { let _ = emu.mem_write(addr_val, &new_val.to_le_bytes()); }
                }

                // Rt = old value
                if rt != 31 { // not xzr
                    emu.reg_write(rt + RegisterARM64::X0 as i32, old).unwrap();
                }

                emu.reg_write(RegisterARM64::PC, pc + 4).unwrap();
                return;
            }

            // BTI (Branch Target Identification): 0xD503241F or 0xD503245F etc.
            if (w & 0xFFFFFF3F) == 0xD503241F {
                emu.reg_write(RegisterARM64::PC, pc + 4).unwrap();
                return;
            }

            // Other: just skip
            emu.reg_write(RegisterARM64::PC, pc + 4).unwrap();
        }
    }).unwrap();

    // Auto-map unmapped data accesses (return zeros)
    emu.add_mem_hook(HookType::MEM_READ_UNMAPPED | HookType::MEM_WRITE_UNMAPPED, 0, u64::MAX,
        |emu: &mut Unicorn<EmuState>, _mt: MemType, addr: u64, _size: usize, _v: i64| -> bool {
            let page = addr & !0xFFF;
            if page == 0 { return false; }
            emu.mem_map(page, 0x1000, Prot::ALL).is_ok()
        },
    ).unwrap();

    // Auto-map unmapped code fetches with RET
    emu.add_mem_hook(HookType::MEM_FETCH_UNMAPPED, 0, u64::MAX,
        |emu: &mut Unicorn<EmuState>, _mt: MemType, addr: u64, _size: usize, _v: i64| -> bool {
            let page = addr & !0xFFF;
            if page == 0 { return false; }
            if emu.mem_map(page, 0x1000, Prot::ALL).is_ok() {
                let ret: Vec<u8> = (0..0x1000/4).flat_map(|_| 0xD65F03C0u32.to_le_bytes().to_vec()).collect();
                let _ = emu.mem_write(page, &ret);
                return true;
            }
            false
        },
    ).unwrap();

    // Probe trampoline + MD5
    emu.add_code_hook(0x7a6c9dc500, 0x7a6c9dc504, |_: &mut Unicorn<EmuState>, _, _| {
        eprintln!("[PROBE] Trampoline 0x7a6c9dc500 hit!");
    }).unwrap();
    emu.add_code_hook(so_base + 0x243C44, so_base + 0x243C48, |_: &mut Unicorn<EmuState>, _, _| {
        eprintln!("[PROBE] MD5_BODY hit!");
    }).unwrap();
    emu.add_code_hook(so_base + 0x258540, so_base + 0x258544, |_: &mut Unicorn<EmuState>, _, _| {
        eprintln!("[PROBE] MD5_WRAPPER_BODY hit!");
    }).unwrap();

    let start = so_base + OFF_MD5_WRAPPER;
    eprintln!("[emu] Starting at SO+0x{:x}", OFF_MD5_WRAPPER);

    match emu.emu_start(start, HALT_ADDR, 60_000_000, 0) {
        Ok(()) => eprintln!("[emu] Completed"),
        Err(e) => {
            let pc = emu.reg_read(RegisterARM64::PC).unwrap_or(0);
            eprintln!("[emu] Error: {:?} PC=0x{:x} (SO+0x{:x})", e, pc, pc.wrapping_sub(so_base));
        }
    }

    let sigs = emu.get_data().signatures.clone();
    eprintln!("[emu] {} signatures", sigs.len());
    sigs
}

pub fn sign(_url: &str) -> HashMap<String, String> { HashMap::new() }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_signing() {
        let sigs = super::test_signing();
        for (k, v) in &sigs { println!("  {}: {}...", k, &v[..v.len().min(60)]); }
        assert!(sigs.iter().any(|(k,_)| k == "X-Helios"), "Missing X-Helios");
    }
}
