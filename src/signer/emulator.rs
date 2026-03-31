//! ARM64 emulator with all crypto fast-pathed.
//! Only CFF dispatch + Helios generation runs in Unicorn.

use std::collections::HashMap;
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Prot};
use unicorn_engine::{RegisterARM64, Unicorn};

const HALT_ADDR: u64 = 0xDEAD0000;

struct Emu {
    so_base: u64,
    heap_next: u64,
    sigs: Vec<(String, String)>,
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

pub fn test_signing() -> Vec<(String, String)> {
    let dir = env!("CARGO_MANIFEST_DIR");
    let memdump = std::fs::read(format!("{}/lib/memdump.bin", dir)).unwrap();
    let mut pos = 0;
    let so_base = u64::from_le_bytes(memdump[pos..pos+8].try_into().unwrap()); pos += 8;
    let count = u32::from_le_bytes(memdump[pos..pos+4].try_into().unwrap()) as usize; pos += 4;

    let mut emu = Unicorn::new_with_data(Arch::ARM64, Mode::LITTLE_ENDIAN, Emu {
        so_base, heap_next: 0x50000000, sigs: vec![],
    }).unwrap();

    // Pre-map address space based on actual dump ranges (4GB aligned super-regions)
    {
        let mut supers = std::collections::HashSet::new();
        let mut scan_pos = 12;
        for _ in 0..count {
            let base = u64::from_le_bytes(memdump[scan_pos..scan_pos+8].try_into().unwrap());
            let size = u64::from_le_bytes(memdump[scan_pos+8..scan_pos+16].try_into().unwrap()) as usize;
            scan_pos += 16 + size;
            // Use 2GB alignment to get more granular coverage
            supers.insert(base & !0x7FFFFFFF); // 2GB aligned
        }
        let mut mapped = 0;
        for s in &supers {
            if emu.mem_map(*s, 0x80000000, Prot::ALL).is_ok() { mapped += 1; } // 2GB
        }
        // Also map low addresses
        if !supers.contains(&0) {
            let _ = emu.mem_map(0, 0x80000000, Prot::ALL);
            mapped += 1;
        }
        eprintln!("[emu] Pre-mapped {}/{} super-regions (2GB each)", mapped, supers.len() + 1);
    }

    // Write halt page
    for off in (0..0x1000u64).step_by(4) {
        emu.mem_write(HALT_ADDR + off, &0xD65F03C0u32.to_le_bytes()).ok();
    }

    // Load all dump ranges
    let mut loaded = 0u32;
    for _ in 0..count {
        let base = u64::from_le_bytes(memdump[pos..pos+8].try_into().unwrap()); pos += 8;
        let size = u64::from_le_bytes(memdump[pos..pos+8].try_into().unwrap()) as usize; pos += 8;
        if emu.mem_write(base, &memdump[pos..pos+size]).is_ok() { loaded += 1; }
        pos += size;
    }
    eprintln!("[emu] Loaded {}/{} ranges, SO=0x{:x}", loaded, count, so_base);

    // Load registers
    for line in std::fs::read_to_string("/tmp/regs_only.txt").unwrap().lines() {
        if let Some(rest) = line.strip_prefix("REG:") {
            let p: Vec<&str> = rest.split(':').collect();
            if p.len() == 2 {
                if let (Some(r), Ok(v)) = (name_to_reg(p[0]), u64::from_str_radix(p[1].trim_start_matches("0x"), 16)) {
                    emu.reg_write(r, v).unwrap();
                }
            }
        }
    }

    // === FAST-PATH HOOKS ===

    // MD5 raw (0x243C34): md5(data, len, out16) — skip body, compute in Rust
    emu.add_code_hook(so_base + 0x243C34, so_base + 0x243C38,
        |emu: &mut Unicorn<Emu>, _, _| {
            let (x0, x1, x2, lr) = (
                emu.reg_read(RegisterARM64::X0).unwrap_or(0),
                emu.reg_read(RegisterARM64::X1).unwrap_or(0) as usize,
                emu.reg_read(RegisterARM64::X2).unwrap_or(0),
                emu.reg_read(RegisterARM64::LR).unwrap_or(0),
            );
            if let Ok(data) = emu.mem_read_as_vec(x0, x1) {
                let hash = md5::compute(&data);
                let _ = emu.mem_write(x2, &hash.0);
            }
            emu.reg_write(RegisterARM64::PC, lr).unwrap();
        }).unwrap();

    // MD5 wrapper (0x258530) — let CFF code run, only raw MD5 is fast-pathed
    /*
    emu.add_code_hook(so_base + 0x258530, so_base + 0x258534,
        |emu: &mut Unicorn<Emu>, _, _| {
            let x0 = emu.reg_read(RegisterARM64::X0).unwrap_or(0);
            let lr = emu.reg_read(RegisterARM64::LR).unwrap_or(0);
            if let (Ok(lb), Ok(pb)) = (emu.mem_read_as_vec(x0 + 0xC, 4), emu.mem_read_as_vec(x0 + 0x10, 8)) {
                let len = u32::from_le_bytes(lb.try_into().unwrap()) as usize;
                let ptr = u64::from_le_bytes(pb.try_into().unwrap());
                if len > 0 && len < 1_000_000 {
                    if let Ok(data) = emu.mem_read_as_vec(ptr, len) {
                        let hash = md5::compute(&data);
                        let s = emu.get_data_mut();
                        let hb = s.heap_next; s.heap_next += 16;
                        let obj = s.heap_next; s.heap_next += 32;
                        let _ = emu.mem_write(hb, &hash.0);
                        let _ = emu.mem_write(obj + 0xC, &16u32.to_le_bytes());
                        let _ = emu.mem_write(obj + 0x10, &hb.to_le_bytes());
                    }
                }
            }
            emu.reg_write(RegisterARM64::X0, 0).unwrap();
            emu.reg_write(RegisterARM64::PC, lr).unwrap();
        }).unwrap();

    */

    // AES key expand (0x241E9C) — fast-path with aes crate
    // AES ECB alt (0x242640) — fast-path
    // SHA1 (0x2451FC/0x2450AC/0x243E50) — fast-path
    // For now, let these run in Unicorn (they're smaller than MD5)
    // TODO: add fast-paths if still too slow

    // MAP_SET hook to capture signatures
    emu.add_code_hook(so_base + 0x25BF3C, so_base + 0x25BF40,
        |emu: &mut Unicorn<Emu>, _, _| {
            let (x1, x2) = (emu.reg_read(RegisterARM64::X1).unwrap_or(0),
                            emu.reg_read(RegisterARM64::X2).unwrap_or(0));
            let ro = |e: &Unicorn<Emu>, p: u64| -> Option<String> {
                let l = u32::from_le_bytes(e.mem_read_as_vec(p+0xC,4).ok()?.try_into().ok()?) as usize;
                let d = u64::from_le_bytes(e.mem_read_as_vec(p+0x10,8).ok()?.try_into().ok()?);
                if l == 0 || l > 10000 { return None; }
                String::from_utf8(e.mem_read_as_vec(d, l.min(2000)).ok()?).ok()
            };
            if let (Some(k), Some(v)) = (ro(emu, x1), ro(emu, x2)) {
                eprintln!("[SIG] {}={}", k, &v[..v.len().min(60)]);
                emu.get_data_mut().sigs.push((k, v));
            }
        }).unwrap();

    // === INTERRUPT HANDLER (SVC, LSE atomics, BTI) ===
    emu.add_intr_hook(|emu: &mut Unicorn<Emu>, _intno: u32| {
        let pc = emu.reg_read(RegisterARM64::PC).unwrap_or(0);
        if let Ok(ib) = emu.mem_read_as_vec(pc, 4) {
            let w = u32::from_le_bytes(ib.try_into().unwrap());

            // SVC
            if (w & 0xFFE0001F) == 0xD4000001 {
                emu.reg_write(RegisterARM64::X0, 0).unwrap();
                emu.reg_write(RegisterARM64::PC, pc + 4).unwrap();
                return;
            }
            // BTI
            if (w & 0xFFFFFF3F) == 0xD503241F {
                emu.reg_write(RegisterARM64::PC, pc + 4).unwrap();
                return;
            }
            // LDADD* (LSE atomic)
            if (w & 0x3F20FC00) == 0x38200000 {
                let rt = (w & 0x1F) as i32;
                let rn = ((w >> 5) & 0x1F) as i32;
                let rs = ((w >> 16) & 0x1F) as i32;
                let sz = (w >> 30) & 3;
                let addr = emu.reg_read(rn + RegisterARM64::X0 as i32).unwrap_or(0);
                let rsv = emu.reg_read(rs + RegisterARM64::X0 as i32).unwrap_or(0);
                let old = match sz {
                    0 => { let mut b=[0u8;1]; let _ = emu.mem_read(addr,&mut b); b[0] as u64 }
                    1 => { let mut b=[0u8;2]; let _ = emu.mem_read(addr,&mut b); u16::from_le_bytes(b) as u64 }
                    2 => { let mut b=[0u8;4]; let _ = emu.mem_read(addr,&mut b); u32::from_le_bytes(b) as u64 }
                    _ => { let mut b=[0u8;8]; let _ = emu.mem_read(addr,&mut b); u64::from_le_bytes(b) }
                };
                let nv = old.wrapping_add(rsv);
                match sz { 0 => {let _ = emu.mem_write(addr,&(nv as u8).to_le_bytes());}
                    1 => {let _ = emu.mem_write(addr,&(nv as u16).to_le_bytes());}
                    2 => {let _ = emu.mem_write(addr,&(nv as u32).to_le_bytes());}
                    _ => {let _ = emu.mem_write(addr,&nv.to_le_bytes());} }
                if rt != 31 { emu.reg_write(rt + RegisterARM64::X0 as i32, old).unwrap(); }
                emu.reg_write(RegisterARM64::PC, pc + 4).unwrap();
                return;
            }
            // LDAXR/LDXR/LDAR
            if (w & 0x3F400000) == 0x08400000 {
                let rt = (w & 0x1F) as i32;
                let rn = ((w >> 5) & 0x1F) as i32;
                let sz = (w >> 30) & 3;
                let addr = if rn!=31 { emu.reg_read(rn+RegisterARM64::X0 as i32).unwrap_or(0) }
                           else { emu.reg_read(RegisterARM64::SP).unwrap_or(0) };
                let v = match sz {
                    0 => { let mut b=[0u8;1]; let _ = emu.mem_read(addr,&mut b); b[0] as u64 }
                    1 => { let mut b=[0u8;2]; let _ = emu.mem_read(addr,&mut b); u16::from_le_bytes(b) as u64 }
                    2 => { let mut b=[0u8;4]; let _ = emu.mem_read(addr,&mut b); u32::from_le_bytes(b) as u64 }
                    _ => { let mut b=[0u8;8]; let _ = emu.mem_read(addr,&mut b); u64::from_le_bytes(b) }
                };
                if rt != 31 { emu.reg_write(rt+RegisterARM64::X0 as i32, v).unwrap(); }
                emu.reg_write(RegisterARM64::PC, pc + 4).unwrap();
                return;
            }
            // STXR/STLXR
            if (w & 0x3F400000) == 0x08000000 {
                let rt = (w & 0x1F) as i32;
                let rn = ((w >> 5) & 0x1F) as i32;
                let rs = ((w >> 16) & 0x1F) as i32;
                let sz = (w >> 30) & 3;
                let addr = if rn!=31 { emu.reg_read(rn+RegisterARM64::X0 as i32).unwrap_or(0) }
                           else { emu.reg_read(RegisterARM64::SP).unwrap_or(0) };
                let v = if rt!=31 { emu.reg_read(rt+RegisterARM64::X0 as i32).unwrap_or(0) } else { 0 };
                match sz { 0 => {let _ = emu.mem_write(addr,&(v as u8).to_le_bytes());}
                    1 => {let _ = emu.mem_write(addr,&(v as u16).to_le_bytes());}
                    2 => {let _ = emu.mem_write(addr,&(v as u32).to_le_bytes());}
                    _ => {let _ = emu.mem_write(addr,&v.to_le_bytes());} }
                if rs != 31 { emu.reg_write(rs+RegisterARM64::X0 as i32, 0).unwrap(); }
                emu.reg_write(RegisterARM64::PC, pc + 4).unwrap();
                return;
            }
        }
        // Default: skip
        emu.reg_write(RegisterARM64::PC, pc + 4).unwrap();
    }).unwrap();

    // Handle unmapped reads/writes by mapping the page on the fly
    emu.add_mem_hook(HookType::MEM_WRITE_UNMAPPED | HookType::MEM_READ_UNMAPPED, 0, u64::MAX,
        |emu: &mut Unicorn<Emu>, _mt: MemType, addr: u64, _sz: usize, _v: i64| -> bool {
            let page = addr & !0xFFF;
            // Try mapping — may fail for extreme addresses
            emu.mem_map(page, 0x1000, Prot::ALL).is_ok()
        }).unwrap();
    emu.add_mem_hook(HookType::MEM_FETCH_UNMAPPED, 0, u64::MAX,
        |emu: &mut Unicorn<Emu>, _mt: MemType, addr: u64, _sz: usize, _v: i64| -> bool {
            // For code fetch: write RET at target to return from unknown functions
            let page = addr & !0xFFF;
            if emu.mem_map(page, 0x1000, Prot::ALL).is_ok() {
                let ret: Vec<u8> = (0..0x1000/4).flat_map(|_| 0xD65F03C0u32.to_le_bytes().to_vec()).collect();
                let _ = emu.mem_write(page, &ret);
                return true;
            }
            false
        }).unwrap();

    emu.add_insn_invalid_hook(|emu: &mut Unicorn<Emu>| -> bool {
        let pc = emu.reg_read(RegisterARM64::PC).unwrap_or(0);
        emu.reg_write(RegisterARM64::PC, pc + 4).unwrap();
        true
    }).unwrap();

    // Execute — 10 minutes timeout
    let start = so_base + 0x286DF4;
    eprintln!("[emu] Starting at SO+0x286DF4");
    match emu.emu_start(start, HALT_ADDR, 600_000_000, 0) {
        Ok(()) => {
            let pc = emu.reg_read(RegisterARM64::PC).unwrap_or(0);
            eprintln!("[emu] Done PC=0x{:x}", pc);
        }
        Err(e) => {
            let pc = emu.reg_read(RegisterARM64::PC).unwrap_or(0);
            eprintln!("[emu] Error: {:?} PC=0x{:x} SO+0x{:x}", e, pc, pc.wrapping_sub(so_base));
        }
    }

    let sigs = emu.get_data().sigs.clone();
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
