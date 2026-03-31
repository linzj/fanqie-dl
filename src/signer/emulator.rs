//! ARM64 emulator for libmetasec_ml.so signing.
//! Starts execution from the first MD5 wrapper call (captured at signing start),
//! then lets the CFF code continue the full signing flow.

use std::collections::HashMap;
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Prot};
use unicorn_engine::{RegisterARM64, Unicorn};

const SO_SIZE: u64 = 0x3E4000;
const HEAP_BASE: u64 = 0x80000000;
const HEAP_SIZE: u64 = 0x1000000;
const HALT_ADDR: u64 = 0xDEAD0000;
const STUB_BASE: u64 = 0xA0000000;
const STUB_SIZE: u64 = 0x100000;

const OFF_MD5_WRAPPER: u64 = 0x258530;
const OFF_MAP_SET: u64 = 0x25BF3C;

struct EmuState {
    heap_next: u64,
    so_base: u64,
    signatures: Vec<(String, String)>,
}

fn read_so_base() -> u64 {
    let d = std::fs::read(format!("{}/lib/emu_state.bin", env!("CARGO_MANIFEST_DIR"))).unwrap();
    u64::from_le_bytes(d[0..8].try_into().unwrap())
}

fn load_so() -> Vec<u8> {
    let dir = env!("CARGO_MANIFEST_DIR");
    let mut data = std::fs::read(format!("{}/lib/so_memdump.bin", dir)).unwrap();
    if let Ok(fixed) = std::fs::read(format!("{}/lib/libmetasec_ml_fixed.so", dir)) {
        for off in (0..data.len().min(fixed.len())).step_by(4096) {
            if data[off..off+4096].iter().all(|&b| b == 0) && fixed[off..off+4096].iter().any(|&b| b != 0) {
                data[off..off+4096].copy_from_slice(&fixed[off..off+4096]);
            }
        }
    }
    // NOP stack guard checks
    let nop = 0xD503201Fu32.to_le_bytes();
    for off in (0..data.len().saturating_sub(16)).step_by(4) {
        let w0 = u32::from_le_bytes(data[off..off+4].try_into().unwrap());
        if (w0 & 0xFFC00000) == 0xF9400000 && ((w0 >> 10) & 0xFFF) == 5 {
            let w1 = u32::from_le_bytes(data[off+4..off+8].try_into().unwrap());
            let w2 = u32::from_le_bytes(data[off+8..off+12].try_into().unwrap());
            let w3 = u32::from_le_bytes(data[off+12..off+16].try_into().unwrap());
            if (w1 >> 21) == 0x7C2 && ((w1 >> 12) & 0x1FF) == 0x1F8 && ((w1 >> 5) & 0x1F) == 29
                && (w2 & 0xFFE0FC1F) == 0xEB00001F && (w3 & 0xFF00001F) == 0x54000001 {
                for i in 0..4 { data[off+i*4..off+i*4+4].copy_from_slice(&nop); }
            }
        }
    }
    data
}

fn patch_got(so: &mut [u8], so_base: u64) {
    let so_end = so_base + SO_SIZE;
    let mut seen = HashMap::new();
    let mut next = 0u64;
    for &(s, e) in &[(0x17b000,0x17c000),(0x241000,0x246000),(0x24b000,0x24c000),
                      (0x25b000,0x25d000),(0x347000,0x349000),(0x34c000,0x376000),(0x379000,0x3D2000)] {
        let (s, e) = (s.min(so.len()), e.min(so.len()));
        let mut off = s;
        while off + 8 <= e {
            let v = u64::from_le_bytes(so[off..off+8].try_into().unwrap());
            if v > 0x10000 && (v < so_base || v >= so_end) && v > 0x7000000000 && v < 0x8000000000 {
                let stub = *seen.entry(v).or_insert_with(|| { let s = next; next += 4; s });
                so[off..off+8].copy_from_slice(&(STUB_BASE + stub).to_le_bytes());
            }
            off += 8;
        }
    }
}

fn load_emu_state(emu: &mut Unicorn<EmuState>, so_base: u64) -> HashMap<String, u64> {
    let data = std::fs::read(format!("{}/lib/emu_state.bin", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let mut pos = 8usize; // skip SO_BASE
    let nr = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize; pos += 4;
    let nm = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize; pos += 4;
    let mut regs = HashMap::new();
    for _ in 0..nr {
        let n = std::str::from_utf8(&data[pos..pos+16]).unwrap().trim_end_matches('\0').to_string(); pos += 16;
        let v = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()); pos += 8;
        regs.insert(n, v);
    }
    let so_end = so_base + SO_SIZE;
    let mut pages: HashMap<u64, Vec<u8>> = HashMap::new();
    for _ in 0..nm {
        let addr = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()); pos += 8;
        let size = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize; pos += 4;
        let rd = &data[pos..pos+size]; pos += size;
        let mut off = 0;
        while off < size {
            let ca = addr + off as u64;
            if ca >= so_base && ca < so_end { off += 1; continue; }
            let pg = ca & !0xFFF;
            let po = (ca - pg) as usize;
            let cl = (0x1000 - po).min(size - off);
            let pd = pages.entry(pg).or_insert_with(|| vec![0u8; 0x1000]);
            pd[po..po+cl].copy_from_slice(&rd[off..off+cl]);
            off += cl;
        }
    }
    // Map in mega-regions
    let mut megas: HashMap<u64, Vec<u64>> = HashMap::new();
    for &pg in pages.keys() { megas.entry(pg & !0xFFFFF).or_default().push(pg); }
    for (_, pgs) in &megas {
        let mn = *pgs.iter().min().unwrap();
        let mx = *pgs.iter().max().unwrap() + 0x1000;
        if emu.mem_map(mn, mx - mn, Prot::ALL).is_ok() {
            for &pg in pgs {
                if let Some(pd) = pages.get(&pg) { let _ = emu.mem_write(pg, pd); }
            }
        }
    }
    regs
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
    let so_base = read_so_base();
    let mut so = load_so();
    patch_got(&mut so, so_base);

    let mut emu = Unicorn::new_with_data(Arch::ARM64, Mode::LITTLE_ENDIAN, EmuState {
        heap_next: HEAP_BASE, so_base, signatures: Vec::new(),
    }).unwrap();

    let sa = (so.len() as u64 + 0xFFF) & !0xFFF;
    emu.mem_map(so_base, sa, Prot::ALL).unwrap();
    emu.mem_write(so_base, &so).unwrap();
    emu.mem_map(HEAP_BASE, HEAP_SIZE, Prot::ALL).unwrap();
    emu.mem_map(HALT_ADDR & !0xFFF, 0x1000, Prot::ALL).unwrap();
    emu.mem_map(STUB_BASE, STUB_SIZE, Prot::ALL).unwrap();
    emu.mem_map(0, 0x10000, Prot::ALL).unwrap();

    let ret = 0xD65F03C0u32.to_le_bytes();
    for (b, s) in [(STUB_BASE, STUB_SIZE), (HALT_ADDR & !0xFFF, 0x1000), (0u64, 0x10000)] {
        let p: Vec<u8> = (0..s/4).flat_map(|_| ret.to_vec()).collect();
        emu.mem_write(b, &p).unwrap();
    }

    let tls = HEAP_BASE + HEAP_SIZE - 0x10000;
    emu.mem_write(tls + 0x28, &0xDEADBEEFCAFEBABEu64.to_le_bytes()).unwrap();
    emu.reg_write(RegisterARM64::TPIDR_EL0, tls).unwrap();

    let regs = load_emu_state(&mut emu, so_base);
    for (n, &v) in &regs { if let Some(r) = name_to_reg(n) { emu.reg_write(r, v).unwrap(); } }

    // Stub handler
    emu.add_code_hook(STUB_BASE, STUB_BASE + STUB_SIZE, |emu: &mut Unicorn<EmuState>, _a: u64, _s: u32| {
        let (x0,x1,x2) = (emu.reg_read(RegisterARM64::X0).unwrap_or(0),
            emu.reg_read(RegisterARM64::X1).unwrap_or(0),
            emu.reg_read(RegisterARM64::X2).unwrap_or(0));
        if x2 > 0 && x2 < 0x100000 && x0 >= 0x10000 && x1 >= 0x10000 {
            if let Ok(b) = emu.mem_read_as_vec(x1, x2 as usize) { let _ = emu.mem_write(x0, &b); }
        } else if x2 > 0 && x2 < 0x100000 && x0 >= 0x10000 && x1 < 256 {
            let b = vec![x1 as u8; x2 as usize]; let _ = emu.mem_write(x0, &b);
        } else if x0 > 0 && x0 < 0x1000000 {
            let s = emu.get_data_mut(); let p = s.heap_next; s.heap_next += (x0+15)&!15;
            emu.reg_write(RegisterARM64::X0, p).unwrap();
        } else {
            let s = emu.get_data_mut(); let p = s.heap_next; s.heap_next += 256;
            emu.reg_write(RegisterARM64::X0, p).unwrap();
        }
    }).unwrap();

    // Auto-map
    emu.add_mem_hook(HookType::MEM_UNMAPPED, 0, u64::MAX,
        |emu: &mut Unicorn<EmuState>, mt: MemType, addr: u64, _s: usize, _v: i64| -> bool {
            let pg = addr & !0xFFF;
            if pg == 0 { return false; }
            if emu.mem_map(pg, 0x1000, Prot::ALL).is_ok() {
                if matches!(mt, MemType::FETCH_UNMAPPED) {
                    let r: Vec<u8> = (0..0x1000/4).flat_map(|_| 0xD65F03C0u32.to_le_bytes().to_vec()).collect();
                    let _ = emu.mem_write(pg, &r);
                }
                return true;
            }
            false
        },
    ).unwrap();

    // Hook MAP_SET to capture signatures
    emu.add_code_hook(so_base + OFF_MAP_SET, so_base + OFF_MAP_SET + 4,
        |emu: &mut Unicorn<EmuState>, _a: u64, _s: u32| {
            let (x1, x2) = (emu.reg_read(RegisterARM64::X1).unwrap_or(0),
                            emu.reg_read(RegisterARM64::X2).unwrap_or(0));
            let read_buf_obj = |emu: &Unicorn<EmuState>, ptr: u64| -> Option<String> {
                let len = u32::from_le_bytes(emu.mem_read_as_vec(ptr + 0xC, 4).ok()?.try_into().ok()?) as usize;
                let dp = u64::from_le_bytes(emu.mem_read_as_vec(ptr + 0x10, 8).ok()?.try_into().ok()?);
                if len == 0 || len > 10000 { return None; }
                String::from_utf8(emu.mem_read_as_vec(dp, len).ok()?).ok()
            };
            if let (Some(k), Some(v)) = (read_buf_obj(emu, x1), read_buf_obj(emu, x2)) {
                eprintln!("[SIG] {}={}", k, &v[..v.len().min(60)]);
                emu.get_data_mut().signatures.push((k, v));
            }
        },
    ).unwrap();

    // Start from MD5 wrapper (0x258530) — this is where our captured state begins
    // The function will return to LR=SO+0x286df8 which is inside the CFF signing function
    // The CFF code will continue the full signing flow
    // Probes
    // Probe: check MD5 wrapper return value
    emu.add_code_hook(so_base + 0x286df8, so_base + 0x286dfc, |emu: &mut Unicorn<EmuState>, _, _| {
        let x0 = emu.reg_read(RegisterARM64::X0).unwrap_or(0);
        eprintln!("[MD5_WRAP_RET] x0=0x{:x}", x0);
    }).unwrap();

    let start = so_base + OFF_MD5_WRAPPER;
    eprintln!("[emu] Starting from MD5 wrapper (SO+0x{:x}), will return to CFF at SO+0x286df8", OFF_MD5_WRAPPER);

    // timeout 60 seconds (in microseconds)
    match emu.emu_start(start, HALT_ADDR, 60_000_000, 0) {
        Ok(()) => eprintln!("[emu] Completed normally"),
        Err(e) => {
            let pc = emu.reg_read(RegisterARM64::PC).unwrap_or(0);
            eprintln!("[emu] Error: {:?} PC=0x{:x} SO+0x{:x}", e, pc, pc.wrapping_sub(so_base));
        }
    }

    let sigs = emu.get_data().signatures.clone();
    eprintln!("[emu] Captured {} signatures", sigs.len());
    sigs
}

pub fn sign(_url: &str) -> HashMap<String, String> { HashMap::new() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_flow() {
        let sigs = test_signing();
        for (k, v) in &sigs {
            println!("  {}: {}", k, &v[..v.len().min(60)]);
        }
        assert!(sigs.iter().any(|(k, _)| k == "X-Helios"), "Missing X-Helios");
        assert!(sigs.iter().any(|(k, _)| k == "X-Medusa"), "Missing X-Medusa");
    }
}
