//! ARM64 JIT emulator using dynarmic-sys for fast signing.
//! Crypto functions are intercepted via SVC breakpoints patched into the SO.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use dynarmic_sys::Dynarmic;

const HALT_ADDR: u64 = 0xDEAD_0000;

/// Encode SVC #imm16 instruction
fn svc_bytes(imm16: u32) -> [u8; 4] {
    (0xD4000001u32 | ((imm16 & 0xFFFF) << 5)).to_le_bytes()
}

// SVC IDs for fast-pathed functions
const SVC_MD5_RAW: u32       = 0x100;
const SVC_MD5_TRANSFORM: u32 = 0x101;
const SVC_SHA1_TRANSFORM: u32= 0x102;
const SVC_AES_ECB: u32       = 0x103;
const SVC_ALLOC_BUF: u32     = 0x104;
const SVC_MALLOC: u32        = 0x105;
const SVC_CREATE_BUF: u32    = 0x106;
const SVC_BUF_OP: u32        = 0x107;
const SVC_FREE: u32          = 0x108;
const SVC_AES_KEY_EXPAND: u32= 0x109;
const SVC_MAP_SET: u32       = 0x10A;
const SVC_LDADDH: u32        = 0x200; // LDADDH W0, W0, [X1]
const SVC_LDADDLH: u32       = 0x201; // LDADDLH W0, W0, [X1]
const SVC_REFCOUNT_NOP: u32  = 0x202; // Stub for ref-counting library functions
const SVC_TRAP_NULL: u32     = 0x300; // Trap at address 0 (null jump detection)

/// No SVC patches in SO — CFF dispatch uses instruction addresses as constants.
const HOOK_TABLE: &[(u64, u32)] = &[];

struct SharedState {
    heap_next: u64,
    sigs: Vec<(String, String)>,
}

fn reg_index(name: &str) -> Option<usize> {
    match name {
        "x0"=>Some(0),"x1"=>Some(1),"x2"=>Some(2),"x3"=>Some(3),
        "x4"=>Some(4),"x5"=>Some(5),"x6"=>Some(6),"x7"=>Some(7),
        "x8"=>Some(8),"x9"=>Some(9),"x10"=>Some(10),"x11"=>Some(11),
        "x12"=>Some(12),"x13"=>Some(13),"x14"=>Some(14),"x15"=>Some(15),
        "x16"=>Some(16),"x17"=>Some(17),
        "x19"=>Some(19),"x20"=>Some(20),"x21"=>Some(21),"x22"=>Some(22),
        "x23"=>Some(23),"x24"=>Some(24),"x25"=>Some(25),"x26"=>Some(26),
        "x27"=>Some(27),"x28"=>Some(28),
        "fp"=>Some(29),"lr"=>Some(30),
        _ => None,
    }
}

// ---------- Crypto helpers ----------

fn md5_transform_impl(state_bytes: &[u8], block: &[u8]) -> [u8; 16] {
    let mut a = u32::from_le_bytes(state_bytes[0..4].try_into().unwrap());
    let mut b = u32::from_le_bytes(state_bytes[4..8].try_into().unwrap());
    let mut c = u32::from_le_bytes(state_bytes[8..12].try_into().unwrap());
    let mut d = u32::from_le_bytes(state_bytes[12..16].try_into().unwrap());
    let (oa, ob, oc, od) = (a, b, c, d);

    let mut m = [0u32; 16];
    for i in 0..16 { m[i] = u32::from_le_bytes(block[i*4..i*4+4].try_into().unwrap()); }

    static T: [u32; 64] = [
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
    ];
    static S: [u32; 64] = [
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21,
    ];
    static MI: [usize; 64] = [
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
        1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,
        5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
        0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9,
    ];

    for i in 0..64 {
        let fv = match i / 16 {
            0 => (b & c) | (!b & d),
            1 => (d & b) | (!d & c),
            2 => b ^ c ^ d,
            _ => c ^ (b | !d),
        };
        a = b.wrapping_add(
            a.wrapping_add(fv).wrapping_add(T[i]).wrapping_add(m[MI[i]]).rotate_left(S[i])
        );
        let tmp = d; d = c; c = b; b = a; a = tmp;
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&oa.wrapping_add(a).to_le_bytes());
    out[4..8].copy_from_slice(&ob.wrapping_add(b).to_le_bytes());
    out[8..12].copy_from_slice(&oc.wrapping_add(c).to_le_bytes());
    out[12..16].copy_from_slice(&od.wrapping_add(d).to_le_bytes());
    out
}

fn sha1_transform_impl(state_bytes: &[u8], block: &[u8]) -> [u8; 20] {
    let mut h = [0u32; 5];
    for i in 0..5 { h[i] = u32::from_be_bytes(state_bytes[i*4..i*4+4].try_into().unwrap()); }

    let mut w = [0u32; 80];
    for i in 0..16 { w[i] = u32::from_be_bytes(block[i*4..i*4+4].try_into().unwrap()); }
    for i in 16..80 { w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1); }

    let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
    for i in 0..80 {
        let (f, k) = match i {
            0..=19  => ((b & c) | (!b & d), 0x5A827999u32),
            20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
            _       => (b ^ c ^ d, 0xCA62C1D6u32),
        };
        let tmp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
        e = d; d = c; c = b.rotate_left(30); b = a; a = tmp;
    }
    h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);

    let mut out = [0u8; 20];
    for i in 0..5 { out[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes()); }
    out
}

/// Read a string from the SO's string-object layout: [vtable(8), ??(4), len(4), data_ptr(8)]
fn read_str_obj(dy: &Dynarmic<()>, ptr: u64) -> Option<String> {
    let lb = dy.mem_read_as_vec(ptr + 0xC, 4).ok()?;
    let len = u32::from_le_bytes(lb.try_into().ok()?) as usize;
    let pb = dy.mem_read_as_vec(ptr + 0x10, 8).ok()?;
    let dp = u64::from_le_bytes(pb.try_into().ok()?);
    if len == 0 || len > 10000 { return None; }
    String::from_utf8(dy.mem_read_as_vec(dp, len.min(2000)).ok()?).ok()
}

// ---------- Main emulator ----------

pub fn test_signing() -> Vec<(String, String)> {
    let dir = env!("CARGO_MANIFEST_DIR");
    let memdump = std::fs::read(format!("{}/lib/memdump.bin", dir)).unwrap();
    let mut pos = 0usize;
    let so_base = u64::from_le_bytes(memdump[pos..pos+8].try_into().unwrap()); pos += 8;
    let count = u32::from_le_bytes(memdump[pos..pos+4].try_into().unwrap()) as usize; pos += 4;

    let dy = std::sync::Arc::new(Dynarmic::<()>::new());

    // Collect all ranges (rebased)
    let mut ranges: Vec<(u64, usize, usize)> = Vec::with_capacity(count);
    for _ in 0..count {
        let base = u64::from_le_bytes(memdump[pos..pos+8].try_into().unwrap()); pos += 8;
        let size = u64::from_le_bytes(memdump[pos..pos+8].try_into().unwrap()) as usize; pos += 8;
        ranges.push((base, size, pos));
        pos += size;
    }

    // Merge overlapping/adjacent page-aligned ranges for mapping
    let mut page_ranges: Vec<(u64, u64)> = ranges.iter()
        .map(|&(base, size, _)| {
            let a = base & !0xFFF;
            let b = (base + size as u64 + 0xFFF) & !0xFFF;
            (a, b)
        })
        .collect();
    page_ranges.sort();
    let mut merged: Vec<(u64, u64)> = vec![];
    for (a, b) in page_ranges {
        if let Some(last) = merged.last_mut() {
            if a <= last.1 {
                last.1 = last.1.max(b);
                continue;
            }
        }
        merged.push((a, b));
    }
    let mut total_mapped = 0usize;
    for &(start, end) in &merged {
        let size = (end - start) as usize;
        dy.mem_map(start, size, 3).unwrap_or_else(|e| {
            eprintln!("[emu] map fail: 0x{:x} +0x{:x}: {}", start, size, e);
        });
        total_mapped += size;
    }

    // Write data for each original range
    let mut loaded = 0u32;
    for &(base, size, data_off) in &ranges {
        let mut ok = true;
        let mut off = 0usize;
        while off < size {
            let chunk_sz = (size - off).min(0x10000);
            if let Err(e) = dy.mem_write(base + off as u64, &memdump[data_off + off..data_off + off + chunk_sz]) {
                if ok { eprintln!("[emu] write fail at 0x{:x}+0x{:x}: {}", base, off, e); }
                ok = false;
                break;
            }
            off += chunk_sz;
        }
        if ok { loaded += 1; }
    }
    eprintln!("[emu] Loaded {}/{} ranges ({}KB mapped), SO=0x{:x}", loaded, count, total_mapped / 1024, so_base);

    // Scan non-SO ranges for LSE atomic instructions and replace with SVC
    // Store original instruction in a lookup table for the SVC handler
    let so_end = so_base + 0x400000;
    let mut lse_map: HashMap<u64, u32> = HashMap::new(); // addr → original insn
    let mut lse_patched = 0u32;
    for &(base, size, data_off) in &ranges {
        if base >= so_base && base < so_end { continue; }
        for off in (0..size).step_by(4) {
            let insn = u32::from_le_bytes(memdump[data_off + off..data_off + off + 4].try_into().unwrap());
            let is_lse = (insn & 0x3F20FC00) == 0x08207C00  // CAS family
                      || (insn & 0x3F200C00) == 0x38200000; // LDADD family
            if is_lse {
                let addr = base + off as u64;
                lse_map.insert(addr, insn);
                dy.mem_write(addr, &svc_bytes(0x500)).ok(); // SVC #0x500 = LSE handler
                lse_patched += 1;
            }
        }
    }
    let lse_map = Arc::new(lse_map);
    if lse_patched > 0 {
        eprintln!("[emu] Patched {} LSE atomic instructions in non-SO ranges", lse_patched);
    }

    // Map and fill halt page with RET
    let _ = dy.mem_map(HALT_ADDR, 0x1000, 3);
    let _ = dy.mem_protect(HALT_ADDR, 0x1000, 7);
    {
        let ret_page: Vec<u8> = (0..0x1000/4)
            .flat_map(|_| 0xD65F03C0u32.to_le_bytes())
            .collect();
        let _ = dy.mem_write(HALT_ADDR, &ret_page);
    }

    // Map heap area
    let _ = dy.mem_map(0x5000_0000, 0x1000_0000, 3); // 256MB heap
    let _ = dy.mem_protect(0x5000_0000, 0x1000_0000, 7);

    // Patch hook addresses with SVC breakpoints
    for &(off, svc_id) in HOOK_TABLE {
        dy.mem_write(so_base + off, &svc_bytes(svc_id)).unwrap();
    }

    eprintln!("[emu] No SVC patches (CFF-safe mode)");

    // Map null page: SVC trap at address 0, rest stays zero for TLS/stack canary reads
    let _ = dy.mem_map(0, 0x1000, 3);
    let _ = dy.mem_protect(0, 0x1000, 7);
    let _ = dy.mem_write(0, &svc_bytes(SVC_TRAP_NULL));
    eprintln!("[emu] Patched {} hooks + null trap (LSE handled dynamically)", HOOK_TABLE.len());

    // Set up fake TLS area for TPIDR_EL0
    // On Android, TPIDR_EL0 points to the thread's TLS block.
    // Without this, MRS TPIDR_EL0 returns 0 and TLS reads go to address 0
    // (which has our SVC trap bytes, corrupting values).
    let tls_base = 0x6000_0000u64;
    let tls_size = 0x2000usize; // 8KB
    let _ = dy.mem_map(tls_base, tls_size, 3);
    let _ = dy.mem_protect(tls_base, tls_size, 7);
    // Point TPIDR_EL0 to middle of TLS area (negative offsets are used by bionic)
    let tpidr = tls_base + 0x1000;
    dy.reg_write_tpidr_el0(tpidr).unwrap();

    eprintln!("[emu] TPIDR_EL0 = 0x{:x}", tpidr);

    // Load registers from dump
    for line in std::fs::read_to_string(format!("{}/lib/regs_only.txt", dir)).unwrap().lines() {
        if let Some(rest) = line.strip_prefix("REG:") {
            let p: Vec<&str> = rest.split(':').collect();
            if p.len() == 2 {
                if let Ok(v) = u64::from_str_radix(p[1].trim_start_matches("0x"), 16) {
                    if p[0] == "sp" {
                        dy.reg_write_sp(v).unwrap();
                    } else if let Some(idx) = reg_index(p[0]) {
                        dy.reg_write_raw(idx, v).unwrap();
                    }
                }
            }
        }
    }

    // Fix stack canary: read the real canary from [FP-8] (saved by the original code
    // using the real TPIDR_EL0) and write it to our fake TPIDR_EL0+0x28
    let fp = dy.reg_read(29).unwrap_or(0);
    if fp > 0x1000 {
        if let Ok(canary_bytes) = dy.mem_read_as_vec(fp - 8, 8) {
            let canary = u64::from_le_bytes(canary_bytes.try_into().unwrap());
            if canary != 0 {
                let _ = dy.mem_write(tpidr + 0x28, &canary.to_le_bytes());
                eprintln!("[emu] Stack canary = 0x{:x} (from [FP-8]=0x{:x})", canary, fp - 8);
            }
        }
    }

    // Shared mutable state for SVC callbacks
    let state = Arc::new(Mutex::new(SharedState {
        heap_next: 0x5000_0000,
        sigs: vec![],
    }));

    // SVC callback — dispatch to fast-path implementations
    let st = state.clone();
    let svc_n = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let svc_nc = svc_n.clone();
    let so_base_cb = so_base;
    let lse_map_cb = lse_map.clone();
    dy.set_svc_callback(move |dy: &Dynarmic<()>, swi: u32, _until: u64, pc: u64| {
        let so_base = so_base_cb;
        let n = svc_nc.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n < 50 {
            let lr = dy.reg_read(30).unwrap_or(0);
            let sp = dy.reg_read_sp().unwrap_or(0);
            eprintln!("[SVC] #{} swi=0x{:x} pc=0x{:x} lr=0x{:x} sp=0x{:x}", n, swi, pc, lr, sp);
        }
        match swi {
            SVC_MD5_RAW => {
                let x0 = dy.reg_read(0).unwrap_or(0);
                let x1 = dy.reg_read(1).unwrap_or(0) as usize;
                let x2 = dy.reg_read(2).unwrap_or(0);
                let lr = dy.reg_read(30).unwrap_or(0);
                eprintln!("[MD5] x0=0x{:x} x1={} x2=0x{:x}", x0, x1, x2);
                if x1 > 0 && x1 < 10_000_000 {
                    if let Ok(data) = dy.mem_read_as_vec(x0, x1) {
                        let preview = String::from_utf8_lossy(&data[..data.len().min(80)]);
                        let hash = md5::compute(&data);
                        eprintln!("[MD5] hash={:x} data={:?}", hash, &preview[..preview.len().min(60)]);
                        let _ = dy.mem_write(x2, &hash.0);
                    }
                } else {
                    // Still write a zero hash so the code has something
                    let _ = dy.mem_write(x2, &[0u8; 16]);
                }
                dy.reg_write_pc(lr).unwrap();
            }
            SVC_MD5_TRANSFORM => {
                let x0 = dy.reg_read(0).unwrap_or(0);
                let x1 = dy.reg_read(1).unwrap_or(0);
                let lr = dy.reg_read(30).unwrap_or(0);
                if let (Ok(sb), Ok(blk)) = (
                    dy.mem_read_as_vec(x0 + 8, 16),
                    dy.mem_read_as_vec(x1, 64),
                ) {
                    let out = md5_transform_impl(&sb, &blk);
                    let _ = dy.mem_write(x0 + 8, &out);
                }
                dy.reg_write_pc(lr).unwrap();
            }
            SVC_SHA1_TRANSFORM => {
                let x0 = dy.reg_read(0).unwrap_or(0);
                let x1 = dy.reg_read(1).unwrap_or(0);
                let lr = dy.reg_read(30).unwrap_or(0);
                // State at ctx+8 (like MD5 layout)
                if let (Ok(sb), Ok(blk)) = (
                    dy.mem_read_as_vec(x0 + 8, 20),
                    dy.mem_read_as_vec(x1, 64),
                ) {
                    let out = sha1_transform_impl(&sb, &blk);
                    let _ = dy.mem_write(x0 + 8, &out);
                }
                dy.reg_write_pc(lr).unwrap();
            }
            SVC_AES_ECB => {
                let x0 = dy.reg_read(0).unwrap_or(0); // ctx (round keys at +0xF0)
                let x1 = dy.reg_read(1).unwrap_or(0); // input 16 bytes
                let x2 = dy.reg_read(2).unwrap_or(0); // output 16 bytes
                let lr = dy.reg_read(30).unwrap_or(0);
                if let (Ok(rk), Ok(input)) = (
                    dy.mem_read_as_vec(x0 + 0xF0, 176),
                    dy.mem_read_as_vec(x1, 16),
                ) {
                    use aes::cipher::{BlockEncrypt, KeyInit};
                    let key: [u8; 16] = rk[0..16].try_into().unwrap();
                    let cipher = aes::Aes128::new_from_slice(&key).unwrap();
                    let mut block = aes::Block::from_slice(&input).clone();
                    cipher.encrypt_block(&mut block);
                    let _ = dy.mem_write(x2, block.as_slice());
                }
                dy.reg_write_pc(lr).unwrap();
            }
            SVC_ALLOC_BUF => {
                let x0 = dy.reg_read(0).unwrap_or(0);
                let lr = dy.reg_read(30).unwrap_or(0);
                let ptr = {
                    let mut s = st.lock().unwrap();
                    let p = s.heap_next;
                    s.heap_next += (x0 + 15) & !15;
                    p
                };
                dy.reg_write_raw(0, ptr).unwrap();
                dy.reg_write_pc(lr).unwrap();
            }
            SVC_MALLOC => {
                let x0 = dy.reg_read(0).unwrap_or(0);
                let lr = dy.reg_read(30).unwrap_or(0);
                let ptr = {
                    let mut s = st.lock().unwrap();
                    let p = s.heap_next;
                    s.heap_next += (x0.max(1) + 15) & !15;
                    p
                };
                dy.reg_write_raw(0, ptr).unwrap();
                dy.reg_write_pc(lr).unwrap();
            }
            SVC_CREATE_BUF => {
                let x0 = dy.reg_read(0).unwrap_or(0); // dst obj
                let x1 = dy.reg_read(1).unwrap_or(0); // src data
                let x2 = dy.reg_read(2).unwrap_or(0) as usize; // len
                let lr = dy.reg_read(30).unwrap_or(0);
                if x2 > 0 && x2 < 100_000 {
                    if let Ok(data) = dy.mem_read_as_vec(x1, x2) {
                        let buf = {
                            let mut s = st.lock().unwrap();
                            let b = s.heap_next;
                            s.heap_next += ((x2 as u64) + 15) & !15;
                            b
                        };
                        let _ = dy.mem_write(buf, &data);
                        let _ = dy.mem_write(x0 + 0xC, &(x2 as u32).to_le_bytes());
                        let _ = dy.mem_write(x0 + 0x10, &buf.to_le_bytes());
                    }
                }
                dy.reg_write_pc(lr).unwrap();
            }
            SVC_BUF_OP => {
                let lr = dy.reg_read(30).unwrap_or(0);
                dy.reg_write_pc(lr).unwrap();
            }
            SVC_FREE => {
                let lr = dy.reg_read(30).unwrap_or(0);
                dy.reg_write_pc(lr).unwrap();
            }
            SVC_AES_KEY_EXPAND => {
                let x0 = dy.reg_read(0).unwrap_or(0); // ctx
                let x1 = dy.reg_read(1).unwrap_or(0); // key
                let x2 = dy.reg_read(2).unwrap_or(0) as usize; // keylen
                let lr = dy.reg_read(30).unwrap_or(0);
                if x2 == 16 {
                    if let Ok(key) = dy.mem_read_as_vec(x1, 16) {
                        let _ = dy.mem_write(x0, &key);
                        let _ = dy.mem_write(x0 + 0xF0, &key);
                    }
                }
                dy.reg_write_pc(lr).unwrap();
            }
            SVC_MAP_SET => {
                let x1 = dy.reg_read(1).unwrap_or(0);
                let x2 = dy.reg_read(2).unwrap_or(0);
                if let (Some(k), Some(v)) = (read_str_obj(dy, x1), read_str_obj(dy, x2)) {
                    eprintln!("[SIG] {}={}", k, &v[..v.len().min(60)]);
                    st.lock().unwrap().sigs.push((k, v));
                }
                // Don't redirect — let the original function body run
                // (the SVC replaced only the first instruction, rest is intact)
                // Actually we need to skip the whole function. Set PC = LR.
                let lr = dy.reg_read(30).unwrap_or(0);
                dy.reg_write_pc(lr).unwrap();
            }
            SVC_REFCOUNT_NOP => {
                // Ref-counting function stub: just return via LR
                let lr = dy.reg_read(30).unwrap_or(0);
                dy.reg_write_pc(lr).unwrap();
            }
            SVC_LDADDH | SVC_LDADDLH => {
                // Atomic add halfword: old = [X1]; [X1] = old + W0; W0 = old; then RET
                let w0 = dy.reg_read(0).unwrap_or(0) as u16;
                let x1 = dy.reg_read(1).unwrap_or(0);
                let lr = dy.reg_read(30).unwrap_or(0);
                let sp = dy.reg_read_sp().unwrap_or(0);
                eprintln!("[SVC] LDADD: W0=0x{:x} X1=0x{:x} LR=0x{:x} SP=0x{:x}", w0, x1, lr, sp);
                // Debug: dump the caller's saved LR on stack
                // Refcount function saves x30 at [SP+8] (from stp [sp,#-0x30]!)
                // And the calling function (SO+0x162944) saves x30 at [SP+0x30+0x20]=[SP+0x50]
                for off in [0x8u64, 0x38, 0x50, 0x58] {
                    if let Ok(b) = dy.mem_read_as_vec(sp + off, 8) {
                        let val = u64::from_le_bytes(b.try_into().unwrap());
                        if val != 0 {
                            let so_off = val.wrapping_sub(so_base);
                            if so_off < 0x400000 {
                                eprintln!("  [SP+0x{:x}]=0x{:x} (SO+0x{:x})", off, val, so_off);
                            } else {
                                eprintln!("  [SP+0x{:x}]=0x{:x}", off, val);
                            }
                        }
                    }
                }
                let old = if let Ok(b) = dy.mem_read_as_vec(x1, 2) {
                    u16::from_le_bytes(b.try_into().unwrap_or([0; 2]))
                } else { 0 };
                let _ = dy.mem_write(x1, &old.wrapping_add(w0).to_le_bytes());
                dy.reg_write_raw(0, old as u64).unwrap();
                dy.reg_write_pc(lr).unwrap();
            }
            SVC_TRAP_NULL => {
                // Null function call — dump full state for debugging
                let lr = dy.reg_read(30).unwrap_or(0);
                let sp = dy.reg_read_sp().unwrap_or(0);
                let fp = dy.reg_read(29).unwrap_or(0);
                eprintln!("[TRAP] NULL pc=0x{:x} lr=0x{:x} sp=0x{:x} fp=0x{:x}", pc, lr, sp, fp);
                // Dump key registers
                for i in [0,1,2,8,9,19,20,21,22,23,24,25] {
                    let v = dy.reg_read(i).unwrap_or(0);
                    if v != 0 { eprintln!("  x{}=0x{:x}", i, v); }
                }
                // Dump stack contents around SP
                if sp > 0x1000 {
                    eprintln!("[TRAP] Stack around SP:");
                    for off in (0..0x80).step_by(8) {
                        if let Ok(b) = dy.mem_read_as_vec(sp + off as u64, 8) {
                            let val = u64::from_le_bytes(b.try_into().unwrap());
                            if val != 0 {
                                eprintln!("  [SP+0x{:02x}] = 0x{:x}", off, val);
                            }
                        }
                    }
                }
                if lr > 0x1000 {
                    dy.reg_write_raw(0, 0).unwrap();
                    dy.reg_write_pc(lr).unwrap();
                } else {
                    // Try to unwind: look for valid return address on stack
                    let mut found = false;
                    if sp > 0x1000 {
                        for off in (0..0x200).step_by(8) {
                            if let Ok(b) = dy.mem_read_as_vec(sp + off as u64, 8) {
                                let val = u64::from_le_bytes(b.try_into().unwrap());
                                // Check if it looks like a code address in SO range
                                if val > so_base && val < so_base + 0x400000 {
                                    eprintln!("[TRAP] Found return addr at [SP+0x{:x}]=0x{:x} (SO+0x{:x})",
                                        off, val, val - so_base);
                                    dy.reg_write_pc(val).unwrap();
                                    dy.reg_write_sp(sp + off as u64 + 8).unwrap();
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }
                    // Don't try to recover from null jumps — it causes wrong returns
                    if !found {
                        eprintln!("[TRAP] No valid return addr found, halting");
                        let _ = dy.emu_stop();
                    }
                }
            }
            0 => {
                // Linux ARM64 system call (SVC #0, syscall number in X8)
                let x8 = dy.reg_read(8).unwrap_or(0);
                let x0 = dy.reg_read(0).unwrap_or(0);
                let x1 = dy.reg_read(1).unwrap_or(0);
                let x2 = dy.reg_read(2).unwrap_or(0);
                let lr = dy.reg_read(30).unwrap_or(0);
                eprintln!("[SYSCALL] nr={} x0=0x{:x} x1=0x{:x} x2=0x{:x} pc=0x{:x} lr=0x{:x}", x8, x0, x1, x2, pc, lr);
                match x8 {
                    222 => {
                        // mmap(addr, len, prot, flags, fd, off)
                        let len = x1 as usize;
                        let ptr = {
                            let mut s = st.lock().unwrap();
                            let p = s.heap_next;
                            s.heap_next += ((len as u64).max(0x1000) + 0xFFF) & !0xFFF;
                            p
                        };
                        if n < 50 { eprintln!("[SYSCALL] mmap len=0x{:x} → 0x{:x}", len, ptr); }
                        dy.reg_write_raw(0, ptr).unwrap();
                    }
                    226 => {
                        // mprotect — just return success
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    233 => {
                        // brk — return current brk
                        dy.reg_write_raw(0, 0x5800_0000).unwrap();
                    }
                    56 => {
                        // openat — return -1 (ENOENT)
                        dy.reg_write_raw(0, (-1i64 as u64)).unwrap();
                    }
                    98 => {
                        // futex — single-threaded: force unlock to avoid deadlock
                        let op = x1 & 0x7F;
                        if op == 0 || op == 9 {
                            // FUTEX_WAIT — force the futex value to 0 (unlocked)
                            // so the CAS retry in pthread_mutex_lock succeeds
                            let _ = dy.mem_write(x0, &0u32.to_le_bytes());
                            dy.reg_write_raw(0, (-110i64 as u64)).unwrap(); // -ETIMEDOUT
                        } else {
                            dy.reg_write_raw(0, 0).unwrap();
                        }
                    }
                    113 | 114 => {
                        // clock_gettime / clock_getres — write a reasonable time to [x1]
                        if x1 != 0 {
                            // struct timespec { time_t tv_sec; long tv_nsec; }
                            let _ = dy.mem_write(x1, &1700000000u64.to_le_bytes()); // ~2023
                            let _ = dy.mem_write(x1 + 8, &0u64.to_le_bytes());
                        }
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    63 => {
                        // read — return 0 (EOF)
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    64 => {
                        // write — return count (pretend success)
                        dy.reg_write_raw(0, x2).unwrap();
                    }
                    29 => {
                        // ioctl — return 0
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    261 => {
                        // prlimit64 — return 0
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    _ => {
                        if n < 100 { eprintln!("[SYSCALL] nr={} x0=0x{:x} x1=0x{:x} → 0", x8, x0, x1); }
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                }
            }
            0x500 => {
                // LSE atomic instruction emulation
                let lr = dy.reg_read(30).unwrap_or(0);
                if let Some(&insn) = lse_map_cb.get(&pc) {
                    let rs = ((insn >> 16) & 0x1F) as usize;
                    let rn = ((insn >> 5) & 0x1F) as usize;
                    let rt = (insn & 0x1F) as usize;
                    let size = (insn >> 30) & 3;
                    let nbytes = 1usize << size;

                    if (insn & 0x3F20FC00) == 0x08207C00 {
                        // CAS: compare [Xn] with Ws, swap with Wt if equal
                        let addr = dy.reg_read(rn).unwrap_or(0);
                        let mut buf = [0u8; 8];
                        let _ = dy.mem_read_as_vec(addr, nbytes).map(|b| buf[..nbytes].copy_from_slice(&b));
                        let old = u64::from_le_bytes(buf);
                        let mask = if nbytes < 8 { (1u64 << (nbytes * 8)) - 1 } else { u64::MAX };
                        let compare = dy.reg_read(rs).unwrap_or(0) & mask;
                        let new_val = dy.reg_read(rt).unwrap_or(0) & mask;
                        if old == compare {
                            let _ = dy.mem_write(addr, &new_val.to_le_bytes()[..nbytes]);
                        }
                        dy.reg_write_raw(rs, old).unwrap();
                    } else {
                        // Atomic LD* family: old = [Xn]; [Xn] = op(old, Ws); Wt = old
                        let opc = (insn >> 12) & 0x7;
                        let o3 = (insn >> 15) & 1;
                        let addr = dy.reg_read(rn).unwrap_or(0);
                        let operand = dy.reg_read(rs).unwrap_or(0);
                        let mut buf = [0u8; 8];
                        let _ = dy.mem_read_as_vec(addr, nbytes).map(|b| buf[..nbytes].copy_from_slice(&b));
                        let old = u64::from_le_bytes(buf);
                        let mask = if nbytes < 8 { (1u64 << (nbytes * 8)) - 1 } else { u64::MAX };
                        let new_val = match (o3, opc) {
                            (0, 0) => old.wrapping_add(operand),  // LDADD
                            (0, 1) => old & !operand,             // LDCLR
                            (0, 2) => old ^ operand,              // LDEOR
                            (0, 3) => old | operand,              // LDSET
                            (0, 4) => std::cmp::max(old as i64, operand as i64) as u64, // LDSMAX
                            (0, 5) => std::cmp::min(old as i64, operand as i64) as u64, // LDSMIN
                            (0, 6) => std::cmp::max(old, operand), // LDUMAX
                            (0, 7) => std::cmp::min(old, operand), // LDUMIN
                            (1, _) => operand,                     // SWP
                            _ => old.wrapping_add(operand),
                        } & mask;
                        let _ = dy.mem_write(addr, &new_val.to_le_bytes()[..nbytes]);
                        if rt != 31 { dy.reg_write_raw(rt, old).unwrap(); }
                    }
                }
                // Continue after the patched instruction
                dy.reg_write_pc(pc + 4).unwrap();
            }
            _ => {
                // Unknown SVC — return 0
                if n < 20 { eprintln!("[SVC] unknown swi=0x{:x} pc=0x{:x}", swi, pc); }
                dy.reg_write_raw(0, 0).unwrap();
            }
        }
    });

    // Unmapped memory callback — record missing pages, map with zeros, signal stop
    let missing_pages = Arc::new(Mutex::new(std::collections::BTreeSet::<u64>::new()));
    let mp = missing_pages.clone();
    let miss_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let miss_flag_cb = miss_flag.clone();
    dy.set_unmapped_mem_callback(move |dy: &Dynarmic<()>, addr: u64, _size: usize, _value: u64| -> bool {
        let page = addr & !0xFFF;
        if page >= 0x7000_0000 && page < 0x8000_0000_0000 {
            let mut pages = mp.lock().unwrap();
            let is_new = pages.insert(page);
            if is_new {
                eprintln!("[MISS] addr=0x{:x} page=0x{:x} (#{} missing)", addr, page, pages.len());
            }
        }
        // Signal main loop to stop — don't map, let C code return 0/halt
        miss_flag_cb.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = dy.emu_stop();
        false
    });

    // Execute with timeout
    let start = so_base + 0x286DF4;
    eprintln!("[emu] Starting at SO+0x286DF4 (dynarmic JIT)");
    let t0 = std::time::Instant::now();

    // Timeout flag + PC sampling thread
    let timed_out = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let timed_out_flag = timed_out.clone();
    let dy_timeout = dy.clone();
    let so_base_timer = so_base;
    let timer = std::thread::spawn(move || {
        for i in 0..60 {
            // 60 iterations × 1s = 60s timeout
            std::thread::sleep(std::time::Duration::from_secs(1));
            let pc = dy_timeout.reg_read_pc().unwrap_or(0);
            let sp = dy_timeout.reg_read_sp().unwrap_or(0);
            let so_off = pc.wrapping_sub(so_base_timer);
            if so_off < 0x400000 {
                eprintln!("[sample] t={}s PC=SO+0x{:x} SP=0x{:x}", i+1, so_off, sp);
            } else {
                eprintln!("[sample] t={}s PC=0x{:x} SP=0x{:x}", i+1, pc, sp);
            }
        }
        timed_out_flag.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = dy_timeout.emu_stop();
        eprintln!("[emu] Timeout: forced stop after 5s");
    });

    let mut retries = 0u32;
    dy.emu_start(start, HALT_ADDR).ok();
    loop {
        let pc = dy.reg_read_pc().unwrap_or(0);
        if pc == HALT_ADDR || timed_out.load(std::sync::atomic::Ordering::Relaxed) || miss_flag.load(std::sync::atomic::Ordering::Relaxed) {
            let elapsed = t0.elapsed().as_secs_f64();
            eprintln!("[emu] Done in {:.1}s, {} retries, PC=0x{:x}", elapsed, retries, pc);
            break;
        }
        retries += 1;
        // Check if PC is in a missing page or garbage address — stop
        let pc_page = pc & !0xFFF;
        if missing_pages.lock().unwrap().contains(&pc_page) || pc > 0x8000_0000_0000 || pc < 0x1000 {
            let elapsed = t0.elapsed().as_secs_f64();
            eprintln!("[emu] Halted at missing page PC=0x{:x} after {:.1}s, {} retries", pc, elapsed, retries);
            break;
        }
        if retries <= 50 {
            let lr = dy.reg_read(30).unwrap_or(0);
            let insn_hex = dy.mem_read_as_vec(pc, 4).ok()
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0);
            eprintln!("[emu] Retry #{}: PC=0x{:x} (SO+0x{:x}) LR=0x{:x} insn=0x{:08x} t={:.1}s",
                retries, pc, pc.wrapping_sub(so_base), lr, insn_hex, t0.elapsed().as_secs_f64());
        }
        if retries > 10000 {
            eprintln!("[emu] Too many retries, giving up");
            break;
        }
        // Check if unsupported instruction is LDADD*H (LSE atomic)
        // Encoding: (insn & 0xFF20FC00) == 0x78200000
        let mut handled = false;
        if let Ok(insn_bytes) = dy.mem_read_as_vec(pc, 4) {
            let insn = u32::from_le_bytes(insn_bytes.try_into().unwrap());
            // LDADD* family: covers LDADDH, LDADDW, LDADDB, etc.
            // 0x38200000 = byte, 0x78200000 = halfword, 0xB8200000 = word, 0xF8200000 = doubleword
            // Common mask: (insn & 0x3F200C00) == 0x38200000
            if (insn & 0x3F200C00) == 0x38200000 {
                let size = (insn >> 30) & 3; // 0=byte, 1=half, 2=word, 3=dword
                let rs = ((insn >> 16) & 0x1F) as usize;
                let rn = ((insn >> 5) & 0x1F) as usize;
                let rt = (insn & 0x1F) as usize;
                let addend = dy.reg_read(rs).unwrap_or(0);
                let xn = dy.reg_read(rn).unwrap_or(0);
                let nbytes = 1usize << size;
                let old = dy.mem_read_as_vec(xn, nbytes).ok()
                    .map(|b| {
                        let mut buf = [0u8; 8];
                        buf[..nbytes].copy_from_slice(&b);
                        u64::from_le_bytes(buf)
                    }).unwrap_or(0);
                let new_val = old.wrapping_add(addend) & ((1u128 << (nbytes * 8)) - 1) as u64;
                let _ = dy.mem_write(xn, &new_val.to_le_bytes()[..nbytes]);
                if rt != 31 {
                    dy.reg_write_raw(rt, old).unwrap();
                }
                if retries <= 50 {
                    eprintln!("[emu] LDADD({}): [X{}=0x{:x}] old=0x{:x} +0x{:x} → W{}", nbytes, rn, xn, old, addend, rt);
                }
                dy.reg_write_pc(pc + 4).unwrap();
                handled = true;
            }
            // CAS/CASA/CASAL Ws, Wt, [Xn] — Compare and Swap (LSE atomics)
            // Encoding: 10 001000 1 L 1 Rs o0 11111 Rn Rt
            // Mask top bits: (insn & 0xFF20FC00) == 0x88A0FC00
            // CAS variants: 1x 001000 1 L 1 Rs o0 11111 Rn Rt  (32-bit: size=10, 64-bit: size=11)
            // Mask: top nibble=0x88 or 0xC8, bits [29:21]=001000 1x1
            // Simpler: (insn & 0x3F20FC00) == 0x0820FC00 covers CAS/CASA/CASL/CASAL 32+64
            if !handled && (insn & 0x3F207C00) == 0x08207C00 {
                let rs = ((insn >> 16) & 0x1F) as usize;
                let rn = ((insn >> 5) & 0x1F) as usize;
                let rt = (insn & 0x1F) as usize;
                let addr = dy.reg_read(rn).unwrap_or(0);
                let is_64 = (insn >> 30) == 3;
                let (old, compare, new_val) = if is_64 {
                    let old = dy.mem_read_as_vec(addr, 8).ok()
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0);
                    (old, dy.reg_read(rs).unwrap_or(0), dy.reg_read(rt).unwrap_or(0))
                } else {
                    let old = dy.mem_read_as_vec(addr, 4).ok()
                        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64).unwrap_or(0);
                    (old, dy.reg_read(rs).unwrap_or(0) & 0xFFFFFFFF, dy.reg_read(rt).unwrap_or(0) & 0xFFFFFFFF)
                };
                if old == compare {
                    if is_64 {
                        let _ = dy.mem_write(addr, &new_val.to_le_bytes());
                    } else {
                        let _ = dy.mem_write(addr, &(new_val as u32).to_le_bytes());
                    }
                }
                dy.reg_write_raw(rs, old).unwrap();
                if retries <= 50 {
                    eprintln!("[emu] CAS: [X{}=0x{:x}] old=0x{:x} cmp=W{}=0x{:x} new=W{}=0x{:x} {}",
                        rn, addr, old, rs, compare, rt, new_val,
                        if old == compare { "SWAPPED" } else { "KEPT" });
                }
                dy.reg_write_pc(pc + 4).unwrap();
                handled = true;
            }
            // LDAXR Wt, [Xn] — Load-Acquire Exclusive Register
            if !handled && (insn & 0xFFE0FC00) == 0x885FFC00 {
                // LDAXR Wt, [Xn]: Wt = [Xn], set exclusive monitor
                let rn = ((insn >> 5) & 0x1F) as usize;
                let rt = (insn & 0x1F) as usize;
                let addr = dy.reg_read(rn).unwrap_or(0);
                let val = dy.mem_read_as_vec(addr, 4).ok()
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                    .unwrap_or(0);
                if rt != 31 { dy.reg_write_raw(rt, val as u64).unwrap(); }
                if retries <= 50 {
                    eprintln!("[emu] LDAXR: W{}=[X{}=0x{:x}] = 0x{:x}", rt, rn, addr, val);
                }
                dy.reg_write_pc(pc + 4).unwrap();
                handled = true;
            }
            // STLXR Ws, Wt, [Xn] — Store-Release Exclusive Register
            // 0x8800FC00 mask
            if !handled && (insn & 0xFFE0FC00) == 0x8800FC00 {
                let rs = ((insn >> 16) & 0x1F) as usize;
                let rt = (insn & 0x1F) as usize;
                let rn = ((insn >> 5) & 0x1F) as usize;
                let addr = dy.reg_read(rn).unwrap_or(0);
                let val = dy.reg_read(rt).unwrap_or(0) as u32;
                let _ = dy.mem_write(addr, &val.to_le_bytes());
                // Ws = 0 (success)
                if rs != 31 { dy.reg_write_raw(rs, 0).unwrap(); }
                if retries <= 50 {
                    eprintln!("[emu] STLXR: [X{}=0x{:x}] = W{}=0x{:x}, W{}=0", rn, addr, rt, val, rs);
                }
                dy.reg_write_pc(pc + 4).unwrap();
                handled = true;
            }
        }
        if !handled {
            dy.reg_write_pc(pc + 4).unwrap();
        }
        // Invalidate JIT cache around the unsupported instruction to prevent stale blocks
        dy.invalidate_cache(pc & !0xFFF, 0x1000);
        dy.emu_start(pc + 4, HALT_ADDR).ok();
    }
    drop(timer); // timer thread will finish on its own

    let total_svcs = svc_n.load(std::sync::atomic::Ordering::Relaxed);
    let sigs = state.lock().unwrap().sigs.clone();
    let pages = missing_pages.lock().unwrap();
    eprintln!("[emu] {} SVCs total, {} signatures captured, {} missing pages", total_svcs, sigs.len(), pages.len());
    if !pages.is_empty() {
        let path = format!("{}/lib/missing_pages.txt", dir);
        let content: String = pages.iter().map(|p| format!("0x{:x}\n", p)).collect();
        std::fs::write(&path, &content).ok();
        eprintln!("[emu] Missing pages saved to {}", path);
    }
    drop(pages);
    sigs
}

pub fn sign(_url: &str) -> HashMap<String, String> { HashMap::new() }

#[cfg(test)]
mod tests {
    #[test]
    fn test_signing() {
        let sigs = super::test_signing();
        for (k, v) in &sigs { println!("  {}: {}...", k, &v[..v.len().min(60)]); }
        assert!(sigs.iter().any(|(k,_)| k == "X-Helios"), "Missing X-Helios");
    }
}
