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

    // MD5 raw (0x243C34): md5(data, len, out16)
    emu.add_code_hook(so_base + 0x243C34, so_base + 0x243C38,
        |emu: &mut Unicorn<Emu>, _, _| {
            eprintln!("[FAST] MD5_RAW");
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

    // MD5 transform (0x24307C): md5_transform(state, block64)
    emu.add_code_hook(so_base + 0x24307C, so_base + 0x243080,
        |emu: &mut Unicorn<Emu>, _, _| {
            eprintln!("[FAST] MD5_TRANSFORM");
            let x0 = emu.reg_read(RegisterARM64::X0).unwrap_or(0);
            let x1 = emu.reg_read(RegisterARM64::X1).unwrap_or(0);
            let lr = emu.reg_read(RegisterARM64::LR).unwrap_or(0);

            // State at ctx+8: A(4) B(4) C(4) D(4) = 16 bytes
            if let (Ok(state_bytes), Ok(block)) = (
                emu.mem_read_as_vec(x0 + 8, 16), // MD5 ABCD at offset +8
                emu.mem_read_as_vec(x1, 64),
            ) {
                let mut a = u32::from_le_bytes(state_bytes[0..4].try_into().unwrap());
                let mut b = u32::from_le_bytes(state_bytes[4..8].try_into().unwrap());
                let mut c = u32::from_le_bytes(state_bytes[8..12].try_into().unwrap());
                let mut d = u32::from_le_bytes(state_bytes[12..16].try_into().unwrap());

                // Parse M[0..15]
                let mut m = [0u32; 16];
                for i in 0..16 {
                    m[i] = u32::from_le_bytes(block[i*4..i*4+4].try_into().unwrap());
                }

                // MD5 rounds (standard)
                macro_rules! f { ($b:expr,$c:expr,$d:expr) => { ($b & $c) | (!$b & $d) } }
                macro_rules! g { ($b:expr,$c:expr,$d:expr) => { ($d & $b) | (!$d & $c) } }
                macro_rules! h { ($b:expr,$c:expr,$d:expr) => { $b ^ $c ^ $d } }
                macro_rules! i_fn { ($b:expr,$c:expr,$d:expr) => { $c ^ ($b | !$d) } }
                macro_rules! round {
                    ($a:expr,$b:expr,$c:expr,$d:expr,$f:expr,$k:expr,$s:expr,$mi:expr) => {
                        $a = $b.wrapping_add(($a.wrapping_add($f).wrapping_add($k).wrapping_add($mi)).rotate_left($s));
                    }
                }

                // Constants
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
                        0 => f!(b, c, d),
                        1 => g!(b, c, d),
                        2 => h!(b, c, d),
                        _ => i_fn!(b, c, d),
                    };
                    round!(a, b, c, d, fv, T[i], S[i], m[MI[i]]);
                    let tmp = d; d = c; c = b; b = a; a = tmp;
                    // Actually MD5 doesn't rotate (a,b,c,d) — the new a becomes the old d
                    // Standard MD5: new_a = d; d = c; c = b; b = b + result; but our macro already does a = b + (...)
                    // Let me fix: after round!, a is already computed. Rotate: temp=d, d=c, c=b, b=a(new), a=temp
                    // Wait, our macro sets a = b + (...), which is the new value for position that was 'a'.
                    // The standard rotation is: the current a gets the computed value, then shift.
                    // Actually: (a,b,c,d) → (d, a_new, b, c) where a_new = b + F(...)
                    // Our macro already set a = b + F, so after: temp=d, d=c, c=b (old), b=a (new a), a=temp
                    // That's exactly what we have. Good.
                }

                // Add to original state
                let oa = u32::from_le_bytes(state_bytes[0..4].try_into().unwrap());
                let ob = u32::from_le_bytes(state_bytes[4..8].try_into().unwrap());
                let oc = u32::from_le_bytes(state_bytes[8..12].try_into().unwrap());
                let od = u32::from_le_bytes(state_bytes[12..16].try_into().unwrap());

                let mut out = [0u8; 16];
                out[0..4].copy_from_slice(&oa.wrapping_add(a).to_le_bytes());
                out[4..8].copy_from_slice(&ob.wrapping_add(b).to_le_bytes());
                out[8..12].copy_from_slice(&oc.wrapping_add(c).to_le_bytes());
                out[12..16].copy_from_slice(&od.wrapping_add(d).to_le_bytes());
                let _ = emu.mem_write(x0 + 8, &out); // write back at offset +8
            }

            // Return to caller (skip the entire transform body)
            emu.reg_write(RegisterARM64::PC, lr).unwrap();
        }).unwrap();

    // MD5 wrapper (0x258530) — let CFF code run, wrapper fast-path disabled
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

    // SHA1 transform (0x243F10): sha1_transform(ctx, block64)
    // ctx layout: similar to MD5 — state H0-H4 at some offset
    // For now, fast-path by hooking the function and computing in Rust
    emu.add_code_hook(so_base + 0x243F10, so_base + 0x243F14,
        |emu: &mut Unicorn<Emu>, _, _| {
            let x0 = emu.reg_read(RegisterARM64::X0).unwrap_or(0);
            let x1 = emu.reg_read(RegisterARM64::X1).unwrap_or(0);
            let lr = emu.reg_read(RegisterARM64::LR).unwrap_or(0);
            // SHA1 transform: read 5 x u32 state from ctx, 64-byte block
            // State likely at ctx+8 (like MD5) or ctx+0
            if let (Ok(sb), Ok(block)) = (emu.mem_read_as_vec(x0, 32), emu.mem_read_as_vec(x1, 64)) {
                // Try state at offset 8 (matching MD5 pattern)
                let mut h = [0u32; 5];
                for i in 0..5 { h[i] = u32::from_be_bytes(sb[8+i*4..12+i*4].try_into().unwrap_or([0;4])); }
                // Parse W[0..15]
                let mut w = [0u32; 80];
                for i in 0..16 { w[i] = u32::from_be_bytes(block[i*4..i*4+4].try_into().unwrap()); }
                for i in 16..80 { w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1); }
                let (mut a,mut b,mut c,mut d,mut e) = (h[0],h[1],h[2],h[3],h[4]);
                for i in 0..80 {
                    let (f,k) = match i {
                        0..=19 => ((b & c) | (!b & d), 0x5A827999u32),
                        20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                        40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                        _ => (b ^ c ^ d, 0xCA62C1D6u32),
                    };
                    let tmp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
                    e = d; d = c; c = b.rotate_left(30); b = a; a = tmp;
                }
                h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
                h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
                h[4] = h[4].wrapping_add(e);
                let mut out = [0u8; 20];
                for i in 0..5 { out[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes()); }
                let _ = emu.mem_write(x0 + 8, &out);
            }
            emu.reg_write(RegisterARM64::PC, lr).unwrap();
        }).unwrap();

    // AES block encrypt alt entry (0x242640): aes_ecb(ctx, in16, out16)
    // CFF-obfuscated AES — fast-path with aes crate
    emu.add_code_hook(so_base + 0x242640, so_base + 0x242644,
        |emu: &mut Unicorn<Emu>, _, _| {
            let x0 = emu.reg_read(RegisterARM64::X0).unwrap_or(0); // ctx (round keys at +0xF0)
            let x1 = emu.reg_read(RegisterARM64::X1).unwrap_or(0); // input 16 bytes
            let x2 = emu.reg_read(RegisterARM64::X2).unwrap_or(0); // output 16 bytes
            let lr = emu.reg_read(RegisterARM64::LR).unwrap_or(0);
            // Read round keys from ctx+0xF0 (176 bytes for AES-128 = 11 round keys)
            if let (Ok(rk), Ok(input)) = (emu.mem_read_as_vec(x0 + 0xF0, 176), emu.mem_read_as_vec(x1, 16)) {
                // Use the aes crate for proper AES-128 encryption
                use aes::cipher::{BlockEncrypt, KeyInit};
                // Extract the original key from round keys (first 16 bytes)
                let key_bytes: [u8; 16] = rk[0..16].try_into().unwrap();
                let cipher = aes::Aes128::new_from_slice(&key_bytes).unwrap();
                let mut block = aes::Block::from_slice(&input).clone();
                cipher.encrypt_block(&mut block);
                let _ = emu.mem_write(x2, block.as_slice());
            }
            emu.reg_write(RegisterARM64::PC, lr).unwrap();
        }).unwrap();

    // ALLOC_BUF (0x25BED4): allocate buffer of given size
    emu.add_code_hook(so_base + 0x25BED4, so_base + 0x25BED8,
        |emu: &mut Unicorn<Emu>, _, _| {
            eprintln!("[FAST] ALLOC_BUF");
            let x0 = emu.reg_read(RegisterARM64::X0).unwrap_or(0) as u64;
            let lr = emu.reg_read(RegisterARM64::LR).unwrap_or(0);
            let s = emu.get_data_mut();
            let ptr = s.heap_next; s.heap_next += (x0 + 15) & !15;
            emu.reg_write(RegisterARM64::X0, ptr).unwrap();
            emu.reg_write(RegisterARM64::PC, lr).unwrap();
        }).unwrap();

    // MALLOC wrapper (0x32A1F0)
    emu.add_code_hook(so_base + 0x32A1F0, so_base + 0x32A1F4,
        |emu: &mut Unicorn<Emu>, _, _| {
            let x0 = emu.reg_read(RegisterARM64::X0).unwrap_or(0) as u64;
            let lr = emu.reg_read(RegisterARM64::LR).unwrap_or(0);
            let s = emu.get_data_mut();
            let ptr = s.heap_next; s.heap_next += (x0.max(1) + 15) & !15;
            emu.reg_write(RegisterARM64::X0, ptr).unwrap();
            emu.reg_write(RegisterARM64::PC, lr).unwrap();
        }).unwrap();

    // CREATE_BUF (0x2481FC): create_buf(dst_obj, src_data, len)
    emu.add_code_hook(so_base + 0x2481FC, so_base + 0x248200,
        |emu: &mut Unicorn<Emu>, _, _| {
            let x0 = emu.reg_read(RegisterARM64::X0).unwrap_or(0); // dst obj
            let x1 = emu.reg_read(RegisterARM64::X1).unwrap_or(0); // src data
            let x2 = emu.reg_read(RegisterARM64::X2).unwrap_or(0) as usize; // len
            let lr = emu.reg_read(RegisterARM64::LR).unwrap_or(0);
            if x2 > 0 && x2 < 100000 {
                if let Ok(data) = emu.mem_read_as_vec(x1, x2) {
                    // Allocate and copy
                    let s = emu.get_data_mut();
                    let buf = s.heap_next; s.heap_next += ((x2 as u64) + 15) & !15;
                    let _ = emu.mem_write(buf, &data);
                    // Write to dst obj: [vtable(8), ??(4), len(4), data_ptr(8)]
                    let _ = emu.mem_write(x0 + 0xC, &(x2 as u32).to_le_bytes());
                    let _ = emu.mem_write(x0 + 0x10, &buf.to_le_bytes());
                }
            }
            emu.reg_write(RegisterARM64::PC, lr).unwrap();
        }).unwrap();

    // BUF_OP (0x248344) — buffer append/copy
    emu.add_code_hook(so_base + 0x248344, so_base + 0x248348,
        |emu: &mut Unicorn<Emu>, _, _| {
            let lr = emu.reg_read(RegisterARM64::LR).unwrap_or(0);
            // Simple: just return (buffer operations are handled by CREATE_BUF)
            emu.reg_write(RegisterARM64::PC, lr).unwrap();
        }).unwrap();

    // FREE (0x15E1A8) — no-op
    emu.add_code_hook(so_base + 0x15E1A8, so_base + 0x15E1AC,
        |emu: &mut Unicorn<Emu>, _, _| {
            let lr = emu.reg_read(RegisterARM64::LR).unwrap_or(0);
            emu.reg_write(RegisterARM64::PC, lr).unwrap();
        }).unwrap();

    // AES key expand (0x241E9C): aes_key_expand(ctx, key, keylen)
    emu.add_code_hook(so_base + 0x241E9C, so_base + 0x241EA0,
        |emu: &mut Unicorn<Emu>, _, _| {
            let x0 = emu.reg_read(RegisterARM64::X0).unwrap_or(0); // ctx
            let x1 = emu.reg_read(RegisterARM64::X1).unwrap_or(0); // key
            let x2 = emu.reg_read(RegisterARM64::X2).unwrap_or(0) as usize; // keylen
            let lr = emu.reg_read(RegisterARM64::LR).unwrap_or(0);
            if x2 == 16 {
                if let Ok(key) = emu.mem_read_as_vec(x1, 16) {
                    // Write key to ctx+0x00 (standard entry) and ctx+0xF0 (alt entry)
                    let _ = emu.mem_write(x0, &key);
                    let _ = emu.mem_write(x0 + 0xF0, &key);
                    // Generate round keys using aes crate
                    use aes::cipher::KeyInit;
                    let cipher = aes::Aes128::new_from_slice(&key).unwrap();
                    // aes crate doesn't expose round keys directly
                    // Store the key at both offsets — AES ECB fast-path reads from +0xF0
                }
            }
            emu.reg_write(RegisterARM64::PC, lr).unwrap();
        }).unwrap();

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
