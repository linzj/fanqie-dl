//! ARM64 JIT emulator using dynarmic-sys for fast signing.
//! Crypto functions are intercepted via SVC breakpoints patched into the SO.

use dynarmic_sys::Dynarmic;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const HALT_ADDR: u64 = 0xDEAD_0000;

/// Encode SVC #imm16 instruction
fn svc_bytes(imm16: u32) -> [u8; 4] {
    (0xD4000001u32 | ((imm16 & 0xFFFF) << 5)).to_le_bytes()
}

// SVC IDs for fast-pathed functions
const SVC_MD5_RAW: u32 = 0x100;
const SVC_MD5_TRANSFORM: u32 = 0x101;
const SVC_SHA1_TRANSFORM: u32 = 0x102;
const SVC_AES_ECB: u32 = 0x103;
const SVC_ALLOC_BUF: u32 = 0x104;
const SVC_MALLOC: u32 = 0x105;
const SVC_CREATE_BUF: u32 = 0x106;
const SVC_BUF_OP: u32 = 0x107;
const SVC_FREE: u32 = 0x108;
const SVC_AES_KEY_EXPAND: u32 = 0x109;
const SVC_MAP_SET: u32 = 0x10A;
const SVC_LDADDH: u32 = 0x200; // LDADDH W0, W0, [X1]
const SVC_LDADDLH: u32 = 0x201; // LDADDLH W0, W0, [X1]
const SVC_REFCOUNT_NOP: u32 = 0x202; // Stub for ref-counting library functions
const SVC_TRAP_NULL: u32 = 0x300; // Trap at address 0 (null jump detection)
const SVC_JNI_BASE: u32 = 0x600; // JNI function stubs: SVC #(0x600 + index)

/// No SVC patches in SO — CFF dispatch uses instruction addresses as constants.
const HOOK_TABLE: &[(u64, u32)] = &[];

// JNI memory layout
const JNI_ENV_ADDR: u64 = 0x4000_0000; // JNIEnv* → [functions_ptr]
const JNI_FUNC_TABLE: u64 = 0x4000_0100; // JNINativeInterface_ function table
const JNI_STUBS_ADDR: u64 = 0x4000_1000; // SVC stub code page
const JNI_STRING_AREA: u64 = 0x4000_2000; // Fake jstring / string data
const JNI_OBJ_AREA: u64 = 0x4000_3000; // Fake jobject / jclass area
const JNI_STACK_BASE: u64 = 0x4800_0000; // Fresh stack for JNI call
const JNI_STACK_SIZE: u64 = 0x0080_0000; // 8MB stack
const JNI_NUM_FUNCS: usize = 232; // Number of JNI functions

// JNI function table indices (from jni.h)
const JNI_FIND_CLASS: usize = 6;
const JNI_EXCEPTION_OCCURRED: usize = 15;
const JNI_EXCEPTION_CLEAR: usize = 17;
const JNI_NEW_GLOBAL_REF: usize = 21;
const JNI_DELETE_GLOBAL_REF: usize = 22;
const JNI_DELETE_LOCAL_REF: usize = 23;
const JNI_ENSURE_LOCAL_CAPACITY: usize = 26;
const JNI_NEW_OBJECT: usize = 28;
const JNI_GET_OBJECT_CLASS: usize = 31;
const JNI_GET_METHOD_ID: usize = 33;
const JNI_CALL_OBJECT_METHOD: usize = 34;
const JNI_CALL_OBJECT_METHOD_V: usize = 35;
const JNI_CALL_OBJECT_METHOD_A: usize = 36;
const JNI_CALL_BOOLEAN_METHOD: usize = 37;
const JNI_CALL_INT_METHOD: usize = 49;
const JNI_CALL_VOID_METHOD: usize = 61;
const JNI_GET_STATIC_METHOD_ID: usize = 113;
const JNI_CALL_STATIC_OBJECT_METHOD: usize = 114;
const JNI_CALL_STATIC_INT_METHOD: usize = 120;
const JNI_CALL_STATIC_VOID_METHOD: usize = 141;
const JNI_GET_FIELD_ID: usize = 94;
const JNI_GET_OBJECT_FIELD: usize = 95;
const JNI_GET_INT_FIELD: usize = 100;
const JNI_GET_LONG_FIELD: usize = 101;
const JNI_SET_OBJECT_FIELD: usize = 104;
const JNI_SET_INT_FIELD: usize = 109;
const JNI_SET_LONG_FIELD: usize = 110;
const JNI_GET_STATIC_FIELD_ID: usize = 144;
const JNI_GET_STATIC_OBJECT_FIELD: usize = 145;
const JNI_NEW_STRING_UTF: usize = 167;
const JNI_GET_STRING_UTF_LENGTH: usize = 168;
const JNI_GET_STRING_UTF_CHARS: usize = 169;
const JNI_RELEASE_STRING_UTF_CHARS: usize = 170;
const JNI_GET_ARRAY_LENGTH: usize = 171;
const JNI_NEW_OBJECT_ARRAY: usize = 172;
const JNI_GET_OBJECT_ARRAY_ELEMENT: usize = 173;
const JNI_SET_OBJECT_ARRAY_ELEMENT: usize = 174;
const JNI_NEW_BYTE_ARRAY: usize = 176;
const JNI_GET_BYTE_ARRAY_ELEMENTS: usize = 184;
const JNI_RELEASE_BYTE_ARRAY_ELEMENTS: usize = 192;
const JNI_GET_BYTE_ARRAY_REGION: usize = 200;
const JNI_SET_BYTE_ARRAY_REGION: usize = 211;
const JNI_EXCEPTION_CHECK: usize = 228;

// Fake JNI object handles (opaque references)
const JCLASS_HANDLE: u64 = 0x4000_3100; // Fake jclass for y2
const JSTRING_URL: u64 = 0x4000_3200; // Fake jstring for URL
const JOBJ_EXTRA: u64 = 0x4000_3300; // Fake jobject for extra headers array

#[derive(Clone, Debug)]
enum JniObject {
    String(String),
    ByteArray(Vec<u8>),
    ObjectArray(Vec<u64>), // handles
    Class(String),
    Null,
}

struct SharedState {
    heap_next: u64,
    sigs: Vec<(String, String)>,
    jni_objects: HashMap<u64, JniObject>, // handle → object
    jni_next_handle: u64,
    jni_string_next: u64, // next address for string data in emulator memory
}

fn reg_index(name: &str) -> Option<usize> {
    match name {
        "x0" => Some(0),
        "x1" => Some(1),
        "x2" => Some(2),
        "x3" => Some(3),
        "x4" => Some(4),
        "x5" => Some(5),
        "x6" => Some(6),
        "x7" => Some(7),
        "x8" => Some(8),
        "x9" => Some(9),
        "x10" => Some(10),
        "x11" => Some(11),
        "x12" => Some(12),
        "x13" => Some(13),
        "x14" => Some(14),
        "x15" => Some(15),
        "x16" => Some(16),
        "x17" => Some(17),
        "x19" => Some(19),
        "x20" => Some(20),
        "x21" => Some(21),
        "x22" => Some(22),
        "x23" => Some(23),
        "x24" => Some(24),
        "x25" => Some(25),
        "x26" => Some(26),
        "x27" => Some(27),
        "x28" => Some(28),
        "fp" => Some(29),
        "lr" => Some(30),
        _ => None,
    }
}

fn jni_name(idx: usize) -> &'static str {
    match idx {
        4 => "GetVersion",
        6 => "FindClass",
        15 => "ExceptionOccurred",
        17 => "ExceptionClear",
        21 => "NewGlobalRef",
        22 => "DeleteGlobalRef",
        23 => "DeleteLocalRef",
        26 => "EnsureLocalCapacity",
        28 => "NewObject",
        31 => "GetObjectClass",
        33 => "GetMethodID",
        34 => "CallObjectMethod",
        35 => "CallObjectMethodV",
        36 => "CallObjectMethodA",
        37 => "CallBooleanMethod",
        49 => "CallIntMethod",
        61 => "CallVoidMethod",
        94 => "GetFieldID",
        95 => "GetObjectField",
        100 => "GetIntField",
        101 => "GetLongField",
        104 => "SetObjectField",
        109 => "SetIntField",
        110 => "SetLongField",
        113 => "GetStaticMethodID",
        114 => "CallStaticObjectMethod",
        120 => "CallStaticIntMethod",
        141 => "CallStaticVoidMethod",
        144 => "GetStaticFieldID",
        145 => "GetStaticObjectField",
        167 => "NewStringUTF",
        168 => "GetStringUTFLength",
        169 => "GetStringUTFChars",
        170 => "ReleaseStringUTFChars",
        171 => "GetArrayLength",
        172 => "NewObjectArray",
        173 => "GetObjectArrayElement",
        174 => "SetObjectArrayElement",
        176 => "NewByteArray",
        184 => "GetByteArrayElements",
        192 => "ReleaseByteArrayElements",
        200 => "GetByteArrayRegion",
        211 => "SetByteArrayRegion",
        228 => "ExceptionCheck",
        _ => "Unknown",
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
    for i in 0..16 {
        m[i] = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }

    static T: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    static S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    static MI: [usize; 64] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3,
        8, 13, 2, 7, 12, 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, 0, 7, 14, 5, 12, 3,
        10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
    ];

    for i in 0..64 {
        let fv = match i / 16 {
            0 => (b & c) | (!b & d),
            1 => (d & b) | (!d & c),
            2 => b ^ c ^ d,
            _ => c ^ (b | !d),
        };
        a = b.wrapping_add(
            a.wrapping_add(fv)
                .wrapping_add(T[i])
                .wrapping_add(m[MI[i]])
                .rotate_left(S[i]),
        );
        let tmp = d;
        d = c;
        c = b;
        b = a;
        a = tmp;
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
    for i in 0..5 {
        h[i] = u32::from_be_bytes(state_bytes[i * 4..i * 4 + 4].try_into().unwrap());
    }

    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
    for i in 0..80 {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5A827999u32),
            20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
            _ => (b ^ c ^ d, 0xCA62C1D6u32),
        };
        let tmp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = tmp;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);

    let mut out = [0u8; 20];
    for i in 0..5 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

/// Read a string from the SO's string-object layout: [vtable(8), ??(4), len(4), data_ptr(8)]
fn read_str_obj(dy: &Dynarmic<()>, ptr: u64) -> Option<String> {
    let lb = dy.mem_read_as_vec(ptr + 0xC, 4).ok()?;
    let len = u32::from_le_bytes(lb.try_into().ok()?) as usize;
    let pb = dy.mem_read_as_vec(ptr + 0x10, 8).ok()?;
    let dp = u64::from_le_bytes(pb.try_into().ok()?);
    if len == 0 || len > 10000 {
        return None;
    }
    String::from_utf8(dy.mem_read_as_vec(dp, len.min(2000)).ok()?).ok()
}

// ---------- Main emulator ----------

pub fn test_signing() -> Vec<(String, String)> {
    let dir = env!("CARGO_MANIFEST_DIR");
    let memdump = std::fs::read(format!("{}/lib/memdump.bin", dir)).unwrap();
    let mut pos = 0usize;
    let so_base = u64::from_le_bytes(memdump[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let count = u32::from_le_bytes(memdump[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;

    let dy = std::sync::Arc::new(Dynarmic::<()>::new());

    // Collect all ranges (rebased)
    let mut ranges: Vec<(u64, usize, usize)> = Vec::with_capacity(count);
    for _ in 0..count {
        let base = u64::from_le_bytes(memdump[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let size = u64::from_le_bytes(memdump[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        ranges.push((base, size, pos));
        pos += size;
    }

    // Merge overlapping/adjacent page-aligned ranges for mapping
    let mut page_ranges: Vec<(u64, u64)> = ranges
        .iter()
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
            if let Err(e) = dy.mem_write(
                base + off as u64,
                &memdump[data_off + off..data_off + off + chunk_sz],
            ) {
                if ok {
                    eprintln!("[emu] write fail at 0x{:x}+0x{:x}: {}", base, off, e);
                }
                ok = false;
                break;
            }
            off += chunk_sz;
        }
        if ok {
            loaded += 1;
        }
    }
    eprintln!(
        "[emu] Loaded {}/{} ranges ({}KB mapped), SO=0x{:x}",
        loaded,
        count,
        total_mapped / 1024,
        so_base
    );

    // Scan non-SO ranges for LSE atomic instructions and replace with SVC
    // Store original instruction in a lookup table for the SVC handler
    let so_end = so_base + 0x400000;
    let mut lse_map: HashMap<u64, u32> = HashMap::new(); // addr → original insn
    let mut lse_patched = 0u32;
    for &(base, size, data_off) in &ranges {
        if base >= so_base && base < so_end {
            continue;
        }
        for off in (0..size).step_by(4) {
            let insn = u32::from_le_bytes(
                memdump[data_off + off..data_off + off + 4]
                    .try_into()
                    .unwrap(),
            );
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
        eprintln!(
            "[emu] Patched {} LSE atomic instructions in non-SO ranges",
            lse_patched
        );
    }

    // Map and fill halt page with RET
    let _ = dy.mem_map(HALT_ADDR, 0x1000, 3);
    let _ = dy.mem_protect(HALT_ADDR, 0x1000, 7);
    {
        let ret_page: Vec<u8> = (0..0x1000 / 4)
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
    eprintln!(
        "[emu] Patched {} hooks + null trap (LSE handled dynamically)",
        HOOK_TABLE.len()
    );

    // ========== Set up fake JNIEnv ==========
    // Map JNI area: 0x4000_0000..0x4000_FFFF
    let _ = dy.mem_map(0x4000_0000, 0x10000, 3);
    let _ = dy.mem_protect(0x4000_0000, 0x10000, 7); // RWX for stubs

    // JNIEnv* → [functions_ptr]
    let _ = dy.mem_write(JNI_ENV_ADDR, &JNI_FUNC_TABLE.to_le_bytes());

    // Build SVC stubs and function table
    for i in 0..JNI_NUM_FUNCS {
        // Stub: SVC #(0x600 + i); RET
        let stub_addr = JNI_STUBS_ADDR + (i as u64) * 8;
        let _ = dy.mem_write(stub_addr, &svc_bytes(SVC_JNI_BASE + i as u32));
        let _ = dy.mem_write(stub_addr + 4, &0xD65F03C0u32.to_le_bytes()); // RET

        // Function table entry → stub
        let _ = dy.mem_write(JNI_FUNC_TABLE + (i as u64) * 8, &stub_addr.to_le_bytes());
    }

    // Map JNI object area
    let _ = dy.mem_write(JCLASS_HANDLE, &[0x01u8; 8]); // non-zero marker
    let _ = dy.mem_write(JOBJ_EXTRA, &[0x02u8; 8]); // non-zero marker

    // Map stack for JNI call (extra page on top for guard)
    let _ = dy.mem_map(JNI_STACK_BASE, JNI_STACK_SIZE as usize + 0x1000, 3);
    let _ = dy.mem_protect(JNI_STACK_BASE, JNI_STACK_SIZE as usize + 0x1000, 7);

    eprintln!(
        "[emu] Fake JNIEnv at 0x{:x}, {} stubs, stack at 0x{:x}",
        JNI_ENV_ADDR, JNI_NUM_FUNCS, JNI_STACK_BASE
    );

    // Set TPIDR_EL0 from register dump (real thread-local storage pointer)
    let mut tpidr = 0u64;
    for line in std::fs::read_to_string(format!("{}/lib/regs_only.txt", dir))
        .unwrap()
        .lines()
    {
        if let Some(rest) = line.strip_prefix("REG:tpidr_el0:") {
            tpidr = u64::from_str_radix(rest.trim_start_matches("0x"), 16).unwrap_or(0);
        }
    }
    assert!(tpidr != 0, "tpidr_el0 not found in regs_only.txt");
    dy.reg_write_tpidr_el0(tpidr).unwrap();
    eprintln!("[emu] TPIDR_EL0 = 0x{:x}", tpidr);

    // NOTE: Not loading registers from dump — using JNI calling convention instead
    // Only TPIDR_EL0 is set from the dump (for TLS/stack canary)

    // Shared mutable state for SVC callbacks
    let state = Arc::new(Mutex::new(SharedState {
        heap_next: 0x5000_0000,
        sigs: vec![],
        jni_objects: HashMap::new(),
        jni_next_handle: 0x4000_A000,
        jni_string_next: JNI_STRING_AREA,
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
            swi if swi >= SVC_JNI_BASE && swi < SVC_JNI_BASE + JNI_NUM_FUNCS as u32 => {
                // JNI function call
                let idx = (swi - SVC_JNI_BASE) as usize;
                let env = dy.reg_read(0).unwrap_or(0);
                let a1 = dy.reg_read(1).unwrap_or(0);
                let a2 = dy.reg_read(2).unwrap_or(0);
                let a3 = dy.reg_read(3).unwrap_or(0);
                let a4 = dy.reg_read(4).unwrap_or(0);
                let _a5 = dy.reg_read(5).unwrap_or(0);

                if n < 200 {
                    eprintln!("[JNI] #{} func={} a1=0x{:x} a2=0x{:x} a3=0x{:x} a4=0x{:x}",
                        n, jni_name(idx), a1, a2, a3, a4);
                }

                match idx {
                    JNI_GET_STRING_UTF_CHARS => {
                        // GetStringUTFChars(env, jstring, isCopy*) → const char*
                        let jstr = a1;
                        let is_copy_ptr = a2;
                        let mut result = 0u64;
                        {
                            let st_lock = st.lock().unwrap();
                            if let Some(JniObject::String(s)) = st_lock.jni_objects.get(&jstr) {
                                // Return pointer to string data in emulator memory
                                // We already wrote URL to JNI_STRING_AREA
                                if jstr == JSTRING_URL {
                                    result = JNI_STRING_AREA;
                                } else {
                                    // Find or create string in emulator memory
                                    drop(st_lock);
                                    let mut st_lock = st.lock().unwrap();
                                    let addr = st_lock.jni_string_next;
                                    let bytes = if let Some(JniObject::String(s)) = st_lock.jni_objects.get(&jstr) {
                                        s.as_bytes().to_vec()
                                    } else { vec![] };
                                    let _ = dy.mem_write(addr, &bytes);
                                    let _ = dy.mem_write(addr + bytes.len() as u64, &[0u8]);
                                    st_lock.jni_string_next = addr + ((bytes.len() as u64 + 16) & !0xF);
                                    result = addr;
                                }
                            }
                        }
                        if is_copy_ptr != 0 {
                            let _ = dy.mem_write(is_copy_ptr, &[0u8]); // isCopy = false
                        }
                        eprintln!("[JNI]   GetStringUTFChars(0x{:x}) → 0x{:x}", a1, result);
                        dy.reg_write_raw(0, result).unwrap();
                    }
                    JNI_RELEASE_STRING_UTF_CHARS => {
                        // ReleaseStringUTFChars(env, jstring, chars) — no-op
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_GET_STRING_UTF_LENGTH => {
                        // GetStringUTFLength(env, jstring) → jsize
                        let jstr = a1;
                        let len = {
                            let st_lock = st.lock().unwrap();
                            if let Some(JniObject::String(s)) = st_lock.jni_objects.get(&jstr) {
                                s.len() as u64
                            } else { 0 }
                        };
                        dy.reg_write_raw(0, len).unwrap();
                    }
                    JNI_NEW_STRING_UTF => {
                        // NewStringUTF(env, const char* utf) → jstring
                        let utf_ptr = a1;
                        // Read null-terminated string from emulator memory
                        let mut bytes = vec![];
                        for i in 0..4096u64 {
                            if let Ok(b) = dy.mem_read_as_vec(utf_ptr + i, 1) {
                                if b[0] == 0 { break; }
                                bytes.push(b[0]);
                            } else { break; }
                        }
                        let s = String::from_utf8_lossy(&bytes).to_string();
                        let handle = {
                            let mut st_lock = st.lock().unwrap();
                            let h = st_lock.jni_next_handle;
                            st_lock.jni_next_handle += 0x10;
                            st_lock.jni_objects.insert(h, JniObject::String(s.clone()));
                            h
                        };
                        eprintln!("[JNI]   NewStringUTF({:?}) → 0x{:x}", &s[..s.len().min(80)], handle);
                        dy.reg_write_raw(0, handle).unwrap();
                    }
                    JNI_FIND_CLASS => {
                        // FindClass(env, const char* name) → jclass
                        let name_ptr = a1;
                        let mut bytes = vec![];
                        for i in 0..256u64 {
                            if let Ok(b) = dy.mem_read_as_vec(name_ptr + i, 1) {
                                if b[0] == 0 { break; }
                                bytes.push(b[0]);
                            } else { break; }
                        }
                        let name = String::from_utf8_lossy(&bytes).to_string();
                        let handle = {
                            let mut st_lock = st.lock().unwrap();
                            let h = st_lock.jni_next_handle;
                            st_lock.jni_next_handle += 0x10;
                            st_lock.jni_objects.insert(h, JniObject::Class(name.clone()));
                            h
                        };
                        eprintln!("[JNI]   FindClass({:?}) → 0x{:x}", name, handle);
                        dy.reg_write_raw(0, handle).unwrap();
                    }
                    JNI_GET_METHOD_ID | JNI_GET_STATIC_METHOD_ID => {
                        // Get(Static)MethodID(env, class, name, sig) → jmethodID
                        let name_ptr = a2;
                        let sig_ptr = a3;
                        let mut read_cstr = |ptr: u64| -> String {
                            let mut bytes = vec![];
                            for i in 0..256u64 {
                                if let Ok(b) = dy.mem_read_as_vec(ptr + i, 1) {
                                    if b[0] == 0 { break; }
                                    bytes.push(b[0]);
                                } else { break; }
                            }
                            String::from_utf8_lossy(&bytes).to_string()
                        };
                        let name = read_cstr(name_ptr);
                        let sig = read_cstr(sig_ptr);
                        // Return a fake method ID (non-zero)
                        let mid = {
                            let mut st_lock = st.lock().unwrap();
                            let h = st_lock.jni_next_handle;
                            st_lock.jni_next_handle += 0x10;
                            h
                        };
                        eprintln!("[JNI]   GetMethodID(0x{:x}, {:?}, {:?}) → 0x{:x}", a1, name, sig, mid);
                        dy.reg_write_raw(0, mid).unwrap();
                    }
                    JNI_GET_FIELD_ID | JNI_GET_STATIC_FIELD_ID => {
                        let name_ptr = a2;
                        let mut bytes = vec![];
                        for i in 0..256u64 {
                            if let Ok(b) = dy.mem_read_as_vec(name_ptr + i, 1) {
                                if b[0] == 0 { break; }
                                bytes.push(b[0]);
                            } else { break; }
                        }
                        let name = String::from_utf8_lossy(&bytes).to_string();
                        let fid = {
                            let mut st_lock = st.lock().unwrap();
                            let h = st_lock.jni_next_handle;
                            st_lock.jni_next_handle += 0x10;
                            h
                        };
                        eprintln!("[JNI]   GetFieldID(0x{:x}, {:?}) → 0x{:x}", a1, name, fid);
                        dy.reg_write_raw(0, fid).unwrap();
                    }
                    JNI_NEW_OBJECT_ARRAY => {
                        // NewObjectArray(env, size, class, init) → jobjectArray
                        let size = a1 as usize;
                        let handle = {
                            let mut st_lock = st.lock().unwrap();
                            let h = st_lock.jni_next_handle;
                            st_lock.jni_next_handle += 0x10;
                            st_lock.jni_objects.insert(h, JniObject::ObjectArray(vec![0; size]));
                            h
                        };
                        eprintln!("[JNI]   NewObjectArray(size={}) → 0x{:x}", size, handle);
                        dy.reg_write_raw(0, handle).unwrap();
                    }
                    JNI_SET_OBJECT_ARRAY_ELEMENT => {
                        // SetObjectArrayElement(env, array, index, value)
                        let array = a1;
                        let index = a2 as usize;
                        let value = a3;
                        {
                            let mut st_lock = st.lock().unwrap();
                            if let Some(JniObject::ObjectArray(ref mut arr)) = st_lock.jni_objects.get_mut(&array) {
                                if index < arr.len() {
                                    arr[index] = value;
                                }
                            }
                        }
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_GET_OBJECT_ARRAY_ELEMENT => {
                        // GetObjectArrayElement(env, array, index) → jobject
                        let array = a1;
                        let index = a2 as usize;
                        let result = {
                            let st_lock = st.lock().unwrap();
                            if let Some(JniObject::ObjectArray(arr)) = st_lock.jni_objects.get(&array) {
                                arr.get(index).copied().unwrap_or(0)
                            } else { 0 }
                        };
                        dy.reg_write_raw(0, result).unwrap();
                    }
                    JNI_GET_ARRAY_LENGTH => {
                        // GetArrayLength(env, array) → jsize
                        let array = a1;
                        let len = {
                            let st_lock = st.lock().unwrap();
                            match st_lock.jni_objects.get(&array) {
                                Some(JniObject::ObjectArray(arr)) => arr.len() as u64,
                                Some(JniObject::ByteArray(arr)) => arr.len() as u64,
                                _ => 0,
                            }
                        };
                        dy.reg_write_raw(0, len).unwrap();
                    }
                    JNI_EXCEPTION_CHECK => {
                        // ExceptionCheck(env) → jboolean (0 = no exception)
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_EXCEPTION_OCCURRED => {
                        // ExceptionOccurred(env) → jthrowable (NULL = no exception)
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_EXCEPTION_CLEAR => {
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_ENSURE_LOCAL_CAPACITY => {
                        // EnsureLocalCapacity(env, capacity) → 0 (JNI_OK)
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_DELETE_LOCAL_REF | JNI_DELETE_GLOBAL_REF => {
                        // Delete ref — no-op
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_NEW_GLOBAL_REF => {
                        // NewGlobalRef(env, obj) → globalRef (just return same ref)
                        dy.reg_write_raw(0, a1).unwrap();
                    }
                    JNI_GET_OBJECT_CLASS => {
                        // GetObjectClass(env, obj) → jclass
                        dy.reg_write_raw(0, JCLASS_HANDLE).unwrap();
                    }
                    JNI_CALL_OBJECT_METHOD | JNI_CALL_OBJECT_METHOD_V | JNI_CALL_OBJECT_METHOD_A
                    | JNI_CALL_STATIC_OBJECT_METHOD => {
                        // CallObjectMethod(V/A) / CallStaticObjectMethod
                        // a1 = object, a2 = methodID, a3+ = args
                        let obj = a1;
                        // Check if this is a getBytes call on a string
                        let result_handle = {
                            let st_lock = st.lock().unwrap();
                            if let Some(JniObject::String(s)) = st_lock.jni_objects.get(&obj) {
                                // Likely getBytes("utf-8") — return byte array of string
                                let bytes = s.as_bytes().to_vec();
                                drop(st_lock);
                                let mut st_lock = st.lock().unwrap();
                                let h = st_lock.jni_next_handle;
                                st_lock.jni_next_handle += 0x10;
                                st_lock.jni_objects.insert(h, JniObject::ByteArray(bytes));
                                eprintln!("[JNI]   CallObjectMethod on string → ByteArray 0x{:x}", h);
                                h
                            } else {
                                eprintln!("[JNI]   CallObjectMethod(0x{:x}) → NULL", obj);
                                0
                            }
                        };
                        dy.reg_write_raw(0, result_handle).unwrap();
                    }
                    JNI_CALL_INT_METHOD | JNI_CALL_STATIC_INT_METHOD => {
                        // CallIntMethod / CallStaticIntMethod — return 0
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_CALL_BOOLEAN_METHOD => {
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_CALL_VOID_METHOD | JNI_CALL_STATIC_VOID_METHOD => {
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_GET_OBJECT_FIELD | JNI_GET_STATIC_OBJECT_FIELD => {
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_GET_INT_FIELD => {
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_GET_LONG_FIELD => {
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_SET_OBJECT_FIELD | JNI_SET_INT_FIELD | JNI_SET_LONG_FIELD => {
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_NEW_BYTE_ARRAY => {
                        // NewByteArray(env, size) → jbyteArray
                        let size = a1 as usize;
                        let handle = {
                            let mut st_lock = st.lock().unwrap();
                            let h = st_lock.jni_next_handle;
                            st_lock.jni_next_handle += 0x10;
                            st_lock.jni_objects.insert(h, JniObject::ByteArray(vec![0; size]));
                            h
                        };
                        dy.reg_write_raw(0, handle).unwrap();
                    }
                    JNI_GET_BYTE_ARRAY_ELEMENTS => {
                        // GetByteArrayElements(env, array, isCopy) → jbyte*
                        let array = a1;
                        let data_copy = {
                            let st_lock = st.lock().unwrap();
                            if let Some(JniObject::ByteArray(ref data)) = st_lock.jni_objects.get(&array) {
                                Some(data.clone())
                            } else { None }
                        };
                        let result = if let Some(data) = data_copy {
                            let mut s = st.lock().unwrap();
                            let addr = s.heap_next;
                            s.heap_next += ((data.len() as u64 + 15) & !15).max(16);
                            let _ = dy.mem_write(addr, &data);
                            addr
                        } else { 0 };
                        if a2 != 0 {
                            let _ = dy.mem_write(a2, &[0u8]); // isCopy = false
                        }
                        dy.reg_write_raw(0, result).unwrap();
                    }
                    JNI_RELEASE_BYTE_ARRAY_ELEMENTS => {
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_GET_BYTE_ARRAY_REGION => {
                        // GetByteArrayRegion(env, array, start, len, buf)
                        let array = a1;
                        let start = a2 as usize;
                        let len = a3 as usize;
                        let buf = a4;
                        let data = {
                            let st_lock = st.lock().unwrap();
                            if let Some(JniObject::ByteArray(ref arr)) = st_lock.jni_objects.get(&array) {
                                let end = (start + len).min(arr.len());
                                if start < arr.len() {
                                    Some(arr[start..end].to_vec())
                                } else { None }
                            } else { None }
                        };
                        if let Some(data) = data {
                            if buf != 0 {
                                let _ = dy.mem_write(buf, &data);
                                eprintln!("[JNI]   GetByteArrayRegion(0x{:x}, {}, {}) → wrote {} bytes to 0x{:x}",
                                    array, start, len, data.len(), buf);
                            }
                        }
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    JNI_SET_BYTE_ARRAY_REGION => {
                        // SetByteArrayRegion(env, array, start, len, buf)
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                    _ => {
                        eprintln!("[JNI] UNHANDLED func={} (idx={})", jni_name(idx), idx);
                        dy.reg_write_raw(0, 0).unwrap();
                    }
                }
            }
            _ => {
                // Unknown SVC — return 0
                if n < 20 { eprintln!("[SVC] unknown swi=0x{:x} pc=0x{:x}", swi, pc); }
                dy.reg_write_raw(0, 0).unwrap();
            }
        }
    });

    // Load Frida agent address ranges (for detecting contaminated function pointers)
    let frida_ranges: Vec<(u64, u64)> = {
        let frida_path = format!("{}/lib/frida_ranges.txt", dir);
        let mut ranges = vec![];
        if let Ok(content) = std::fs::read_to_string(&frida_path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.split('-').collect();
                if parts.len() == 2 {
                    if let (Ok(s), Ok(e)) = (
                        u64::from_str_radix(parts[0], 16),
                        u64::from_str_radix(parts[1], 16),
                    ) {
                        ranges.push((s, e));
                    }
                }
            }
            eprintln!("[emu] Loaded {} Frida ranges", ranges.len());
        }
        ranges
    };
    let frida_ranges = Arc::new(frida_ranges);

    // Unmapped memory callback — record missing pages, map with zeros, signal stop
    let missing_pages = Arc::new(Mutex::new(std::collections::BTreeSet::<u64>::new()));
    let mp = missing_pages.clone();
    let miss_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let miss_flag_cb = miss_flag.clone();
    let so_base_miss = so_base;
    let frida_ranges_cb = frida_ranges.clone();
    let st_miss = state.clone();
    dy.set_unmapped_mem_callback(
        move |dy: &Dynarmic<()>, addr: u64, _size: usize, _value: u64| -> bool {
            // Strip MTE tag from top byte (Android memory tagging)
            let addr = addr & 0x00FF_FFFF_FFFF_FFFF;
            let page = addr & !0xFFF;
            let pc = dy.reg_read_pc().unwrap_or(0);

            // Check if this is a code fetch into Frida agent range
            let in_frida = frida_ranges_cb.iter().any(|&(s, e)| addr >= s && addr < e);
            let is_code_fetch = (pc & !0xFFF) == page || pc == addr;

            if in_frida || is_code_fetch {
                let lr = dy.reg_read(30).unwrap_or(0);
                let x0 = dy.reg_read(0).unwrap_or(0);
                eprintln!(
                    "[MISS] Frida/code fetch at 0x{:x} pc=0x{:x} LR=0x{:x} x0=0x{:x}",
                    addr, pc, lr, x0
                );
                // Skip the function: allocate heap block as return value and return to caller
                let ptr = {
                    let mut s = st_miss.lock().unwrap();
                    let p = s.heap_next;
                    s.heap_next += 0x100;
                    p
                };
                let _ = dy.mem_write(ptr, &[0u8; 0x100]);
                dy.reg_write_raw(0, ptr).unwrap();
                dy.reg_write_pc(lr).unwrap();
                let _ = dy.emu_stop(); // stop so retry loop picks up at LR
                return false;
            }

            eprintln!("[MISS] addr=0x{:x} page=0x{:x} pc=0x{:x}", addr, page, pc);
            if page < 0x8000_0000_0000 {
                mp.lock().unwrap().insert(page);
            }
            miss_flag_cb.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = dy.emu_stop();
            false
        },
    );

    // ========== Set up JNI call to SO+0x26e684 ==========
    // y2.a(int tag, int type, long handle, String url, Object extra)
    // JNI convention: x0=JNIEnv*, x1=jclass, x2=tag, x3=type, x4=handle, x5=url, x6=extra

    // Write URL string to emulator memory and register as JNI object
    let test_url = "https://novel.snssdk.com/api/novel/book/directory/list_v2/?device_platform=android&parent_enterfrom=novel_channel_search.tab.&aid=1967&app_name=novel_android&version_code=71332&device_type=sdk_gphone64_arm64&device_brand=google&language=zh&os_api=35&os_version=15&ac=wifi&channel=googleplay&device_id=3722313718058683&iid=3722313718062779&cdid=e1f62191-7252-491d-a4ef-6936fee1c2f7&openudid=9809e655-067c-47fe-a937-b150bfad0be9";
    {
        // Store URL string data in emulator memory
        let url_data_addr = JNI_STRING_AREA;
        let url_bytes = test_url.as_bytes();
        let _ = dy.mem_write(url_data_addr, url_bytes);
        let _ = dy.mem_write(url_data_addr + url_bytes.len() as u64, &[0u8]); // null terminator

        // Register URL jstring in object table
        let mut st = state.lock().unwrap();
        st.jni_objects
            .insert(JSTRING_URL, JniObject::String(test_url.to_string()));
        // Register extra as empty array
        st.jni_objects
            .insert(JOBJ_EXTRA, JniObject::ObjectArray(vec![]));
        st.jni_objects
            .insert(JCLASS_HANDLE, JniObject::Class("ms.bd.c.y2".into()));
        st.jni_string_next = url_data_addr + ((url_bytes.len() as u64 + 16) & !0xF);
    }

    // Set up fresh stack
    let stack_top = JNI_STACK_BASE + JNI_STACK_SIZE - 0x100; // leave headroom
    dy.reg_write_sp(stack_top).unwrap();
    dy.reg_write_raw(29, stack_top).unwrap(); // FP = SP

    // Set JNI call registers
    dy.reg_write_raw(0, JNI_ENV_ADDR).unwrap(); // x0 = JNIEnv*
    dy.reg_write_raw(1, JCLASS_HANDLE).unwrap(); // x1 = jclass
    dy.reg_write_raw(2, 0x3000001).unwrap(); // x2 = tag (signing)
    dy.reg_write_raw(3, 0).unwrap(); // x3 = type
                                     // Load real MetaSec handle object from dump
    let handle_addr;
    let handle_dump_path = format!("{}/lib/handle_dump.bin", dir);
    if std::path::Path::new(&handle_dump_path).exists() {
        let hdata = std::fs::read(&handle_dump_path).unwrap();
        let orig_addr = u64::from_le_bytes(hdata[0..8].try_into().unwrap());
        let data_len = u32::from_le_bytes(hdata[8..12].try_into().unwrap()) as usize;
        let data = &hdata[12..12 + data_len];

        // Map the handle at its original address (so internal pointers remain valid)
        let page = orig_addr & !0xFFF;
        let page_end = ((orig_addr + data_len as u64) + 0xFFF) & !0xFFF;
        let map_size = (page_end - page) as usize;
        let _ = dy.mem_map(page, map_size, 3);
        let _ = dy.mem_write(orig_addr, data);
        handle_addr = orig_addr;
        eprintln!(
            "[emu] Loaded real MetaSec handle: 0x{:x} ({} bytes)",
            handle_addr, data_len
        );

        // Also map pages for pointers found in handle data (follow internal pointers)
        for off in (0..data_len).step_by(8) {
            if off + 8 <= data_len {
                let ptr = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
                // Check if it's a heap-like pointer in the same range (not SO, not stack)
                let ptr_page = ptr & !0xFFF;
                if ptr > 0x7000_0000_0000 && ptr < 0x8000_0000_0000
                    && !(ptr >= so_base && ptr < so_base + 0x400000) // not in SO
                    && ptr_page != page
                // not same page as handle
                {
                    // Try to map it if not already mapped (will fail silently if already mapped)
                    let _ = dy.mem_map(ptr_page, 0x1000, 3);
                }
            }
        }
    } else {
        // Fallback: allocate fake handle
        handle_addr = {
            let mut st = state.lock().unwrap();
            let h = st.heap_next;
            st.heap_next += 0x1000;
            h
        };
        let _ = dy.mem_write(handle_addr, &vec![0u8; 0x1000]);
        eprintln!(
            "[emu] WARNING: No handle_dump.bin, using fake handle at 0x{:x}",
            handle_addr
        );
    }
    dy.reg_write_raw(4, handle_addr).unwrap(); // x4 = handle (MetaSec context)
    dy.reg_write_raw(5, JSTRING_URL).unwrap(); // x5 = url (jstring)
    dy.reg_write_raw(6, JOBJ_EXTRA).unwrap(); // x6 = extra (jobject)
    dy.reg_write_raw(30, HALT_ADDR).unwrap(); // LR = halt (return here when done)

    // Write stack canary at [TPIDR+0x28] if not already present
    if tpidr != 0 {
        if let Ok(b) = dy.mem_read_as_vec(tpidr + 0x28, 8) {
            let canary = u64::from_le_bytes(b.try_into().unwrap());
            if canary == 0 {
                // Write a fixed canary value
                let _ = dy.mem_write(tpidr + 0x28, &0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
                eprintln!("[emu] Wrote fake stack canary");
            }
        }
    }

    let start = so_base + 0x26e684;
    eprintln!("[emu] Starting at SO+0x26e684 (JNI native entry, dynarmic JIT)");
    eprintln!(
        "[emu]   x0(JNIEnv)=0x{:x} x1(jclass)=0x{:x} x2(tag)=0x{:x}",
        JNI_ENV_ADDR, JCLASS_HANDLE, 0x3000001u64
    );
    eprintln!(
        "[emu]   x3(type)=0 x4(handle)=0 x5(url)=0x{:x} x6(extra)=0x{:x}",
        JSTRING_URL, JOBJ_EXTRA
    );
    eprintln!("[emu]   SP=0x{:x} LR=0x{:x}", stack_top, HALT_ADDR);
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
                eprintln!("[sample] t={}s PC=SO+0x{:x} SP=0x{:x}", i + 1, so_off, sp);
            } else {
                eprintln!("[sample] t={}s PC=0x{:x} SP=0x{:x}", i + 1, pc, sp);
            }
        }
        timed_out_flag.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = dy_timeout.emu_stop();
        eprintln!("[emu] Timeout: forced stop after 5s");
    });

    // Trace mode: set EMU_TRACE=1 to enable single-step tracing
    if std::env::var("EMU_TRACE").is_ok() {
        eprintln!("[emu] Trace mode enabled");
        let mut trace_pc = start;
        for step in 0..20000 {
            dy.emu_step(trace_pc).ok();
            let pc = dy.reg_read_pc().unwrap_or(0);
            let so_off = pc.wrapping_sub(so_base);
            let is_branch = pc != trace_pc + 4;
            if step < 30 || is_branch || pc == HALT_ADDR {
                let insn = dy
                    .mem_read_as_vec(trace_pc, 4)
                    .ok()
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap_or([0; 4])))
                    .unwrap_or(0);
                if so_off < 0x400000 {
                    eprintln!(
                        "[trace] #{:4} SO+0x{:x} → SO+0x{:x} insn=0x{:08x}{}",
                        step,
                        trace_pc.wrapping_sub(so_base),
                        so_off,
                        insn,
                        if is_branch { " <<<" } else { "" }
                    );
                } else {
                    eprintln!(
                        "[trace] #{:4} SO+0x{:x} → 0x{:x} insn=0x{:08x} <<<",
                        step,
                        trace_pc.wrapping_sub(so_base),
                        pc,
                        insn
                    );
                }
            }
            if pc == HALT_ADDR || miss_flag.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!("[trace] Reached HALT/MISS at step {}", step);
                break;
            }
            trace_pc = pc;
        }
        // Reset for actual run
        dy.reg_write_sp(stack_top).unwrap();
        dy.reg_write_raw(29, stack_top).unwrap();
        dy.reg_write_raw(0, JNI_ENV_ADDR).unwrap();
        dy.reg_write_raw(1, JCLASS_HANDLE).unwrap();
        dy.reg_write_raw(2, 0x3000001).unwrap();
        dy.reg_write_raw(3, 0).unwrap();
        dy.reg_write_raw(4, handle_addr).unwrap();
        dy.reg_write_raw(5, JSTRING_URL).unwrap();
        dy.reg_write_raw(6, JOBJ_EXTRA).unwrap();
        dy.reg_write_raw(30, HALT_ADDR).unwrap();
        miss_flag.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    let mut retries = 0u32;
    dy.emu_start(start, HALT_ADDR).ok();
    loop {
        let pc = dy.reg_read_pc().unwrap_or(0);
        if pc == HALT_ADDR
            || timed_out.load(std::sync::atomic::Ordering::Relaxed)
            || miss_flag.load(std::sync::atomic::Ordering::Relaxed)
        {
            let elapsed = t0.elapsed().as_secs_f64();
            eprintln!(
                "[emu] Done in {:.1}s, {} retries, PC=0x{:x}",
                elapsed, retries, pc
            );
            break;
        }
        retries += 1;
        // Check if PC is in a missing page or garbage address — stop
        let pc_page = pc & !0xFFF;
        if missing_pages.lock().unwrap().contains(&pc_page) || pc > 0x8000_0000_0000 || pc < 0x1000
        {
            let elapsed = t0.elapsed().as_secs_f64();
            eprintln!(
                "[emu] Halted at missing page PC=0x{:x} after {:.1}s, {} retries",
                pc, elapsed, retries
            );
            break;
        }
        if retries <= 50 {
            let lr = dy.reg_read(30).unwrap_or(0);
            let insn_hex = dy
                .mem_read_as_vec(pc, 4)
                .ok()
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0);
            eprintln!(
                "[emu] Retry #{}: PC=0x{:x} (SO+0x{:x}) LR=0x{:x} insn=0x{:08x} t={:.1}s",
                retries,
                pc,
                pc.wrapping_sub(so_base),
                lr,
                insn_hex,
                t0.elapsed().as_secs_f64()
            );
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
                let old = dy
                    .mem_read_as_vec(xn, nbytes)
                    .ok()
                    .map(|b| {
                        let mut buf = [0u8; 8];
                        buf[..nbytes].copy_from_slice(&b);
                        u64::from_le_bytes(buf)
                    })
                    .unwrap_or(0);
                let new_val = old.wrapping_add(addend) & ((1u128 << (nbytes * 8)) - 1) as u64;
                let _ = dy.mem_write(xn, &new_val.to_le_bytes()[..nbytes]);
                if rt != 31 {
                    dy.reg_write_raw(rt, old).unwrap();
                }
                if retries <= 50 {
                    eprintln!(
                        "[emu] LDADD({}): [X{}=0x{:x}] old=0x{:x} +0x{:x} → W{}",
                        nbytes, rn, xn, old, addend, rt
                    );
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
                    let old = dy
                        .mem_read_as_vec(addr, 8)
                        .ok()
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                        .unwrap_or(0);
                    (
                        old,
                        dy.reg_read(rs).unwrap_or(0),
                        dy.reg_read(rt).unwrap_or(0),
                    )
                } else {
                    let old = dy
                        .mem_read_as_vec(addr, 4)
                        .ok()
                        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64)
                        .unwrap_or(0);
                    (
                        old,
                        dy.reg_read(rs).unwrap_or(0) & 0xFFFFFFFF,
                        dy.reg_read(rt).unwrap_or(0) & 0xFFFFFFFF,
                    )
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
                    eprintln!(
                        "[emu] CAS: [X{}=0x{:x}] old=0x{:x} cmp=W{}=0x{:x} new=W{}=0x{:x} {}",
                        rn,
                        addr,
                        old,
                        rs,
                        compare,
                        rt,
                        new_val,
                        if old == compare { "SWAPPED" } else { "KEPT" }
                    );
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
                let val = dy
                    .mem_read_as_vec(addr, 4)
                    .ok()
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                    .unwrap_or(0);
                if rt != 31 {
                    dy.reg_write_raw(rt, val as u64).unwrap();
                }
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
                if rs != 31 {
                    dy.reg_write_raw(rs, 0).unwrap();
                }
                if retries <= 50 {
                    eprintln!(
                        "[emu] STLXR: [X{}=0x{:x}] = W{}=0x{:x}, W{}=0",
                        rn, addr, rt, val, rs
                    );
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
    let pc = dy.reg_read_pc().unwrap_or(0);

    // Extract result from JNI return value (x0)
    let ret_obj = dy.reg_read(0).unwrap_or(0);
    eprintln!("[emu] Return value x0=0x{:x}", ret_obj);
    {
        let st = state.lock().unwrap();
        if let Some(obj) = st.jni_objects.get(&ret_obj) {
            eprintln!("[emu] Return object: {:?}", obj);
            // If it's a String[] (ObjectArray of strings), extract key-value pairs
            if let JniObject::ObjectArray(arr) = obj {
                for pair in arr.chunks(2) {
                    if pair.len() == 2 {
                        let key = st
                            .jni_objects
                            .get(&pair[0])
                            .map(|o| match o {
                                JniObject::String(s) => s.clone(),
                                _ => format!("obj:0x{:x}", pair[0]),
                            })
                            .unwrap_or_default();
                        let val = st
                            .jni_objects
                            .get(&pair[1])
                            .map(|o| match o {
                                JniObject::String(s) => s.clone(),
                                _ => format!("obj:0x{:x}", pair[1]),
                            })
                            .unwrap_or_default();
                        eprintln!("[SIG] {}={}", key, &val[..val.len().min(80)]);
                    }
                }
            }
        }
    }

    let mut sigs = state.lock().unwrap().sigs.clone();

    // Also extract from JNI objects if the function returned a string array
    {
        let st = state.lock().unwrap();
        if let Some(JniObject::ObjectArray(arr)) = st.jni_objects.get(&ret_obj) {
            for pair in arr.chunks(2) {
                if pair.len() == 2 {
                    if let (Some(JniObject::String(k)), Some(JniObject::String(v))) =
                        (st.jni_objects.get(&pair[0]), st.jni_objects.get(&pair[1]))
                    {
                        if !sigs.iter().any(|(sk, _)| sk == k) {
                            sigs.push((k.clone(), v.clone()));
                        }
                    }
                }
            }
        }
    }

    let pages = missing_pages.lock().unwrap();
    eprintln!(
        "[emu] {} SVCs total, {} signatures captured, {} missing pages",
        total_svcs,
        sigs.len(),
        pages.len()
    );
    if pc == HALT_ADDR {
        eprintln!("[emu] Function returned normally!");
    }
    if !pages.is_empty() {
        let path = format!("{}/lib/missing_pages.txt", dir);
        let content: String = pages.iter().map(|p| format!("0x{:x}\n", p)).collect();
        std::fs::write(&path, &content).ok();
        eprintln!("[emu] Missing pages saved to {}", path);
    }
    drop(pages);
    sigs
}

/// Compute Helios part1+part2 (32 bytes) using the custom VM.
/// Input: h1_hex (32 bytes ASCII hex of MD5(R+"1967")) + ts_str ("{ts}-{dev_reg_id}-1967")
/// Output: 32 bytes (part1 + part2)
fn vm_compute_helios(h1_hex: &[u8; 32], ts_str: &[u8]) -> [u8; 32] {
    use dynarmic_sys::Dynarmic;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    let dir = env!("CARGO_MANIFEST_DIR");
    let so_code = std::fs::read(format!("{}/lib/so_code.bin", dir)).expect("so_code.bin");
    let so_data1 = std::fs::read(format!("{}/lib/so_data1.bin", dir)).expect("so_data1.bin");
    let so_data2 = std::fs::read(format!("{}/lib/so_data2.bin", dir)).expect("so_data2.bin");

    let so_base: u64 = 0x6d88_01b0_00;
    let dy = Arc::new(Dynarmic::<()>::new());

    // Map SO
    let code_page = so_base & !0xFFF;
    dy.mem_map(code_page, ((0x348700 + 0xFFF) & !0xFFF) + 0x1000, 3)
        .unwrap();
    dy.mem_write(so_base, &so_code[..0x348700]).unwrap();
    let d1 = so_base + 0x34C700;
    dy.mem_map(
        d1 & !0xFFF,
        ((0x28F10 + 0xFFF + (d1 & 0xFFF) as usize) & !0xFFF),
        3,
    )
    .unwrap();
    dy.mem_write(d1, &so_data1[..0x28F10]).unwrap();
    let d2 = so_base + 0x379610;
    dy.mem_map(
        d2 & !0xFFF,
        ((0x6A460 + 0xFFF + (d2 & 0xFFF) as usize) & !0xFFF),
        3,
    )
    .unwrap();
    dy.mem_write(d2, &so_data2[..0x6A460]).unwrap();

    // Stack + halt + TPIDR
    let stack_base: u64 = 0x7000_0000;
    dy.mem_map(stack_base, 0x10_0000, 3).unwrap();
    let sp = stack_base + 0x10_0000 - 0x1000;

    let halt_addr: u64 = 0xDEAD_0000;
    dy.mem_map(halt_addr, 0x1000, 3).unwrap();
    for off in (0..0x1000).step_by(4) {
        dy.mem_write(halt_addr + off, &0xD65F03C0u32.to_le_bytes())
            .unwrap();
    }

    let tpidr: u64 = 0x8000_0000;
    dy.mem_map(tpidr, 0x1000, 3).unwrap();
    dy.mem_write(tpidr + 0x28, &0xCAFE_BABE_DEAD_BEEFu64.to_le_bytes())
        .unwrap();
    dy.reg_write_tpidr_el0(tpidr).unwrap();

    // PKCS#7 padding: h1_hex(32) + ts_str(26) = 58 → pad to 64
    let mut padded = Vec::with_capacity(64);
    padded.extend_from_slice(h1_hex);
    padded.extend_from_slice(ts_str);
    let pad_len = 16 - (padded.len() % 16);
    let pad_len = if pad_len == 0 { 16 } else { pad_len };
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));

    let input_addr: u64 = stack_base + 0x200;
    dy.mem_write(input_addr, &padded).unwrap();
    let output_addr: u64 = stack_base + 0x400;
    dy.mem_write(output_addr, &vec![0u8; padded.len()]).unwrap();
    let workspace: u64 = stack_base + 0x600;
    dy.mem_write(workspace, &[0u8; 256]).unwrap();

    // Callbacks
    let miss = Arc::new(AtomicBool::new(false));
    {
        let m = miss.clone();
        dy.set_unmapped_mem_callback(
            move |d: &Dynarmic<()>, addr: u64, _: usize, _: u64| -> bool {
                eprintln!("[helios] UNMAPPED 0x{:x}", addr & 0x00FF_FFFF_FFFF_FFFF);
                m.store(true, std::sync::atomic::Ordering::SeqCst);
                d.emu_stop().ok();
                false
            },
        );
    }
    dy.set_svc_callback(|_: &Dynarmic<()>, n: u32, _: u64, _: u64| {
        eprintln!("[helios] SVC #{:#x}", n);
    });

    // Run VM for each 16-byte block
    let entry = so_base + 0x168324;
    let bytecode = so_base + 0x118F50;
    let callback = so_base + 0x2884AC;

    for i in 0..(padded.len() / 16) {
        let off = (i * 16) as u64;
        let pa = sp - 0x100;
        dy.mem_write(pa, &workspace.to_le_bytes()).unwrap();
        dy.mem_write(pa + 8, &(input_addr + off).to_le_bytes())
            .unwrap();
        dy.mem_write(pa + 16, &(output_addr + off).to_le_bytes())
            .unwrap();

        let ctx = sp - 0x200;
        let vm_stk = sp - 0x300 - (i as u64) * 0x200;
        dy.mem_write(ctx, &callback.to_le_bytes()).unwrap();
        dy.mem_write(ctx + 8, &vm_stk.to_le_bytes()).unwrap();
        dy.mem_write(ctx + 16, &0u64.to_le_bytes()).unwrap();

        dy.reg_write_raw(0, bytecode).unwrap();
        dy.reg_write_raw(1, pa).unwrap();
        dy.reg_write_raw(2, 0).unwrap();
        dy.reg_write_raw(3, 0).unwrap();
        dy.reg_write_raw(4, ctx).unwrap();
        dy.reg_write_sp(sp).unwrap();
        dy.reg_write_lr(halt_addr).unwrap();

        dy.reg_write_pc(entry).unwrap();
        let mut steps = 0u64;
        loop {
            let pc = dy.reg_read_pc().unwrap_or(0);
            if pc == halt_addr || pc == halt_addr + 4 {
                break;
            }
            if miss.load(std::sync::atomic::Ordering::SeqCst) || steps >= 200_000 {
                break;
            }
            dy.emu_step(pc).ok();
            steps += 1;
        }
        miss.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    let mut result = [0u8; 32];
    dy.mem_read(output_addr, &mut result).unwrap();
    result
}

/// Sign a URL query string. Returns headers: X-Helios (and eventually X-Medusa).
pub fn sign(url_query: &str) -> HashMap<String, String> {
    use rand::Rng;

    let mut headers = HashMap::new();

    // H0 = MD5(url_query_params)
    let _h0 = md5::compute(url_query.as_bytes());

    // R = 4 random bytes
    let r: [u8; 4] = rand::thread_rng().gen();

    // H1 = MD5(R + "1967")
    let mut h1_input = Vec::with_capacity(8);
    h1_input.extend_from_slice(&r);
    h1_input.extend_from_slice(b"1967");
    let h1 = md5::compute(&h1_input);

    // H1_hex = lowercase hex of H1 (32 bytes ASCII)
    let h1_hex_str = hex::encode(h1.0);
    let h1_hex: [u8; 32] = h1_hex_str.as_bytes().try_into().unwrap();

    // ts_str = "{unix_ts}-{device_reg_id}-1967"
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ts_str = format!("{}-1394812046-1967", ts);

    // Compute part1+part2 via VM
    let parts = vm_compute_helios(&h1_hex, ts_str.as_bytes());

    // Helios = base64(R(4) + part1(16) + part2(16))
    let mut helios_raw = Vec::with_capacity(36);
    helios_raw.extend_from_slice(&r);
    helios_raw.extend_from_slice(&parts);

    use base64::Engine;
    let helios_b64 = base64::engine::general_purpose::STANDARD.encode(&helios_raw);
    headers.insert("X-Helios".to_string(), helios_b64);

    eprintln!("[sign] X-Helios generated ({} bytes raw)", helios_raw.len());

    // === X-Medusa construction ===
    // AES-128-ECB key = MD5("1967" + [0xab,0x7c,0xfe,0x85] + "1967")
    let aes_key_input = [
        b'1', b'9', b'6', b'7', 0xab, 0x7c, 0xfe, 0x85, b'1', b'9', b'6', b'7',
    ];
    let aes_key = md5::compute(&aes_key_input).0; // 059874c397db2a6594024f0aa1c288c4

    // Medusa plaintext: constructed from URL hash + device info + constants
    // H0 = MD5(url_query) — URL-dependent
    let h0 = md5::compute(url_query.as_bytes()).0;
    // H2 = MD5(session_uuid + "0") — session-dependent, use device_id as proxy
    let h2 = md5::compute(b"00000000-0000-0000-0000-0000000000000").0;
    // H4 = MD5(fixed_constant1) from ISSUE.md
    let h4_input = hex::decode("abd3c178a46d39ad4fb312d3d23941c3").unwrap();
    let h4 = md5::compute(&h4_input).0;
    // H5 = MD5(fixed_constant2)
    let h5_input = hex::decode("447c28b7a74153a038708f7aa92f9575").unwrap();
    let h5 = md5::compute(&h5_input).0;

    // Build Medusa plaintext (272 bytes = 17 AES blocks)
    // Structure: concatenate known hashes + padding + device info
    let mut medusa_plain = Vec::with_capacity(272);
    // Block 0-1: URL hash repeated
    medusa_plain.extend_from_slice(&h0);
    medusa_plain.extend_from_slice(&h0);
    // Block 2-3: H2 + H4
    medusa_plain.extend_from_slice(&h2);
    medusa_plain.extend_from_slice(&h4);
    // Block 4-5: H5 + timestamp
    medusa_plain.extend_from_slice(&h5);
    medusa_plain.extend_from_slice(&ts.to_le_bytes());
    medusa_plain.extend_from_slice(&[0u8; 8]); // padding
                                               // Remaining blocks: zeros/device info
    while medusa_plain.len() < 272 {
        medusa_plain.push(0);
    }

    // AES-128-ECB encrypt in-place
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes128::new(aes::cipher::generic_array::GenericArray::from_slice(
        &aes_key,
    ));
    let mut medusa_enc = medusa_plain.clone();
    for chunk in medusa_enc.chunks_exact_mut(16) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }

    // Medusa header (24 bytes)
    let ts_bytes = (ts as u32).to_le_bytes();
    let mut medusa_header = Vec::with_capacity(24);
    medusa_header.push(ts_bytes[0] ^ 0x05); // byte 0: XOR with 0x05
    medusa_header.extend_from_slice(&ts_bytes[1..4]);
    // bytes 4-19: session constant — use MD5(device_id) as guess
    let session_const = md5::compute(b"3405654380789289").0;
    medusa_header.extend_from_slice(&session_const);
    // bytes 20-21: random
    let rand_bytes: [u8; 2] = rand::thread_rng().gen();
    medusa_header.extend_from_slice(&rand_bytes);
    // bytes 22-23: 0x0001
    medusa_header.extend_from_slice(&[0x00, 0x01]);

    // SHA-1 component: SHA1(AES_output[0:4] + "1967" + [0xab,0x7c,0xfe,0x85])
    let mut sha1_input = Vec::with_capacity(12);
    sha1_input.extend_from_slice(&medusa_enc[0..4]);
    sha1_input.extend_from_slice(b"1967");
    sha1_input.extend_from_slice(&[0xab, 0x7c, 0xfe, 0x85]);
    let sha1_hash = {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(&sha1_input);
        hasher.finalize()
    };

    // Full Medusa body = AES encrypted (272) + SHA-1 (20) + padding to 936 bytes
    let mut medusa_body = medusa_enc;
    medusa_body.extend_from_slice(&sha1_hash);
    // Pad remaining with H4, H5, device info hashes to reach 936 bytes
    while medusa_body.len() < 936 {
        medusa_body.push(0);
    }

    // Full Medusa = header (24) + body (936) = 960 bytes
    let mut medusa_raw = medusa_header;
    medusa_raw.extend_from_slice(&medusa_body);

    let medusa_b64 = base64::engine::general_purpose::STANDARD.encode(&medusa_raw);
    headers.insert("X-Medusa".to_string(), medusa_b64);

    eprintln!(
        "[sign] X-Medusa generated ({} bytes raw, {} b64)",
        medusa_raw.len(),
        headers["X-Medusa"].len()
    );
    headers
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_signing() {
        let sigs = super::test_signing();
        for (k, v) in &sigs {
            println!("  {}: {}...", k, &v[..v.len().min(60)]);
        }
        assert!(
            sigs.iter().any(|(k, _)| k == "X-Helios"),
            "Missing X-Helios"
        );
    }

    /// Test actual download with signing
    #[test]
    fn test_download_chapter() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let client = reqwest::Client::builder()
                .user_agent("com.dragon.read/71332 (Linux; U; Android 15; zh_CN; sdk_gphone64_arm64; Build/AP3A.241105.008;tt-ok/3.12.13.20)")
                .timeout(std::time::Duration::from_secs(15))
                .build().unwrap();

            let did = "1751989655468474";
            let iid = "1751989655701946";
            let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();

            let qs = format!("ac=wifi&aid=1967&app_name=novelapp&version_code=71332&version_name=7.1.3.32&device_platform=android&os=android&ssmix=a&device_type=sdk_gphone64_arm64&device_brand=google&os_api=35&os_version=15&device_id={}&iid={}&_rticket={}", did, iid, ts);

            let sigs = super::sign(&qs);
            eprintln!("[test] Helios: {} chars", sigs.get("X-Helios").map(|s| s.len()).unwrap_or(0));
            eprintln!("[test] Medusa: {} chars", sigs.get("X-Medusa").map(|s| s.len()).unwrap_or(0));

            // Test 1: book detail (simpler endpoint)
            let url = format!("https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?{}&book_id=7143038691944959011", qs);
            let mut req = client.get(&url)
                .header("Accept", "application/json")
                .header("sdk-version", "2");
            for (k, v) in &sigs { req = req.header(k.as_str(), v.as_str()); }

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let hdrs: Vec<_> = resp.headers().iter()
                        .filter(|(k,_)| k.as_str().starts_with("x-"))
                        .map(|(k,v)| format!("{}={}", k, v.to_str().unwrap_or("?")))
                        .collect();
                    let body = resp.text().await.unwrap_or_default();
                    eprintln!("[test] detail: status={}, body_len={}, x-headers={:?}",
                        status, body.len(), hdrs);
                    if !body.is_empty() {
                        eprintln!("[test] body: {}...", &body[..body.len().min(300)]);
                    }
                }
                Err(e) => eprintln!("[test] request error: {}", e),
            }

            // Test 2: chapter content
            let qs2 = format!("{}&book_id=7143038691944959011&item_id=7143039479064498176", qs);
            let sigs2 = super::sign(&qs2);
            let url2 = format!("https://api5-normal-sinfonlinec.fqnovel.com/reading/reader/full/v1/?{}", qs2);
            let mut req2 = client.get(&url2)
                .header("Accept", "application/json")
                .header("sdk-version", "2");
            for (k, v) in &sigs2 { req2 = req2.header(k.as_str(), v.as_str()); }

            match req2.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    eprintln!("[test] chapter: status={}, body_len={}", status, body.len());
                    if !body.is_empty() {
                        eprintln!("[test] body: {}...", &body[..body.len().min(300)]);
                    }
                }
                Err(e) => eprintln!("[test] chapter error: {}", e),
            }
        });
    }

    /// Mini-emulator: runs the custom VM that computes Helios part1/part2.
    ///
    /// The VM is a register-based bytecode interpreter embedded in libmetasec_ml.so.
    /// Bytecode at SO+0x118F50, dispatch table in data section, 48 unique handlers.
    /// Handlers are pure computation (0 external BL calls), so no libc/JNI/handle needed.
    #[test]
    fn test_vm_helios() {
        use dynarmic_sys::Dynarmic;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        };

        let dir = env!("CARGO_MANIFEST_DIR");

        // --- Load SO sections from IDA-dumped files ---
        let so_code = std::fs::read(format!("{}/lib/so_code.bin", dir))
            .expect("Missing lib/so_code.bin — dump from IDA");
        let so_data1 =
            std::fs::read(format!("{}/lib/so_data1.bin", dir)).expect("Missing lib/so_data1.bin");
        let so_data2 =
            std::fs::read(format!("{}/lib/so_data2.bin", dir)).expect("Missing lib/so_data2.bin");

        // Runtime base address (from IDA)
        let so_base: u64 = 0x6d88_01b0_00;
        let code_size = 0x348700usize;
        let data1_off: u64 = 0x34C700;
        let data1_size = 0x28F10usize;
        let data2_off: u64 = 0x379610;
        let data2_size = 0x6A460usize;

        eprintln!(
            "[vm] SO base=0x{:x}, code={}KB, data={}KB",
            so_base,
            code_size / 1024,
            (data1_size + data2_size) / 1024
        );

        // --- Create dynarmic instance ---
        let dy = Arc::new(Dynarmic::<()>::new());

        // Map SO code section (R-X) — contains handler code + bytecode
        let code_page = so_base & !0xFFF;
        let code_map_size = ((code_size + 0xFFF) & !0xFFF) + 0x1000;
        dy.mem_map(code_page, code_map_size, 3).expect("map code");
        dy.mem_write(so_base, &so_code[..code_size])
            .expect("write code");
        eprintln!("[vm] Mapped code: 0x{:x} +0x{:x}", code_page, code_map_size);

        // Map data sections (RW-) — contains dispatch table ptr + runtime data
        let d1_addr = so_base + data1_off;
        let d1_page = d1_addr & !0xFFF;
        let d1_map = ((d1_addr + data1_size as u64 + 0xFFF) & !0xFFF) - d1_page;
        dy.mem_map(d1_page as u64, d1_map as usize, 3)
            .expect("map data1");
        dy.mem_write(d1_addr, &so_data1[..data1_size])
            .expect("write data1");

        let d2_addr = so_base + data2_off;
        let d2_page = d2_addr & !0xFFF;
        let d2_map = ((d2_addr + data2_size as u64 + 0xFFF) & !0xFFF) - d2_page;
        dy.mem_map(d2_page as u64, d2_map as usize, 3)
            .expect("map data2");
        dy.mem_write(d2_addr, &so_data2[..data2_size])
            .expect("write data2");
        eprintln!("[vm] Mapped data sections");

        // --- Map the external dispatch table ---
        // off_3948D8 (at so_base + 0x3798D8) contains pointer 0x6d893d68f0
        // The dispatch table is at 0x6d88367f68 (= off_val + cff_offset)
        // which is INSIDE data1 — already mapped! ✓
        // But the raw entries in the table contain absolute addresses that resolve
        // to handler addresses via: handler = table[opcode] - 0x33DC5
        // These addresses are already correct since we mapped code at the runtime base.

        // --- Set up stack and VM state ---
        let stack_base: u64 = 0x7000_0000;
        let stack_size: usize = 0x10_0000; // 1MB
        dy.mem_map(stack_base, stack_size, 3).expect("map stack");

        let sp = stack_base + stack_size as u64 - 0x1000; // leave some room at top

        // --- Prepare Helios input data ---
        // H1_hex(32 bytes ASCII) + ts_str(26 bytes) = 58, PKCS#7 padded to 64
        // Test data: use known patterns
        let h1_hex = b"bb7a9a17c05b0a773849723adc3bc5af"; // sample H1 hex string (32 bytes)
        let ts_str = b"1774952267-1394812046-1967"; // sample ts string (26 bytes)
        let mut padded_input = Vec::with_capacity(64);
        padded_input.extend_from_slice(h1_hex);
        padded_input.extend_from_slice(ts_str);
        // PKCS#7 pad to 64 bytes: 64 - 58 = 6 bytes of 0x06
        let pad_len = 64 - padded_input.len();
        padded_input.extend(std::iter::repeat(pad_len as u8).take(pad_len));
        assert_eq!(padded_input.len(), 64);
        eprintln!(
            "[vm] Padded input ({} bytes): {}",
            padded_input.len(),
            hex::encode(&padded_input)
        );

        let input_addr: u64 = stack_base + 0x200;
        dy.mem_write(input_addr, &padded_input)
            .expect("write input");

        // Output accumulator: 64 bytes, initially zero (same size as padded input)
        let output_accum_addr: u64 = stack_base + 0x400;
        dy.mem_write(output_accum_addr, &[0u8; 64])
            .expect("write output accum");

        // Workspace buffer for VM
        let workspace_addr: u64 = stack_base + 0x600;
        dy.mem_write(workspace_addr, &[0u8; 256])
            .expect("write workspace");

        // --- HALT page ---
        let halt_addr: u64 = 0xDEAD_0000;
        dy.mem_map(halt_addr, 0x1000, 3).expect("map halt");
        let ret_insn = 0xD65F03C0u32.to_le_bytes();
        for off in (0..0x1000).step_by(4) {
            dy.mem_write(halt_addr + off, &ret_insn).unwrap();
        }

        // TPIDR_EL0 setup
        let tpidr_area: u64 = 0x8000_0000;
        dy.mem_map(tpidr_area, 0x1000, 3).expect("map tpidr");
        dy.mem_write(tpidr_area + 0x28, &0xCAFE_BABE_DEAD_BEEFu64.to_le_bytes())
            .unwrap();
        dy.reg_write_tpidr_el0(tpidr_area).unwrap();

        // --- Set up SVC + unmapped memory callbacks ---
        let miss_flag = Arc::new(AtomicBool::new(false));
        let miss_addr = Arc::new(Mutex::new(0u64));
        {
            let miss_flag2 = miss_flag.clone();
            let miss_addr2 = miss_addr.clone();
            dy.set_unmapped_mem_callback(
                move |dy_ref: &Dynarmic<()>, addr: u64, _size: usize, _pc: u64| -> bool {
                    let clean = addr & 0x00FF_FFFF_FFFF_FFFF;
                    eprintln!("[vm] UNMAPPED: 0x{:x} (clean=0x{:x})", addr, clean);
                    miss_flag2.store(true, Ordering::SeqCst);
                    *miss_addr2.lock().unwrap() = clean;
                    dy_ref.emu_stop().ok();
                    false
                },
            );
        }
        dy.set_svc_callback(|_dy_ref: &Dynarmic<()>, svc_num: u32, _pc: u64, _lr: u64| {
            eprintln!("[vm] SVC #{:#x} — unexpected!", svc_num);
        });

        // --- Run VM for each 16-byte block (4 iterations for 64-byte padded input) ---
        let bytecode_addr = so_base + 0x118F50;
        let callback_func_addr = so_base + 0x2884AC;
        let entry_pc = so_base + 0x168324;
        let num_blocks = padded_input.len() / 16;

        eprintln!("[vm] Running {} VM iterations...", num_blocks);
        let start = std::time::Instant::now();

        for block_idx in 0..num_blocks {
            let offset = (block_idx * 16) as u64;

            // packed_args = [workspace, input_block_ptr, output_block_ptr]
            let packed_args_addr = sp - 0x100;
            dy.mem_write(packed_args_addr, &workspace_addr.to_le_bytes())
                .unwrap();
            dy.mem_write(packed_args_addr + 8, &(input_addr + offset).to_le_bytes())
                .unwrap();
            dy.mem_write(
                packed_args_addr + 16,
                &(output_accum_addr + offset).to_le_bytes(),
            )
            .unwrap();

            // callback context: [callback_func, stack_area_ptr, 0]
            let vm_stack_area = sp - 0x300 - (block_idx as u64) * 0x200;
            let callback_ctx_addr = sp - 0x200;
            dy.mem_write(callback_ctx_addr, &callback_func_addr.to_le_bytes())
                .unwrap();
            dy.mem_write(callback_ctx_addr + 8, &vm_stack_area.to_le_bytes())
                .unwrap();
            dy.mem_write(callback_ctx_addr + 16, &0u64.to_le_bytes())
                .unwrap();

            // Set registers for sub_168324 call
            dy.reg_write_raw(0, bytecode_addr).unwrap();
            dy.reg_write_raw(1, packed_args_addr).unwrap();
            dy.reg_write_raw(2, 0).unwrap();
            dy.reg_write_raw(3, 0).unwrap();
            dy.reg_write_raw(4, callback_ctx_addr).unwrap();
            dy.reg_write_sp(sp).unwrap();
            dy.reg_write_lr(halt_addr).unwrap();

            // Run with emu_step loop (emu_start + timeout threads unreliable on Windows)
            dy.reg_write_pc(entry_pc).unwrap();
            let max_steps = 100_000u64;
            let mut steps = 0u64;
            let mut halted = false;
            loop {
                let pc = dy.reg_read_pc().unwrap_or(0);
                if pc == halt_addr || pc == halt_addr + 4 {
                    halted = true;
                    break;
                }
                if miss_flag.load(Ordering::SeqCst) {
                    let addr = *miss_addr.lock().unwrap();
                    eprintln!("[vm] Block {}: UNMAPPED at 0x{:x}", block_idx, addr);
                    break;
                }
                if steps >= max_steps {
                    eprintln!(
                        "[vm] Block {}: max steps ({}) at PC=SO+0x{:x}",
                        block_idx,
                        max_steps,
                        pc.wrapping_sub(so_base)
                    );
                    break;
                }
                if let Err(e) = dy.emu_step(pc) {
                    eprintln!(
                        "[vm] Block {}: step error at SO+0x{:x}: {}",
                        block_idx,
                        pc.wrapping_sub(so_base),
                        e
                    );
                    break;
                }
                steps += 1;
            }
            if !halted {
                eprintln!("[vm] Block {} failed after {} steps", block_idx, steps);
                break;
            }

            // Read output block
            let mut out_block = [0u8; 16];
            dy.mem_read(output_accum_addr + offset, &mut out_block)
                .unwrap();
            eprintln!(
                "[vm] Block {}: output={}",
                block_idx,
                hex::encode(&out_block)
            );

            miss_flag.store(false, Ordering::SeqCst);
        }

        let elapsed = start.elapsed();
        eprintln!("[vm] All blocks done in {:?}", elapsed);

        // Read full output accumulator
        let mut full_output = [0u8; 64];
        dy.mem_read(output_accum_addr, &mut full_output).unwrap();
        eprintln!("[vm] Full output: {}", hex::encode(&full_output));

        // The Helios result is the first 32 bytes (part1 + part2)
        eprintln!(
            "[vm] Helios part1+part2: {}",
            hex::encode(&full_output[..32])
        );

        let result: Result<(), anyhow::Error> = Ok(());

        eprintln!("[vm] Done in {:?}", elapsed);
    }

    /// Run Medusa VM for N instructions and dump register file state.
    /// Used to extract embedded constants (like r12 base offset).
    #[test]
    fn test_vm_medusa_regs() {
        use dynarmic_sys::Dynarmic;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        };

        let dir = env!("CARGO_MANIFEST_DIR");
        let so_code = std::fs::read(format!("{}/lib/so_code.bin", dir)).expect("so_code.bin");
        let so_data1 = std::fs::read(format!("{}/lib/so_data1.bin", dir)).expect("so_data1.bin");
        let so_data2 = std::fs::read(format!("{}/lib/so_data2.bin", dir)).expect("so_data2.bin");

        let so_base: u64 = 0x6d88_01b0_00;
        let dy = Arc::new(Dynarmic::<()>::new());

        // Map SO
        dy.mem_map(so_base & !0xFFF, ((0x348700 + 0xFFF) & !0xFFF) + 0x1000, 3)
            .unwrap();
        dy.mem_write(so_base, &so_code[..0x348700]).unwrap();
        let d1 = so_base + 0x34C700;
        dy.mem_map(
            d1 & !0xFFF,
            ((0x28F10 + 0xFFF + (d1 & 0xFFF) as usize) & !0xFFF),
            3,
        )
        .unwrap();
        dy.mem_write(d1, &so_data1[..0x28F10]).unwrap();
        let d2 = so_base + 0x379610;
        dy.mem_map(
            d2 & !0xFFF,
            ((0x6A460 + 0xFFF + (d2 & 0xFFF) as usize) & !0xFFF),
            3,
        )
        .unwrap();
        dy.mem_write(d2, &so_data2[..0x6A460]).unwrap();

        let stack_base: u64 = 0x7000_0000;
        dy.mem_map(stack_base, 0x10_0000, 3).unwrap();
        let sp = stack_base + 0x10_0000 - 0x1000;

        let halt: u64 = 0xDEAD_0000;
        dy.mem_map(halt, 0x1000, 3).unwrap();
        for off in (0..0x1000).step_by(4) {
            dy.mem_write(halt + off, &0xD65F03C0u32.to_le_bytes())
                .unwrap();
        }
        let tpidr: u64 = 0x8000_0000;
        dy.mem_map(tpidr, 0x1000, 3).unwrap();
        dy.mem_write(tpidr + 0x28, &0xCAFE_BABE_DEAD_BEEFu64.to_le_bytes())
            .unwrap();
        dy.reg_write_tpidr_el0(tpidr).unwrap();

        // Medusa args
        let bytecode = so_base + 0x119050;
        let callback = so_base + 0x2884AC;
        let output: u64 = stack_base + 0x400;
        dy.mem_write(output, &[0u8; 1024]).unwrap();
        let pa = sp - 0x100;
        dy.mem_write(pa, &output.to_le_bytes()).unwrap();
        dy.mem_write(pa + 8, &output.to_le_bytes()).unwrap();
        dy.mem_write(pa + 16, &0u64.to_le_bytes()).unwrap();
        let ctx = sp - 0x200;
        dy.mem_write(ctx, &callback.to_le_bytes()).unwrap();
        dy.mem_write(ctx + 8, &(sp - 0x400).to_le_bytes()).unwrap();
        dy.mem_write(ctx + 16, &0u64.to_le_bytes()).unwrap();

        // Stop on unmapped
        let miss = Arc::new(AtomicBool::new(false));
        let miss_a = Arc::new(Mutex::new(0u64));
        {
            let m = miss.clone();
            let ma = miss_a.clone();
            dy.set_unmapped_mem_callback(move |d: &Dynarmic<()>, addr: u64, _, _| -> bool {
                let c = addr & 0x00FF_FFFF_FFFF_FFFF;
                eprintln!("[medusa] UNMAPPED 0x{:x}", c);
                m.store(true, Ordering::SeqCst);
                *ma.lock().unwrap() = c;
                d.emu_stop().ok();
                false
            });
        }
        dy.set_svc_callback(|_: &Dynarmic<()>, n: u32, _, _| {
            eprintln!("[medusa] SVC {:#x}", n);
        });

        dy.reg_write_raw(0, bytecode).unwrap();
        dy.reg_write_raw(1, pa).unwrap();
        dy.reg_write_raw(2, so_base + 0x37A6D0).unwrap();
        dy.reg_write_raw(3, so_base + 0x37A730).unwrap();
        dy.reg_write_raw(4, ctx).unwrap();
        dy.reg_write_sp(sp).unwrap();
        dy.reg_write_lr(halt).unwrap();

        let entry = so_base + 0x168324;
        dy.reg_write_pc(entry).unwrap();

        // Step until we hit unmapped memory (table pointer dereference)
        let mut steps = 0u64;
        loop {
            let pc = dy.reg_read_pc().unwrap_or(0);
            if pc == halt || pc == halt + 4 {
                eprintln!("[medusa] HALT at {}", steps);
                break;
            }
            if miss.load(Ordering::SeqCst) {
                let a = *miss_a.lock().unwrap();
                eprintln!("[medusa] Hit unmapped at step {}, addr=0x{:x}", steps, a);
                break;
            }
            if steps > 100_000 {
                eprintln!("[medusa] max steps");
                break;
            }
            dy.emu_step(pc).ok();
            steps += 1;
        }

        // Dump VM register file
        let x28 = dy.reg_read(28).unwrap_or(0);
        eprintln!("[medusa] X28 (reg file base) = 0x{:x}", x28);
        if x28 > 0 {
            for i in 0..32 {
                let mut buf = [0u8; 8];
                if dy.mem_read(x28 + i * 8, &mut buf).is_ok() {
                    let val = u64::from_le_bytes(buf);
                    if val != 0 {
                        eprintln!("[medusa] r{} = 0x{:016x}", i, val);
                    }
                }
            }
        }
    }

    /// Probe Medusa VM: run with unmapped handle data to discover all external reads.
    /// Maps a page on-demand at each unmapped access (filled with zeros), logs the address.
    /// This reveals exactly which data entries the Medusa VM reads.
    #[test]
    fn test_vm_medusa_probe() {
        use dynarmic_sys::Dynarmic;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        };

        let dir = env!("CARGO_MANIFEST_DIR");
        let so_code = std::fs::read(format!("{}/lib/so_code.bin", dir)).expect("so_code.bin");
        let so_data1 = std::fs::read(format!("{}/lib/so_data1.bin", dir)).expect("so_data1.bin");
        let so_data2 = std::fs::read(format!("{}/lib/so_data2.bin", dir)).expect("so_data2.bin");

        let so_base: u64 = 0x6d88_01b0_00;
        let dy = Arc::new(Dynarmic::<()>::new());

        // Map SO code + data (same as Helios test)
        dy.mem_map(so_base & !0xFFF, ((0x348700 + 0xFFF) & !0xFFF) + 0x1000, 3)
            .unwrap();
        dy.mem_write(so_base, &so_code[..0x348700]).unwrap();
        let d1 = so_base + 0x34C700;
        dy.mem_map(
            d1 & !0xFFF,
            ((0x28F10 + 0xFFF + (d1 & 0xFFF) as usize) & !0xFFF),
            3,
        )
        .unwrap();
        dy.mem_write(d1, &so_data1[..0x28F10]).unwrap();
        let d2 = so_base + 0x379610;
        dy.mem_map(
            d2 & !0xFFF,
            ((0x6A460 + 0xFFF + (d2 & 0xFFF) as usize) & !0xFFF),
            3,
        )
        .unwrap();
        dy.mem_write(d2, &so_data2[..0x6A460]).unwrap();

        let stack_base: u64 = 0x7000_0000;
        dy.mem_map(stack_base, 0x10_0000, 3).unwrap();
        let sp = stack_base + 0x10_0000 - 0x1000;

        let halt_addr: u64 = 0xDEAD_0000;
        dy.mem_map(halt_addr, 0x1000, 3).unwrap();
        for off in (0..0x1000).step_by(4) {
            dy.mem_write(halt_addr + off, &0xD65F03C0u32.to_le_bytes())
                .unwrap();
        }
        let tpidr: u64 = 0x8000_0000;
        dy.mem_map(tpidr, 0x1000, 3).unwrap();
        dy.mem_write(tpidr + 0x28, &0xCAFE_BABE_DEAD_BEEFu64.to_le_bytes())
            .unwrap();
        dy.reg_write_tpidr_el0(tpidr).unwrap();

        // Medusa VM args: sub_2A3C5C(a1=output_struct, a2=flags_byte, a3=??)
        // Inside: sub_168324(bytecode_0x119050, packed=[a3, a1, a2_byte], off_37A6D0, off_37A730, cb)
        // So:
        //   X0 = bytecode (SO+0x119050)
        //   X1 = packed_args
        //   X2 = off_37A6D0 address (SO+0x37A6D0)
        //   X3 = off_37A730 address (SO+0x37A730)
        //   X4 = callback context

        let bytecode = so_base + 0x119050;
        let callback = so_base + 0x2884AC; // dummy callback, same as Helios

        // Packed args: [some_struct, output_ptr, flags]
        let output_buf: u64 = stack_base + 0x400;
        dy.mem_write(output_buf, &[0u8; 1024]).unwrap();
        let packed_args = sp - 0x100;
        dy.mem_write(packed_args, &output_buf.to_le_bytes())
            .unwrap(); // a3 (struct?)
        dy.mem_write(packed_args + 8, &output_buf.to_le_bytes())
            .unwrap(); // a1 (output)
        dy.mem_write(packed_args + 16, &0u64.to_le_bytes()).unwrap(); // a2 (flags=0)

        let ctx = sp - 0x200;
        let vm_stk = sp - 0x400;
        dy.mem_write(ctx, &callback.to_le_bytes()).unwrap();
        dy.mem_write(ctx + 8, &vm_stk.to_le_bytes()).unwrap();
        dy.mem_write(ctx + 16, &0u64.to_le_bytes()).unwrap();

        // Track unmapped accesses — stop immediately on first external access
        let miss_flag = Arc::new(AtomicBool::new(false));
        let miss_info = Arc::new(Mutex::new((0u64, 0u64))); // (addr, pc)
        {
            let mf = miss_flag.clone();
            let mi = miss_info.clone();
            dy.set_unmapped_mem_callback(
                move |d: &Dynarmic<()>, addr: u64, _: usize, pc: u64| -> bool {
                    let clean = addr & 0x00FF_FFFF_FFFF_FFFF;
                    mf.store(true, Ordering::SeqCst);
                    *mi.lock().unwrap() = (clean, pc);
                    d.emu_stop().ok();
                    false
                },
            );
        }
        dy.set_svc_callback(|_: &Dynarmic<()>, n: u32, _: u64, _: u64| {
            eprintln!("[probe] SVC #{:#x}", n);
        });

        // Set registers
        dy.reg_write_raw(0, bytecode).unwrap();
        dy.reg_write_raw(1, packed_args).unwrap();
        dy.reg_write_raw(2, so_base + 0x37A6D0).unwrap(); // off_37A6D0
        dy.reg_write_raw(3, so_base + 0x37A730).unwrap(); // off_37A730
        dy.reg_write_raw(4, ctx).unwrap();
        dy.reg_write_sp(sp).unwrap();
        dy.reg_write_lr(halt_addr).unwrap();

        let entry = so_base + 0x168324;
        eprintln!("[probe] Running Medusa VM probe (stop on first unmapped)...");

        // Iteratively run: on each unmapped access, log it, provide zero page, retry
        let mut external_reads: Vec<(u64, u64)> = Vec::new(); // (addr, pc)
        let mut total_steps = 0u64;

        for round in 0..50 {
            // Reset state for first round only
            if round == 0 {
                dy.reg_write_raw(0, bytecode).unwrap();
                dy.reg_write_raw(1, packed_args).unwrap();
                dy.reg_write_raw(2, so_base + 0x37A6D0).unwrap();
                dy.reg_write_raw(3, so_base + 0x37A730).unwrap();
                dy.reg_write_raw(4, ctx).unwrap();
                dy.reg_write_sp(sp).unwrap();
                dy.reg_write_lr(halt_addr).unwrap();
                dy.reg_write_pc(entry).unwrap();
            }

            miss_flag.store(false, Ordering::SeqCst);
            let max_steps = 200_000u64;
            let mut steps = 0u64;
            let mut halted = false;

            loop {
                let pc = dy.reg_read_pc().unwrap_or(0);
                if pc == halt_addr || pc == halt_addr + 4 {
                    halted = true;
                    break;
                }
                if miss_flag.load(Ordering::SeqCst) {
                    break;
                }
                if steps >= max_steps {
                    break;
                }
                if let Err(_) = dy.emu_step(pc) {
                    break;
                }
                steps += 1;
            }
            total_steps += steps;

            if halted {
                eprintln!(
                    "[probe] VM halted after {} total steps, {} rounds",
                    total_steps,
                    round + 1
                );
                break;
            }

            if miss_flag.load(Ordering::SeqCst) {
                let (addr, pc) = *miss_info.lock().unwrap();
                external_reads.push((addr, pc));
                eprintln!(
                    "[probe] R{}: unmapped 0x{:x} at PC=SO+0x{:x} (step {})",
                    round,
                    addr,
                    pc.wrapping_sub(so_base),
                    total_steps
                );

                // Map the page with distinguishable pattern (not zero)
                let page = addr & !0xFFF;
                dy.mem_map(page, 0x1000, 3).ok();
                // Fill with a pattern: page_idx repeated
                let marker = ((external_reads.len() & 0xFF) as u8).wrapping_add(0x10);
                dy.mem_write(page, &vec![marker; 0x1000]).ok();
                continue;
            }

            eprintln!("[probe] Max steps at round {}", round);
            break;
        }

        eprintln!(
            "\n[probe] {} external memory accesses:",
            external_reads.len()
        );
        // Classify
        let table_a: Vec<u64> = vec![
            0x6d8892e690,
            0x6d8892e6b0,
            0x6d8892e650,
            0x6d885db208,
            0x6d885db350,
            0x6d8892e658,
            0x6d885db20c,
            0x6d885db34c,
            0x6d8892e660,
            0x6d885db210,
            0x6d885db348,
            0x6d8892e688,
        ];
        let table_b: Vec<u64> = vec![
            0x6d885db220,
            0x6d885db330,
            0x6d8892e6ac,
            0x6d885db240,
            0x6d885db310,
            0x6d8892e6bc,
            0x6d885db25c,
            0x6d885db304,
            0x6d8892e5c8,
            0x6d8892e5d0,
            0x6d885db1c4,
            0x6d885db390,
        ];
        for (addr, pc) in &external_reads {
            let idx_a = table_a.iter().position(|t| *addr >= *t && *addr < *t + 64);
            let idx_b = table_b.iter().position(|t| *addr >= *t && *addr < *t + 64);
            if let Some(i) = idx_a {
                eprintln!(
                    "  0x{:x} = TABLE_A[{}]+{} (PC=SO+0x{:x})",
                    addr,
                    i,
                    addr - table_a[i],
                    pc.wrapping_sub(so_base)
                );
            } else if let Some(i) = idx_b {
                eprintln!(
                    "  0x{:x} = TABLE_B[{}]+{} (PC=SO+0x{:x})",
                    addr,
                    i,
                    addr - table_b[i],
                    pc.wrapping_sub(so_base)
                );
            } else {
                eprintln!(
                    "  0x{:x} = UNKNOWN (PC=SO+0x{:x})",
                    addr,
                    pc.wrapping_sub(so_base)
                );
            }
        }
    }

    /// Trace Medusa VM instruction-by-instruction.
    /// Monitors the bytecode pointer (*X19) to detect VM instruction boundaries.
    /// At each boundary, dumps the full VM register file diff.
    /// Uses synthetic handle data with identifiable patterns.
    #[test]
    fn test_vm_medusa_trace() {
        use dynarmic_sys::Dynarmic;
        use std::sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Mutex,
        };

        let dir = env!("CARGO_MANIFEST_DIR");
        let so_code = std::fs::read(format!("{}/lib/so_code.bin", dir)).expect("so_code.bin");
        let so_data1 = std::fs::read(format!("{}/lib/so_data1.bin", dir)).expect("so_data1.bin");
        let so_data2 = std::fs::read(format!("{}/lib/so_data2.bin", dir)).expect("so_data2.bin");

        let so_base: u64 = 0x6d88_01b0_00;
        let dy = Arc::new(Dynarmic::<()>::new());

        // Map SO code + data
        dy.mem_map(so_base & !0xFFF, ((0x348700 + 0xFFF) & !0xFFF) + 0x1000, 3)
            .unwrap();
        dy.mem_write(so_base, &so_code[..0x348700]).unwrap();
        let d1 = so_base + 0x34C700;
        dy.mem_map(
            d1 & !0xFFF,
            ((0x28F10 + 0xFFF + (d1 & 0xFFF) as usize) & !0xFFF),
            3,
        )
        .unwrap();
        dy.mem_write(d1, &so_data1[..0x28F10]).unwrap();
        let d2 = so_base + 0x379610;
        dy.mem_map(
            d2 & !0xFFF,
            ((0x6A460 + 0xFFF + (d2 & 0xFFF) as usize) & !0xFFF),
            3,
        )
        .unwrap();
        dy.mem_write(d2, &so_data2[..0x6A460]).unwrap();

        // Stack
        let stack_base: u64 = 0x7000_0000;
        dy.mem_map(stack_base, 0x10_0000, 3).unwrap();
        let sp = stack_base + 0x10_0000 - 0x1000;

        // Halt
        let halt: u64 = 0xDEAD_0000;
        dy.mem_map(halt, 0x1000, 3).unwrap();
        for off in (0..0x1000).step_by(4) {
            dy.mem_write(halt + off, &0xD65F03C0u32.to_le_bytes())
                .unwrap();
        }

        // TPIDR
        let tpidr: u64 = 0x8000_0000;
        dy.mem_map(tpidr, 0x1000, 3).unwrap();
        dy.mem_write(tpidr + 0x28, &0xCAFE_BABE_DEAD_BEEFu64.to_le_bytes())
            .unwrap();
        dy.reg_write_tpidr_el0(tpidr).unwrap();

        // ====== Synthetic handle data ======
        // Fill r12-adjusted regions with non-zero test data so the VM can progress.
        // Pattern: each qword at offset N = (N/8 + 1), small sequential integers.
        let ta_off_in_d2: usize = 0x37A6D0 - 0x379610;
        let tb_off_in_d2: usize = 0x37A730 - 0x379610;
        let r12: i64 = -0xAFEE18;
        let mut mapped_pages = std::collections::HashSet::<u64>::new();

        let map_page =
            |dy: &Dynarmic<()>, addr: u64, pages: &mut std::collections::HashSet<u64>| {
                let page = addr & !0xFFF;
                if pages.insert(page) {
                    dy.mem_map(page, 0x1000, 3).ok();
                }
            };

        // Collect all table pointers and their r12-adjusted versions
        let mut handle_addrs: Vec<u64> = Vec::new();
        for tbl in 0..2u8 {
            let base_off = if tbl == 0 { ta_off_in_d2 } else { tb_off_in_d2 };
            for i in 0..24usize {
                let off = base_off + i * 8;
                if off + 8 > so_data2.len() {
                    break;
                }
                let ptr = u64::from_le_bytes(so_data2[off..off + 8].try_into().unwrap());
                if ptr > 0x1000 && ptr < 0x800000000000 {
                    map_page(&dy, ptr, &mut mapped_pages);
                    map_page(&dy, ptr + 0x1000, &mut mapped_pages);
                    let adj = (ptr as i64 + r12) as u64;
                    map_page(&dy, adj, &mut mapped_pages);
                    map_page(&dy, adj + 0x1000, &mut mapped_pages);
                    handle_addrs.push(adj);
                }
            }
        }

        // Fill r12-adjusted addresses: write the ADDRESS itself as value.
        // When VM reads from addr+offset, register = addr+offset → directly reveals offset.
        for &addr in &handle_addrs {
            for slot in 0..32u64 {
                let a = addr + slot * 8;
                dy.mem_write(a, &a.to_le_bytes()).ok();
            }
        }
        // Also fill the original (non-adjusted) TABLE entry targets the same way
        for tbl in 0..2u8 {
            let base_off = if tbl == 0 { ta_off_in_d2 } else { tb_off_in_d2 };
            for i in 0..24usize {
                let off = base_off + i * 8;
                if off + 8 > so_data2.len() {
                    break;
                }
                let ptr = u64::from_le_bytes(so_data2[off..off + 8].try_into().unwrap());
                if ptr > 0x1000 && ptr < 0x800000000000 {
                    for slot in 0..32u64 {
                        let a = ptr + slot * 8;
                        dy.mem_write(a, &a.to_le_bytes()).ok();
                    }
                }
            }
        }

        // Map page 0 and wide low range
        dy.mem_map(0, 0x10000, 3).unwrap();

        // Packed args
        let output_buf: u64 = stack_base + 0x400;
        dy.mem_write(output_buf, &[0u8; 2048]).unwrap();
        let pa = sp - 0x100;
        dy.mem_write(pa, &output_buf.to_le_bytes()).unwrap();
        dy.mem_write(pa + 8, &output_buf.to_le_bytes()).unwrap();
        dy.mem_write(pa + 16, &0u64.to_le_bytes()).unwrap();

        // Callback context — use a RET stub instead of real SO callback.
        // This lets SPLIT/OR/SPLIT patterns complete without needing real handle context.
        let cb_stub: u64 = 0x9000_0000;
        dy.mem_map(cb_stub, 0x1000, 3).unwrap();
        // Write: MOV X0, #0; RET (return 0)
        dy.mem_write(cb_stub, &0xD2800000u32.to_le_bytes()).unwrap(); // MOV X0, #0
        dy.mem_write(cb_stub + 4, &0xD65F03C0u32.to_le_bytes())
            .unwrap(); // RET
                       // Also fill a few more RET instructions for safety
        for off in (8..0x100).step_by(4) {
            dy.mem_write(cb_stub + off, &0xD65F03C0u32.to_le_bytes())
                .unwrap();
        }

        let ctx = sp - 0x200;
        dy.mem_write(ctx, &cb_stub.to_le_bytes()).unwrap();
        dy.mem_write(ctx + 8, &(sp - 0x400).to_le_bytes()).unwrap();
        dy.mem_write(ctx + 16, &0u64.to_le_bytes()).unwrap();

        // Also patch r22/r25 source: instruction 11 does r22 = r7 | something.
        // r7 initially = 0, but after TABLE load r7 = TA[0]. Before TABLE load,
        // the OR at [11] picks up whatever r7 had. The callback addr ends up in r22.
        // We need r22 to point to our stub instead of SO+0x2884AC.
        // The simplest fix: write cb_stub address into the ctx callback slot (already done)
        // and also into the VM's initial "callback context" at ctx[0].

        // Unmapped callback: map on demand, continue
        let miss_flag = Arc::new(AtomicBool::new(false));
        let miss_addr = Arc::new(AtomicU64::new(0));
        {
            let mf = miss_flag.clone();
            let ma = miss_addr.clone();
            dy.set_unmapped_mem_callback(
                move |d: &Dynarmic<()>, addr: u64, _sz: usize, _pc: u64| -> bool {
                    let clean = addr & 0x00FF_FFFF_FFFF_FFFF;
                    let page = clean & !0xFFF;
                    // Map with zeros and retry
                    if d.mem_map(page, 0x1000, 3).is_ok() {
                        d.mem_write(page, &vec![0u8; 0x1000]).ok();
                        return true; // retry
                    }
                    mf.store(true, Ordering::SeqCst);
                    ma.store(clean, Ordering::SeqCst);
                    d.emu_stop().ok();
                    false
                },
            );
        }
        dy.set_svc_callback(|_: &Dynarmic<()>, _: u32, _: u64, _: u64| {});

        // Set initial registers
        let bytecode_base = so_base + 0x119050;
        dy.reg_write_raw(0, bytecode_base).unwrap();
        dy.reg_write_raw(1, pa).unwrap();
        dy.reg_write_raw(2, so_base + 0x37A6D0).unwrap(); // TABLE_A
        dy.reg_write_raw(3, so_base + 0x37A730).unwrap(); // TABLE_B
        dy.reg_write_raw(4, ctx).unwrap();
        dy.reg_write_sp(sp).unwrap();
        dy.reg_write_lr(halt).unwrap();
        dy.reg_write_pc(so_base + 0x168324).unwrap();

        eprintln!("[trace] Starting Medusa VM trace...");
        eprintln!("[trace] bytecode_base = 0x{:x}", bytecode_base);

        // Read bytecodes for opcode display
        let mut bytecodes = [0u32; 256];
        for i in 0..256 {
            let off = 0x119050 + i * 4;
            bytecodes[i] = u32::from_le_bytes(so_code[off..off + 4].try_into().unwrap());
        }

        // Run with instruction-level tracing
        // Strategy: after each ARM64 step, read X19 → bytecode_ptr.
        // When bytecode_ptr advances by 4, a VM instruction completed.
        let mut prev_regs = [0u64; 32];
        let mut prev_bc_ptr: u64 = 0;
        let mut vm_insn_count = 0u32;
        let mut arm_steps = 0u64;
        let mut steps_since_advance = 0u64; // stuck detection
        let max_vm_insns = 260u32;
        let max_arm_steps = 5_000_000u64;
        let stuck_threshold = 100_000u64; // if no bc_ptr advance in 100K steps → stuck

        loop {
            let pc = dy.reg_read_pc().unwrap_or(0);
            if pc == halt || pc == halt + 4 {
                eprintln!("[trace] VM halted at arm_step={}", arm_steps);
                break;
            }
            if miss_flag.load(Ordering::SeqCst) {
                eprintln!(
                    "[trace] Stuck unmapped at 0x{:x}",
                    miss_addr.load(Ordering::SeqCst)
                );
                break;
            }
            if arm_steps >= max_arm_steps || vm_insn_count >= max_vm_insns {
                eprintln!(
                    "[trace] Limit reached: {} arm steps, {} vm insns",
                    arm_steps, vm_insn_count
                );
                break;
            }

            dy.emu_step(pc).ok();
            arm_steps += 1;

            // Check bytecode pointer: read X19, then read [X19] to get current bc_ptr
            let x19 = dy.reg_read(19).unwrap_or(0);
            if x19 == 0 {
                continue;
            }
            let mut bc_buf = [0u8; 8];
            if dy.mem_read(x19, &mut bc_buf).is_err() {
                continue;
            }
            let bc_ptr = u64::from_le_bytes(bc_buf);

            steps_since_advance += 1;
            if steps_since_advance > stuck_threshold {
                let insn_idx = if prev_bc_ptr >= bytecode_base {
                    ((prev_bc_ptr - bytecode_base) / 4) as usize
                } else {
                    999
                };
                let stuck_pc = dy.reg_read_pc().unwrap_or(0);
                let stuck_lr = dy.reg_read(30).unwrap_or(0);
                eprintln!(
                    "[trace] STUCK at vm_insn {} after {}K arm steps, PC=SO+0x{:x} LR=SO+0x{:x}",
                    insn_idx,
                    stuck_threshold / 1000,
                    stuck_pc.wrapping_sub(so_base),
                    stuck_lr.wrapping_sub(so_base)
                );
                // Dump ARM64 X0-X5 to help diagnose
                for i in 0..6usize {
                    let v = dy.reg_read(i).unwrap_or(0);
                    eprint!(" X{}=0x{:x}", i, v);
                }
                eprintln!();
                break;
            }

            if bc_ptr != prev_bc_ptr && bc_ptr >= bytecode_base && bc_ptr < bytecode_base + 1024 {
                steps_since_advance = 0;
                // VM instruction boundary!
                let insn_idx = ((bc_ptr - bytecode_base) / 4) as usize;

                // Read current register file
                let x28 = dy.reg_read(28).unwrap_or(0);
                let mut cur_regs = [0u64; 32];
                if x28 > 0 {
                    for i in 0..32 {
                        let mut buf = [0u8; 8];
                        if dy.mem_read(x28 + (i as u64) * 8, &mut buf).is_ok() {
                            cur_regs[i] = u64::from_le_bytes(buf);
                        }
                    }
                }

                if vm_insn_count > 0 {
                    // Print the PREVIOUS instruction's effect (register changes)
                    let prev_idx = if insn_idx > 0 { insn_idx - 1 } else { 0 };
                    let prev_raw = if prev_idx < 256 {
                        bytecodes[prev_idx]
                    } else {
                        0
                    };
                    let opc = prev_raw & 0x3F;
                    let opc_name = match opc {
                        24 => "LOAD64",
                        26 => "STORE64",
                        22 => "STORE32",
                        59 => "LOAD32S",
                        15 => "ADDPTR",
                        52 => "MOVI_HI",
                        48 => "ORI_LO",
                        1 => "SEXT",
                        45 => "BEQ",
                        17 => {
                            let sub = (prev_raw >> 6) & 0x3F;
                            match sub {
                                14 => "ADD",
                                16 => "SUB",
                                44 => "OR",
                                54 => "AND",
                                29 => "XOR_M",
                                10 => "AND2",
                                51 => "ADDW",
                                46 => "SUBW",
                                23 => "SHL",
                                3 => "SHLW",
                                7 => "SHRW",
                                50 => "SPLIT",
                                13 => "NOP",
                                _ => "ALU?",
                            }
                        }
                        4 => "OP4",
                        20 => "OP20",
                        40 => "OP40",
                        16 => "OP16",
                        53 => "OP53",
                        _ => "???",
                    };

                    // Collect changes
                    let mut changes = Vec::new();
                    for i in 0..32 {
                        if cur_regs[i] != prev_regs[i] {
                            changes
                                .push(format!("r{}:0x{:x}→0x{:x}", i, prev_regs[i], cur_regs[i]));
                        }
                    }

                    if !changes.is_empty() || opc == 26 || opc == 22 {
                        // always show stores
                        eprintln!(
                            "[{:3}] {:7} 0x{:08x} | {}",
                            prev_idx,
                            opc_name,
                            prev_raw,
                            if changes.is_empty() {
                                "(no reg change)".to_string()
                            } else {
                                changes.join(", ")
                            }
                        );
                    }
                }

                prev_regs = cur_regs;
                prev_bc_ptr = bc_ptr;
                vm_insn_count += 1;
            }
        }

        eprintln!(
            "\n[trace] Total: {} VM instructions, {} ARM64 steps",
            vm_insn_count, arm_steps
        );

        // Final register dump
        let x28 = dy.reg_read(28).unwrap_or(0);
        eprintln!("\n[trace] Final register file:");
        if x28 > 0 {
            for i in 0..32 {
                let mut buf = [0u8; 8];
                if dy.mem_read(x28 + (i as u64) * 8, &mut buf).is_ok() {
                    let val = u64::from_le_bytes(buf);
                    if val != 0 {
                        // Decode tagged values
                        let tag = (val >> 60) & 0xF;
                        let desc = match tag {
                            0xA => format!("TA[{}] slot{}", (val >> 48) & 0xFF, (val >> 40) & 0xFF),
                            0xB => format!("TB[{}] slot{}", (val >> 48) & 0xFF, (val >> 40) & 0xFF),
                            0xC => format!(
                                "r12adj TA/B[{}][{}]",
                                (val >> 48) & 0xFF,
                                (val >> 40) & 0xFF
                            ),
                            _ => String::new(),
                        };
                        eprintln!("  r{:2} = 0x{:016x}  {}", i, val, desc);
                    }
                }
            }
        }
    }
}
