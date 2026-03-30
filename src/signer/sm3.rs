//! SM3 cryptographic hash function (Chinese national standard GB/T 32905-2016).

const IV: [u32; 8] = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

const TJ: [u32; 64] = [
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
];

fn rotate_left(a: u32, k: u32) -> u32 {
    let k = k % 32;
    ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k))
}

fn ff(x: u32, y: u32, z: u32, j: usize) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (x & z) | (y & z)
    }
}

fn gg(x: u32, y: u32, z: u32, j: usize) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | ((!x) & z)
    }
}

fn p0(x: u32) -> u32 {
    x ^ rotate_left(x, 9) ^ rotate_left(x, 17)
}

fn p1(x: u32) -> u32 {
    x ^ rotate_left(x, 15) ^ rotate_left(x, 23)
}

fn cf(v_i: &[u32; 8], b_i: &[u8]) -> [u32; 8] {
    let mut w = [0u32; 68];
    for i in 0..16 {
        w[i] = ((b_i[i * 4] as u32) << 24)
            | ((b_i[i * 4 + 1] as u32) << 16)
            | ((b_i[i * 4 + 2] as u32) << 8)
            | (b_i[i * 4 + 3] as u32);
    }
    for j in 16..68 {
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ rotate_left(w[j - 3], 15))
            ^ rotate_left(w[j - 13], 7)
            ^ w[j - 6];
    }

    let mut w1 = [0u32; 64];
    for j in 0..64 {
        w1[j] = w[j] ^ w[j + 4];
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *v_i;

    for j in 0..64 {
        let ss1 = rotate_left(
            rotate_left(a, 12)
                .wrapping_add(e)
                .wrapping_add(rotate_left(TJ[j], j as u32))
                & 0xFFFFFFFF,
            7,
        );
        let ss2 = ss1 ^ rotate_left(a, 12);
        let tt1 = ff(a, b, c, j)
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(w1[j])
            & 0xFFFFFFFF;
        let tt2 = gg(e, f, g, j)
            .wrapping_add(h)
            .wrapping_add(ss1)
            .wrapping_add(w[j])
            & 0xFFFFFFFF;
        d = c;
        c = rotate_left(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = rotate_left(f, 19);
        f = e;
        e = p0(tt2);
    }

    [
        a & 0xFFFFFFFF ^ v_i[0],
        b & 0xFFFFFFFF ^ v_i[1],
        c & 0xFFFFFFFF ^ v_i[2],
        d & 0xFFFFFFFF ^ v_i[3],
        e & 0xFFFFFFFF ^ v_i[4],
        f & 0xFFFFFFFF ^ v_i[5],
        g & 0xFFFFFFFF ^ v_i[6],
        h & 0xFFFFFFFF ^ v_i[7],
    ]
}

/// Compute SM3 hash, returns 32 bytes.
pub fn sm3_hash(msg: &[u8]) -> Vec<u8> {
    let mut data = msg.to_vec();
    let bit_len = (msg.len() as u64) * 8;

    // Padding
    data.push(0x80);
    let range_end = if (msg.len() % 64) + 1 > 56 {
        56 + 64
    } else {
        56
    };
    while data.len() % 64 != 56 {
        data.push(0x00);
    }
    // Append bit length as big-endian 8 bytes
    data.extend_from_slice(&bit_len.to_be_bytes());

    let _ = range_end; // suppress warning

    let group_count = data.len() / 64;
    let mut v = IV;

    for i in 0..group_count {
        let block = &data[i * 64..(i + 1) * 64];
        v = cf(&v, block);
    }

    let mut result = Vec::with_capacity(32);
    for val in &v {
        result.extend_from_slice(&val.to_be_bytes());
    }
    result
}
