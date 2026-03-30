//! Simon 128/256 block cipher implementation.

const Z: u64 = 0x3DC94C3A046D678B;

fn rotate_left(v: u64, n: u32) -> u64 {
    ((v << n) | (v >> (64 - n))) & 0xffffffffffffffff
}

fn rotate_right(v: u64, n: u32) -> u64 {
    ((v >> n) | (v << (64 - n))) & 0xffffffffffffffff
}

fn get_bit(val: u64, pos: u32) -> u64 {
    if val & (1u64 << pos) != 0 {
        1
    } else {
        0
    }
}

fn key_expansion(key: &mut [u64; 72]) {
    for i in 4..72 {
        let mut tmp = rotate_right(key[i - 1], 3);
        tmp ^= key[i - 3];
        tmp ^= rotate_right(tmp, 1);
        key[i] = (!key[i - 4]) ^ tmp ^ get_bit(Z, ((i - 4) % 62) as u32) ^ 3;
    }
}

/// Simon encrypt: plaintext [x_i, x_i1] with key list k[0..3].
pub fn simon_enc(pt: [u64; 2], k: &[u64; 4]) -> [u64; 2] {
    let mut key = [0u64; 72];
    key[0] = k[0];
    key[1] = k[1];
    key[2] = k[2];
    key[3] = k[3];
    key_expansion(&mut key);

    let mut x_i = pt[0];
    let mut x_i1 = pt[1];

    for i in 0..72 {
        let tmp = x_i1;
        let f = rotate_left(x_i1, 1) & rotate_left(x_i1, 8);
        x_i1 = x_i ^ f ^ rotate_left(x_i1, 2) ^ key[i];
        x_i = tmp;
    }

    [x_i, x_i1]
}
