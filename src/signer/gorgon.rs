//! X-Gorgon 0404 signature algorithm.

fn hex_string(num: u8) -> String {
    format!("{:02x}", num)
}

fn reverse(num: u8) -> u8 {
    let s = format!("{:02x}", num);
    let bytes = s.as_bytes();
    // Swap nibbles: "ab" → "ba"
    let swapped = format!("{}{}", bytes[1] as char, bytes[0] as char);
    u8::from_str_radix(&swapped, 16).unwrap_or(0)
}

fn rbit(num: u8) -> u8 {
    num.reverse_bits()
}

struct XG {
    length: usize,
    debug: Vec<u8>,
    hex_510: [u8; 8],
}

impl XG {
    fn new(debug: Vec<u8>) -> Self {
        let a1: u8 = 228;
        let a2: u8 = 208;
        Self {
            length: 0x14,
            debug,
            hex_510: [0x1E, 0x00, 0xE0, a1, 0x93, 0x45, 0x01, a2],
        }
    }

    fn addr_920(&self) -> Vec<u16> {
        let mut hex_920: Vec<u16> = (0..0x100).map(|i| i as u16).collect();
        let mut tmp: Option<u16> = None;

        for i in 0..0x100u16 {
            let a = if i == 0 {
                0u16
            } else if let Some(t) = tmp {
                t
            } else {
                hex_920[i as usize - 1]
            };

            let b = self.hex_510[(i % 8) as usize] as u16;

            let mut a_val = a;
            if a_val == 0x55 && i != 1 {
                if tmp != Some(0x55) {
                    a_val = 0;
                }
            }

            let mut c = a_val + i + b;
            while c >= 0x100 {
                c -= 0x100;
            }

            if c < i {
                tmp = Some(c);
            } else {
                tmp = None;
            }

            let d = hex_920[c as usize];
            hex_920[i as usize] = d;
        }
        hex_920
    }

    fn initial(&mut self, hex_920: &[u16]) -> Vec<u8> {
        let mut tmp_hex = hex_920.to_vec();
        let mut tmp_add: Vec<u16> = Vec::new();

        for i in 0..self.length {
            let a = self.debug[i];
            let b = if tmp_add.is_empty() {
                0u16
            } else {
                *tmp_add.last().unwrap()
            };

            let mut c = hex_920[i + 1] + b;
            while c >= 0x100 {
                c -= 0x100;
            }
            tmp_add.push(c);

            let d = tmp_hex[c as usize];
            tmp_hex[i + 1] = d;

            let mut e = d + d;
            while e >= 0x100 {
                e -= 0x100;
            }
            let f = tmp_hex[e as usize];
            self.debug[i] = a ^ (f as u8);
        }
        self.debug.clone()
    }

    fn calculate(&mut self) -> Vec<u8> {
        for i in 0..self.length {
            let a = self.debug[i];
            let b = reverse(a);
            let c = self.debug[(i + 1) % self.length];
            let d = b ^ c;
            let e = rbit(d);
            let f = e ^ (self.length as u8);
            let g = !f;
            self.debug[i] = g;
        }
        self.debug.clone()
    }

    fn main_calc(&mut self) -> String {
        let hex_920 = self.addr_920();
        self.initial(&hex_920);
        let result = self.calculate();

        let mut hex_result = String::new();
        for &item in &result {
            hex_result.push_str(&hex_string(item));
        }
        format!(
            "0404{}{}0001{}",
            hex_string(self.hex_510[7]),
            hex_string(self.hex_510[3]),
            hex_result
        )
    }
}

/// Generate X-Gorgon header value.
pub fn get_xgorgon(params: &str, data: &str, cookie: &str, timestamp: u64) -> String {
    let mut gorgon: Vec<u8> = Vec::with_capacity(20);
    let khronos = format!("{:x}", timestamp);

    // MD5 of params → first 4 bytes
    let url_md5 = md5_hex(params.as_bytes());
    for i in 0..4 {
        gorgon.push(u8::from_str_radix(&url_md5[2 * i..2 * i + 2], 16).unwrap_or(0));
    }

    // MD5 of data → next 4 bytes (or zeros)
    if !data.is_empty() {
        let data_md5 = md5_hex(data.as_bytes());
        for i in 0..4 {
            gorgon.push(u8::from_str_radix(&data_md5[2 * i..2 * i + 2], 16).unwrap_or(0));
        }
    } else {
        gorgon.extend_from_slice(&[0, 0, 0, 0]);
    }

    // MD5 of cookie → next 4 bytes (or zeros)
    if !cookie.is_empty() {
        let cookie_md5 = md5_hex(cookie.as_bytes());
        for i in 0..4 {
            gorgon.push(u8::from_str_radix(&cookie_md5[2 * i..2 * i + 2], 16).unwrap_or(0));
        }
    } else {
        gorgon.extend_from_slice(&[0, 0, 0, 0]);
    }

    // 4 zero bytes
    gorgon.extend_from_slice(&[0, 0, 0, 0]);

    // Timestamp hex → 4 bytes
    for i in 0..4 {
        if 2 * i + 2 <= khronos.len() {
            gorgon.push(u8::from_str_radix(&khronos[2 * i..2 * i + 2], 16).unwrap_or(0));
        } else {
            gorgon.push(0);
        }
    }

    XG::new(gorgon).main_calc()
}

fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
}
