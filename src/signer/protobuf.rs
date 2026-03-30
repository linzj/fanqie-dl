//! Minimal protobuf writer for X-Argus construction.

pub struct ProtoWriter {
    data: Vec<u8>,
}

impl ProtoWriter {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    fn write_byte(&mut self, b: u8) {
        self.data.push(b);
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    fn write_varint(&mut self, mut v: u64) {
        let v32 = v as u32;
        v = v32 as u64; // truncate to u32 like Python
        while v > 0x80 {
            self.write_byte(((v & 0x7F) | 0x80) as u8);
            v >>= 7;
        }
        self.write_byte((v & 0x7F) as u8);
    }

    fn write_int32(&mut self, val: u32) {
        self.write_bytes(&val.to_le_bytes());
    }

    fn write_int64(&mut self, val: u64) {
        self.write_bytes(&val.to_le_bytes());
    }

    fn write_string(&mut self, bytes: &[u8]) {
        self.write_varint(bytes.len() as u64);
        self.write_bytes(bytes);
    }

    /// Encode a field: key = (idx << 3) | wire_type
    fn write_field_varint(&mut self, idx: u32, val: u64) {
        let key = (idx << 3) | 0; // wire type 0 = VARINT
        self.write_varint(key as u64);
        self.write_varint(val);
    }

    fn write_field_string(&mut self, idx: u32, val: &[u8]) {
        let key = (idx << 3) | 2; // wire type 2 = STRING
        self.write_varint(key as u64);
        self.write_string(val);
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.data
    }
}

/// Value types for protobuf dict encoding.
pub enum ProtoValue {
    Varint(u64),
    Utf8(String),
    Bytes(Vec<u8>),
    Dict(Vec<(u32, ProtoValue)>),
}

/// Encode a list of (field_id, value) pairs into protobuf bytes.
pub fn encode_dict(fields: &[(u32, ProtoValue)]) -> Vec<u8> {
    let mut writer = ProtoWriter::new();
    for (idx, val) in fields {
        match val {
            ProtoValue::Varint(v) => writer.write_field_varint(*idx, *v),
            ProtoValue::Utf8(s) => writer.write_field_string(*idx, s.as_bytes()),
            ProtoValue::Bytes(b) => writer.write_field_string(*idx, b),
            ProtoValue::Dict(sub) => {
                let sub_bytes = encode_dict(sub);
                writer.write_field_string(*idx, &sub_bytes);
            }
        }
    }
    writer.to_bytes()
}
