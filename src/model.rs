use serde::Deserialize;
use std::collections::HashMap;

/// Generic API response wrapper
#[derive(Deserialize, Debug)]
pub struct ApiResponse<T> {
    pub code: i64,
    #[serde(default)]
    pub message: String,
    pub data: Option<T>,
}

// ============ Search ============

#[derive(Deserialize, Debug, Clone)]
pub struct SearchBook {
    #[serde(default)]
    pub book_id: serde_json::Value,
    #[serde(default)]
    pub book_name: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub word_count: serde_json::Value,
    #[serde(default)]
    pub category: String,
}

impl SearchBook {
    pub fn book_id_str(&self) -> String {
        match &self.book_id {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => String::new(),
        }
    }

    pub fn word_count_str(&self) -> String {
        match &self.word_count {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => "0".to_string(),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct SearchData {
    #[serde(default)]
    pub data: Vec<SearchCell>,
}

#[derive(Deserialize, Debug)]
pub struct SearchCell {
    #[serde(default)]
    pub book_data: Option<Vec<SearchBook>>,
}

// ============ Book Detail ============

#[derive(Deserialize, Debug)]
pub struct BookDetailData {
    #[serde(default)]
    pub book_id: serde_json::Value,
    #[serde(default)]
    pub book_name: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub word_count: serde_json::Value,
    #[serde(default, rename = "abstract")]
    pub abstract_text: String,
    #[serde(default)]
    pub creation_status: String,
}

// ============ Directory (Chapter List) ============

/// Response from /reading/bookapi/directory/all_items/v1/
/// The actual chapter list is in `item_data_list`
#[derive(Deserialize, Debug)]
pub struct DirectoryData {
    #[serde(default)]
    pub item_data_list: Vec<DirectoryItem>,
    #[serde(default)]
    pub book_info: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DirectoryItem {
    #[serde(default)]
    pub item_id: serde_json::Value,
    #[serde(default)]
    pub title: String,
}

impl DirectoryItem {
    pub fn item_id_str(&self) -> String {
        match &self.item_id {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => String::new(),
        }
    }
}

// ============ Chapter Content ============

/// Response from /reading/reader/full/v1/
#[derive(Deserialize, Debug)]
pub struct ItemContent {
    #[serde(default)]
    pub content: String,
    #[serde(default, rename = "originContent")]
    pub origin_content: String,
    #[serde(default)]
    pub title: String,
    #[serde(default, alias = "cryptStatus", alias = "crypt_status")]
    pub crypt_status: i16,
    #[serde(default, alias = "compressStatus", alias = "compress_status")]
    pub compress_status: i16,
    #[serde(default, alias = "keyVersion", alias = "key_version")]
    pub key_version: i32,
}

/// batch_full data field: item_id → ItemContent
pub type BatchFullData = HashMap<String, ItemContent>;

// ============ Key Registration ============

#[derive(Deserialize, Debug)]
pub struct RegisterKeyData {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub keyver: i32,
    #[serde(default)]
    pub kmskey: String,
    #[serde(default, alias = "keyRegisterTs", alias = "key_register_ts")]
    pub key_register_ts: i64,
}
