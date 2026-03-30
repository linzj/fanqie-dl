use crate::api::client::FanqieClient;
use crate::crypto;
use crate::model::*;
use anyhow::Result;
use regex::Regex;

pub async fn get_chapter_content(
    client: &FanqieClient,
    book_id: &str,
    item_id: &str,
) -> Result<String> {
    let resp: ApiResponse<ItemContent> = client
        .get(
            "/reading/reader/full/v1/",
            &[("book_id", book_id), ("item_id", item_id)],
        )
        .await?;

    if resp.code != 0 {
        anyhow::bail!("code={}, msg={}", resp.code, resp.message);
    }

    match resp.data {
        Some(item) => decode_item_content(&item, client.v1_key()),
        None => Ok(String::new()),
    }
}

fn decode_item_content(item: &ItemContent, v1_key: &str) -> Result<String> {
    let content_str = if !item.content.is_empty() {
        &item.content
    } else {
        &item.origin_content
    };
    if content_str.is_empty() || content_str == "Invalid" {
        return Ok(String::new());
    }

    let raw_bytes = match item.crypt_status {
        0 if !v1_key.is_empty() => crypto::decrypt_content(content_str, v1_key)?,
        _ => content_str.as_bytes().to_vec(),
    };

    let text_bytes = if item.compress_status > 0 {
        crypto::decompress(&raw_bytes)?
    } else {
        raw_bytes
    };

    Ok(html_to_text(&String::from_utf8_lossy(&text_bytes)))
}

fn html_to_text(html: &str) -> String {
    if !html.contains('<') {
        return html.to_string();
    }
    let p_re = Regex::new(r"(?is)<p[^>]*>(.*?)</p>").unwrap();
    let tag_re = Regex::new(r"<[^>]+>").unwrap();
    let mut lines = Vec::new();
    for cap in p_re.captures_iter(html) {
        let clean = tag_re
            .replace_all(&cap[1], "")
            .replace("&nbsp;", " ")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
            .replace("&quot;", "\"")
            .replace("&#39;", "'");
        let clean = clean.trim();
        if !clean.is_empty() {
            lines.push(format!("\u{3000}\u{3000}{}", clean));
        }
    }
    if lines.is_empty() {
        tag_re.replace_all(html, "").trim().to_string()
    } else {
        lines.join("\n")
    }
}
