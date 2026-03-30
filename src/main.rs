mod api;
mod crypto;
mod device;
mod model;
mod signer;

use anyhow::Result;
use api::book;
use api::client::FanqieClient;
use api::reader;
use dialoguer::{Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== 番茄小说下载器 ===\n");

    let client = match FanqieClient::new().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("初始化失败: {}", e);
            eprintln!("请确保 sign_proxy_simple.py <PID> 已启动");
            return Ok(());
        }
    };
    println!("就绪!\n");

    loop {
        let query: String = Input::new()
            .with_prompt("输入书名搜索 或 book_id (q退出)")
            .interact_text()?;
        let query = query.trim().to_string();
        if query == "q" || query == "quit" {
            break;
        }

        // Extract book_id from input (supports raw ID, URL, or search)
        let book_id = extract_book_id(&query).unwrap_or_else(|| {
            // Try search (may not work due to API restrictions)
            println!("提示: 搜索 API 可能不可用，建议直接输入 book_id");
            println!("  从 fanqienovel.com 搜索后复制 URL 中的数字 ID");
            query.clone()
        });

        if book_id.is_empty() || !book_id.chars().all(|c| c.is_ascii_digit()) {
            println!("无效的 book_id\n");
            continue;
        }

        let book_name = match book::get_book_detail(&client, &book_id).await {
            Ok(d) => {
                println!("《{}》{}", d.book_name, d.author);
                d.book_name
            }
            Err(_) => format!("book_{}", book_id),
        };

        println!("获取章节...");
        let chapters = match book::get_chapter_list(&client, &book_id).await {
            Ok(c) if !c.is_empty() => c,
            _ => {
                eprintln!("章节列表为空\n");
                continue;
            }
        };
        println!("共 {} 章", chapters.len());

        if Select::new()
            .with_prompt("下载?")
            .items(&["是", "否"])
            .default(0)
            .interact()?
            != 0
        {
            continue;
        }

        let dir = format!("downloads/{}", sanitize_filename::sanitize(&book_name));
        std::fs::create_dir_all(&dir)?;

        let pb = ProgressBar::new(chapters.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("=>-"),
        );

        let (mut ok, mut fail) = (0u64, 0u64);
        for (i, ch) in chapters.iter().enumerate() {
            let id = ch.item_id_str();
            let title = if ch.title.is_empty() {
                format!("第{}章", i + 1)
            } else {
                ch.title.clone()
            };
            pb.set_message(title.clone());

            match reader::get_chapter_content(&client, &book_id, &id).await {
                Ok(t) if !t.is_empty() => {
                    let f = format!(
                        "{}/{:04}_{}.txt",
                        dir,
                        i + 1,
                        sanitize_filename::sanitize(&title)
                    );
                    std::fs::write(&f, &t)?;
                    ok += 1;
                }
                Ok(_) => {
                    pb.println(format!("  {} - 空", title));
                    fail += 1;
                }
                Err(e) => {
                    pb.println(format!("  {} - {}", title, e));
                    fail += 1;
                }
            }
            pb.inc(1);
            tokio::time::sleep(Duration::from_millis(1500)).await;
        }
        pb.finish_with_message("完成!");
        println!("\n成功:{ok} 失败:{fail} 保存:{dir}\n");
    }
    Ok(())
}

/// Extract book_id from various input formats:
/// - Raw numeric ID: "7143038691944959011"
/// - fanqienovel.com URL: "https://fanqienovel.com/page/7143038691944959011"
/// - Partial URL: "page/7143038691944959011"
fn extract_book_id(input: &str) -> Option<String> {
    let input = input.trim();

    // Pure numeric
    if input.chars().all(|c| c.is_ascii_digit()) && input.len() > 10 {
        return Some(input.to_string());
    }

    // URL with /page/{id}
    if let Some(pos) = input.find("/page/") {
        let rest = &input[pos + 6..];
        let id: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if id.len() > 10 {
            return Some(id);
        }
    }

    // Any long number in the string
    let re = regex::Regex::new(r"\d{15,}").ok()?;
    re.find(input).map(|m| m.as_str().to_string())
}
