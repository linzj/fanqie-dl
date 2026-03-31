mod api;
mod crypto;
mod device;
mod model;
mod signer;

use anyhow::Result;
use api::book;
use api::client::FanqieClient;
use api::reader;
use api::search;
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
        let book_id = match extract_book_id(&query) {
            Some(id) => id,
            None => {
                // Try keyword search
                println!("搜索 \"{}\"...", query);
                match search::search(&client, &query, 0, 20).await {
                    Ok(books) if !books.is_empty() => {
                        let items: Vec<String> = books
                            .iter()
                            .enumerate()
                            .map(|(i, b)| {
                                format!(
                                    "[{}] {} - {} ({}字)",
                                    i + 1,
                                    b.book_name,
                                    b.author,
                                    b.word_count_str()
                                )
                            })
                            .collect();
                        let sel = Select::new()
                            .with_prompt("选择")
                            .items(&items)
                            .default(0)
                            .interact()?;
                        books[sel].book_id_str()
                    }
                    Ok(_) => {
                        println!("未找到结果\n");
                        continue;
                    }
                    Err(e) => {
                        eprintln!("搜索失败: {}\n", e);
                        continue;
                    }
                }
            }
        };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_book_id() {
        assert_eq!(
            extract_book_id("7143038691944959011"),
            Some("7143038691944959011".into())
        );
        assert_eq!(
            extract_book_id("https://fanqienovel.com/page/7143038691944959011"),
            Some("7143038691944959011".into())
        );
        assert_eq!(
            extract_book_id("page/7143038691944959011"),
            Some("7143038691944959011".into())
        );
        assert_eq!(extract_book_id("hello"), None);
    }

    #[tokio::test]
    async fn test_search_api() {
        let client = match FanqieClient::new().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("跳过: 初始化失败 {}", e);
                return;
            }
        };
        println!("device_id: {}", client.config.device_id);

        let results = search::search(&client, "停尸房兼职", 0, 10).await;
        match results {
            Ok(books) => {
                println!("搜索到 {} 本书:", books.len());
                for b in &books {
                    println!(
                        "  {} - {} (id={}, {}字)",
                        b.book_name,
                        b.author,
                        b.book_id_str(),
                        b.word_count_str()
                    );
                }
                assert!(!books.is_empty(), "搜索结果不应为空");
            }
            Err(e) => {
                eprintln!("搜索失败: {}", e);
                // 不 panic，可能是网络问题
            }
        }
    }

    #[tokio::test]
    async fn test_download_book() {
        let client = match FanqieClient::new().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("跳过: {}", e);
                return;
            }
        };

        let book_id = "7373660003258862617";

        // 获取书籍详情
        let book_name = match book::get_book_detail(&client, book_id).await {
            Ok(d) => {
                println!("《{}》 作者: {}", d.book_name, d.author);
                d.book_name
            }
            Err(e) => {
                eprintln!("详情失败: {}", e);
                return;
            }
        };

        // 获取章节列表
        let chapters = match book::get_chapter_list(&client, book_id).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("章节失败: {}", e);
                return;
            }
        };
        println!("共 {} 章", chapters.len());

        // 创建下载目录
        let dir = format!("downloads/{}", sanitize_filename::sanitize(&book_name));
        std::fs::create_dir_all(&dir).unwrap();

        // 下载前3章作为测试
        let limit = chapters.len().min(3);
        let mut ok = 0u64;
        let mut fail = 0u64;
        for (i, ch) in chapters.iter().take(limit).enumerate() {
            let id = ch.item_id_str();
            let title = if ch.title.is_empty() {
                format!("第{}章", i + 1)
            } else {
                ch.title.clone()
            };

            match reader::get_chapter_content(&client, book_id, &id).await {
                Ok(t) if !t.is_empty() => {
                    let f = format!(
                        "{}/{:04}_{}.txt",
                        dir,
                        i + 1,
                        sanitize_filename::sanitize(&title)
                    );
                    std::fs::write(&f, &t).unwrap();
                    println!("  ✓ {}", title);
                    ok += 1;
                }
                Ok(_) => {
                    println!("  ✗ {} - 空内容", title);
                    fail += 1;
                }
                Err(e) => {
                    println!("  ✗ {} - {}", title, e);
                    fail += 1;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        }
        println!("\n成功:{ok} 失败:{fail} 保存:{dir}");
        assert!(ok > 0, "至少应成功下载一章");
    }

    #[tokio::test]
    async fn test_book_detail_and_chapters() {
        let client = match FanqieClient::new().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("跳过: {}", e);
                return;
            }
        };

        // 使用一本已知的书
        let book_id = "7258325096933100578";
        match book::get_book_detail(&client, book_id).await {
            Ok(d) => println!("书名: 《{}》 作者: {}", d.book_name, d.author),
            Err(e) => eprintln!("详情失败: {}", e),
        }

        match book::get_chapter_list(&client, book_id).await {
            Ok(chapters) => {
                println!("共 {} 章", chapters.len());
                if let Some(ch) = chapters.first() {
                    println!("  第一章: {} (id={})", ch.title, ch.item_id_str());
                }
                assert!(!chapters.is_empty(), "章节列表不应为空");
            }
            Err(e) => eprintln!("章节失败: {}", e),
        }
    }
}
