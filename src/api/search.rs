use crate::api::client::FanqieClient;
use crate::model::*;
use anyhow::Result;

/// Search books by keyword
pub async fn search(
    client: &FanqieClient,
    query: &str,
    offset: u32,
    count: u32,
) -> Result<Vec<SearchBook>> {
    let offset_str = offset.to_string();
    let count_str = count.to_string();

    let resp: ApiResponse<SearchData> = client
        .get(
            "/reading/bookapi/search/tab/v",
            &[
                ("query", query),
                ("offset", &offset_str),
                ("count", &count_str),
                ("search_source", "1"),
                ("is_first_enter_search", "true"),
                ("use_correct", "false"),
                ("from_rs", "false"),
                ("only_feed", "false"),
                ("only_large_card", "false"),
                ("from_half_screen", "false"),
            ],
        )
        .await?;

    if resp.code != 0 {
        anyhow::bail!("Search failed: code={}, msg={}", resp.code, resp.message);
    }

    let mut books = Vec::new();
    if let Some(data) = resp.data {
        for cell in data.data {
            if let Some(book_data) = cell.book_data {
                for book in book_data {
                    if !book.book_id_str().is_empty() {
                        books.push(book);
                    }
                }
            }
        }
    }
    Ok(books)
}
