use crate::api::client::FanqieClient;
use crate::model::*;
use anyhow::Result;

/// Get book detail info
pub async fn get_book_detail(client: &FanqieClient, book_id: &str) -> Result<BookDetailData> {
    let resp: ApiResponse<BookDetailData> = client
        .get("/reading/bookapi/detail/v1/", &[("book_id", book_id)])
        .await?;

    if resp.code != 0 {
        anyhow::bail!(
            "Get book detail failed: code={}, msg={}",
            resp.code,
            resp.message
        );
    }

    resp.data
        .ok_or_else(|| anyhow::anyhow!("Book detail data is null"))
}

/// Get all chapters for a book (returns items with item_id + title)
pub async fn get_chapter_list(client: &FanqieClient, book_id: &str) -> Result<Vec<DirectoryItem>> {
    let resp: ApiResponse<DirectoryData> = client
        .get(
            "/reading/bookapi/directory/all_items/v1/",
            &[("book_id", book_id)],
        )
        .await?;

    if resp.code != 0 {
        anyhow::bail!(
            "Get chapter list failed: code={}, msg={}",
            resp.code,
            resp.message
        );
    }

    let data = resp
        .data
        .ok_or_else(|| anyhow::anyhow!("Directory data is null"))?;
    Ok(data.item_data_list)
}
