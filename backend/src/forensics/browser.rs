use crate::forensics::timestamp::webkit_to_utc_string;
use crate::models::BrowserArtifact;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::Row;
use std::str::FromStr;
use uuid::Uuid;

/// Extract real Chrome / Edge browser history from an acquired SQLite evidence file.
/// STRICT FORENSIC REQUIREMENT: Opened in read-only mode so original evidence is NEVER altered.
pub async fn extract_browser_history(
    file_path: &str,
    browser_name: &str,
    case_id: &str,
    evidence_id: &str,
) -> Result<Vec<BrowserArtifact>, String> {
    let path_obj = std::path::Path::new(file_path);
    if !path_obj.exists() {
        return Err(format!(
            "Evidence file does not exist at path: {}",
            file_path
        ));
    }

    // Connect to SQLite in STRICT READ-ONLY MODE
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", file_path))
        .map_err(|e| format!("Invalid SQLite database URI: {}", e))?
        .read_only(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .map_err(|e| format!("Failed to open evidence SQLite database read-only: {}", e))?;

    // Try joining urls and visits tables
    let query_res = sqlx::query(
        "SELECT 
            urls.url, 
            urls.title, 
            urls.visit_count, 
            COALESCE(visits.visit_time, urls.last_visit_time) AS visit_time
         FROM urls
         LEFT JOIN visits ON urls.id = visits.url",
    )
    .fetch_all(&pool)
    .await;

    let rows = match query_res {
        Ok(r) => r,
        Err(_) => {
            // Fallback: Query urls table directly if visits table is missing/different
            sqlx::query(
                "SELECT 
                    url, 
                    title, 
                    visit_count, 
                    last_visit_time AS visit_time
                 FROM urls",
            )
            .fetch_all(&pool)
            .await
            .map_err(|e| {
                format!(
                    "Malformed or unsupported SQLite History database schema: {}",
                    e
                )
            })?
        }
    };

    let extracted_at = chrono::Utc::now().format("%d-%m-%Y %H:%M:%S").to_string();
    let mut artifacts = Vec::new();

    for r in rows {
        let raw_url: String = r.try_get("url").unwrap_or_default();
        if raw_url.is_empty() {
            continue;
        }

        let raw_title: String = r.try_get("title").unwrap_or_default();
        let raw_visit_count: i64 = r.try_get::<i64, _>("visit_count").unwrap_or(1);
        let raw_visit_time: i64 = r.try_get::<i64, _>("visit_time").unwrap_or(0);

        let title = if raw_title.trim().is_empty() {
            raw_url.clone()
        } else {
            raw_title
        };

        let visit_time_str = webkit_to_utc_string(raw_visit_time);

        artifacts.push(BrowserArtifact {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            evidence_id: evidence_id.to_string(),
            url: raw_url,
            title,
            visit_time: visit_time_str,
            visit_count: raw_visit_count.max(1) as u32,
            browser: if browser_name.is_empty() {
                "Chrome".to_string()
            } else {
                browser_name.to_string()
            },
            category: "History".to_string(),
            extracted_at: extracted_at.clone(),
        });
    }

    Ok(artifacts)
}
