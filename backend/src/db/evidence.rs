use crate::db::{AppState, DbPool};
use crate::models::EvidenceItem;
use chrono::Utc;
use sqlx::Row;
use uuid::Uuid;

pub async fn create_evidence_item(
    state: &AppState,
    item: &EvidenceItem,
) -> Result<EvidenceItem, String> {
    let now_str = Utc::now().format("%d-%m-%Y %H:%M:%S").to_string();

    match &state.db {
        DbPool::Postgres(pool) => {
            let id_uuid = Uuid::parse_str(&item.id).unwrap_or_else(|_| Uuid::new_v4());
            let case_uuid = Uuid::parse_str(&item.case_id).unwrap_or_else(|_| Uuid::new_v4());

            let _ = sqlx::query(
                "INSERT INTO evidence_items (id, case_id, file_name, source_path, stored_path, file_size, sha256_hash, sha1_hash, acquired_at, write_blocked, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP, $9, $10, CURRENT_TIMESTAMP)"
            )
            .bind(id_uuid)
            .bind(case_uuid)
            .bind(&item.file_name)
            .bind(&item.file_path)
            .bind(&item.file_path)
            .bind(item.file_size_bytes as i64)
            .bind(&item.sha256_hash)
            .bind(&item.sha1_hash)
            .bind(item.write_blocked)
            .bind(&item.status)
            .execute(pool)
            .await
            .map_err(|e| format!("Database insertion failed: {}", e))?;
        }
        DbPool::Sqlite(pool) => {
            let wb_int = if item.write_blocked { 1i64 } else { 0i64 };
            let size_i64 = item.file_size_bytes as i64;
            let _ = sqlx::query(
                "INSERT INTO evidence_items (id, case_id, file_name, source_path, stored_path, file_size, sha256_hash, sha1_hash, acquired_at, write_blocked, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(&item.id)
            .bind(&item.case_id)
            .bind(&item.file_name)
            .bind(&item.file_path)
            .bind(&item.file_path)
            .bind(size_i64)
            .bind(&item.sha256_hash)
            .bind(&item.sha1_hash)
            .bind(&now_str)
            .bind(wb_int)
            .bind(&item.status)
            .bind(&now_str)
            .execute(pool)
            .await
            .map_err(|e| format!("Database insertion failed: {}", e))?;
        }
    }

    Ok(item.clone())
}

pub async fn list_evidence_items(state: &AppState) -> Result<Vec<EvidenceItem>, String> {
    match &state.db {
        DbPool::Postgres(pool) => {
            let rows = sqlx::query(
                "SELECT id, case_id, file_name, source_path, file_size, sha256_hash, sha1_hash, write_blocked, status, acquired_at FROM evidence_items"
            )
            .fetch_all(pool)
            .await
            .map_err(|e| e.to_string())?;

            let list = rows
                .into_iter()
                .map(|r| {
                    let id_val: Uuid = r.get("id");
                    let case_uuid: Uuid = r.get("case_id");
                    let file_name: String = r.get("file_name");
                    let source_path: Option<String> = r.get("source_path");
                    let file_size: i64 = r.get("file_size");
                    let sha256: String = r.get("sha256_hash");
                    let sha1: Option<String> = r.get("sha1_hash");
                    let wb: bool = r.get("write_blocked");
                    let status: String = r.get("status");
                    let acq_at: chrono::DateTime<Utc> = r.get("acquired_at");

                    EvidenceItem {
                        id: id_val.to_string(),
                        case_id: case_uuid.to_string(),
                        file_name,
                        file_path: source_path.unwrap_or_default(),
                        file_size_bytes: file_size as u64,
                        sha256_hash: sha256,
                        sha1_hash: sha1.unwrap_or_default(),
                        acquired_by: "Lead Investigator".to_string(),
                        acquired_at: acq_at.format("%d-%m-%Y %H:%M:%S").to_string(),
                        write_blocked: wb,
                        status,
                    }
                })
                .collect();
            Ok(list)
        }
        DbPool::Sqlite(pool) => {
            let rows = sqlx::query(
                "SELECT id, case_id, file_name, source_path, file_size, sha256_hash, sha1_hash, write_blocked, status, acquired_at FROM evidence_items"
            )
            .fetch_all(pool)
            .await
            .map_err(|e| e.to_string())?;

            let list = rows
                .into_iter()
                .map(|r| {
                    let id_val: String = r.get("id");
                    let case_id: String = r.get("case_id");
                    let file_name: String = r.get("file_name");
                    let source_path: Option<String> = r.get("source_path");
                    let file_size: i64 = r.get("file_size");
                    let sha256: String = r.get("sha256_hash");
                    let sha1: Option<String> = r.get("sha1_hash");
                    let wb: i64 = r.get("write_blocked");
                    let status: String = r.get("status");
                    let acq_at: String = r.get("acquired_at");

                    EvidenceItem {
                        id: id_val,
                        case_id,
                        file_name,
                        file_path: source_path.unwrap_or_default(),
                        file_size_bytes: file_size as u64,
                        sha256_hash: sha256,
                        sha1_hash: sha1.unwrap_or_default(),
                        acquired_by: "Lead Investigator".to_string(),
                        acquired_at: acq_at,
                        write_blocked: wb == 1,
                        status,
                    }
                })
                .collect();
            Ok(list)
        }
    }
}

pub async fn get_evidence_by_id(
    state: &AppState,
    evidence_id: &str,
) -> Result<EvidenceItem, String> {
    let items = list_evidence_items(state).await?;
    items
        .into_iter()
        .find(|e| e.id == evidence_id)
        .ok_or_else(|| "Evidence item not found".to_string())
}
