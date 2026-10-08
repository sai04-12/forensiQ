use crate::db::{AppState, DbPool};
use crate::models::ChainOfCustodyLog;
use chrono::Utc;
use sqlx::Row;
use uuid::Uuid;

pub async fn create_custody_log(
    state: &AppState,
    log: &ChainOfCustodyLog,
) -> Result<ChainOfCustodyLog, String> {
    let now_str = Utc::now().format("%d-%m-%Y %H:%M:%S").to_string();

    match &state.db {
        DbPool::Postgres(pool) => {
            let log_uuid = Uuid::parse_str(&log.id).unwrap_or_else(|_| Uuid::new_v4());
            let case_uuid = Uuid::parse_str(&log.case_id).unwrap_or_else(|_| Uuid::new_v4());
            let ev_uuid = Uuid::parse_str(&log.evidence_id).ok();

            let _ = sqlx::query(
                "INSERT INTO chain_of_custody (id, case_id, evidence_id, timestamp, action, custodian, sha256_at_action, integrity_status, notes) VALUES ($1, $2, $3, CURRENT_TIMESTAMP, $4, $5, $6, $7, $8)"
            )
            .bind(log_uuid)
            .bind(case_uuid)
            .bind(ev_uuid)
            .bind(&log.action)
            .bind(&log.custodian)
            .bind(&log.sha256_at_action)
            .bind(&log.integrity_status)
            .bind(&log.notes)
            .execute(pool)
            .await
            .map_err(|e| format!("Database custody insert failed: {}", e))?;
        }
        DbPool::Sqlite(pool) => {
            let _ = sqlx::query(
                "INSERT INTO chain_of_custody (id, case_id, evidence_id, timestamp, action, custodian, sha256_at_action, integrity_status, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(&log.id)
            .bind(&log.case_id)
            .bind(&log.evidence_id)
            .bind(&now_str)
            .bind(&log.action)
            .bind(&log.custodian)
            .bind(&log.sha256_at_action)
            .bind(&log.integrity_status)
            .bind(&log.notes)
            .execute(pool)
            .await
            .map_err(|e| format!("Database custody insert failed: {}", e))?;
        }
    }

    Ok(log.clone())
}

pub async fn list_custody_logs(state: &AppState) -> Result<Vec<ChainOfCustodyLog>, String> {
    match &state.db {
        DbPool::Postgres(pool) => {
            let rows = sqlx::query(
                "SELECT id, case_id, evidence_id, timestamp, action, custodian, sha256_at_action, integrity_status, notes FROM chain_of_custody ORDER BY timestamp ASC"
            )
            .fetch_all(pool)
            .await
            .map_err(|e| e.to_string())?;

            let logs = rows
                .into_iter()
                .map(|r| {
                    let id_val: Uuid = r.get("id");
                    let case_uuid: Uuid = r.get("case_id");
                    let ev_uuid: Option<Uuid> = r.get("evidence_id");
                    let ts: chrono::DateTime<Utc> = r.get("timestamp");
                    let action: String = r.get("action");
                    let custodian: String = r.get("custodian");
                    let sha256: Option<String> = r.get("sha256_at_action");
                    let status: String = r.get("integrity_status");
                    let notes: Option<String> = r.get("notes");

                    ChainOfCustodyLog {
                        id: id_val.to_string(),
                        case_id: case_uuid.to_string(),
                        evidence_id: ev_uuid.map(|u| u.to_string()).unwrap_or_default(),
                        timestamp: ts.format("%d-%m-%Y %H:%M:%S").to_string(),
                        action,
                        custodian,
                        sha256_at_action: sha256.unwrap_or_default(),
                        integrity_status: status,
                        notes: notes.unwrap_or_default(),
                    }
                })
                .collect();
            Ok(logs)
        }
        DbPool::Sqlite(pool) => {
            let rows = sqlx::query(
                "SELECT id, case_id, evidence_id, timestamp, action, custodian, sha256_at_action, integrity_status, notes FROM chain_of_custody ORDER BY id ASC"
            )
            .fetch_all(pool)
            .await
            .map_err(|e| e.to_string())?;

            let logs = rows
                .into_iter()
                .map(|r| {
                    let id_val: String = r.get("id");
                    let case_id: String = r.get("case_id");
                    let ev_id: Option<String> = r.get("evidence_id");
                    let ts: String = r.get("timestamp");
                    let action: String = r.get("action");
                    let custodian: String = r.get("custodian");
                    let sha256: Option<String> = r.get("sha256_at_action");
                    let status: String = r.get("integrity_status");
                    let notes: Option<String> = r.get("notes");

                    ChainOfCustodyLog {
                        id: id_val,
                        case_id,
                        evidence_id: ev_id.unwrap_or_default(),
                        timestamp: ts,
                        action,
                        custodian,
                        sha256_at_action: sha256.unwrap_or_default(),
                        integrity_status: status,
                        notes: notes.unwrap_or_default(),
                    }
                })
                .collect();
            Ok(logs)
        }
    }
}
