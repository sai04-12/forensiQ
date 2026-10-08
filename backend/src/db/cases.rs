use crate::db::{AppState, DbPool};
use crate::models::Case;
use chrono::Utc;
use sqlx::Row;
use uuid::Uuid;

pub async fn list_cases(state: &AppState) -> Result<Vec<Case>, String> {
    match &state.db {
        DbPool::Postgres(pool) => {
            let rows = sqlx::query(
                "SELECT id, case_number, title, investigator_id, status, created_at FROM cases ORDER BY created_at DESC"
            )
            .fetch_all(pool)
            .await
            .map_err(|e| e.to_string())?;

            let cases = rows
                .into_iter()
                .map(|r| {
                    let id_val: Uuid = r.get("id");
                    let case_num: String = r.get("case_number");
                    let title: String = r.get("title");
                    let status: String = r.get("status");
                    let created_at: chrono::DateTime<Utc> = r.get("created_at");

                    Case {
                        id: id_val.to_string(),
                        case_number: case_num,
                        title,
                        investigator: "Lead Investigator".to_string(),
                        status,
                        created_at: created_at.format("%d-%m-%Y").to_string(),
                        evidence_count: 0,
                    }
                })
                .collect();
            Ok(cases)
        }
        DbPool::Sqlite(pool) => {
            let rows = sqlx::query(
                "SELECT id, case_number, title, investigator, status, created_at FROM cases ORDER BY id DESC"
            )
            .fetch_all(pool)
            .await
            .map_err(|e| e.to_string())?;

            let mut cases = Vec::new();
            for r in rows {
                let id_val: String = r.get("id");
                let case_num: String = r.get("case_number");
                let title: String = r.get("title");
                let investigator: Option<String> = r.get("investigator");
                let status: String = r.get("status");
                let created_at: String = r.get("created_at");

                let ev_count: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM evidence_items WHERE case_id = ?")
                        .bind(&id_val)
                        .fetch_one(pool)
                        .await
                        .unwrap_or(0);

                cases.push(Case {
                    id: id_val,
                    case_number: case_num,
                    title,
                    investigator: investigator.unwrap_or_else(|| "Unassigned".to_string()),
                    status,
                    created_at,
                    evidence_count: ev_count as usize,
                });
            }
            Ok(cases)
        }
    }
}

pub async fn create_case(
    state: &AppState,
    title: &str,
    investigator: &str,
) -> Result<Case, String> {
    let case_count = list_cases(state).await.map(|c| c.len()).unwrap_or(0);
    let case_number = format!("CASE-2024-{:03}", case_count + 1);
    let id_str = Uuid::new_v4().to_string();
    let now_str = Utc::now().format("%d-%m-%Y").to_string();

    match &state.db {
        DbPool::Postgres(pool) => {
            let uuid_val = Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::new_v4());
            let _ = sqlx::query(
                "INSERT INTO cases (id, case_number, title, investigator_id, status, created_at, updated_at) VALUES ($1, $2, $3, $4, 'Open', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
            .bind(uuid_val)
            .bind(&case_number)
            .bind(title)
            .bind(uuid_val)
            .execute(pool)
            .await
            .map_err(|e| e.to_string())?;
        }
        DbPool::Sqlite(pool) => {
            let _ = sqlx::query(
                "INSERT INTO cases (id, case_number, title, investigator, status, created_at, updated_at) VALUES (?, ?, ?, ?, 'Open', ?, ?)"
            )
            .bind(&id_str)
            .bind(&case_number)
            .bind(title)
            .bind(investigator)
            .bind(&now_str)
            .bind(&now_str)
            .execute(pool)
            .await
            .map_err(|e| e.to_string())?;
        }
    }

    Ok(Case {
        id: case_number.clone(),
        case_number,
        title: title.to_string(),
        investigator: investigator.to_string(),
        status: "Open".to_string(),
        created_at: now_str,
        evidence_count: 0,
    })
}

pub async fn get_case_by_id(state: &AppState, id: &str) -> Result<Case, String> {
    let cases = list_cases(state).await?;
    cases
        .into_iter()
        .find(|c| c.id == id || c.case_number == id)
        .ok_or_else(|| "Case not found".to_string())
}

pub async fn seed_demo_data_if_empty(state: &AppState) -> Result<(), String> {
    let existing = list_cases(state).await.unwrap_or_default();
    if !existing.is_empty() {
        return Ok(());
    }

    let _ = create_case(state, "Cyber Fraud Investigation", "John Doe").await;
    let _ = create_case(state, "Data Theft Analysis", "G. Sai").await;
    let _ = create_case(state, "Unauthorized Access Case", "G. Sharan Kumar").await;
    let _ = create_case(state, "USB Device Analysis", "K. Shanmukh Rao").await;

    Ok(())
}
