use crate::db::{AppState, DbPool};
use crate::models::*;
use sqlx::Row;

pub async fn save_file_artifacts(
    state: &AppState,
    artifacts: &[FileArtifact],
) -> Result<usize, String> {
    if artifacts.is_empty() {
        return Ok(0);
    }
    let mut count = 0;
    match &state.db {
        DbPool::Postgres(pool) => {
            for a in artifacts {
                let id_uuid = uuid::Uuid::parse_str(&a.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
                let case_uuid =
                    uuid::Uuid::parse_str(&a.case_id).unwrap_or_else(|_| uuid::Uuid::new_v4());
                let ev_uuid = uuid::Uuid::parse_str(&a.evidence_id).ok();

                let res = sqlx::query(
                    "INSERT INTO file_artifacts (id, case_id, evidence_id, name, path, size_bytes, file_type, mime_type, offset_bytes, created_at, modified_at, sha256_hash, sha1_hash, source_evidence_hash, is_carved, recovery_status, validation_status)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, $10, $11, $12, $13, $14, $15)"
                )
                .bind(id_uuid)
                .bind(case_uuid)
                .bind(ev_uuid)
                .bind(&a.name)
                .bind(&a.path)
                .bind(a.size_bytes as i64)
                .bind(&a.file_type)
                .bind(&a.mime_type)
                .bind(a.offset_bytes as i64)
                .bind(&a.sha256_hash)
                .bind(&a.sha1_hash)
                .bind(&a.source_evidence_hash)
                .bind(a.is_carved)
                .bind(&a.recovery_status)
                .bind(&a.validation_status)
                .execute(pool)
                .await;

                if res.is_ok() {
                    count += 1;
                }
            }
        }
        DbPool::Sqlite(pool) => {
            for a in artifacts {
                let res = sqlx::query(
                    "INSERT INTO file_artifacts (id, case_id, evidence_id, name, path, size_bytes, file_type, mime_type, offset_bytes, created_at, modified_at, sha256_hash, sha1_hash, source_evidence_hash, is_carved, recovery_status, validation_status)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                )
                .bind(&a.id)
                .bind(&a.case_id)
                .bind(&a.evidence_id)
                .bind(&a.name)
                .bind(&a.path)
                .bind(a.size_bytes as i64)
                .bind(&a.file_type)
                .bind(&a.mime_type)
                .bind(a.offset_bytes as i64)
                .bind(&a.created_at)
                .bind(&a.modified_at)
                .bind(&a.sha256_hash)
                .bind(&a.sha1_hash)
                .bind(&a.source_evidence_hash)
                .bind(if a.is_carved { 1i64 } else { 0i64 })
                .bind(&a.recovery_status)
                .bind(&a.validation_status)
                .execute(pool)
                .await;

                if res.is_ok() {
                    count += 1;
                }
            }
        }
    }
    Ok(count)
}

pub async fn list_file_artifacts(state: &AppState) -> Vec<FileArtifact> {
    match &state.db {
        DbPool::Postgres(pool) => {
            let rows = sqlx::query(
                "SELECT id, case_id, COALESCE(evidence_id::text, '') AS evidence_id, name, path, size_bytes, file_type, COALESCE(mime_type, 'application/octet-stream') AS mime_type, COALESCE(offset_bytes, 0) AS offset_bytes, created_at, modified_at, sha256_hash, COALESCE(sha1_hash, '') AS sha1_hash, COALESCE(source_evidence_hash, '') AS source_evidence_hash, is_carved, recovery_status, COALESCE(validation_status, 'VALID') AS validation_status FROM file_artifacts ORDER BY created_at DESC"
            )
            .fetch_all(pool)
            .await
            .unwrap_or_default();

            rows.into_iter()
                .map(|r| {
                    let id_val: uuid::Uuid = r.get("id");
                    let case_uuid: uuid::Uuid = r.get("case_id");
                    let ev_id: String = r.get("evidence_id");
                    let name: String = r.get("name");
                    let path: String = r.get("path");
                    let size: i64 = r.get("size_bytes");
                    let ftype: String = r.get("file_type");
                    let mtype: String = r.get("mime_type");
                    let off: i64 = r.get("offset_bytes");
                    let cr_at: chrono::DateTime<chrono::Utc> = r.get("created_at");
                    let mod_at: chrono::DateTime<chrono::Utc> = r.get("modified_at");
                    let sha256: String = r.get("sha256_hash");
                    let sha1: String = r.get("sha1_hash");
                    let src_hash: String = r.get("source_evidence_hash");
                    let carved: bool = r.get("is_carved");
                    let rec_status: String = r.get("recovery_status");
                    let val_status: String = r.get("validation_status");

                    FileArtifact {
                        id: id_val.to_string(),
                        case_id: case_uuid.to_string(),
                        evidence_id: ev_id,
                        name,
                        path,
                        size_bytes: size as u64,
                        file_type: ftype,
                        mime_type: mtype,
                        offset_bytes: off as u64,
                        created_at: cr_at.format("%d-%m-%Y %H:%M").to_string(),
                        modified_at: mod_at.format("%d-%m-%Y %H:%M").to_string(),
                        sha256_hash: sha256,
                        sha1_hash: sha1,
                        source_evidence_hash: src_hash,
                        is_carved: carved,
                        recovery_status: rec_status,
                        validation_status: val_status,
                    }
                })
                .collect()
        }
        DbPool::Sqlite(pool) => {
            let rows = sqlx::query(
                "SELECT id, case_id, COALESCE(evidence_id, '') AS evidence_id, name, path, size_bytes, file_type, COALESCE(mime_type, 'application/octet-stream') AS mime_type, COALESCE(offset_bytes, 0) AS offset_bytes, created_at, modified_at, sha256_hash, COALESCE(sha1_hash, '') AS sha1_hash, COALESCE(source_evidence_hash, '') AS source_evidence_hash, is_carved, recovery_status, COALESCE(validation_status, 'VALID') AS validation_status FROM file_artifacts ORDER BY created_at DESC"
            )
            .fetch_all(pool)
            .await
            .unwrap_or_default();

            rows.into_iter()
                .map(|r| {
                    let id_val: String = r.get("id");
                    let case_id: String = r.get("case_id");
                    let ev_id: String = r.get("evidence_id");
                    let name: String = r.get("name");
                    let path: String = r.get("path");
                    let size: i64 = r.get("size_bytes");
                    let ftype: String = r.get("file_type");
                    let mtype: String = r.get("mime_type");
                    let off: i64 = r.get("offset_bytes");
                    let cr_at: String = r.get("created_at");
                    let mod_at: String = r.get("modified_at");
                    let sha256: String = r.get("sha256_hash");
                    let sha1: String = r.get("sha1_hash");
                    let src_hash: String = r.get("source_evidence_hash");
                    let carved: i64 = r.get("is_carved");
                    let rec_status: String = r.get("recovery_status");
                    let val_status: String = r.get("validation_status");

                    FileArtifact {
                        id: id_val,
                        case_id,
                        evidence_id: ev_id,
                        name,
                        path,
                        size_bytes: size as u64,
                        file_type: ftype,
                        mime_type: mtype,
                        offset_bytes: off as u64,
                        created_at: cr_at,
                        modified_at: mod_at,
                        sha256_hash: sha256,
                        sha1_hash: sha1,
                        source_evidence_hash: src_hash,
                        is_carved: carved == 1,
                        recovery_status: rec_status,
                        validation_status: val_status,
                    }
                })
                .collect()
        }
    }
}

pub async fn get_file_artifact_by_id(state: &AppState, id: &str) -> Option<FileArtifact> {
    let all = list_file_artifacts(state).await;
    all.into_iter().find(|f| f.id == id)
}

pub async fn save_browser_artifacts(
    state: &AppState,
    artifacts: &[BrowserArtifact],
) -> Result<usize, String> {
    if artifacts.is_empty() {
        return Ok(0);
    }
    let mut count = 0;
    match &state.db {
        DbPool::Postgres(pool) => {
            for a in artifacts {
                let id_uuid = uuid::Uuid::parse_str(&a.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
                let case_uuid =
                    uuid::Uuid::parse_str(&a.case_id).unwrap_or_else(|_| uuid::Uuid::new_v4());
                let ev_uuid = uuid::Uuid::parse_str(&a.evidence_id).ok();

                let res = sqlx::query(
                    "INSERT INTO browser_artifacts (id, case_id, evidence_id, url, title, visit_time, visit_count, browser, category, extracted_at)
                     VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, $6, $7, $8, CURRENT_TIMESTAMP)"
                )
                .bind(id_uuid)
                .bind(case_uuid)
                .bind(ev_uuid)
                .bind(&a.url)
                .bind(&a.title)
                .bind(a.visit_count as i32)
                .bind(&a.browser)
                .bind(&a.category)
                .execute(pool)
                .await;
                if res.is_ok() {
                    count += 1;
                }
            }
        }
        DbPool::Sqlite(pool) => {
            for a in artifacts {
                let res = sqlx::query(
                    "INSERT INTO browser_artifacts (id, case_id, evidence_id, url, title, visit_time, visit_count, browser, category, extracted_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                )
                .bind(&a.id)
                .bind(&a.case_id)
                .bind(&a.evidence_id)
                .bind(&a.url)
                .bind(&a.title)
                .bind(&a.visit_time)
                .bind(a.visit_count as i64)
                .bind(&a.browser)
                .bind(&a.category)
                .bind(&a.extracted_at)
                .execute(pool)
                .await;
                if res.is_ok() {
                    count += 1;
                }
            }
        }
    }
    Ok(count)
}

pub async fn save_system_artifacts(
    state: &AppState,
    artifacts: &[SystemArtifact],
) -> Result<usize, String> {
    if artifacts.is_empty() {
        return Ok(0);
    }
    let mut count = 0;
    match &state.db {
        DbPool::Postgres(pool) => {
            for a in artifacts {
                let id_uuid = uuid::Uuid::parse_str(&a.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
                let case_uuid =
                    uuid::Uuid::parse_str(&a.case_id).unwrap_or_else(|_| uuid::Uuid::new_v4());
                let ev_uuid = uuid::Uuid::parse_str(&a.evidence_id).ok();

                let res = sqlx::query(
                    "INSERT INTO system_artifacts (id, case_id, evidence_id, artifact_type, source, timestamp, description, severity, extracted_at)
                     VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, $6, $7, CURRENT_TIMESTAMP)"
                )
                .bind(id_uuid)
                .bind(case_uuid)
                .bind(ev_uuid)
                .bind(&a.artifact_type)
                .bind(&a.source)
                .bind(&a.description)
                .bind(&a.severity)
                .execute(pool)
                .await;
                if res.is_ok() {
                    count += 1;
                }
            }
        }
        DbPool::Sqlite(pool) => {
            for a in artifacts {
                let res = sqlx::query(
                    "INSERT INTO system_artifacts (id, case_id, evidence_id, artifact_type, source, timestamp, description, severity, extracted_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                )
                .bind(&a.id)
                .bind(&a.case_id)
                .bind(&a.evidence_id)
                .bind(&a.artifact_type)
                .bind(&a.source)
                .bind(&a.timestamp)
                .bind(&a.description)
                .bind(&a.severity)
                .bind(&a.extracted_at)
                .execute(pool)
                .await;
                if res.is_ok() {
                    count += 1;
                }
            }
        }
    }
    Ok(count)
}

pub async fn list_browser_artifacts(
    state: &AppState,
    filter_case_id: Option<&str>,
    filter_browser: Option<&str>,
    search_query: Option<&str>,
) -> Vec<BrowserArtifact> {
    match &state.db {
        DbPool::Postgres(pool) => {
            let rows = sqlx::query(
                "SELECT id, case_id, COALESCE(evidence_id::text, '') AS evidence_id, url, title, visit_time, visit_count, browser, category, COALESCE(extracted_at::text, '') AS extracted_at FROM browser_artifacts ORDER BY visit_time DESC"
            )
            .fetch_all(pool)
            .await
            .unwrap_or_default();

            rows.into_iter()
                .map(|r| {
                    let id_val: uuid::Uuid = r.get("id");
                    let case_uuid: uuid::Uuid = r.get("case_id");
                    let ev_id: String = r.get("evidence_id");
                    let url: String = r.get("url");
                    let title: String = r.get("title");
                    let vtime: chrono::DateTime<chrono::Utc> = r.get("visit_time");
                    let vcount: i32 = r.get("visit_count");
                    let browser: String = r.get("browser");
                    let cat: String = r.get("category");
                    let ext_at: String = r.get("extracted_at");

                    BrowserArtifact {
                        id: id_val.to_string(),
                        case_id: case_uuid.to_string(),
                        evidence_id: ev_id,
                        url,
                        title,
                        visit_time: vtime.format("%d-%m-%Y %H:%M:%S").to_string(),
                        visit_count: vcount as u32,
                        browser,
                        category: cat,
                        extracted_at: ext_at,
                    }
                })
                .filter(|b| {
                    if let Some(cid) = filter_case_id {
                        if !cid.is_empty() && b.case_id != cid {
                            return false;
                        }
                    }
                    if let Some(br) = filter_browser {
                        if !br.is_empty() && br != "All" && !b.browser.eq_ignore_ascii_case(br) {
                            return false;
                        }
                    }
                    if let Some(q) = search_query {
                        if !q.is_empty() {
                            let q_lower = q.to_lowercase();
                            if !b.url.to_lowercase().contains(&q_lower)
                                && !b.title.to_lowercase().contains(&q_lower)
                            {
                                return false;
                            }
                        }
                    }
                    true
                })
                .collect()
        }
        DbPool::Sqlite(pool) => {
            let rows = sqlx::query(
                "SELECT id, case_id, COALESCE(evidence_id, '') AS evidence_id, url, title, visit_time, visit_count, browser, category, COALESCE(extracted_at, '') AS extracted_at FROM browser_artifacts ORDER BY visit_time DESC"
            )
            .fetch_all(pool)
            .await
            .unwrap_or_default();

            rows.into_iter()
                .map(|r| {
                    let id_val: String = r.get("id");
                    let case_id: String = r.get("case_id");
                    let ev_id: String = r.get("evidence_id");
                    let url: String = r.get("url");
                    let title: String = r.get("title");
                    let vtime: String = r.get("visit_time");
                    let vcount: i64 = r.get("visit_count");
                    let browser: String = r.get("browser");
                    let cat: String = r.get("category");
                    let ext_at: String = r.get("extracted_at");

                    BrowserArtifact {
                        id: id_val,
                        case_id,
                        evidence_id: ev_id,
                        url,
                        title,
                        visit_time: vtime,
                        visit_count: vcount as u32,
                        browser,
                        category: cat,
                        extracted_at: ext_at,
                    }
                })
                .filter(|b| {
                    if let Some(cid) = filter_case_id {
                        if !cid.is_empty() && b.case_id != cid {
                            return false;
                        }
                    }
                    if let Some(br) = filter_browser {
                        if !br.is_empty() && br != "All" && !b.browser.eq_ignore_ascii_case(br) {
                            return false;
                        }
                    }
                    if let Some(q) = search_query {
                        if !q.is_empty() {
                            let q_lower = q.to_lowercase();
                            if !b.url.to_lowercase().contains(&q_lower)
                                && !b.title.to_lowercase().contains(&q_lower)
                            {
                                return false;
                            }
                        }
                    }
                    true
                })
                .collect()
        }
    }
}

pub async fn list_system_artifacts(
    state: &AppState,
    filter_case_id: Option<&str>,
    search_query: Option<&str>,
) -> Vec<SystemArtifact> {
    match &state.db {
        DbPool::Postgres(pool) => {
            let rows = sqlx::query(
                "SELECT id, case_id, COALESCE(evidence_id::text, '') AS evidence_id, artifact_type, source, timestamp, description, severity, COALESCE(extracted_at::text, '') AS extracted_at FROM system_artifacts ORDER BY timestamp DESC"
            )
            .fetch_all(pool)
            .await
            .unwrap_or_default();

            rows.into_iter()
                .map(|r| {
                    let id_val: uuid::Uuid = r.get("id");
                    let case_uuid: uuid::Uuid = r.get("case_id");
                    let ev_id: String = r.get("evidence_id");
                    let atype: String = r.get("artifact_type");
                    let src: String = r.get("source");
                    let ts: chrono::DateTime<chrono::Utc> = r.get("timestamp");
                    let desc: String = r.get("description");
                    let sev: String = r.get("severity");
                    let ext_at: String = r.get("extracted_at");

                    SystemArtifact {
                        id: id_val.to_string(),
                        case_id: case_uuid.to_string(),
                        evidence_id: ev_id,
                        artifact_type: atype,
                        source: src,
                        timestamp: ts.format("%d-%m-%Y %H:%M:%S").to_string(),
                        description: desc,
                        severity: sev,
                        extracted_at: ext_at,
                    }
                })
                .filter(|s| {
                    if let Some(cid) = filter_case_id {
                        if !cid.is_empty() && s.case_id != cid {
                            return false;
                        }
                    }
                    if let Some(q) = search_query {
                        if !q.is_empty() {
                            let q_lower = q.to_lowercase();
                            if !s.description.to_lowercase().contains(&q_lower)
                                && !s.source.to_lowercase().contains(&q_lower)
                            {
                                return false;
                            }
                        }
                    }
                    true
                })
                .collect()
        }
        DbPool::Sqlite(pool) => {
            let rows = sqlx::query(
                "SELECT id, case_id, COALESCE(evidence_id, '') AS evidence_id, artifact_type, source, timestamp, description, severity, COALESCE(extracted_at, '') AS extracted_at FROM system_artifacts ORDER BY timestamp DESC"
            )
            .fetch_all(pool)
            .await
            .unwrap_or_default();

            rows.into_iter()
                .map(|r| {
                    let id_val: String = r.get("id");
                    let case_id: String = r.get("case_id");
                    let ev_id: String = r.get("evidence_id");
                    let atype: String = r.get("artifact_type");
                    let src: String = r.get("source");
                    let ts: String = r.get("timestamp");
                    let desc: String = r.get("description");
                    let sev: String = r.get("severity");
                    let ext_at: String = r.get("extracted_at");

                    SystemArtifact {
                        id: id_val,
                        case_id,
                        evidence_id: ev_id,
                        artifact_type: atype,
                        source: src,
                        timestamp: ts,
                        description: desc,
                        severity: sev,
                        extracted_at: ext_at,
                    }
                })
                .filter(|s| {
                    if let Some(cid) = filter_case_id {
                        if !cid.is_empty() && s.case_id != cid {
                            return false;
                        }
                    }
                    if let Some(q) = search_query {
                        if !q.is_empty() {
                            let q_lower = q.to_lowercase();
                            if !s.description.to_lowercase().contains(&q_lower)
                                && !s.source.to_lowercase().contains(&q_lower)
                            {
                                return false;
                            }
                        }
                    }
                    true
                })
                .collect()
        }
    }
}

pub async fn list_timeline_events(state: &AppState) -> Vec<TimelineEvent> {
    match &state.db {
        DbPool::Postgres(pool) => {
            let rows = sqlx::query(
                "SELECT id, case_id, timestamp, category, title, description, source_artifact, icon FROM timeline_events"
            )
            .fetch_all(pool)
            .await
            .unwrap_or_default();

            rows.into_iter()
                .map(|r| {
                    let id_val: uuid::Uuid = r.get("id");
                    let case_uuid: uuid::Uuid = r.get("case_id");
                    let ts: chrono::DateTime<chrono::Utc> = r.get("timestamp");
                    let cat: String = r.get("category");
                    let title: String = r.get("title");
                    let desc: String = r.get("description");
                    let src: String = r.get("source_artifact");
                    let icon: String = r.get("icon");

                    TimelineEvent {
                        id: id_val.to_string(),
                        case_id: case_uuid.to_string(),
                        timestamp: ts.format("%d-%m-%Y %H:%M:%S").to_string(),
                        category: cat,
                        title,
                        description: desc,
                        source_artifact: src,
                        icon,
                    }
                })
                .collect()
        }
        DbPool::Sqlite(pool) => {
            let rows = sqlx::query(
                "SELECT id, case_id, timestamp, category, title, description, source_artifact, icon FROM timeline_events"
            )
            .fetch_all(pool)
            .await
            .unwrap_or_default();

            rows.into_iter()
                .map(|r| {
                    let id_val: String = r.get("id");
                    let case_id: String = r.get("case_id");
                    let ts: String = r.get("timestamp");
                    let cat: String = r.get("category");
                    let title: String = r.get("title");
                    let desc: String = r.get("description");
                    let src: String = r.get("source_artifact");
                    let icon: String = r.get("icon");

                    TimelineEvent {
                        id: id_val,
                        case_id,
                        timestamp: ts,
                        category: cat,
                        title,
                        description: desc,
                        source_artifact: src,
                        icon,
                    }
                })
                .collect()
        }
    }
}
