use crate::auth::hash_password;
use crate::db::{AppState, DbPool};
use crate::models::{User, UserResponse};
use chrono::Utc;
use sqlx::Row;
use uuid::Uuid;

pub async fn create_user(
    state: &AppState,
    username: &str,
    password_plain: &str,
    role: &str,
) -> Result<User, String> {
    let pwd_hash = hash_password(password_plain)?;
    let id_str = Uuid::new_v4().to_string();
    let now_str = Utc::now().format("%d-%m-%Y %H:%M:%S").to_string();

    match &state.db {
        DbPool::Postgres(pool) => {
            let id_uuid = Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::new_v4());
            let _ = sqlx::query(
                "INSERT INTO users (id, username, password_hash, role, created_at) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)"
            )
            .bind(id_uuid)
            .bind(username)
            .bind(&pwd_hash)
            .bind(role)
            .execute(pool)
            .await
            .map_err(|e| format!("Database user insertion failed: {}", e))?;
        }
        DbPool::Sqlite(pool) => {
            let _ = sqlx::query(
                "INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)"
            )
            .bind(&id_str)
            .bind(username)
            .bind(&pwd_hash)
            .bind(role)
            .bind(&now_str)
            .execute(pool)
            .await
            .map_err(|e| format!("Database user insertion failed: {}", e))?;
        }
    }

    Ok(User {
        id: id_str,
        username: username.to_string(),
        password_hash: pwd_hash,
        role: role.to_string(),
        created_at: now_str,
    })
}

pub async fn find_user_by_username(state: &AppState, username: &str) -> Result<User, String> {
    match &state.db {
        DbPool::Postgres(pool) => {
            let row = sqlx::query(
                "SELECT id, username, password_hash, role, created_at FROM users WHERE username = $1"
            )
            .bind(username)
            .fetch_optional(pool)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Invalid username or password".to_string())?;

            let id_uuid: Uuid = row.get("id");
            let uname: String = row.get("username");
            let pwd_hash: String = row.get("password_hash");
            let role: String = row.get("role");
            let created_at: chrono::DateTime<Utc> = row.get("created_at");

            Ok(User {
                id: id_uuid.to_string(),
                username: uname,
                password_hash: pwd_hash,
                role,
                created_at: created_at.format("%d-%m-%Y %H:%M:%S").to_string(),
            })
        }
        DbPool::Sqlite(pool) => {
            let row = sqlx::query(
                "SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?"
            )
            .bind(username)
            .fetch_optional(pool)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Invalid username or password".to_string())?;

            let id_val: String = row.get("id");
            let uname: String = row.get("username");
            let pwd_hash: String = row.get("password_hash");
            let role: String = row.get("role");
            let created_at: String = row.get("created_at");

            Ok(User {
                id: id_val,
                username: uname,
                password_hash: pwd_hash,
                role,
                created_at,
            })
        }
    }
}

pub async fn seed_admin_bootstrap_if_empty(state: &AppState) -> Result<(), String> {
    let admin_username =
        std::env::var("FORENSIQ_ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string());
    let admin_password = std::env::var("FORENSIQ_ADMIN_PASSWORD")
        .unwrap_or_else(|_| "AdminSecretPass123!".to_string());

    if find_user_by_username(state, &admin_username).await.is_err() {
        let _ = create_user(state, &admin_username, &admin_password, "ADMIN").await?;
        tracing::info!(
            "Bootstrap administrator account created (Username: '{}')",
            admin_username
        );
    }

    // Seed default investigator accounts for test roles
    if find_user_by_username(state, "investigator1").await.is_err() {
        let _ = create_user(
            state,
            "investigator1",
            "InvestigatorPass123!",
            "INVESTIGATOR",
        )
        .await;
    }
    if find_user_by_username(state, "analyst1").await.is_err() {
        let _ = create_user(state, "analyst1", "AnalystPass123!", "ANALYST").await;
    }
    if find_user_by_username(state, "viewer1").await.is_err() {
        let _ = create_user(state, "viewer1", "ViewerPass123!", "VIEWER").await;
    }

    Ok(())
}

impl User {
    pub fn to_response(&self) -> UserResponse {
        UserResponse {
            id: self.id.clone(),
            username: self.username.clone(),
            role: self.role.clone(),
        }
    }
}
