pub mod artifacts;
pub mod cases;
pub mod custody;
pub mod evidence;
pub mod users;

use sqlx::{Pool, Postgres, Sqlite};
use std::env;
use std::sync::Arc;
use tracing::info;

#[derive(Clone)]
pub enum DbPool {
    Postgres(Pool<Postgres>),
    Sqlite(Pool<Sqlite>),
}

#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub evidence_root: String,
    pub jwt_secret: String,
    pub jwt_expiration_secs: u64,
    pub reports_count: Arc<std::sync::Mutex<usize>>,
}

impl AppState {
    pub async fn init() -> Self {
        // Load .env if present
        let _ = dotenvy::dotenv();

        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/forensiq".to_string());

        let evidence_root = env::var("FORENSIQ_EVIDENCE_ROOT")
            .unwrap_or_else(|_| "c:\\forensiQ\\evidence_vault".to_string());

        // Ensure evidence root intake directory exists
        let _ = std::fs::create_dir_all(&evidence_root);

        info!(
            "Initializing ForensiQ Database Pool from URL: {}",
            database_url
        );

        let db_pool = if database_url.starts_with("postgres://")
            || database_url.starts_with("postgresql://")
        {
            match sqlx::postgres::PgPoolOptions::new()
                .max_connections(10)
                .min_connections(1)
                .acquire_timeout(std::time::Duration::from_secs(3))
                .connect(&database_url)
                .await
            {
                Ok(pool) => {
                    info!("Successfully connected to PostgreSQL connection pool.");
                    // Run migrations
                    if let Err(e) = sqlx::migrate!("./migrations").run(&pool).await {
                        tracing::warn!("PostgreSQL migration notice: {}", e);
                    }
                    DbPool::Postgres(pool)
                }
                Err(err) => {
                    tracing::warn!("Could not connect to PostgreSQL at {}: {}. Falling back to embedded SQLite persistent store.", database_url, err);
                    Self::init_sqlite_fallback().await
                }
            }
        } else {
            Self::init_sqlite_fallback().await
        };

        let jwt_secret = env::var("JWT_SECRET")
            .unwrap_or_else(|_| "ForensiQ_Secret_Key_Change_In_Production_982371948".to_string());

        let jwt_expiration_secs = env::var("JWT_EXPIRATION_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);

        let state = Self {
            db: db_pool,
            evidence_root,
            jwt_secret,
            jwt_expiration_secs,
            reports_count: Arc::new(std::sync::Mutex::new(4)),
        };

        // Seed initial admin bootstrap & demo data into DB if empty
        let _ = users::seed_admin_bootstrap_if_empty(&state).await;
        let _ = cases::seed_demo_data_if_empty(&state).await;

        state
    }

    async fn init_sqlite_fallback() -> DbPool {
        let db_path = "sqlite:forensiq_store.db?mode=rwc";
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect(db_path)
            .await
            .expect("Failed to initialize SQLite persistent store");

        info!("Embedded SQLite persistent database initialized at forensiq_store.db");

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            );",
        )
        .execute(&pool)
        .await;

        // Run migrations for SQLite
        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                case_number TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                investigator TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )
        .execute(&pool)
        .await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS evidence_items (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                source_path TEXT,
                stored_path TEXT,
                file_size INTEGER NOT NULL,
                sha256_hash TEXT NOT NULL,
                sha1_hash TEXT,
                acquired_at TEXT NOT NULL,
                write_blocked INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );",
        )
        .execute(&pool)
        .await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS chain_of_custody (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                evidence_id TEXT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                custodian TEXT NOT NULL,
                sha256_at_action TEXT,
                integrity_status TEXT NOT NULL,
                notes TEXT
            );",
        )
        .execute(&pool)
        .await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS file_artifacts (
                id TEXT PRIMARY KEY, case_id TEXT NOT NULL, evidence_id TEXT, name TEXT NOT NULL, path TEXT NOT NULL,
                size_bytes INTEGER NOT NULL, file_type TEXT NOT NULL, mime_type TEXT NOT NULL, offset_bytes INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL, modified_at TEXT NOT NULL, sha256_hash TEXT NOT NULL, sha1_hash TEXT NOT NULL DEFAULT '',
                source_evidence_hash TEXT NOT NULL DEFAULT '', is_carved INTEGER NOT NULL DEFAULT 0,
                recovery_status TEXT NOT NULL, validation_status TEXT NOT NULL DEFAULT 'VALID'
            );"
        ).execute(&pool).await;

        let _ = sqlx::query("ALTER TABLE file_artifacts ADD COLUMN evidence_id TEXT;")
            .execute(&pool)
            .await;
        let _ = sqlx::query("ALTER TABLE file_artifacts ADD COLUMN mime_type TEXT DEFAULT 'application/octet-stream';").execute(&pool).await;
        let _ =
            sqlx::query("ALTER TABLE file_artifacts ADD COLUMN offset_bytes INTEGER DEFAULT 0;")
                .execute(&pool)
                .await;
        let _ = sqlx::query("ALTER TABLE file_artifacts ADD COLUMN sha1_hash TEXT DEFAULT '';")
            .execute(&pool)
            .await;
        let _ = sqlx::query(
            "ALTER TABLE file_artifacts ADD COLUMN source_evidence_hash TEXT DEFAULT '';",
        )
        .execute(&pool)
        .await;
        let _ = sqlx::query(
            "ALTER TABLE file_artifacts ADD COLUMN validation_status TEXT DEFAULT 'VALID';",
        )
        .execute(&pool)
        .await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS browser_artifacts (
                id TEXT PRIMARY KEY, case_id TEXT NOT NULL, url TEXT NOT NULL, title TEXT NOT NULL,
                visit_time TEXT NOT NULL, visit_count INTEGER NOT NULL, browser TEXT NOT NULL, category TEXT NOT NULL
            );"
        ).execute(&pool).await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS system_artifacts (
                id TEXT PRIMARY KEY, case_id TEXT NOT NULL, artifact_type TEXT NOT NULL, source TEXT NOT NULL,
                timestamp TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL
            );"
        ).execute(&pool).await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS timeline_events (
                id TEXT PRIMARY KEY, case_id TEXT NOT NULL, timestamp TEXT NOT NULL, category TEXT NOT NULL,
                title TEXT NOT NULL, description TEXT NOT NULL, source_artifact TEXT NOT NULL, icon TEXT NOT NULL
            );"
        ).execute(&pool).await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS ioc_matches (
                id TEXT PRIMARY KEY, case_id TEXT NOT NULL, ioc_type TEXT NOT NULL, indicator_value TEXT NOT NULL,
                matched_source TEXT NOT NULL, threat_severity TEXT NOT NULL, confidence_percentage INTEGER NOT NULL,
                description TEXT NOT NULL, matched_at TEXT NOT NULL
            );"
        ).execute(&pool).await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS threat_watchlists (
                id TEXT PRIMARY KEY, category TEXT NOT NULL, value TEXT NOT NULL, threat_name TEXT NOT NULL, added_by TEXT NOT NULL
            );"
        ).execute(&pool).await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS memory_processes (
                pid INTEGER NOT NULL, ppid INTEGER NOT NULL, process_name TEXT NOT NULL, path TEXT NOT NULL,
                mem_usage_mb REAL NOT NULL, has_dll_injection INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
                PRIMARY KEY (pid, process_name)
            );"
        ).execute(&pool).await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS network_sessions (
                session_id TEXT PRIMARY KEY, protocol TEXT NOT NULL, src_ip TEXT NOT NULL, src_port INTEGER NOT NULL,
                dst_ip TEXT NOT NULL, dst_port INTEGER NOT NULL, packet_count INTEGER NOT NULL, total_bytes INTEGER NOT NULL,
                is_suspicious INTEGER NOT NULL DEFAULT 0, timestamp TEXT NOT NULL
            );"
        ).execute(&pool).await;

        DbPool::Sqlite(pool)
    }
}
