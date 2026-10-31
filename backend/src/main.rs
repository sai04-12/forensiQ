mod auth;
mod db;
mod forensics;
mod handlers;
mod models;

use axum::{
    routing::{get, post},
    Router,
};
use db::AppState;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Initialize database pool, JWT secret, and admin bootstrap account
    let state = AppState::init().await;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        // Public Auth Endpoint
        .route("/api/auth/login", post(handlers::login))
        // Protected Investigator APIs
        .route("/api/stats", get(handlers::get_stats))
        .route(
            "/api/cases",
            get(handlers::list_cases).post(handlers::create_case),
        )
        .route("/api/cases/:id", get(handlers::get_case_by_id))
        .route("/api/custody", get(handlers::list_custody_logs))
        .route("/api/evidence/acquire", post(handlers::acquire_evidence))
        .route("/api/evidence/verify", post(handlers::verify_hash))
        .route(
            "/api/artifacts/files",
            get(handlers::list_filesystem_artifacts),
        )
        .route("/api/artifacts/carve", post(handlers::carve_files))
        .route(
            "/api/artifacts/carved/:id/download",
            get(handlers::download_carved_file),
        )
        .route(
            "/api/artifacts/browser",
            get(handlers::list_browser_artifacts),
        )
        .route(
            "/api/artifacts/browser/extract",
            post(handlers::extract_browser_artifacts),
        )
        .route(
            "/api/artifacts/system",
            get(handlers::list_system_artifacts),
        )
        .route(
            "/api/artifacts/system/extract",
            post(handlers::extract_system_artifacts),
        )
        .route(
            "/api/artifacts/timeline",
            get(handlers::list_timeline_events),
        )
        .route("/api/reports/generate", post(handlers::generate_report))
        .route("/api/ioc/scan", post(handlers::scan_ioc_watchlist))
        .route("/api/ioc/watchlists", get(handlers::list_threat_watchlists))
        .route(
            "/api/forensics/memory",
            get(handlers::list_memory_processes),
        )
        .route(
            "/api/forensics/network",
            get(handlers::list_network_sessions),
        )
        .layer(cors)
        .with_state(state);

    let static_dir_path = if std::path::Path::new("static").exists() {
        "static"
    } else if std::path::Path::new("backend/static").exists() {
        "backend/static"
    } else if std::path::Path::new("../static").exists() {
        "../static"
    } else {
        "static"
    };

    let static_service = tower_http::services::ServeDir::new(static_dir_path)
        .fallback(tower_http::services::ServeFile::new(format!("{}/index.html", static_dir_path)));

    let app = app.fallback_service(static_service);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       ForensiQ Digital Forensic Toolkit Backend          ║");
    println!("║       Axum REST Server listening on http://{}   ║", addr);
    println!("║       Database Persistence: ACTIVE (SQLx Engine)        ║");
    println!("║       JWT Authentication & Role Security: ACTIVE        ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use auth::{hash_password, verify_password, AuthUser};
    use axum::http::StatusCode;
    use models::{AcquireEvidenceRequest, LoginRequest};
    use std::io::Write;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_argon2id_password_hashing() {
        let password = "InvestigatorSecretPass123!";
        let hash = hash_password(password).expect("Hashing failed");
        assert_ne!(password, hash);
        assert!(verify_password(password, &hash));
        assert!(!verify_password("WrongPassword!", &hash));
    }

    #[tokio::test]
    async fn test_jwt_generation_and_verification() {
        let secret = "TestSecretKey1234567890";
        let token =
            auth::create_token("user-123", "investigator_sai", "INVESTIGATOR", secret, 3600)
                .expect("Token creation failed");

        let claims = auth::verify_token(&token, secret).expect("Verification failed");
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.username, "investigator_sai");
        assert_eq!(claims.role, "INVESTIGATOR");
    }

    #[tokio::test]
    async fn test_jwt_expired_token_rejection() {
        let secret = "TestSecretKey1234567890";
        // Create token with 0 expiration (already expired)
        let token = auth::create_token("user-123", "investigator_sai", "INVESTIGATOR", secret, 0)
            .expect("Token creation failed");

        // Small sleep to ensure exp time passes
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let result = auth::verify_token(&token, secret);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_login_api_valid_credentials() {
        let state = AppState::init().await;

        let login_req = LoginRequest {
            username: "admin".to_string(),
            password: "AdminSecretPass123!".to_string(),
        };

        let res = handlers::login(axum::extract::State(state), axum::Json(login_req)).await;

        assert!(res.is_ok());
        let body = res.unwrap().0;
        assert!(body.success);
        let data = body.data.unwrap();
        assert_eq!(data.user.username, "admin");
        assert_eq!(data.user.role, "ADMIN");
        assert!(!data.access_token.is_empty());
    }

    #[tokio::test]
    async fn test_login_api_invalid_credentials() {
        let state = AppState::init().await;

        let login_req = LoginRequest {
            username: "admin".to_string(),
            password: "WrongInvalidPassword!".to_string(),
        };

        let res = handlers::login(axum::extract::State(state), axum::Json(login_req)).await;

        assert!(res.is_err());
        let (status, msg) = res.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(msg, "Invalid username or password");
    }

    #[tokio::test]
    async fn test_role_authorization_viewer_rejection_on_acquisition() {
        let state = AppState::init().await;

        // VIEWER role user
        let viewer_user = AuthUser {
            user_id: "viewer-id".to_string(),
            username: "viewer1".to_string(),
            role: "VIEWER".to_string(),
        };

        let req = AcquireEvidenceRequest {
            case_id: "CASE-2024-001".to_string(),
            file_name: "test.raw".to_string(),
            file_path: "c:\\forensiQ\\ForensiQ_Project_Abstract.pdf".to_string(),
            custodian: "ImpersonatedName".to_string(),
            write_blocked: false,
        };

        // VIEWER attempting evidence acquisition -> MUST return 403 FORBIDDEN
        let res =
            handlers::acquire_evidence(viewer_user, axum::extract::State(state), axum::Json(req))
                .await;

        assert!(res.is_err());
        let (status, _msg) = res.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_custodian_identity_derived_from_authenticated_jwt_user() {
        let state = AppState::init().await;

        // Create a real case first
        let test_case =
            db::cases::create_case(&state, "Custodian Test Case", "Investigator Dinesh")
                .await
                .expect("Failed to create test case");

        // Create temporary test evidence file in current workspace directory
        let curr_dir = std::env::current_dir().unwrap();
        let test_file_path = curr_dir.join("forensiq_custodian_auth_test.raw");
        {
            let mut file = std::fs::File::create(&test_file_path).unwrap();
            file.write_all(b"Custodian Identity Security Test Payload")
                .unwrap();
        }

        // INVESTIGATOR role user authenticated as "real_investigator_dinesh"
        let inv_user = AuthUser {
            user_id: "inv-uuid-1".to_string(),
            username: "real_investigator_dinesh".to_string(),
            role: "INVESTIGATOR".to_string(),
        };

        let req = AcquireEvidenceRequest {
            case_id: test_case.id,
            file_name: "custodian_auth_test.raw".to_string(),
            file_path: test_file_path.to_str().unwrap().to_string(),
            custodian: "AttackerFakeImpersonatedName".to_string(), // Client attempting impersonation!
            write_blocked: false,
        };

        let res = handlers::acquire_evidence(
            inv_user,
            axum::extract::State(state.clone()),
            axum::Json(req),
        )
        .await;

        assert!(res.is_ok());
        let evidence = res.unwrap().0;

        // Verify custodian was override with authentic JWT username!
        assert_eq!(evidence.acquired_by, "real_investigator_dinesh");
        assert_ne!(evidence.acquired_by, "AttackerFakeImpersonatedName");

        // Clean up temp file
        let _ = std::fs::remove_file(test_file_path);
    }

    #[tokio::test]
    async fn test_webkit_timestamp_conversion() {
        let chromium_us: i64 = 13350000000000000;
        let formatted = forensics::timestamp::webkit_to_utc_string(chromium_us);
        assert!(!formatted.is_empty());
        assert_ne!(formatted, "01-01-1601 00:00:00");
    }

    #[tokio::test]
    async fn test_chrome_history_sqlite_extraction() {
        use std::str::FromStr;
        let curr_dir = std::env::current_dir().unwrap();
        let db_file_path = curr_dir.join("forensiq_test_chrome_history.sqlite");
        let _ = std::fs::remove_file(&db_file_path);

        {
            let opts = sqlx::sqlite::SqliteConnectOptions::from_str(&format!(
                "sqlite://{}",
                db_file_path.display()
            ))
            .unwrap()
            .create_if_missing(true);
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .connect_with(opts)
                .await
                .unwrap();

            sqlx::query("CREATE TABLE IF NOT EXISTS urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);")
                .execute(&pool).await.unwrap();
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);",
            )
            .execute(&pool)
            .await
            .unwrap();

            sqlx::query("INSERT INTO urls VALUES (1, 'https://example.com', 'Example Domain', 5, 13350000000000000);")
                .execute(&pool).await.unwrap();
            sqlx::query("INSERT INTO urls VALUES (2, 'https://example.org', 'Example Organization', 3, 13350000000000000);")
                .execute(&pool).await.unwrap();

            sqlx::query("INSERT INTO visits VALUES (101, 1, 13350000000000000);")
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO visits VALUES (102, 2, 13350000000000000);")
                .execute(&pool)
                .await
                .unwrap();
        }

        let extracted = forensics::browser::extract_browser_history(
            db_file_path.to_str().unwrap(),
            "Chrome",
            "case-test-1",
            "ev-test-1",
        )
        .await
        .expect("Extraction failed");

        assert_eq!(extracted.len(), 2);
        assert_eq!(extracted[0].browser, "Chrome");
        assert_eq!(extracted[0].case_id, "case-test-1");
        assert_eq!(extracted[0].evidence_id, "ev-test-1");
        assert!(extracted.iter().any(|a| a.url == "https://example.com"));
        assert!(extracted.iter().any(|a| a.url == "https://example.org"));

        let _ = std::fs::remove_file(db_file_path);
    }

    #[tokio::test]
    async fn test_empty_history_database() {
        use std::str::FromStr;
        let curr_dir = std::env::current_dir().unwrap();
        let db_file_path = curr_dir.join("forensiq_test_empty_history.sqlite");
        let _ = std::fs::remove_file(&db_file_path);

        {
            let opts = sqlx::sqlite::SqliteConnectOptions::from_str(&format!(
                "sqlite://{}",
                db_file_path.display()
            ))
            .unwrap()
            .create_if_missing(true);
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .connect_with(opts)
                .await
                .unwrap();
            sqlx::query("CREATE TABLE IF NOT EXISTS urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);")
                .execute(&pool).await.unwrap();
        }

        let extracted = forensics::browser::extract_browser_history(
            db_file_path.to_str().unwrap(),
            "Edge",
            "case-empty-1",
            "ev-empty-1",
        )
        .await
        .expect("Extraction failed");

        assert_eq!(extracted.len(), 0);
        let _ = std::fs::remove_file(db_file_path);
    }

    #[tokio::test]
    async fn test_viewer_role_extraction_rejection() {
        let state = AppState::init().await;

        let viewer_user = AuthUser {
            user_id: "viewer-uuid".to_string(),
            username: "viewer_user".to_string(),
            role: "VIEWER".to_string(),
        };

        let req = models::ExtractBrowserRequest {
            case_id: "CASE-2024-001".to_string(),
            evidence_id: "ev-1".to_string(),
            browser: Some("Chrome".to_string()),
        };

        let res = handlers::extract_browser_artifacts(
            viewer_user,
            axum::extract::State(state),
            axum::Json(req),
        )
        .await;

        assert!(res.is_err());
        let (status, _) = res.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_synthetic_binary_file_carving_and_provenance() {
        let state = AppState::init().await;

        let case_title = format!("Carving Test Case {}", Uuid::new_v4());
        let test_case = db::cases::create_case(&state, &case_title, "Investigator Alpha")
            .await
            .expect("Failed to create test case");

        // Construct synthetic binary disk image payload with noise + valid PDF + noise + valid PNG + noise + valid JPEG
        let mut raw_image: Vec<u8> = vec![0xAA; 512]; // 512 bytes noise

        // 1. PDF
        let pdf_offset = raw_image.len();
        let pdf_payload =
            b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";
        raw_image.extend_from_slice(pdf_payload);

        // 512 bytes noise
        raw_image.extend(vec![0xBB; 512]);

        // 2. PNG
        let png_offset = raw_image.len();
        let mut png_payload: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]; // Header
                                                                                             // IHDR chunk (13 bytes payload + 4 bytes type + 4 bytes len + 4 bytes crc = 25 bytes)
        png_payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]); // Len 13
        png_payload.extend_from_slice(b"IHDR"); // Type
        png_payload.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x06, 0x00, 0x00, 0x00,
        ]); // 16x16 RGBA
        png_payload.extend_from_slice(&[0x1F, 0x5C, 0x9F, 0xC1]); // CRC
                                                                  // IEND chunk
        png_payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Len 0
        png_payload.extend_from_slice(b"IEND"); // Type
        png_payload.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]); // CRC
        raw_image.extend_from_slice(&png_payload);

        // 512 bytes noise
        raw_image.extend(vec![0xCC; 512]);

        // 3. JPEG
        let jpeg_offset = raw_image.len();
        let jpeg_payload = vec![
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01,
            0x00, 0x60, 0x00, 0x60, 0x00, 0x00, 0xFF, 0xD9,
        ];
        raw_image.extend_from_slice(&jpeg_payload);

        // Save raw image into intake directory
        let curr_dir = std::env::current_dir().unwrap();
        let evidence_file_path =
            curr_dir.join(format!("synthetic_evidence_{}.raw", Uuid::new_v4()));
        {
            let mut f = std::fs::File::create(&evidence_file_path).unwrap();
            f.write_all(&raw_image).unwrap();
        }

        let inv_user = AuthUser {
            user_id: "carve-inv-uuid".to_string(),
            username: "investigator_carver".to_string(),
            role: "INVESTIGATOR".to_string(),
        };

        // Acquire evidence first
        let acq_req = AcquireEvidenceRequest {
            case_id: test_case.id.clone(),
            file_name: "synthetic_evidence_disk.raw".to_string(),
            file_path: evidence_file_path.to_str().unwrap().to_string(),
            custodian: "investigator_carver".to_string(),
            write_blocked: true,
        };

        let acq_res = handlers::acquire_evidence(
            inv_user.clone(),
            axum::extract::State(state.clone()),
            axum::Json(acq_req),
        )
        .await
        .expect("Failed to acquire synthetic evidence");

        let evidence_id = acq_res.0.id;
        let original_hash = acq_res.0.sha256_hash;

        // Perform carving
        let carve_req = models::FileCarveRequest {
            case_id: test_case.id.clone(),
            evidence_id: evidence_id.clone(),
            file_types: Some(vec![
                "pdf".to_string(),
                "png".to_string(),
                "jpeg".to_string(),
            ]),
            max_files: None,
            max_file_size: None,
        };

        let carve_res = handlers::carve_files(
            inv_user.clone(),
            axum::extract::State(state.clone()),
            axum::Json(carve_req),
        )
        .await
        .expect("Carving failed");

        let carve_data = carve_res.0.data.unwrap();

        assert_eq!(carve_data.candidates_found, 3);
        assert_eq!(carve_data.files_recovered, 3);
        assert_eq!(carve_data.files_invalid, 0);
        assert_eq!(carve_data.duplicates_skipped, 0);

        // CRITICAL INTEGRITY TEST: Verify original evidence hash remains unchanged
        let after_raw_bytes = std::fs::read(&evidence_file_path).unwrap();
        let (after_hash, _) = forensics::carving::compute_bytes_hashes(&after_raw_bytes);
        assert_eq!(
            original_hash, after_hash,
            "ORIGINAL EVIDENCE WAS MODIFIED DURING CARVING!"
        );

        // Retrieve persisted artifacts and inspect metadata
        let all_artifacts = db::artifacts::list_file_artifacts(&state).await;
        let artifacts: Vec<_> = all_artifacts
            .into_iter()
            .filter(|a| a.case_id == test_case.id)
            .collect();

        assert_eq!(artifacts.len(), 3);

        let pdf_art = artifacts.iter().find(|a| a.file_type == "PDF").unwrap();
        assert_eq!(pdf_art.offset_bytes, pdf_offset as u64);
        assert_eq!(pdf_art.size_bytes, pdf_payload.len() as u64);
        assert_eq!(pdf_art.validation_status, "VALID");
        assert_eq!(pdf_art.source_evidence_hash, original_hash);

        let png_art = artifacts.iter().find(|a| a.file_type == "PNG").unwrap();
        assert_eq!(png_art.offset_bytes, png_offset as u64);
        assert_eq!(png_art.size_bytes, png_payload.len() as u64);
        assert_eq!(png_art.validation_status, "VALID");

        let jpeg_art = artifacts.iter().find(|a| a.file_type == "JPEG").unwrap();
        assert_eq!(jpeg_art.offset_bytes, jpeg_offset as u64);
        assert_eq!(jpeg_art.size_bytes, jpeg_payload.len() as u64);
        assert_eq!(jpeg_art.validation_status, "VALID");

        // Clean up
        let _ = std::fs::remove_file(evidence_file_path);
    }

    #[tokio::test]
    async fn test_carve_empty_or_no_signature_evidence_returns_zero() {
        let state = AppState::init().await;

        let case_title = format!("Empty Carve Case {}", Uuid::new_v4());
        let test_case = db::cases::create_case(&state, &case_title, "Investigator Beta")
            .await
            .expect("Failed to create test case");

        let curr_dir = std::env::current_dir().unwrap();
        let evidence_file_path = curr_dir.join(format!("empty_noise_{}.raw", Uuid::new_v4()));
        {
            let mut f = std::fs::File::create(&evidence_file_path).unwrap();
            f.write_all(&[0x11; 1024]).unwrap(); // pure noise, no magic bytes
        }

        let inv_user = AuthUser {
            user_id: "carve-inv-uuid-2".to_string(),
            username: "investigator_carver_2".to_string(),
            role: "INVESTIGATOR".to_string(),
        };

        let acq_res = handlers::acquire_evidence(
            inv_user.clone(),
            axum::extract::State(state.clone()),
            axum::Json(AcquireEvidenceRequest {
                case_id: test_case.id.clone(),
                file_name: "empty_noise_evidence.raw".to_string(),
                file_path: evidence_file_path.to_str().unwrap().to_string(),
                custodian: "investigator_carver_2".to_string(),
                write_blocked: true,
            }),
        )
        .await
        .unwrap();

        let carve_res = handlers::carve_files(
            inv_user,
            axum::extract::State(state.clone()),
            axum::Json(models::FileCarveRequest {
                case_id: test_case.id.clone(),
                evidence_id: acq_res.0.id,
                file_types: Some(vec![
                    "pdf".to_string(),
                    "png".to_string(),
                    "jpeg".to_string(),
                ]),
                max_files: None,
                max_file_size: None,
            }),
        )
        .await
        .unwrap();

        let carve_data = carve_res.0.data.unwrap();
        assert_eq!(carve_data.candidates_found, 0);
        assert_eq!(carve_data.files_recovered, 0);
        assert_eq!(carve_data.files_invalid, 0);
        assert_eq!(carve_data.duplicates_skipped, 0);

        let _ = std::fs::remove_file(evidence_file_path);
    }

    #[tokio::test]
    async fn test_carve_viewer_role_rejection() {
        let state = AppState::init().await;

        let viewer_user = AuthUser {
            user_id: "viewer-carve-id".to_string(),
            username: "viewer_carver".to_string(),
            role: "VIEWER".to_string(),
        };

        let res = handlers::carve_files(
            viewer_user,
            axum::extract::State(state),
            axum::Json(models::FileCarveRequest {
                case_id: "case-1".to_string(),
                evidence_id: "ev-1".to_string(),
                file_types: Some(vec!["pdf".to_string()]),
                max_files: None,
                max_file_size: None,
            }),
        )
        .await;

        assert!(res.is_err());
        let (status, _) = res.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
