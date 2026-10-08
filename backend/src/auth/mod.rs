use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts, StatusCode},
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,      // User UUID
    pub username: String, // Username
    pub role: String,     // "ADMIN", "INVESTIGATOR", "ANALYST", "VIEWER"
    pub iat: usize,
    pub exp: usize,
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
    pub username: String,
    pub role: String,
}

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Password hashing failed: {}", e))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub fn create_token(
    user_id: &str,
    username: &str,
    role: &str,
    secret: &str,
    expires_in_secs: u64,
) -> Result<String, String> {
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        role: role.to_string(),
        iat: now,
        exp: now + (expires_in_secs as usize),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| format!("JWT generation error: {}", e))
}

pub fn verify_token(token: &str, secret: &str) -> Result<Claims, String> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    validation.leeway = 0; // Strict zero leeway for expiration enforcement
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| format!("Invalid or expired authentication token: {}", e))
}

impl AuthUser {
    pub fn require_role(&self, allowed_roles: &[&str]) -> Result<(), (StatusCode, String)> {
        if allowed_roles.contains(&self.role.as_str()) {
            Ok(())
        } else {
            Err((
                StatusCode::FORBIDDEN,
                format!(
                    "Access Denied: Role '{}' is unauthorized for this forensic operation",
                    self.role
                ),
            ))
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    crate::db::AppState: axum::extract::FromRef<S>,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = crate::db::AppState::from_ref(state);

        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    "Missing Authorization header".to_string(),
                )
            })?;

        if !auth_header.starts_with("Bearer ") {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Invalid Authorization format. Expected 'Bearer <token>'".to_string(),
            ));
        }

        let token = auth_header[7..].trim();
        let claims = verify_token(token, &app_state.jwt_secret)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;

        Ok(AuthUser {
            user_id: claims.sub,
            username: claims.username,
            role: claims.role,
        })
    }
}
