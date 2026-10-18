use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::header::{self, HeaderValue};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tower_http::services::{ServeDir, ServeFile};

use crate::config::{origin_of, ServerConfig};
use crate::crypto::{self, KdfParams};
use crate::db::{self, Database, DbError, E2eKeys, PublicUser, RecoveryMethod};
use crate::session::{self, RateLimiter, Session, SessionStore};

pub struct AppState {
    pub config: Arc<ServerConfig>,
    pub db: Arc<Database>,
    pub sessions: Arc<SessionStore>,
    pub limiter: Arc<RateLimiter>,
    pub dist_dir: PathBuf,
}

type Shared = State<Arc<AppState>>;
type Peer = ConnectInfo<SocketAddr>;

/// Size limits for client-encrypted blobs.
const MAX_VAULT_BLOB: usize = 32 * 1024 * 1024;
const MAX_KEY_BLOB: usize = 8 * 1024;
const MAX_NAME: usize = 100;

// ---------------------------------------------------------------------------
// Errors & responses
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ApiError {
    BadRequest(&'static str),
    Unauthorized(&'static str, Option<u32>),
    Forbidden(&'static str),
    NotFound,
    Conflict(i64),
    Taken,
    TooMany(i64),
    Internal(String),
}

impl From<DbError> for ApiError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::Unauthorized => ApiError::Unauthorized("Invalid credentials", None),
            DbError::Conflict(revision) => ApiError::Conflict(revision),
            DbError::Taken => ApiError::Taken,
            DbError::NotFound => ApiError::NotFound,
            DbError::Internal(message) => ApiError::Internal(message),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, serde_json::json!({ "error": m })),
            ApiError::Unauthorized(m, left) => (
                StatusCode::UNAUTHORIZED,
                match left {
                    Some(left) => serde_json::json!({ "error": m, "attemptsLeft": left }),
                    None => serde_json::json!({ "error": m }),
                },
            ),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, serde_json::json!({ "error": m })),
            ApiError::NotFound => (StatusCode::NOT_FOUND, serde_json::json!({ "error": "Not found" })),
            ApiError::Conflict(revision) => (
                StatusCode::CONFLICT,
                serde_json::json!({ "error": "The vault was modified elsewhere", "revision": revision }),
            ),
            ApiError::Taken => (
                StatusCode::CONFLICT,
                serde_json::json!({ "error": "This username is already taken", "code": "username_taken" }),
            ),
            ApiError::TooMany(retry_ms) => {
                let minutes = (retry_ms + 59_999) / 60_000;
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({
                        "error": "Too many failed attempts. Please try again later.",
                        "attemptsLeft": 0,
                        "lockoutTime": minutes,
                    })),
                )
                    .into_response();
                if let Ok(value) = HeaderValue::from_str(&((retry_ms + 999) / 1000).to_string()) {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                }
                return response;
            }
            ApiError::Internal(message) => {
                eprintln!("internal error: {message}");
                (StatusCode::INTERNAL_SERVER_ERROR, serde_json::json!({ "error": "Internal server error" }))
            }
        };
        (status, Json(body)).into_response()
    }
}

type ApiResult = Result<Response, ApiError>;

fn ok(value: serde_json::Value) -> ApiResult {
    Ok((StatusCode::OK, Json(value)).into_response())
}

fn parse<T: DeserializeOwned>(body: &Bytes) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|_| ApiError::BadRequest("Invalid request body"))
}

/// Runs CPU-heavy work (Argon2) off the async workers.
async fn blocking<T, F>(work: F) -> Result<T, ApiError>
where
    F: FnOnce() -> Result<T, DbError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|err| ApiError::Internal(format!("worker failed: {err}")))?
        .map_err(ApiError::from)
}

// ---------------------------------------------------------------------------
// Cookies & sessions
// ---------------------------------------------------------------------------

/// `__Host-` cookies are pinned to this exact origin over HTTPS; plain-HTTP
/// development keeps the unprefixed name.
fn cookie_name(config: &ServerConfig) -> &'static str {
    if config.is_https() {
        "__Host-xvault_session"
    } else {
        session::SESSION_COOKIE_NAME
    }
}

fn parse_cookies(headers: &HeaderMap) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for value in headers.get_all(header::COOKIE) {
        let Ok(value) = value.to_str() else { continue };
        for part in value.split(';') {
            if let Some((key, value)) = part.trim().split_once('=') {
                cookies.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    cookies
}

fn session_token(headers: &HeaderMap, config: &ServerConfig) -> Option<String> {
    parse_cookies(headers).remove(cookie_name(config))
}

fn require_session(headers: &HeaderMap, state: &AppState) -> Result<(Session, String), ApiError> {
    let token = session_token(headers, &state.config)
        .ok_or(ApiError::Unauthorized("Authentication required", None))?;
    let session = state
        .sessions
        .get(&token)
        .ok_or(ApiError::Unauthorized("Authentication required", None))?;
    Ok((session, token))
}

fn session_cookie(config: &ServerConfig, token: &str, expires_at: i64) -> String {
    let max_age = ((expires_at - session::now_ms()) / 1000).max(0);
    let secure = if config.is_https() { "; Secure" } else { "" };
    format!(
        "{}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}",
        cookie_name(config)
    )
}

fn cleared_cookie(config: &ServerConfig) -> String {
    let secure = if config.is_https() { "; Secure" } else { "" };
    format!("{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}", cookie_name(config))
}

fn with_cookie(mut response: Response, cookie: String) -> Response {
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

fn start_session(state: &AppState, user: &PublicUser) -> ApiResult {
    let (token, expires_at) = state.sessions.create(user.id, &user.login_id);
    let response = ok(serde_json::json!({ "success": true, "user": user_json(user) }))?;
    Ok(with_cookie(response, session_cookie(&state.config, &token, expires_at)))
}

fn user_json(user: &PublicUser) -> serde_json::Value {
    serde_json::json!({
        "id": user.id,
        "loginId": user.login_id,
        "name": user.name,
        "logo": user.logo,
        "recoveryEnabled": user.recovery_enabled,
        "masterKeyEnabled": user.master_key_enabled,
    })
}

// ---------------------------------------------------------------------------
// Client IP & rate limiting
// ---------------------------------------------------------------------------

fn client_ip(headers: &HeaderMap, peer: SocketAddr, config: &ServerConfig) -> IpAddr {
    if config.trust_proxy {
        // Right-most hop is the one added by our own reverse proxy; anything
        // to its left is client-controlled.
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
    }
    peer.ip()
}

struct Guard {
    check_keys: Vec<String>,
    fail_keys: Vec<(String, u32)>,
    reset_keys: Vec<String>,
}

impl Guard {
    /// Sign-in / recovery guard: per (account, IP), per IP, per account.
    fn account(scope: &str, login_id: &str, ip: IpAddr) -> Self {
        let acct_ip = format!("{scope}-acct-ip:{login_id}:{ip}");
        let ip_key = format!("ip:{ip}");
        let acct = format!("{scope}-acct:{login_id}");
        Guard {
            check_keys: vec![acct_ip.clone(), ip_key.clone(), acct.clone()],
            fail_keys: vec![
                (acct_ip.clone(), session::LIMIT_ACCOUNT_IP),
                (ip_key, session::LIMIT_IP),
                (acct, session::LIMIT_ACCOUNT),
            ],
            reset_keys: vec![acct_ip],
        }
    }

    /// Re-authentication guard for an already signed-in user.
    fn user(user_id: i64, ip: IpAddr) -> Self {
        let user = format!("user:{user_id}");
        let ip_key = format!("ip:{ip}");
        Guard {
            check_keys: vec![user.clone(), ip_key.clone()],
            fail_keys: vec![(user.clone(), session::LIMIT_USER_REAUTH), (ip_key, session::LIMIT_IP)],
            reset_keys: vec![user],
        }
    }

    fn check(&self, limiter: &RateLimiter) -> Result<(), ApiError> {
        limiter
            .check(&self.check_keys)
            .map_err(|blocked| ApiError::TooMany(blocked.retry_after_ms))
    }

    /// Converts the outcome into rate-limiter bookkeeping.
    fn settle<T>(&self, limiter: &RateLimiter, result: Result<T, ApiError>) -> Result<T, ApiError> {
        match result {
            Ok(value) => {
                limiter.success(&self.reset_keys);
                Ok(value)
            }
            Err(ApiError::Unauthorized(message, _)) => {
                let left = limiter.fail(&self.fail_keys);
                Err(ApiError::Unauthorized(message, Some(left)))
            }
            Err(other) => Err(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

/// Normalizes a username for sign-in / recovery. Malformed input gets the
/// same answer as a wrong password: no format oracle.
fn valid_login_id(login_id: &str) -> Result<String, ApiError> {
    crypto::normalize_username(login_id).ok_or(ApiError::Unauthorized("Invalid credentials", None))
}

fn valid_proof(proof: &str) -> Result<(), ApiError> {
    if crypto::is_valid_proof(proof) {
        Ok(())
    } else {
        Err(ApiError::BadRequest("Malformed key material"))
    }
}

fn valid_blob(blob: &str, max: usize) -> Result<(), ApiError> {
    if crypto::is_valid_blob(blob, max) {
        Ok(())
    } else {
        Err(ApiError::BadRequest("Malformed encrypted payload"))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewKeys {
    auth_key: String,
    kdf: serde_json::Value,
    vault_key_wrapped: String,
}

impl NewKeys {
    fn validate(&self) -> Result<KdfParams, ApiError> {
        valid_proof(&self.auth_key)?;
        valid_blob(&self.vault_key_wrapped, MAX_KEY_BLOB)?;
        KdfParams::from_json(&self.kdf).map_err(|_| ApiError::BadRequest("Invalid KDF parameters"))
    }
}

fn parse_method(method: &str) -> Result<RecoveryMethod, ApiError> {
    match method {
        "phrase" => Ok(RecoveryMethod::Phrase),
        "key" => Ok(RecoveryMethod::MasterKey),
        _ => Err(ApiError::BadRequest("Unknown recovery method")),
    }
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginIdBody {
    login_id: String,
}

/// Returns the KDF parameters the browser must use to derive keys. Unknown
/// login IDs get deterministic fake parameters (no enumeration).
async fn prelogin(State(state): Shared, body: Bytes) -> ApiResult {
    let body: LoginIdBody = parse(&body)?;
    let kdf = match crypto::normalize_username(&body.login_id) {
        Some(username) => state.db.prelogin(&username)?,
        None => KdfParams::fake(b"invalid-username", body.login_id.trim()),
    };
    ok(serde_json::json!({ "kdf": kdf }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterBody {
    username: String,
    #[serde(flatten)]
    keys: NewKeys,
    encrypted_data: String,
    invite_code: Option<String>,
}

async fn register(State(state): Shared, ConnectInfo(peer): Peer, headers: HeaderMap, body: Bytes) -> ApiResult {
    if !state.config.allow_registration {
        return Err(ApiError::Forbidden("Registration is disabled"));
    }
    let ip = client_ip(&headers, peer, &state.config);
    let key = format!("register:{ip}");
    state
        .limiter
        .check(&[key.clone()])
        .map_err(|b| ApiError::TooMany(b.retry_after_ms))?;

    let body: RegisterBody = parse(&body)?;
    // Every sign-up attempt consumes budget: at most a few per IP per day.
    state.limiter.fail(&[(key, 5)]);
    if let Some(expected) = &state.config.registration_code {
        let given = body.invite_code.as_deref().unwrap_or("").trim();
        if !crypto::ct_eq(given.as_bytes(), expected.as_bytes()) {
            return Err(ApiError::Forbidden("Invalid invitation code"));
        }
    }
    let username = crypto::normalize_username(&body.username).ok_or(ApiError::BadRequest(
        "Username must be 3-32 characters: letters, digits, '.', '_' or '-' (not at the start or end)",
    ))?;
    let kdf = body.keys.validate()?;
    valid_blob(&body.encrypted_data, MAX_VAULT_BLOB)?;

    let db = state.db.clone();
    let login_id = username.clone();
    let user_id = blocking(move || {
        let keys = E2eKeys {
            auth_key: &body.keys.auth_key,
            kdf: &kdf,
            vault_key_wrapped: &body.keys.vault_key_wrapped,
        };
        db.create_user(&username, &keys, &body.encrypted_data)
    })
    .await?;

    let user = state.db.get_user_profile(user_id)?;
    let (token, expires_at) = state.sessions.create(user.id, &user.login_id);
    let response = ok(serde_json::json!({ "success": true, "loginId": login_id, "user": user_json(&user) }))?;
    Ok(with_cookie(response, session_cookie(&state.config, &token, expires_at)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginBody {
    login_id: String,
    auth_key: String,
}

async fn login(State(state): Shared, ConnectInfo(peer): Peer, headers: HeaderMap, body: Bytes) -> ApiResult {
    let body: LoginBody = parse(&body)?;
    let ip = client_ip(&headers, peer, &state.config);
    let login_id = body.login_id.trim().to_ascii_lowercase();
    let guard = Guard::account("login", &login_id, ip);
    guard.check(&state.limiter)?;
    valid_proof(&body.auth_key)?;

    let db = state.db.clone();
    let auth_key = body.auth_key;
    let result = match valid_login_id(&login_id) {
        Ok(id) => blocking(move || db.authenticate(&id, &auth_key)).await,
        Err(err) => {
            let _ = tokio::task::spawn_blocking(move || crypto::dummy_verify(&auth_key)).await;
            Err(err)
        }
    };
    let user = guard.settle(&state.limiter, result)?;
    start_session(&state, &user)
}

async fn logout(State(state): Shared, headers: HeaderMap) -> ApiResult {
    if let Some(token) = session_token(&headers, &state.config) {
        state.sessions.destroy(&token);
    }
    let response = ok(serde_json::json!({ "success": true }))?;
    Ok(with_cookie(response, cleared_cookie(&state.config)))
}

async fn status(State(state): Shared, headers: HeaderMap) -> ApiResult {
    let registration = state.config.allow_registration;
    let invite = registration && state.config.registration_code.is_some();
    match session_token(&headers, &state.config).and_then(|t| state.sessions.get(&t)) {
        Some(session) => ok(serde_json::json!({
            "authenticated": true,
            "loginId": session.login_id,
            "registrationEnabled": registration,
            "inviteRequired": invite,
        })),
        None => ok(serde_json::json!({
            "authenticated": false,
            "registrationEnabled": registration,
            "inviteRequired": invite,
        })),
    }
}

// ---------------------------------------------------------------------------
// Profile & account
// ---------------------------------------------------------------------------

async fn get_profile(State(state): Shared, headers: HeaderMap) -> ApiResult {
    let (session, _) = require_session(&headers, &state)?;
    let user = state.db.get_user_profile(session.user_id)?;
    ok(serde_json::json!({ "success": true, "user": user_json(&user) }))
}

async fn put_profile(State(state): Shared, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (session, _) = require_session(&headers, &state)?;
    let payload: serde_json::Value = parse(&body)?;

    let name = match payload.get("name") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => {
            let name = value.as_str().ok_or(ApiError::BadRequest("Invalid name"))?.trim();
            if name.is_empty() || name.chars().count() > MAX_NAME || name.chars().any(char::is_control) {
                return Err(ApiError::BadRequest("Vault name must be 1-100 characters"));
            }
            Some(name.to_string())
        }
    };
    let logo = match payload.get("logo") {
        None => None,
        Some(serde_json::Value::Null) => Some(None),
        Some(value) => {
            let logo = value.as_str().ok_or(ApiError::BadRequest("Invalid logo"))?;
            if !db::is_valid_logo(logo) {
                return Err(ApiError::BadRequest("Logo must be a PNG, JPEG, WebP or GIF image under 256 KB"));
            }
            Some(Some(logo.to_string()))
        }
    };

    state.db.update_user_profile(
        session.user_id,
        name.as_deref(),
        logo.as_ref().map(|l| l.as_deref()),
    )?;
    ok(serde_json::json!({ "success": true }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePasswordBody {
    current_auth_key: String,
    #[serde(flatten)]
    keys: NewKeys,
}

async fn change_password(State(state): Shared, ConnectInfo(peer): Peer, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (session, token) = require_session(&headers, &state)?;
    let guard = Guard::user(session.user_id, client_ip(&headers, peer, &state.config));
    guard.check(&state.limiter)?;
    let body: ChangePasswordBody = parse(&body)?;
    valid_proof(&body.current_auth_key)?;
    let kdf = body.keys.validate()?;

    let db = state.db.clone();
    let user_id = session.user_id;
    let result = blocking(move || {
        let keys = E2eKeys {
            auth_key: &body.keys.auth_key,
            kdf: &kdf,
            vault_key_wrapped: &body.keys.vault_key_wrapped,
        };
        db.change_password(user_id, &body.current_auth_key, &keys)
    })
    .await;
    guard.settle(&state.limiter, result)?;

    // Every other device must sign in again with the new password.
    state.sessions.revoke_user(session.user_id, Some(&token));
    ok(serde_json::json!({ "success": true }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthKeyBody {
    auth_key: String,
}

async fn delete_account(State(state): Shared, ConnectInfo(peer): Peer, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (session, _) = require_session(&headers, &state)?;
    let guard = Guard::user(session.user_id, client_ip(&headers, peer, &state.config));
    guard.check(&state.limiter)?;
    let body: AuthKeyBody = parse(&body)?;
    valid_proof(&body.auth_key)?;

    let db = state.db.clone();
    let user_id = session.user_id;
    let result = blocking(move || db.verify_auth_key(user_id, &body.auth_key)).await;
    guard.settle(&state.limiter, result)?;
    state.db.delete_user(session.user_id)?;
    state.sessions.revoke_user(session.user_id, None);

    let response = ok(serde_json::json!({ "success": true }))?;
    Ok(with_cookie(response, cleared_cookie(&state.config)))
}

// ---------------------------------------------------------------------------
// Vault (opaque, client-encrypted)
// ---------------------------------------------------------------------------

async fn get_vault(State(state): Shared, headers: HeaderMap) -> ApiResult {
    let (session, _) = require_session(&headers, &state)?;
    let record = state.db.get_vault(session.user_id)?;
    ok(serde_json::json!({
        "kdf": record.kdf,
        "vaultKeyWrapped": record.vault_key_wrapped,
        "encryptedData": record.encrypted_data,
        "revision": record.revision,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveVaultBody {
    encrypted_data: String,
    revision: i64,
}

async fn put_vault(State(state): Shared, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (session, _) = require_session(&headers, &state)?;
    let body: SaveVaultBody = parse(&body)?;
    valid_blob(&body.encrypted_data, MAX_VAULT_BLOB)?;
    let revision = state.db.save_vault(session.user_id, &body.encrypted_data, body.revision)?;
    ok(serde_json::json!({ "success": true, "revision": revision }))
}

// ---------------------------------------------------------------------------
// Recovery (phrase + master-key file)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnableRecoveryBody {
    method: String,
    auth_key: String,
    proof: String,
    wrapped: String,
}

async fn enable_recovery(State(state): Shared, ConnectInfo(peer): Peer, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (session, _) = require_session(&headers, &state)?;
    let guard = Guard::user(session.user_id, client_ip(&headers, peer, &state.config));
    guard.check(&state.limiter)?;
    let body: EnableRecoveryBody = parse(&body)?;
    let method = parse_method(&body.method)?;
    valid_proof(&body.auth_key)?;
    valid_proof(&body.proof)?;
    valid_blob(&body.wrapped, MAX_KEY_BLOB)?;

    let db = state.db.clone();
    let user_id = session.user_id;
    let result = blocking(move || {
        db.verify_auth_key(user_id, &body.auth_key)?;
        db.set_recovery(user_id, method, Some((&body.proof, &body.wrapped)))
    })
    .await;
    guard.settle(&state.limiter, result)?;
    ok(serde_json::json!({ "success": true }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DisableRecoveryBody {
    method: String,
    auth_key: String,
}

async fn disable_recovery(State(state): Shared, ConnectInfo(peer): Peer, headers: HeaderMap, body: Bytes) -> ApiResult {
    let (session, _) = require_session(&headers, &state)?;
    let guard = Guard::user(session.user_id, client_ip(&headers, peer, &state.config));
    guard.check(&state.limiter)?;
    let body: DisableRecoveryBody = parse(&body)?;
    let method = parse_method(&body.method)?;
    valid_proof(&body.auth_key)?;

    let db = state.db.clone();
    let user_id = session.user_id;
    let result = blocking(move || {
        db.verify_auth_key(user_id, &body.auth_key)?;
        db.set_recovery(user_id, method, None)
    })
    .await;
    guard.settle(&state.limiter, result)?;
    ok(serde_json::json!({ "success": true }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoverChallengeBody {
    login_id: String,
    method: String,
    proof: String,
}

fn recovery_failure(err: ApiError) -> ApiError {
    match err {
        ApiError::Unauthorized(..) => ApiError::Unauthorized("Invalid recovery credentials", None),
        other => other,
    }
}

/// Verifies a recovery proof and returns the vault key wrapped for that
/// recovery method, so the browser can re-key it. Every failure looks the same.
async fn recover_challenge(State(state): Shared, ConnectInfo(peer): Peer, headers: HeaderMap, body: Bytes) -> ApiResult {
    let body: RecoverChallengeBody = parse(&body)?;
    let method = parse_method(&body.method)?;
    let ip = client_ip(&headers, peer, &state.config);
    let login_id = valid_login_id(&body.login_id).unwrap_or_default();
    let guard = Guard::account("recover", &login_id, ip);
    guard.check(&state.limiter)?;
    valid_proof(&body.proof)?;

    let db = state.db.clone();
    let result = blocking(move || db.recovery_challenge(&login_id, method, &body.proof)).await;
    let (_, wrapped) = guard.settle(&state.limiter, result.map_err(recovery_failure))?;
    ok(serde_json::json!({ "wrapped": wrapped }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoverCompleteBody {
    login_id: String,
    method: String,
    proof: String,
    #[serde(flatten)]
    keys: NewKeys,
}

async fn recover_complete(State(state): Shared, ConnectInfo(peer): Peer, headers: HeaderMap, body: Bytes) -> ApiResult {
    let body: RecoverCompleteBody = parse(&body)?;
    let method = parse_method(&body.method)?;
    let ip = client_ip(&headers, peer, &state.config);
    let login_id = valid_login_id(&body.login_id).unwrap_or_default();
    let guard = Guard::account("recover", &login_id, ip);
    guard.check(&state.limiter)?;
    valid_proof(&body.proof)?;
    let kdf = body.keys.validate()?;

    let db = state.db.clone();
    let result = blocking(move || {
        let keys = E2eKeys {
            auth_key: &body.keys.auth_key,
            kdf: &kdf,
            vault_key_wrapped: &body.keys.vault_key_wrapped,
        };
        db.recovery_complete(&login_id, method, &body.proof, &keys)
    })
    .await;
    let user_id = guard.settle(&state.limiter, result.map_err(recovery_failure))?;
    // Whoever held a session before the reset is signed out.
    state.sessions.revoke_user(user_id, None);
    ok(serde_json::json!({ "success": true }))
}

// ---------------------------------------------------------------------------
// Middleware: security headers & CSRF
// ---------------------------------------------------------------------------

const CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; \
style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: blob:; \
connect-src 'self'; media-src 'self' blob:; worker-src 'self' blob:; object-src 'none'; \
base-uri 'none'; form-action 'self'; frame-ancestors 'none'; manifest-src 'self'";

async fn security_headers(State(state): Shared, request: Request, next: Next) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let set = |headers: &mut HeaderMap, name: &'static str, value: &'static str| {
        headers.insert(name, HeaderValue::from_static(value));
    };
    set(headers, "content-security-policy", CSP);
    set(headers, "x-content-type-options", "nosniff");
    set(headers, "x-frame-options", "DENY");
    set(headers, "referrer-policy", "no-referrer");
    set(headers, "cross-origin-opener-policy", "same-origin");
    set(headers, "cross-origin-resource-policy", "same-origin");
    set(
        headers,
        "permissions-policy",
        "camera=(self), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    );
    if state.config.is_https() {
        set(headers, "strict-transport-security", "max-age=63072000; includeSubDomains");
    }
    let is_html = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/html"));
    if is_api || is_html {
        set(headers, "cache-control", "no-store");
    }
    response
}

/// Rejects cross-site state-changing API requests: JSON content type is
/// mandatory (no "simple" form posts), and when the browser sends an
/// `Origin` (or `Sec-Fetch-Site`) it must be our own.
async fn csrf_guard(State(state): Shared, request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let is_api = request.uri().path().starts_with("/api/");
    if is_api && !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) {
        let headers = request.headers();
        let json = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json"));
        if !json {
            return ApiError::BadRequest("Content-Type must be application/json").into_response();
        }
        if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            let origin = origin_of(origin);
            if !state.config.allowed_origins().iter().any(|allowed| *allowed == origin) {
                return ApiError::Forbidden("Cross-origin request rejected").into_response();
            }
        }
        if headers
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "cross-site")
        {
            return ApiError::Forbidden("Cross-origin request rejected").into_response();
        }
    }
    next.run(request).await
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

async fn api_not_found() -> ApiError {
    ApiError::NotFound
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let index_path = state.dist_dir.join("index.html");
    let serve = ServeDir::new(&state.dist_dir).not_found_service(ServeFile::new(index_path));

    // Small JSON bodies only.
    let small = Router::new()
        .route("/api/auth/prelogin", post(prelogin))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/status", get(status))
        .route("/api/user/change-password", post(change_password))
        .route("/api/user/delete-account", post(delete_account))
        .route("/api/vault/recovery/enable", post(enable_recovery))
        .route("/api/vault/recovery/disable", post(disable_recovery))
        .route("/api/auth/recover/challenge", post(recover_challenge))
        .layer(DefaultBodyLimit::max(64 * 1024));

    let profile = Router::new()
        .route("/api/user/profile", get(get_profile).put(put_profile))
        .layer(DefaultBodyLimit::max(512 * 1024));

    // Encrypted vault payloads (may embed icons).
    let large = Router::new()
        .route("/api/auth/register", post(register))
        .route("/api/vault", get(get_vault).put(put_vault))
        .route("/api/auth/recover/complete", post(recover_complete))
        .layer(DefaultBodyLimit::max(MAX_VAULT_BLOB + 64 * 1024));

    Router::new()
        .merge(small)
        .merge(profile)
        .merge(large)
        .route(
            "/api/{*rest}",
            get(api_not_found).post(api_not_found).put(api_not_found).delete(api_not_found),
        )
        .fallback_service(serve)
        .layer(middleware::from_fn_with_state(state.clone(), csrf_guard))
        .layer(middleware::from_fn_with_state(state.clone(), security_headers))
        .with_state(state)
}
