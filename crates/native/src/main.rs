use std::{env, sync::{Arc, Mutex}, time::{SystemTime, UNIX_EPOCH}};

use argon2::{password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use keylite_core::{digest, etag, matches_precondition, Head, Revision, MAX_BLOB_BYTES, CHUNK_BYTES, MAX_HISTORY};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

type Db = Arc<Mutex<Connection>>;

fn limit(name: &str) -> i64 {
    env::var(name).ok().and_then(|v| v.parse::<i64>().ok()).filter(|n| *n >= 0).unwrap_or(0)
}

type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
struct ApiError(StatusCode, String);

impl ApiError {
    fn new(code: StatusCode, message: impl Into<String>) -> Self {
        Self(code, message.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error": self.1}))).into_response()
    }
}

fn db_error(error: rusqlite::Error) -> ApiError {
    eprintln!("Database error: {error}");
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "database error")
}

fn lock_db(db: &Db) -> ApiResult<std::sync::MutexGuard<'_, Connection>> {
    db.lock().map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "database lock poisoned"))
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

#[derive(Deserialize)]
struct Credentials {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct CreateVault {
    name: String,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
}

#[derive(Serialize)]
struct VaultInfo {
    id: String,
    name: String,
    revision: i64,
    hash: Option<String>,
}

#[derive(Serialize)]
struct VaultResponse {
    id: String,
    head: Head,
}

fn bearer(headers: &HeaderMap) -> ApiResult<&str> {
    headers.get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "bearer token required"))
}

fn authenticated(db: &Db, headers: &HeaderMap) -> ApiResult<String> {
    let token = bearer(headers)?;
    let token_hash = digest(token.as_bytes());
    lock_db(db)?.query_row(
        "SELECT user_id FROM sessions WHERE token_hash = ?1 AND expires_at > ?2",
        params![token_hash, now()],
        |row| row.get(0),
    ).optional().map_err(db_error)?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "invalid or expired token"))
}

fn vault_head(conn: &Connection, vault_id: &str, user_id: &str) -> ApiResult<Head> {
    conn.query_row(
        "SELECT latest_revision, latest_hash FROM vaults WHERE id = ?1 AND user_id = ?2",
        params![vault_id, user_id],
        |row| Ok(Head {revision: row.get(0)?, hash: row.get(1)?}),
    ).optional().map_err(db_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "vault not found"))
}

async fn register(State(db): State<Db>, Json(input): Json<Credentials>) -> ApiResult<StatusCode> {
    let email = input.email.trim().to_lowercase();
    if !email.contains('@') || email.len() > 254 || input.password.len() < 12 || input.password.len() > 1024 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid email or password length (minimum 12)"));
    }
    let salt = SaltString::encode_b64(Uuid::new_v4().as_bytes())
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "salt generation failed"))?;
    let password_hash = Argon2::default().hash_password(input.password.as_bytes(), &salt)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "password hashing failed"))?.to_string();
    let registration_limit = limit("KEYLITE_MAX_USERS");
    let result = lock_db(&db)?.execute(
        "INSERT INTO users (id, email, password_hash)
         SELECT ?1, ?2, ?3 WHERE ?4 = 0 OR (SELECT count(*) FROM users) < ?4",
        params![Uuid::new_v4().to_string(), email, password_hash, registration_limit],
    );
    match result {
        Ok(1) => Ok(StatusCode::CREATED),
        Ok(_) => Err(ApiError::new(StatusCode::FORBIDDEN, "user registration limit reached")),
        Err(rusqlite::Error::SqliteFailure(err, _)) if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            Err(ApiError::new(StatusCode::CONFLICT, "account already exists")),
        Err(err) => Err(db_error(err)),
    }
}

async fn login(State(db): State<Db>, Json(input): Json<Credentials>) -> ApiResult<Json<TokenResponse>> {
    let email = input.email.trim().to_lowercase();
    let user: Option<(String, String)> = lock_db(&db)?.query_row(
        "SELECT id, password_hash FROM users WHERE email = ?1",
        params![email],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional().map_err(db_error)?;

    let valid = user.as_ref().and_then(|(_, hash)| PasswordHash::new(hash).ok())
        .map(|hash| Argon2::default().verify_password(input.password.as_bytes(), &hash).is_ok())
        .unwrap_or(false);
    if !valid {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let token_hash = digest(token.as_bytes());
    lock_db(&db)?.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?1, ?2, ?3)",
        params![token_hash, user.unwrap().0, now() + 86400],
    ).map_err(db_error)?;
    Ok(Json(TokenResponse { token }))
}

async fn logout(State(db): State<Db>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let user_id = authenticated(&db, &headers)?;
    let token_hash = digest(bearer(&headers)?.as_bytes());
    lock_db(&db)?.execute(
        "DELETE FROM sessions WHERE token_hash = ?1 AND user_id = ?2",
        params![token_hash, user_id],
    ).map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_vaults(State(db): State<Db>, headers: HeaderMap) -> ApiResult<Json<Vec<VaultInfo>>> {
    let user = authenticated(&db, &headers)?;
    let conn = lock_db(&db)?;
    let mut stmt = conn.prepare("SELECT id, name, latest_revision, latest_hash FROM vaults WHERE user_id = ?1 ORDER BY name").map_err(db_error)?;
    let rows = stmt.query_map(params![user], |r| Ok(VaultInfo {
        id: r.get(0)?, name: r.get(1)?, revision: r.get(2)?, hash: r.get(3)?,
    })).map_err(db_error)?;
    let items = rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?;
    Ok(Json(items))
}

async fn create_vault(State(db): State<Db>, headers: HeaderMap, Json(input): Json<CreateVault>) -> ApiResult<(StatusCode, Json<VaultResponse>)> {
    let user = authenticated(&db, &headers)?;
    let name = input.name.trim();
    if name.is_empty() || name.len() > 200 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid vault name"));
    }
    let id = Uuid::new_v4().to_string();
    let vault_limit = limit("KEYLITE_MAX_VAULTS_PER_USER");
    let inserted = lock_db(&db)?.execute(
        "INSERT INTO vaults (id, user_id, name)
         SELECT ?1, ?2, ?3 WHERE ?4 = 0 OR
            (SELECT count(*) FROM vaults WHERE user_id = ?2) < ?4",
        params![id, user, name, vault_limit],
    ).map_err(db_error)?;
    if inserted == 0 {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "per-user vault limit reached"));
    }
    Ok((StatusCode::CREATED, Json(VaultResponse { id, head: Head {revision: 0, hash: None} })))
}

fn bytes_response(blob: Vec<u8>, revision: i64, hash: &str) -> ApiResult<Response> {
    let mut response = (StatusCode::OK, blob).into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    response.headers_mut().insert(header::ETAG, HeaderValue::from_str(&etag(hash))
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid stored digest"))?);
    response.headers_mut().insert("x-keylite-revision", HeaderValue::from_str(&revision.to_string())
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid revision"))?);
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

fn read_chunks(conn: &Connection, id: &str, revision: i64) -> ApiResult<Vec<u8>> {
    let mut stmt = conn.prepare(
        "SELECT data FROM vault_chunks WHERE vault_id=?1 AND revision=?2 ORDER BY chunk_index",
    ).map_err(db_error)?;
    let chunks = stmt.query_map(params![id, revision], |row| row.get::<_, Vec<u8>>(0))
        .map_err(db_error)?.collect::<Result<Vec<_>, _>>().map_err(db_error)?;
    Ok(chunks.into_iter().flatten().collect())
}

async fn get_vault(State(db): State<Db>, Path(id): Path<String>, headers: HeaderMap) -> ApiResult<Response> {
    let user = authenticated(&db, &headers)?;
    let conn = lock_db(&db)?;
    let head = vault_head(&conn, &id, &user)?;
    if head.revision == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "vault is empty"));
    }
    let blob = read_chunks(&conn, &id, head.revision)?;
    let hash = head.hash.as_deref().unwrap_or("");
    if digest(&blob) != hash {
        return Err(ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "vault integrity check failed"));
    }
    bytes_response(blob, head.revision, hash)
}

async fn history(State(db): State<Db>, Path(id): Path<String>, headers: HeaderMap) -> ApiResult<Json<Vec<Revision>>> {
    let user = authenticated(&db, &headers)?;
    let conn = lock_db(&db)?;
    vault_head(&conn, &id, &user)?;
    let mut stmt = conn.prepare(
        "SELECT revision, hash, size, created_at FROM vault_revisions WHERE vault_id = ?1 ORDER BY revision DESC LIMIT 5",
    ).map_err(db_error)?;
    let versions = stmt.query_map(params![id], |r| Ok(Revision {
        revision: r.get(0)?, hash: r.get(1)?, size: r.get(2)?, created_at: r.get(3)?,
    })).map_err(db_error)?.collect::<Result<Vec<_>, _>>().map_err(db_error)?;
    Ok(Json(versions))
}

async fn old_revision(State(db): State<Db>, Path((id, revision)): Path<(String, i64)>, headers: HeaderMap) -> ApiResult<Response> {
    let user = authenticated(&db, &headers)?;
    let conn = lock_db(&db)?;
    vault_head(&conn, &id, &user)?;
    let hash: Option<String> = conn.query_row(
        "SELECT hash FROM vault_revisions WHERE vault_id = ?1 AND revision = ?2",
        params![id, revision], |r| r.get(0),
    ).optional().map_err(db_error)?;
    let hash = hash.ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "revision not found"))?;
    let blob = read_chunks(&conn, &id, revision)?;
    if digest(&blob) != hash {
        return Err(ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "vault integrity check failed"));
    }
    bytes_response(blob, revision, &hash)
}

async fn put_vault(State(db): State<Db>, Path(id): Path<String>, headers: HeaderMap, bytes: Bytes) -> ApiResult<Response> {
    let user = authenticated(&db, &headers)?;
    if bytes.len() > MAX_BLOB_BYTES {
        return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "vault exceeds 8 MiB"));
    }
    let if_match = headers.get(header::IF_MATCH).and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::new(StatusCode::PRECONDITION_REQUIRED, "If-Match is required"))?;
    let hash = digest(&bytes);
    let mut conn = lock_db(&db)?;
    let tx = conn.transaction().map_err(db_error)?;
    let previous = vault_head(&tx, &id, &user)?;
    if !matches_precondition(if_match, previous.hash.as_deref()) {
        let mut response = (StatusCode::PRECONDITION_FAILED, Json(serde_json::json!({
            "error": "stale vault version",
            "head": previous,
        }))).into_response();
        if let Some(ref current_hash) = previous.hash {
            response.headers_mut().insert(header::ETAG, HeaderValue::from_str(&etag(current_hash))
                .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid digest"))?);
        }
        return Ok(response);
    }
    let revision = previous.revision + 1;
    tx.execute("INSERT INTO vault_revisions (vault_id, revision, hash, size, commit_id) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, revision, hash, bytes.len() as i64, Uuid::new_v4().to_string()]).map_err(db_error)?;
    for (index, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
        tx.execute(
            "INSERT INTO vault_chunks(vault_id,revision,chunk_index,data) VALUES(?1,?2,?3,?4)",
            params![id, revision, index as i64, chunk],
        ).map_err(db_error)?;
    }
    tx.execute("UPDATE vaults SET latest_revision = ?1, latest_hash = ?2 WHERE id = ?3 AND user_id = ?4",
        params![revision, hash, id, user]).map_err(db_error)?;
    tx.execute(
        "DELETE FROM vault_revisions WHERE vault_id = ?1 AND revision <= ?2",
        params![id, revision - MAX_HISTORY],
    ).map_err(db_error)?;
    tx.commit().map_err(db_error)?;
    let mut response = Json(VaultResponse {id, head: Head {revision, hash: Some(hash.clone())}}).into_response();
    response.headers_mut().insert(header::ETAG, HeaderValue::from_str(&etag(&hash))
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid digest"))?);
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn delete_vault(State(db): State<Db>, Path(id): Path<String>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let user = authenticated(&db, &headers)?;
    let affected = lock_db(&db)?.execute("DELETE FROM vaults WHERE id = ?1 AND user_id = ?2",
        params![id, user]).map_err(db_error)?;
    if affected == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "vault not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::var("KEYLITE_DB").unwrap_or_else(|_| "keylite.sqlite".into());
    let listen = env::var("KEYLITE_LISTEN").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let conn = Connection::open(path)?;
    conn.execute_batch(include_str!("../../../migrations/0001_init.sql"))?;
    let db: Db = Arc::new(Mutex::new(conn));
    let app = Router::new()
        .route("/api/register", post(register))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/vaults", get(list_vaults).post(create_vault))
        .route("/api/vaults/:id", get(get_vault).put(put_vault).delete(delete_vault))
        .route("/api/vaults/:id/history", get(history))
        .route("/api/vaults/:id/history/:revision", get(old_revision))
        .with_state(db)
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BLOB_BYTES));
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    eprintln!("Keylite native listening at {listen}");
    axum::serve(listener, app).await?;
    Ok(())
}
