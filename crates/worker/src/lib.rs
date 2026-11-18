use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use keylite_core::{digest, etag, matches_precondition, Head, Revision, MAX_BLOB_BYTES};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::*;

#[derive(Deserialize)]
struct Credentials {
    email: String,
    password: String,
}
#[derive(Deserialize)]
struct CreateVault {
    name: String,
}
#[derive(Deserialize)]
struct UserRow {
    id: String,
    password_hash: String,
}
#[derive(Deserialize)]
struct AuthRow {
    user_id: String,
}
#[derive(Serialize, Deserialize)]
struct VaultRow {
    id: String,
    name: String,
    revision: i64,
    hash: Option<String>,
}
#[derive(Deserialize)]
struct HeadRow {
    revision: i64,
    hash: Option<String>,
}
#[derive(Deserialize)]
struct ContentRow {
    hash: String,
    blob: Vec<u8>,
}
#[derive(Deserialize)]
struct CountRow {
    count: i64,
}
#[derive(Serialize)]
struct Token {
    token: String,
}
#[derive(Serialize)]
struct CreatedVault {
    id: String,
    head: Head,
}
#[derive(Serialize)]
struct ErrBody<'a> {
    error: &'a str,
}
fn fail(status: u16, message: &str) -> Result<Response> {
    Ok(Response::from_json(&ErrBody { error: message })?.with_status(status))
}
fn quota(env: &Env, name: &str) -> i64 {
    env.var(name).ok().and_then(|x| x.to_string().parse::<i64>().ok())
        .filter(|x| *x >= 0).unwrap_or(0)
}
fn now() -> i64 {
    (js_sys::Date::now() / 1000.) as i64
}
fn random_id() -> String {
    Uuid::new_v4().to_string()
}
fn token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
async fn auth(req: &Request, ctx: &RouteContext<()>) -> Result<Option<String>> {
    let header = req.headers().get("Authorization")?.unwrap_or_default();
    let Some(raw) = header.strip_prefix("Bearer ") else { return Ok(None); };
    let db = ctx.d1("DB")?;
    let row = query!(
        &db,
        "SELECT user_id FROM sessions WHERE token_hash=?1 AND expires_at>?2",
        digest(raw.as_bytes()), now()
    )?.first::<AuthRow>(None).await?;
    Ok(row.map(|r| r.user_id))
}
async fn owned_head(ctx: &RouteContext<()>, user: &str, id: &str) -> Result<Option<Head>> {
    let db = ctx.d1("DB")?;
    Ok(query!(
        &db,
        "SELECT latest_revision AS revision, latest_hash AS hash FROM vaults WHERE id=?1 AND user_id=?2",
        id, user
    )?.first::<HeadRow>(None).await?.map(|r| Head {
        revision: r.revision, hash: r.hash
    }))
}
fn binary(data: Vec<u8>, hash: &str, revision: i64) -> Result<Response> {
    let response = Response::from_bytes(data)?;
    response.headers().set("ETag", &etag(hash))?;
    response.headers().set("X-Keylite-Revision", &revision.to_string())?;
    response.headers().set("Cache-Control", "no-store")?;
    Ok(response)
}
fn affected(result: &worker::d1::D1Result) -> Result<bool> {
    Ok(result.meta()?.and_then(|m| m.changes).unwrap_or(0) > 0)
}

#[event(fetch, respond_with_errors)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    Router::new()
        .post_async("/api/register", |mut req, ctx| async move {
            let input: Credentials = match req.json().await {
                Ok(input) => input, Err(_) => return fail(400, "invalid request")
            };
            let email = input.email.trim().to_lowercase();
            if !email.contains('@') || email.len() > 254 ||
                input.password.len() < 12 || input.password.len() > 1024 {
                return fail(400, "invalid email or password length");
            }
            let salt = SaltString::encode_b64(Uuid::new_v4().as_bytes())
                .map_err(|_| Error::RustError("salt generation failed".into()))?;
            let hash = Argon2::default()
                .hash_password(input.password.as_bytes(), &salt)
                .map_err(|_| Error::RustError("password hashing failed".into()))?
                .to_string();
            let db = ctx.d1("DB")?;
            let max = quota(&ctx.env, "KEYLITE_MAX_USERS");
            let result = query!(&db,
                "INSERT INTO users (id,email,password_hash)
                 SELECT ?1,?2,?3 WHERE ?4=0 OR (SELECT count(*) FROM users)<?4",
                random_id(), email, hash, max
            )?.run().await;
            match result {
                Ok(result) if affected(&result)? => Ok(Response::empty()?.with_status(201)),
                Ok(_) => fail(403, "user registration limit reached"),
                Err(_) => fail(409, "account already exists"),
            }
        })
        .post_async("/api/login", |mut req, ctx| async move {
            let input: Credentials = match req.json().await {
                Ok(input) => input, Err(_) => return fail(400, "invalid request")
            };
            let db = ctx.d1("DB")?;
            let email = input.email.trim().to_lowercase();
            let row = query!(&db, "SELECT id,password_hash FROM users WHERE email=?1", email)?
                .first::<UserRow>(None).await?;
            let valid = row.as_ref().and_then(|r| PasswordHash::new(&r.password_hash).ok())
                .map(|hash| Argon2::default().verify_password(input.password.as_bytes(), &hash).is_ok())
                .unwrap_or(false);
            if !valid { return fail(401, "invalid credentials"); }
            let raw = token();
            query!(&db, "INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?1,?2,?3)",
                digest(raw.as_bytes()), row.unwrap().id, now()+86400)?.run().await?;
            Response::from_json(&Token {token: raw})
        })
        .post_async("/api/logout", |req, ctx| async move {
            let Some(user) = auth(&req, &ctx).await? else { return fail(401, "bearer token required"); };
            let raw = req.headers().get("Authorization")?.unwrap_or_default();
            let token = raw.strip_prefix("Bearer ").unwrap_or("");
            let db = ctx.d1("DB")?;
            query!(&db, "DELETE FROM sessions WHERE token_hash=?1 AND user_id=?2",
                digest(token.as_bytes()), user)?.run().await?;
            Ok(Response::empty()?.with_status(204))
        })
        .get_async("/api/vaults", |req, ctx| async move {
            let Some(user) = auth(&req, &ctx).await? else { return fail(401, "bearer token required"); };
            let db = ctx.d1("DB")?;
            let rows = query!(&db,
                "SELECT id,name,latest_revision AS revision,latest_hash AS hash FROM vaults WHERE user_id=?1 ORDER BY name", user)?
                .all().await?.results::<VaultRow>()?;
            Response::from_json(&rows)
        })
        .post_async("/api/vaults", |mut req, ctx| async move {
            let Some(user) = auth(&req, &ctx).await? else { return fail(401, "bearer token required"); };
            let input: CreateVault = match req.json().await {
                Ok(input) => input, Err(_) => return fail(400, "invalid request")
            };
            let name = input.name.trim();
            if name.is_empty() || name.len() > 200 { return fail(400, "invalid vault name"); }
            let id = random_id();
            let db = ctx.d1("DB")?;
            let max = quota(&ctx.env, "KEYLITE_MAX_VAULTS_PER_USER");
            let result = query!(&db,
                "INSERT INTO vaults (id,user_id,name)
                 SELECT ?1,?2,?3 WHERE ?4=0 OR (SELECT count(*) FROM vaults WHERE user_id=?2)<?4",
                id, user, name, max
            )?.run().await?;
            if !affected(&result)? { return fail(403, "per-user vault limit reached"); }
            Ok(Response::from_json(&CreatedVault {
                id, head: Head { revision: 0, hash: None }
            })?.with_status(201))
        })
        .get_async("/api/vaults/:id", |req, ctx| async move {
            let Some(user) = auth(&req, &ctx).await? else { return fail(401, "bearer token required"); };
            let id = ctx.param("id").ok_or_else(|| Error::RustError("missing id".into()))?;
            let Some(head) = owned_head(&ctx, &user, id).await? else {return fail(404, "vault not found");};
            if head.revision == 0 {return fail(404, "vault is empty");}
            let db = ctx.d1("DB")?;
            let row = query!(&db,
                "SELECT hash,blob FROM vault_revisions WHERE vault_id=?1 AND revision=?2",
                id, head.revision)?.first::<ContentRow>(None).await?;
            match row {
                Some(row) => binary(row.blob, &row.hash, head.revision),
                None => fail(404, "revision not found")
            }
        })
        .get_async("/api/vaults/:id/history", |req, ctx| async move {
            let Some(user) = auth(&req, &ctx).await? else { return fail(401, "bearer token required"); };
            let id = ctx.param("id").ok_or_else(|| Error::RustError("missing id".into()))?;
            if owned_head(&ctx, &user, id).await?.is_none() { return fail(404, "vault not found"); }
            let db = ctx.d1("DB")?;
            let rows = query!(&db,
                "SELECT revision,hash,length(blob) AS size,created_at FROM vault_revisions
                 WHERE vault_id=?1 ORDER BY revision DESC LIMIT 5", id)?
                .all().await?.results::<Revision>()?;
            Response::from_json(&rows)
        })
        .get_async("/api/vaults/:id/history/:revision", |req, ctx| async move {
            let Some(user) = auth(&req, &ctx).await? else { return fail(401, "bearer token required"); };
            let id = ctx.param("id").ok_or_else(|| Error::RustError("missing id".into()))?;
            if owned_head(&ctx, &user, id).await?.is_none() {return fail(404, "vault not found");}
            let revision = match ctx.param("revision").and_then(|s| s.parse::<i64>().ok()) {
                Some(v) if v > 0 => v, _ => return fail(400, "invalid revision")
            };
            let db = ctx.d1("DB")?;
            match query!(&db, "SELECT hash,blob FROM vault_revisions WHERE vault_id=?1 AND revision=?2",
                id, revision)?.first::<ContentRow>(None).await? {
                Some(row) => binary(row.blob, &row.hash, revision),
                None => fail(404, "revision not found")
            }
        })
        .put_async("/api/vaults/:id", |mut req, ctx| async move {
            let Some(user) = auth(&req, &ctx).await? else { return fail(401, "bearer token required"); };
            let id = ctx.param("id").ok_or_else(|| Error::RustError("missing id".into()))?;
            let match_header = match req.headers().get("If-Match")? {
                Some(v) => v, None => return fail(428, "If-Match is required")
            };
            let Some(before) = owned_head(&ctx, &user, id).await? else {return fail(404, "vault not found");};
            if !matches_precondition(&match_header, before.hash.as_deref()) {
                return Ok(Response::from_json(&serde_json::json!({
                    "error": "stale vault version", "head": before
                }))?.with_status(412));
            }
            let bytes = req.bytes().await?;
            if bytes.len() > MAX_BLOB_BYTES {return fail(413, "vault exceeds 1 MiB");}
            let hash = digest(&bytes);
            let revision = before.revision + 1;
            let db = ctx.d1("DB")?;
            let result = query!(&db,
                "INSERT INTO vault_revisions(vault_id,revision,hash,blob)
                 SELECT id,latest_revision+1,?1,?2 FROM vaults
                 WHERE id=?3 AND user_id=?4 AND latest_revision=?5 AND latest_hash IS ?6",
                hash, bytes, id, user, before.revision, before.hash)?.run().await?;
            if !affected(&result)? {
                let current = owned_head(&ctx, &user, id).await?;
                return Ok(Response::from_json(&serde_json::json!({
                    "error": "stale vault version", "head": current
                }))?.with_status(412));
            }
            let response = Response::from_json(&CreatedVault {
                id: id.to_owned(), head: Head { revision, hash: Some(hash.clone()) }
            })?;
            response.headers().set("ETag", &etag(&hash))?;
            response.headers().set("Cache-Control", "no-store")?;
            Ok(response)
        })
        .delete_async("/api/vaults/:id", |req, ctx| async move {
            let Some(user) = auth(&req, &ctx).await? else { return fail(401, "bearer token required"); };
            let id = ctx.param("id").ok_or_else(|| Error::RustError("missing id".into()))?;
            let db = ctx.d1("DB")?;
            let result = query!(&db, "DELETE FROM vaults WHERE id=?1 AND user_id=?2", id, user)?
                .run().await?;
            if !affected(&result)? {return fail(404, "vault not found");}
            Ok(Response::empty()?.with_status(204))
        })
        .run(req, env).await
}
