use actix_web::http::StatusCode;
use actix_web::{
    HttpRequest,
    HttpResponse,
    delete,
    get,
    patch,
    post,
    put,
    web,
};
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::{
    Value,
    json,
};
use time::{
    Duration,
    OffsetDateTime,
};
use web_misc::db::DBPool;

use crate::api::{
    json_created,
    json_err,
    json_ok,
    json_status,
    request_id,
};
use crate::auth::{
    AdminUser,
    AuthUser,
};
use crate::db::{
    self,
    ItemRow,
};
use crate::util;

const TOKEN_TTL_SECS: i64 = 2_592_000;
const ALG: &str = "xchacha20poly1305";
const ALG_NONE: &str = "none";

fn ts(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| t.to_string())
}

fn pool(db: &web::Data<DBPool>) -> &sqlx::PgPool {
    &db.pg_pool
}

fn blob_json(alg: &str, nonce: &[u8], ciphertext: &[u8], key_revision: i32) -> Value {
    json!({
        "alg": alg,
        "nonce": util::b64_encode(nonce),
        "ciphertext": util::b64_encode(ciphertext),
        "key_revision": key_revision,
    })
}

fn item_json(item: &ItemRow) -> Value {
    json!({
        "item_id": item.item_id,
        "sync_key": item.sync_key,
        "item_type": item.item_type,
        "rev": item.rev,
        "deleted": item.deleted,
        "seq": item.seq,
        "updated_at": ts(item.updated_at),
        "modified_timestamp": ts(item.modified_timestamp),
        "blob": blob_json(&item.alg, &item.nonce, &item.ciphertext, item.key_revision),
    })
}

#[get("/health")]
async fn health() -> HttpResponse {
    json_ok(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
    device_id: Option<String>,
    device_label: Option<String>,
}

#[post("/auth/login")]
async fn login(db: web::Data<DBPool>, body: web::Json<LoginReq>) -> HttpResponse {
    let Some(user) = db::get_user_by_username(pool(&db), &body.username).await.ok().flatten() else {
        return json_err(StatusCode::UNAUTHORIZED, "Invalid username or password.");
    };
    if !util::verify_password(&body.password, &user.password_hash) {
        return json_err(StatusCode::UNAUTHORIZED, "Invalid username or password.");
    }
    if !user.enabled {
        return json_err(StatusCode::FORBIDDEN, "Account disabled.");
    }
    if let Some(device_id) = body.device_id.as_deref() {
        let _ = db::revoke_device_token(pool(&db), user.id, device_id).await;
    }
    let (token, hash) = util::issue_token();
    let expires = OffsetDateTime::now_utc() + Duration::seconds(TOKEN_TTL_SECS);
    let token_id = match db::insert_token(
        pool(&db),
        user.id,
        &user.username,
        &hash,
        body.device_id.as_deref(),
        body.device_label.as_deref(),
        expires,
    )
    .await {
        Ok(token_id) => token_id,
        Err(_) => return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    };
    let _ = db::touch_login(pool(&db), user.id).await;
    let crypto = db::get_crypto(pool(&db), user.id).await.ok().flatten();
    let key_revision = crypto.map(|c| c.current_key_revision).unwrap_or(0);
    json_ok(json!({
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "token": token,
        "token_id": token_id,
        "device_id": body.device_id,
        "expires_at": ts(expires),
        "server_time": ts(OffsetDateTime::now_utc()),
        "key_revision": key_revision,
    }))
}

#[post("/auth/logout")]
async fn logout(db: web::Data<DBPool>, auth: AuthUser) -> HttpResponse {
    if auth.app_token {
        let _ = db::delete_app_token(pool(&db), auth.user_id()).await;
    } else {
        let _ = db::revoke_token(pool(&db), auth.user_id(), auth.token_id).await;
    }
    json_ok(json!({}))
}

#[get("/auth/tokens")]
async fn list_tokens(db: web::Data<DBPool>, auth: AuthUser) -> HttpResponse {
    let Ok(rows) = db::list_tokens(pool(&db), auth.user_id()).await else {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    let tokens: Vec<Value> = rows
        .into_iter()
        .map(|t| {
            json!({
                "token_id": t.id,
                "device_id": t.device_id,
                "device_label": t.device_label,
                "created_at": ts(t.created_at),
                "expires_at": ts(t.expires_at),
                "last_used_at": t.last_used_at.map(ts),
                "is_current": t.id == auth.token_id,
            })
        })
        .collect();
    json_ok(json!({ "tokens": tokens }))
}

#[delete("/auth/tokens/{token_id}")]
async fn delete_token(db: web::Data<DBPool>, auth: AuthUser, path: web::Path<i64>) -> HttpResponse {
    let n = db::revoke_token(pool(&db), auth.user_id(), path.into_inner())
        .await
        .unwrap_or(0);
    if n == 0 {
        return json_err(StatusCode::NOT_FOUND, "Not found.");
    }
    json_ok(json!({}))
}

#[derive(Deserialize)]
struct PasswordReq {
    current_password: String,
    new_password: String,
}

#[post("/auth/password")]
async fn change_password(db: web::Data<DBPool>, auth: AuthUser, body: web::Json<PasswordReq>) -> HttpResponse {
    if body.new_password.len() < 8 || body.new_password.len() > 128 {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "Password must be 8–128 bytes.");
    }
    if !util::verify_password(&body.current_password, &auth.user.password_hash) {
        return json_err(StatusCode::UNAUTHORIZED, "Invalid username or password.");
    }
    let Ok(hash) = util::hash_password(&body.new_password) else {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    if db::set_password_hash(pool(&db), &auth.user.username, &hash)
        .await
        .is_err()
    {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    let _ = db::revoke_other_tokens(pool(&db), auth.user_id(), auth.token_id).await;
    json_ok(json!({}))
}

#[get("/me")]
async fn me(db: web::Data<DBPool>, auth: AuthUser) -> HttpResponse {
    let crypto = db::get_crypto(pool(&db), auth.user_id()).await.ok().flatten();
    json_ok(json!({
        "username": auth.user.username,
        "display_name": auth.user.display_name,
        "role": auth.user.role,
        "enabled": auth.user.enabled,
        "key_revision": crypto.as_ref().map(|c| c.current_key_revision).unwrap_or(0),
        "rotation_status": crypto.as_ref().map(|c| c.rotation_status.as_str()).unwrap_or("idle"),
        "token_id": auth.token_id,
        "token_expires_at": auth.expires_at.map(ts),
        "server_time": ts(OffsetDateTime::now_utc()),
    }))
}

#[derive(Deserialize)]
struct BlobIn {
    alg: String,
    nonce: String,
    ciphertext: String,
    key_revision: i32,
}

#[derive(Deserialize)]
struct PushItem {
    item_id: Option<i64>,
    sync_key: String,
    item_type: String,
    rev: i64,
    base_rev: i64,
    deleted: bool,
    resolve: Option<String>,
    blob: BlobIn,
}

#[derive(Deserialize)]
struct PushReq {
    items: Vec<PushItem>,
}

fn decode_blob(blob: &BlobIn) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let ciphertext = util::b64_decode(&blob.ciphertext).map_err(|_| "Invalid ciphertext.")?;
    if ciphertext.len() > 65536 {
        return Err("Ciphertext too large.");
    }
    if blob.alg == ALG_NONE {
        let nonce = if blob.nonce.is_empty() {
            Vec::new()
        } else {
            util::b64_decode(&blob.nonce).map_err(|_| "Invalid nonce.")?
        };
        return Ok((nonce, ciphertext));
    }
    if blob.alg != ALG {
        return Err("Unknown alg.");
    }
    let nonce = util::b64_decode(&blob.nonce).map_err(|_| "Invalid nonce.")?;
    if nonce.len() < 8 || nonce.len() > 32 {
        return Err("Invalid nonce length.");
    }
    Ok((nonce, ciphertext))
}

#[post("/sync/items")]
async fn push_items(db: web::Data<DBPool>, auth: AuthUser, body: web::Json<PushReq>) -> HttpResponse {
    if body.items.is_empty() || body.items.len() > 20 {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "Batch must contain 1–20 items.");
    }
    let crypto = db::get_crypto(pool(&db), auth.user_id()).await.ok().flatten();
    let mut seen = std::collections::HashSet::new();
    let mut results = Vec::new();
    let single = body.items.len() == 1;
    let mut single_conflict: Option<ItemRow> = None;

    for item in &body.items {
        if item.sync_key.is_empty() || item.sync_key.len() > 128 {
            results.push(json!({
                "item_id": item.item_id,
                "sync_key": item.sync_key,
                "item_type": item.item_type,
                "outcome": "invalid",
                "error": { "err": "sync_key must be 1–128 bytes." }
            }));
            continue;
        }
        if !seen.insert(item.sync_key.as_str()) {
            results.push(json!({
                "item_id": item.item_id,
                "sync_key": item.sync_key,
                "item_type": item.item_type,
                "outcome": "invalid",
                "error": { "err": "Duplicate item in batch." }
            }));
            continue;
        }
        if item.item_type != "event" && item.item_type != "hide_flag" {
            results.push(json!({
                "item_id": item.item_id,
                "item_type": item.item_type,
                "outcome": "invalid",
                "error": { "err": "item_type must be event or hide_flag." }
            }));
            continue;
        }
        if item.rev < 1 {
            results.push(json!({
                "item_id": item.item_id,
                "item_type": item.item_type,
                "outcome": "invalid",
                "error": { "err": "rev must be >= 1." }
            }));
            continue;
        }
        if let Some(r) = &item.resolve
            && r != "keep_client"
        {
            results.push(json!({
                "item_id": item.item_id,
                "item_type": item.item_type,
                "outcome": "invalid",
                "error": { "err": "resolve must be keep_client or null." }
            }));
            continue;
        }
        let (nonce, ciphertext) = match decode_blob(&item.blob) {
            Ok(v) => v,
            Err(msg) => {
                results.push(json!({
                    "item_id": item.item_id,
                    "item_type": item.item_type,
                    "outcome": "invalid",
                    "error": { "err": msg }
                }));
                continue;
            }
        };
        if let Some(c) = &crypto {
            if c.rotation_status == "idle"
                && c.current_key_revision > 0
                && item.blob.key_revision < c.current_key_revision
            {
                results.push(json!({
                    "item_id": item.item_id,
                    "item_type": item.item_type,
                    "outcome": "invalid",
                    "error": { "err": "stale_key_revision" }
                }));
                continue;
            }
            if c.rotation_status == "in_progress" {
                let from = c.from_key_revision.unwrap_or(0);
                let to = c.to_key_revision.unwrap_or(0);
                if item.blob.key_revision != from && item.blob.key_revision != to {
                    results.push(json!({
                        "item_id": item.item_id,
                        "item_type": item.item_type,
                        "outcome": "invalid",
                        "error": { "err": "key_revision" }
                    }));
                    continue;
                }
            }
        }

        let existing = if let Some(item_id) = item.item_id {
            db::get_item(pool(&db), auth.user_id(), item_id).await.ok().flatten()
        } else {
            db::get_item_by_sync_key(pool(&db), auth.user_id(), &item.sync_key).await.ok().flatten()
        };
        match existing {
            None => {
                if item.item_id.is_some() {
                    results.push(json!({
                        "item_id": item.item_id,
                        "sync_key": item.sync_key,
                        "item_type": item.item_type,
                        "outcome": "invalid",
                        "error": { "err": "Unknown item_id." }
                    }));
                    continue;
                }
                if item.base_rev != 0 {
                    results.push(json!({
                        "item_id": item.item_id,
                        "item_type": item.item_type,
                        "outcome": "invalid",
                        "error": { "err": "base_rev must be 0 for a new item." }
                    }));
                    continue;
                }
                let Ok(seq) = db::next_seq(pool(&db), auth.user_id()).await else {
                    return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
                };
                let row = ItemRow {
                    item_id: 0,
                    sync_key: item.sync_key.clone(),
                    item_type: item.item_type.clone(),
                    rev: item.rev,
                    deleted: item.deleted,
                    seq,
                    updated_at: OffsetDateTime::now_utc(),
                    modified_timestamp: OffsetDateTime::now_utc(),
                    key_revision: item.blob.key_revision,
                    alg: item.blob.alg.clone(),
                    nonce,
                    ciphertext,
                };
                let item_id = match db::insert_item(pool(&db), auth.user_id(), &row).await {
                    Ok(item_id) => item_id,
                    Err(_) => return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
                };
                let mut row = row;
                row.item_id = item_id;
                results.push(json!({
                    "item_id": row.item_id,
                    "sync_key": row.sync_key,
                    "item_type": row.item_type,
                    "outcome": "applied",
                    "idempotent": false,
                    "rev": row.rev,
                    "deleted": row.deleted,
                    "seq": row.seq,
                    "updated_at": ts(row.updated_at),
                    "key_revision": row.key_revision,
                }));
            }
            Some(row) => {
                if item.item_id.is_some_and(|item_id| item_id != row.item_id) || item.sync_key != row.sync_key {
                    results.push(json!({
                        "item_id": item.item_id,
                        "sync_key": item.sync_key,
                        "item_type": item.item_type,
                        "outcome": "invalid",
                        "error": { "err": "item_id and sync_key do not identify the same item." }
                    }));
                    continue;
                }
                if row.item_type != item.item_type {
                    results.push(json!({
                        "item_id": item.item_id,
                        "item_type": item.item_type,
                        "outcome": "invalid",
                        "error": { "err": "item_type cannot change." }
                    }));
                    continue;
                }
                let same = row.rev == item.rev
                    && row.deleted == item.deleted
                    && row.nonce == nonce
                    && row.ciphertext == ciphertext
                    && row.alg == item.blob.alg
                    && row.key_revision == item.blob.key_revision;
                let retry_of_last_write = item.item_id.is_none()
                    && item.rev == row.rev
                    && item.base_rev == row.rev - 1;
                if same || retry_of_last_write {
                    results.push(json!({
                        "item_id": row.item_id,
                        "sync_key": row.sync_key,
                        "item_type": row.item_type,
                        "outcome": "applied",
                        "idempotent": true,
                        "rev": row.rev,
                        "deleted": row.deleted,
                        "seq": row.seq,
                        "updated_at": ts(row.updated_at),
                        "key_revision": row.key_revision,
                    }));
                    continue;
                }
                if item.rev == row.rev || item.base_rev != row.rev {
                    if single {
                        single_conflict = Some(row);
                    } else {
                        results.push(json!({
                            "item_id": item.item_id,
                            "sync_key": item.sync_key,
                            "item_type": item.item_type,
                            "outcome": "conflict",
                            "server": item_json(&row),
                        }));
                    }
                    continue;
                }
                if item.rev != row.rev + 1 {
                    results.push(json!({
                        "item_id": item.item_id,
                        "item_type": item.item_type,
                        "outcome": "invalid",
                        "error": { "err": "rev must equal server rev + 1." }
                    }));
                    continue;
                }
                let Ok(seq) = db::next_seq(pool(&db), auth.user_id()).await else {
                    return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
                };
                let updated = ItemRow {
                    item_id: row.item_id,
                    sync_key: row.sync_key.clone(),
                    item_type: item.item_type.clone(),
                    rev: item.rev,
                    deleted: item.deleted,
                    seq,
                    updated_at: OffsetDateTime::now_utc(),
                    modified_timestamp: OffsetDateTime::now_utc(),
                    key_revision: item.blob.key_revision,
                    alg: item.blob.alg.clone(),
                    nonce,
                    ciphertext,
                };
                if db::update_item(pool(&db), auth.user_id(), &updated).await.is_err() {
                    return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
                }
                results.push(json!({
                    "item_id": updated.item_id,
                    "sync_key": updated.sync_key,
                    "item_type": updated.item_type,
                    "outcome": "applied",
                    "idempotent": false,
                    "rev": updated.rev,
                    "deleted": updated.deleted,
                    "seq": updated.seq,
                    "updated_at": ts(updated.updated_at),
                    "key_revision": updated.key_revision,
                }));
            }
        }
    }

    if let Some(row) = single_conflict {
        return json_status(
            StatusCode::CONFLICT,
            json!({
                "server": item_json(&row),
                "err": "Event has a newer server revision.",
            }),
        );
    }
    json_ok(json!({ "results": results }))
}

#[derive(Deserialize)]
struct PullQuery {
    cursor: Option<String>,
    limit: Option<i64>,
}

#[get("/sync/items")]
async fn pull_items(db: web::Data<DBPool>, auth: AuthUser, q: web::Query<PullQuery>) -> HttpResponse {
    let limit = q.limit.unwrap_or(100);
    if limit < 1 || limit > 200 {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "limit must be 1–200.");
    }
    let after = match util::decode_user_cursor(q.cursor.as_deref().unwrap_or("")) {
        Ok(s) => s,
        Err(()) => return json_err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid cursor."),
    };
    let Ok(items) = db::pull_items(pool(&db), auth.user_id(), after, limit).await else {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    let last_seq = items.last().map(|i| i.seq).unwrap_or(after);
    let more = db::count_items_after(pool(&db), auth.user_id(), last_seq)
        .await
        .unwrap_or(0)
        > 0;
    let body: Vec<Value> = items.iter().map(item_json).collect();
    json_ok(json!({
        "items": body,
        "next_cursor": util::encode_user_cursor(last_seq),
        "has_more": more,
    }))
}

#[get("/sync/items/{item_id}")]
async fn get_item(db: web::Data<DBPool>, auth: AuthUser, path: web::Path<i64>) -> HttpResponse {
    match db::get_item(pool(&db), auth.user_id(), path.into_inner()).await {
        Ok(Some(item)) => json_ok(item_json(&item)),
        Ok(None) => json_err(StatusCode::NOT_FOUND, "Not found."),
        Err(_) => json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    }
}

#[derive(Deserialize, Serialize)]
struct KdfIn {
    alg: String,
    salt: String,
    m_kib: u32,
    t: u32,
    p: u32,
    key_len: u32,
}

#[derive(Deserialize)]
struct VerifierIn {
    alg: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct PutKeyReq {
    key_revision: i32,
    kdf: KdfIn,
    verifier: VerifierIn,
}

#[put("/crypto/key")]
async fn put_key(db: web::Data<DBPool>, auth: AuthUser, body: web::Json<PutKeyReq>) -> HttpResponse {
    if body.key_revision != 1 {
        return json_err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "First publish must use key_revision 1.",
        );
    }
    if body.kdf.alg != "argon2id" || body.verifier.alg != ALG {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "Unsupported kdf or verifier alg.");
    }
    let existing = db::get_crypto(pool(&db), auth.user_id()).await.ok().flatten();
    if let Some(c) = existing {
        let same = c.current_key_revision == body.key_revision;
        if same {
            return json_ok(json!({ "current_key_revision": c.current_key_revision }));
        }
        return json_status(
            StatusCode::CONFLICT,
            json!({
                "current_key_revision": c.current_key_revision,
                "err": "A data key is already published.",
            }),
        );
    }
    let nonce = match util::b64_decode(&body.verifier.nonce) {
        Ok(n) => n,
        Err(()) => return json_err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid nonce."),
    };
    let ct = match util::b64_decode(&body.verifier.ciphertext) {
        Ok(n) => n,
        Err(()) => return json_err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid ciphertext."),
    };
    let kdf = serde_json::to_value(&body.kdf).unwrap_or(json!({}));
    if db::upsert_crypto_first(
        pool(&db),
        auth.user_id(),
        body.key_revision,
        sqlx::types::Json(kdf),
        &body.verifier.alg,
        &nonce,
        &ct,
    )
    .await
    .is_err()
    {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    json_ok(json!({ "current_key_revision": 1 }))
}

#[get("/crypto/key")]
async fn get_key(db: web::Data<DBPool>, auth: AuthUser) -> HttpResponse {
    match db::get_crypto(pool(&db), auth.user_id()).await {
        Ok(None) => json_ok(json!({
            "current_key_revision": 0,
            "kdf": null,
            "verifier": null,
            "rotation": { "status": "idle" },
        })),
        Ok(Some(c)) => json_ok(json!({
            "current_key_revision": c.current_key_revision,
            "kdf": c.kdf_json.map(|j| j.0),
            "verifier": c.verifier_alg.as_ref().map(|alg| json!({
                "alg": alg,
                "nonce": c.verifier_nonce.as_deref().map(util::b64_encode),
                "ciphertext": c.verifier_ciphertext.as_deref().map(util::b64_encode),
            })),
            "rotation": { "status": c.rotation_status },
        })),
        Err(_) => json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    }
}

#[derive(Deserialize)]
struct StartRotReq {
    from_key_revision: i32,
    to_key_revision: i32,
    kdf: KdfIn,
    verifier: VerifierIn,
}

#[post("/crypto/rotation/start")]
async fn rotation_start(db: web::Data<DBPool>, auth: AuthUser, body: web::Json<StartRotReq>) -> HttpResponse {
    let Some(c) = db::get_crypto(pool(&db), auth.user_id()).await.ok().flatten() else {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "key_not_published");
    };
    if body.to_key_revision != body.from_key_revision + 1 || body.from_key_revision != c.current_key_revision {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid key revision pair.");
    }
    if c.rotation_status == "in_progress" {
        return json_ok(json!({
            "rotation_id": c.to_key_revision,
            "status": "in_progress",
            "from_key_revision": c.from_key_revision,
            "to_key_revision": c.to_key_revision,
            "remaining_items": db::count_stale_crypto_items(pool(&db), auth.user_id(), body.to_key_revision).await.unwrap_or(0),
        }));
    }
    let nonce = match util::b64_decode(&body.verifier.nonce) {
        Ok(n) => n,
        Err(()) => return json_err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid nonce."),
    };
    let ct = match util::b64_decode(&body.verifier.ciphertext) {
        Ok(n) => n,
        Err(()) => return json_err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid ciphertext."),
    };
    let kdf = serde_json::to_value(&body.kdf).unwrap_or(json!({}));
    let rotation_id = match db::start_rotation(
        pool(&db),
        auth.user_id(),
        body.from_key_revision,
        body.to_key_revision,
        sqlx::types::Json(kdf),
        &body.verifier.alg,
        &nonce,
        &ct,
    )
    .await {
        Ok(rotation_id) => rotation_id,
        Err(_) => return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    };
    let remaining = db::count_stale_crypto_items(pool(&db), auth.user_id(), body.to_key_revision)
        .await
        .unwrap_or(0);
    json_ok(json!({
        "rotation_id": rotation_id,
        "status": "in_progress",
        "from_key_revision": body.from_key_revision,
        "to_key_revision": body.to_key_revision,
        "started_at": ts(OffsetDateTime::now_utc()),
        "remaining_items": remaining,
    }))
}

#[get("/crypto/rotation")]
async fn rotation_get(db: web::Data<DBPool>, auth: AuthUser) -> HttpResponse {
    match db::get_crypto(pool(&db), auth.user_id()).await {
        Ok(None) => json_ok(json!({ "status": "idle", "current_key_revision": 0 })),
        Ok(Some(c)) if c.rotation_status == "idle" => json_ok(json!({
            "status": "idle",
            "current_key_revision": c.current_key_revision,
        })),
        Ok(Some(c)) => {
            let remaining = db::count_stale_crypto_items(
                pool(&db),
                auth.user_id(),
                c.to_key_revision.unwrap_or(c.current_key_revision),
            )
            .await
            .unwrap_or(0);
            json_ok(json!({
                "rotation_id": c.to_key_revision,
                "status": "in_progress",
                "from_key_revision": c.from_key_revision,
                "to_key_revision": c.to_key_revision,
                "started_at": c.rotation_started_at.map(ts),
                "remaining_items": remaining,
                "pending_kdf": c.pending_kdf_json.map(|j| j.0),
            }))
        }
        Err(_) => json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    }
}

#[derive(Deserialize)]
struct RotItemsQuery {
    cursor: Option<String>,
    limit: Option<i64>,
}

#[get("/crypto/rotation/items")]
async fn rotation_items(db: web::Data<DBPool>, auth: AuthUser, q: web::Query<RotItemsQuery>) -> HttpResponse {
    let Some(c) = db::get_crypto(pool(&db), auth.user_id()).await.ok().flatten() else {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "rotation_not_in_progress");
    };
    if c.rotation_status != "in_progress" {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "rotation_not_in_progress");
    }
    let limit = q.limit.unwrap_or(200);
    if limit < 1 || limit > 200 {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "limit must be 1–200.");
    }
    let after = q.cursor.as_deref().and_then(|s| s.parse::<i64>().ok());
    let to = c.to_key_revision.unwrap_or(c.current_key_revision + 1);
    let Ok(items) = db::rotation_items(pool(&db), auth.user_id(), to, after, limit).await else {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    let next = items.last().map(|i| i.item_id.to_string());
    json_ok(json!({
        "items": items.iter().map(|i| json!({
            "item_id": i.item_id,
            "item_type": i.item_type,
            "rev": i.rev,
            "deleted": i.deleted,
            "key_revision": i.key_revision,
        })).collect::<Vec<_>>(),
        "next_cursor": next,
        "has_more": items.len() as i64 == limit,
    }))
}

#[post("/crypto/rotation/complete")]
async fn rotation_complete(db: web::Data<DBPool>, auth: AuthUser) -> HttpResponse {
    let Some(c) = db::get_crypto(pool(&db), auth.user_id()).await.ok().flatten() else {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "rotation_not_in_progress");
    };
    if c.rotation_status != "in_progress" {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "rotation_not_in_progress");
    }
    let to = c.to_key_revision.unwrap_or(0);
    let remaining = db::count_stale_crypto_items(pool(&db), auth.user_id(), to)
        .await
        .unwrap_or(1);
    if remaining > 0 {
        return json_status(
            StatusCode::CONFLICT,
            json!({
                "remaining_items": remaining,
                "err": "Not all items are at the new key revision.",
            }),
        );
    }
    if db::complete_rotation(pool(&db), auth.user_id()).await.is_err() {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    json_ok(json!({ "status": "idle", "current_key_revision": to }))
}

#[get("/admin/health")]
async fn admin_health(db: web::Data<DBPool>, _admin: AdminUser) -> HttpResponse {
    match db::count_users(pool(&db)).await {
        Ok((total, enabled)) => json_ok(json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "postgres": "ok",
            "user_count": total,
            "enabled_user_count": enabled,
        })),
        Err(_) => json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    }
}

#[derive(Deserialize)]
struct UserListQuery {
    limit: Option<i64>,
    cursor: Option<String>,
    q: Option<String>,
}

async fn credential_count(pool: &sqlx::PgPool, user_id: i64) -> i64 {
    let sessions = db::count_live_tokens(pool, user_id).await.unwrap_or(0);
    let app = db::count_live_app_token(pool, user_id).await.unwrap_or(0);
    sessions + app
}

fn app_token_json(row: Option<db::AppTokenRow>) -> Value {
    match row {
        Some(row) => json!({
            "token": row.token,
            "expires_at": row.expires_at.map(ts),
            "created_at": ts(row.created_at),
        }),
        None => json!({
            "token": Value::Null,
            "expires_at": Value::Null,
            "created_at": Value::Null,
        }),
    }
}

#[derive(Deserialize)]
struct IssueAppTokenReq {
    unlimited: Option<bool>,
    expires_at: Option<String>,
}

#[get("/auth/app-token")]
async fn get_app_token(db: web::Data<DBPool>, auth: AuthUser) -> HttpResponse {
    match db::get_app_token(pool(&db), auth.user_id()).await {
        Ok(row) => json_ok(app_token_json(row)),
        Err(_) => json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    }
}

#[post("/auth/app-token")]
async fn issue_app_token(db: web::Data<DBPool>, auth: AuthUser, body: web::Json<IssueAppTokenReq>) -> HttpResponse {
    let unlimited = body.unlimited.unwrap_or(false);
    let expires_at = if unlimited {
        if body.expires_at.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            return json_err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Do not set an expiry when the token does not expire.",
            );
        }
        None
    } else {
        let Some(raw) = body.expires_at.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
            return json_err(StatusCode::UNPROCESSABLE_ENTITY, "Choose an expiry date, or no expiry.");
        };
        match util::parse_expires_at(raw) {
            Ok(t) if t > OffsetDateTime::now_utc() => Some(t),
            Ok(_) => return json_err(StatusCode::UNPROCESSABLE_ENTITY, "Expiry must be in the future."),
            Err(()) => {
                return json_err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Expiry must be a date (YYYY-MM-DD) or a UTC time.",
                );
            }
        }
    };
    let (token, hash) = util::issue_token();
    match db::upsert_app_token(pool(&db), auth.user_id(), &token, &hash, expires_at).await {
        Ok(row) => json_ok(app_token_json(Some(row))),
        Err(_) => json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    }
}

#[delete("/auth/app-token")]
async fn delete_app_token(db: web::Data<DBPool>, auth: AuthUser) -> HttpResponse {
    if db::delete_app_token(pool(&db), auth.user_id()).await.is_err() {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    json_ok(app_token_json(None))
}

fn user_public(u: &db::UserRow, token_count: i64) -> Value {
    json!({
        "username": u.username,
        "display_name": u.display_name,
        "role": u.role,
        "enabled": u.enabled,
        "created_at": ts(u.created_at),
        "last_login_at": u.last_login_at.map(ts),
        "token_count": token_count,
    })
}

#[get("/admin/users")]
async fn admin_list_users(db: web::Data<DBPool>, _admin: AdminUser, q: web::Query<UserListQuery>) -> HttpResponse {
    let limit = q.limit.unwrap_or(50);
    if limit < 1 || limit > 200 {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "limit must be 1–200.");
    }
    let Ok(users) = db::list_users(pool(&db), q.q.as_deref(), q.cursor.as_deref(), limit + 1).await else {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    let has_more = users.len() as i64 > limit;
    let mut users = users;
    users.truncate(limit as usize);
    let mut out = Vec::new();
    for u in &users {
        let tc = credential_count(pool(&db), u.id).await;
        out.push(user_public(u, tc));
    }
    let next = users.last().map(|u| u.username.clone());
    json_ok(json!({ "users": out, "next_cursor": next, "has_more": has_more }))
}

#[derive(Deserialize)]
struct CreateUserReq {
    username: String,
    display_name: Option<String>,
    role: Option<String>,
    enabled: Option<bool>,
}

#[post("/admin/users")]
async fn admin_create_user(
    db: web::Data<DBPool>,
    admin: AdminUser,
    req: HttpRequest,
    body: web::Json<CreateUserReq>,
) -> HttpResponse {
    if !util::valid_username(&body.username) {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid username.");
    }
    let role = body.role.as_deref().unwrap_or("user");
    if role != "user" && role != "admin" {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid role.");
    }
    if db::get_user_by_username(pool(&db), &body.username)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return json_status(StatusCode::CONFLICT, json!({ "err": "Username taken." }));
    }
    let temp = util::temporary_password();
    let Ok(hash) = util::hash_password(&temp) else {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    if db::insert_user(
        pool(&db),
        &body.username,
        body.display_name.as_deref(),
        &hash,
        role,
        body.enabled.unwrap_or(true),
    )
    .await
    .is_err()
    {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    let _ = db::audit(
        pool(&db),
        &admin.0.user.username,
        "create_user",
        Some(&body.username),
        &request_id(&req),
    )
    .await;
    let user = db::get_user_by_username(pool(&db), &body.username)
        .await
        .ok()
        .flatten()
        .unwrap();
    json_created(json!({
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "enabled": user.enabled,
        "created_at": ts(user.created_at),
        "temporary_password": temp,
    }))
}

#[get("/admin/users/{username}")]
async fn admin_get_user(db: web::Data<DBPool>, _admin: AdminUser, path: web::Path<String>) -> HttpResponse {
    match db::get_user_by_username(pool(&db), &path).await {
        Ok(Some(u)) => {
            let tc = credential_count(pool(&db), u.id).await;
            json_ok(user_public(&u, tc))
        }
        Ok(None) => json_err(StatusCode::NOT_FOUND, "Not found."),
        Err(_) => json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable."),
    }
}

#[derive(Deserialize)]
struct PatchUserReq {
    display_name: Option<String>,
    enabled: Option<bool>,
}

#[patch("/admin/users/{username}")]
async fn admin_patch_user(
    db: web::Data<DBPool>,
    admin: AdminUser,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<PatchUserReq>,
) -> HttpResponse {
    let username = path.into_inner();
    let Some(user) = db::get_user_by_username(pool(&db), &username).await.ok().flatten() else {
        return json_err(StatusCode::NOT_FOUND, "Not found.");
    };
    if body.enabled == Some(false) && user.role == "admin" {
        let n = db::count_enabled_admins(pool(&db)).await.unwrap_or(0);
        if n <= 1 {
            return json_status(StatusCode::CONFLICT, json!({ "err": "Cannot remove the last admin." }));
        }
    }
    if db::update_user(pool(&db), &username, body.display_name.as_deref(), body.enabled)
        .await
        .is_err()
    {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    let _ = db::audit(
        pool(&db),
        &admin.0.user.username,
        "patch_user",
        Some(&username),
        &request_id(&req),
    )
    .await;
    let user = db::get_user_by_username(pool(&db), &username)
        .await
        .ok()
        .flatten()
        .unwrap();
    let tc = credential_count(pool(&db), user.id).await;
    json_ok(user_public(&user, tc))
}

#[delete("/admin/users/{username}")]
async fn admin_delete_user(
    db: web::Data<DBPool>,
    admin: AdminUser,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let username = path.into_inner();
    let Some(user) = db::get_user_by_username(pool(&db), &username).await.ok().flatten() else {
        return json_err(StatusCode::NOT_FOUND, "Not found.");
    };
    if user.role == "admin" && db::count_enabled_admins(pool(&db)).await.unwrap_or(0) <= 1 {
        return json_status(StatusCode::CONFLICT, json!({ "err": "Cannot remove the last admin." }));
    }
    if db::delete_user(pool(&db), &username).await.is_err() {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    let _ = db::audit(
        pool(&db),
        &admin.0.user.username,
        "delete_user",
        Some(&username),
        &request_id(&req),
    )
    .await;
    json_ok(json!({}))
}

#[post("/admin/users/{username}/password/reset")]
async fn admin_reset_password(
    db: web::Data<DBPool>,
    admin: AdminUser,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let username = path.into_inner();
    let Some(user) = db::get_user_by_username(pool(&db), &username).await.ok().flatten() else {
        return json_err(StatusCode::NOT_FOUND, "Not found.");
    };
    let temp = util::temporary_password();
    let Ok(hash) = util::hash_password(&temp) else {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    };
    if db::set_password_hash(pool(&db), &username, &hash).await.is_err() {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.");
    }
    let _ = db::revoke_all_tokens(pool(&db), user.id).await;
    let _ = db::delete_app_token(pool(&db), user.id).await;
    let _ = db::audit(
        pool(&db),
        &admin.0.user.username,
        "reset_password",
        Some(&username),
        &request_id(&req),
    )
    .await;
    json_ok(json!({
        "username": username,
        "temporary_password": temp,
    }))
}

#[post("/admin/users/{username}/tokens/revoke")]
async fn admin_revoke_tokens(
    db: web::Data<DBPool>,
    admin: AdminUser,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let username = path.into_inner();
    let Some(user) = db::get_user_by_username(pool(&db), &username).await.ok().flatten() else {
        return json_err(StatusCode::NOT_FOUND, "Not found.");
    };
    let n = db::revoke_all_tokens(pool(&db), user.id).await.unwrap_or(0);
    let app = db::delete_app_token(pool(&db), user.id).await.unwrap_or(0);
    let _ = db::audit(
        pool(&db),
        &admin.0.user.username,
        "revoke_tokens",
        Some(&username),
        &request_id(&req),
    )
    .await;
    json_ok(json!({ "username": username, "tokens_revoked": n + app }))
}

pub fn v1_public(cfg: &mut web::ServiceConfig) {
    cfg.service(health).service(login);
}

pub fn v1_user(cfg: &mut web::ServiceConfig) {
    cfg.service(logout)
        .service(list_tokens)
        .service(delete_token)
        .service(get_app_token)
        .service(issue_app_token)
        .service(delete_app_token)
        .service(change_password)
        .service(me)
        .service(push_items)
        .service(pull_items)
        .service(get_item)
        .service(put_key)
        .service(get_key)
        .service(rotation_start)
        .service(rotation_get)
        .service(rotation_items)
        .service(rotation_complete);
}

pub fn v1_admin(cfg: &mut web::ServiceConfig) {
    cfg.service(admin_health)
        .service(admin_list_users)
        .service(admin_create_user)
        .service(admin_get_user)
        .service(admin_patch_user)
        .service(admin_delete_user)
        .service(admin_reset_password)
        .service(admin_revoke_tokens);
}
