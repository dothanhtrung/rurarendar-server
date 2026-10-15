use sqlx::PgPool;
use sqlx::types::Json;
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub display_name: Option<String>,
    pub password_hash: String,
    pub role: String,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub last_login_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct TokenRow {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub device_id: Option<String>,
    pub device_label: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct AppTokenRow {
    pub id: i64,
    pub token: String,
    pub expires_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug)]
pub struct ItemRow {
    pub item_id: i64,
    pub sync_key: String,
    pub item_type: String,
    pub rev: i64,
    pub deleted: bool,
    pub seq: i64,
    pub updated_at: OffsetDateTime,
    pub modified_timestamp: OffsetDateTime,
    pub key_revision: i32,
    pub alg: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CryptoRow {
    pub current_key_revision: i32,
    pub kdf_json: Option<Json<serde_json::Value>>,
    pub verifier_alg: Option<String>,
    pub verifier_nonce: Option<Vec<u8>>,
    pub verifier_ciphertext: Option<Vec<u8>>,
    pub rotation_status: String,
    pub from_key_revision: Option<i32>,
    pub to_key_revision: Option<i32>,
    pub pending_kdf_json: Option<Json<serde_json::Value>>,
    pub pending_verifier_alg: Option<String>,
    pub pending_verifier_nonce: Option<Vec<u8>>,
    pub pending_verifier_ciphertext: Option<Vec<u8>>,
    pub rotation_started_at: Option<OffsetDateTime>,
}

pub async fn insert_user(
    pool: &PgPool,
    username: &str,
    display_name: Option<&str>,
    password_hash: &str,
    role: &str,
    enabled: bool,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(
        r#"INSERT INTO users (username, display_name, password_hash, role, enabled)
         VALUES ($1, $2, $3, $4, $5) RETURNING id as "id!: i64""#,
        username,
        display_name,
        password_hash,
        role,
        enabled
    )
    .fetch_one(pool)
    .await
}

pub async fn setup_needed(pool: &PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar!(r#"SELECT NOT completed AS "needed!" FROM server_setup WHERE id = TRUE"#)
        .fetch_one(pool)
        .await
}

pub async fn initialize_admin(
    pool: &PgPool,
    username: &str,
    display_name: Option<&str>,
    password_hash: &str,
) -> Result<bool, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let completed = sqlx::query_scalar!("SELECT completed FROM server_setup WHERE id = TRUE FOR UPDATE")
        .fetch_one(&mut *transaction)
        .await?;
    if completed {
        return Ok(false);
    }
    sqlx::query!(
        "INSERT INTO users (username, display_name, password_hash, role, enabled)
         VALUES ($1, $2, $3, 'admin', TRUE)",
        username,
        display_name,
        password_hash
    )
    .execute(&mut *transaction)
    .await?;
    sqlx::query!("UPDATE server_setup SET completed = TRUE WHERE id = TRUE")
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn get_user_by_username(pool: &PgPool, username: &str) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as!(
        UserRow,
        r#"SELECT id, username, display_name, password_hash, role, enabled,
                  created_at, updated_at, last_login_at
           FROM users WHERE username = $1"#,
        username
    )
    .fetch_optional(pool)
    .await
}

pub async fn list_users(
    pool: &PgPool,
    q: Option<&str>,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<UserRow>, sqlx::Error> {
    sqlx::query_as!(
        UserRow,
        r#"SELECT id, username, display_name, password_hash, role, enabled,
                  created_at, updated_at, last_login_at
           FROM users
           WHERE ($1::text IS NULL OR username LIKE $1 || '%')
             AND ($2::text IS NULL OR username > $2)
           ORDER BY username
           LIMIT $3"#,
        q,
        after,
        limit
    )
    .fetch_all(pool)
    .await
}

pub async fn count_enabled_admins(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let n = sqlx::query_scalar!(r#"SELECT COUNT(*) as "count!" FROM users WHERE role = 'admin' AND enabled = TRUE"#)
        .fetch_one(pool)
        .await?;
    Ok(n)
}

pub async fn update_user(
    pool: &PgPool,
    username: &str,
    display_name: Option<&str>,
    enabled: Option<bool>,
) -> Result<u64, sqlx::Error> {
    let res = sqlx::query!(
        "UPDATE users SET
            display_name = COALESCE($2, display_name),
            enabled = COALESCE($3, enabled),
            updated_at = now()
         WHERE username = $1",
        username,
        display_name,
        enabled
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

pub async fn set_password_hash(pool: &PgPool, username: &str, hash: &str) -> Result<u64, sqlx::Error> {
    let res = sqlx::query!(
        "UPDATE users SET password_hash = $2, updated_at = now() WHERE username = $1",
        username,
        hash
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

pub async fn touch_login(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query!("UPDATE users SET last_login_at = now() WHERE id = $1", id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_user(pool: &PgPool, username: &str) -> Result<u64, sqlx::Error> {
    let res = sqlx::query!("DELETE FROM users WHERE username = $1", username)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

pub async fn insert_token(
    pool: &PgPool,
    user_id: i64,
    username: &str,
    token_hash: &[u8],
    device_id: Option<&str>,
    device_label: Option<&str>,
    expires_at: OffsetDateTime,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(
        r#"INSERT INTO tokens (user_id, username, token_hash, device_id, device_label, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id as "id!: i64""#,
        user_id,
        username,
        token_hash,
        device_id,
        device_label,
        expires_at
    )
    .fetch_one(pool)
    .await
}

pub async fn revoke_device_token(pool: &PgPool, user_id: i64, device_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE tokens SET revoked_at = now()
         WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL AND expires_at > now()",
        user_id,
        device_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn lookup_token(pool: &PgPool, token_hash: &[u8]) -> Result<Option<(UserRow, TokenRow)>, sqlx::Error> {
    let row = sqlx::query!(
        r#"SELECT
            u.id as "user_id!", u.username, u.display_name, u.password_hash, u.role, u.enabled,
            u.created_at, u.updated_at, u.last_login_at,
            t.id as "token_id!", t.device_id, t.device_label,
            t.created_at as token_created_at, t.expires_at, t.last_used_at
           FROM tokens t
           JOIN users u ON u.id = t.user_id
           WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND t.expires_at > now()"#,
        token_hash
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| {
        (
            UserRow {
                id: r.user_id,
                username: r.username.clone(),
                display_name: r.display_name,
                password_hash: r.password_hash,
                role: r.role,
                enabled: r.enabled,
                created_at: r.created_at,
                updated_at: r.updated_at,
                last_login_at: r.last_login_at,
            },
            TokenRow {
                id: r.token_id,
                user_id: r.user_id,
                username: r.username,
                device_id: r.device_id,
                device_label: r.device_label,
                created_at: r.token_created_at,
                expires_at: r.expires_at,
                last_used_at: r.last_used_at,
            },
        )
    }))
}

pub async fn list_tokens(pool: &PgPool, user_id: i64) -> Result<Vec<TokenRow>, sqlx::Error> {
    sqlx::query_as!(
        TokenRow,
        r#"SELECT id, user_id, username, device_id, device_label, created_at, expires_at, last_used_at
           FROM tokens
           WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
           ORDER BY created_at"#,
        user_id
    )
    .fetch_all(pool)
    .await
}

pub async fn revoke_token(pool: &PgPool, user_id: i64, token_id: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query!(
        "UPDATE tokens SET revoked_at = now()
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
        token_id,
        user_id
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

pub async fn revoke_all_tokens(pool: &PgPool, user_id: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query!(
        "UPDATE tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
        user_id
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

pub async fn revoke_other_tokens(pool: &PgPool, user_id: i64, keep: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query!(
        "UPDATE tokens SET revoked_at = now()
         WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL",
        user_id,
        keep
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

pub async fn count_live_tokens(pool: &PgPool, user_id: i64) -> Result<i64, sqlx::Error> {
    let n = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "count!" FROM tokens
           WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()"#,
        user_id
    )
    .fetch_one(pool)
    .await?;
    Ok(n)
}

pub async fn lookup_app_token(pool: &PgPool, token_hash: &[u8]) -> Result<Option<(UserRow, AppTokenRow)>, sqlx::Error> {
    let row = sqlx::query!(
        r#"SELECT
            u.id as "user_id!", u.username, u.display_name, u.password_hash, u.role, u.enabled,
            u.created_at, u.updated_at, u.last_login_at,
            t.id as "token_id!", t.token, t.expires_at, t.created_at as token_created_at
           FROM app_tokens t
           JOIN users u ON u.id = t.user_id
           WHERE t.token_hash = $1 AND (t.expires_at IS NULL OR t.expires_at > now())"#,
        token_hash
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| {
        (
            UserRow {
                id: r.user_id,
                username: r.username,
                display_name: r.display_name,
                password_hash: r.password_hash,
                role: r.role,
                enabled: r.enabled,
                created_at: r.created_at,
                updated_at: r.updated_at,
                last_login_at: r.last_login_at,
            },
            AppTokenRow {
                id: r.token_id,
                token: r.token,
                expires_at: r.expires_at,
                created_at: r.token_created_at,
            },
        )
    }))
}

pub async fn get_app_token(pool: &PgPool, user_id: i64) -> Result<Option<AppTokenRow>, sqlx::Error> {
    sqlx::query_as!(
        AppTokenRow,
        r#"SELECT id, token, expires_at, created_at
           FROM app_tokens WHERE user_id = $1"#,
        user_id
    )
    .fetch_optional(pool)
    .await
}

pub async fn upsert_app_token(
    pool: &PgPool,
    user_id: i64,
    token: &str,
    token_hash: &[u8],
    expires_at: Option<OffsetDateTime>,
) -> Result<AppTokenRow, sqlx::Error> {
    sqlx::query_as!(
        AppTokenRow,
          r#"INSERT INTO app_tokens (user_id, token, token_hash, expires_at)
              VALUES ($1, $2, $3, $4)
           ON CONFLICT (user_id) DO UPDATE
              SET token = EXCLUDED.token,
               token_hash = EXCLUDED.token_hash,
               expires_at = EXCLUDED.expires_at,
               created_at = now()
              RETURNING id, token, expires_at, created_at"#,
        user_id,
        token,
        token_hash,
        expires_at
    )
    .fetch_one(pool)
    .await
}

pub async fn delete_app_token(pool: &PgPool, user_id: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query!("DELETE FROM app_tokens WHERE user_id = $1", user_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

pub async fn count_live_app_token(pool: &PgPool, user_id: i64) -> Result<i64, sqlx::Error> {
    let n = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "count!" FROM app_tokens
           WHERE user_id = $1 AND (expires_at IS NULL OR expires_at > now())"#,
        user_id
    )
    .fetch_one(pool)
    .await?;
    Ok(n)
}

pub async fn next_seq(pool: &PgPool, user_id: i64) -> Result<i64, sqlx::Error> {
    let seq = sqlx::query_scalar!(
        r#"INSERT INTO user_seq (user_id, last_seq) VALUES ($1, 1)
           ON CONFLICT (user_id) DO UPDATE SET last_seq = user_seq.last_seq + 1
           RETURNING last_seq as "last_seq!""#,
        user_id
    )
    .fetch_one(pool)
    .await?;
    Ok(seq)
}

pub async fn get_item(pool: &PgPool, user_id: i64, item_id: i64) -> Result<Option<ItemRow>, sqlx::Error> {
    sqlx::query_as!(
        ItemRow,
        r#"SELECT item_id, sync_key, item_type, rev, deleted, seq, updated_at, modified_timestamp, key_revision,
                  alg, nonce, ciphertext
           FROM user_items WHERE user_id = $1 AND item_id = $2"#,
        user_id,
        item_id
    )
    .fetch_optional(pool)
    .await
}

pub async fn get_item_by_sync_key(pool: &PgPool, user_id: i64, sync_key: &str) -> Result<Option<ItemRow>, sqlx::Error> {
    sqlx::query_as!(
        ItemRow,
        r#"SELECT item_id, sync_key, item_type, rev, deleted, seq, updated_at, modified_timestamp, key_revision,
                  alg, nonce, ciphertext
           FROM user_items WHERE user_id = $1 AND sync_key = $2"#,
        user_id,
        sync_key
    )
    .fetch_optional(pool)
    .await
}

pub async fn insert_item(pool: &PgPool, user_id: i64, item: &ItemRow) -> Result<i64, sqlx::Error> {
    let item_id = sqlx::query_scalar!(
        r#"INSERT INTO user_items
            (user_id, sync_key, item_type, rev, deleted, seq, updated_at, modified_timestamp, key_revision, alg, nonce, ciphertext)
         VALUES ($1, $2, $3, $4, $5, $6, now(), now(), $7, $8, $9, $10)
         RETURNING item_id as "item_id!: i64""#,
        user_id,
        item.sync_key,
        item.item_type,
        item.rev,
        item.deleted,
        item.seq,
        item.key_revision,
        item.alg,
        item.nonce,
        item.ciphertext
    )
    .fetch_one(pool)
    .await?;
    Ok(item_id)
}

pub async fn update_item(pool: &PgPool, user_id: i64, item: &ItemRow) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE user_items SET
            rev = $3, deleted = $4, seq = $5, updated_at = now(), modified_timestamp = now(),
            key_revision = $6, alg = $7, nonce = $8, ciphertext = $9
         WHERE user_id = $1 AND item_id = $2",
        user_id,
        item.item_id,
        item.rev,
        item.deleted,
        item.seq,
        item.key_revision,
        item.alg,
        item.nonce,
        item.ciphertext
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn pull_items(pool: &PgPool, user_id: i64, after_seq: i64, limit: i64) -> Result<Vec<ItemRow>, sqlx::Error> {
    sqlx::query_as!(
        ItemRow,
        r#"SELECT item_id, sync_key, item_type, rev, deleted, seq, updated_at, modified_timestamp, key_revision,
                  alg, nonce, ciphertext
           FROM user_items
           WHERE user_id = $1 AND seq > $2
           ORDER BY seq
           LIMIT $3"#,
        user_id,
        after_seq,
        limit
    )
    .fetch_all(pool)
    .await
}

pub async fn count_items_after(pool: &PgPool, user_id: i64, seq: i64) -> Result<i64, sqlx::Error> {
    let n = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "count!" FROM user_items WHERE user_id = $1 AND seq > $2"#,
        user_id,
        seq
    )
    .fetch_one(pool)
    .await?;
    Ok(n)
}

pub async fn get_crypto(pool: &PgPool, user_id: i64) -> Result<Option<CryptoRow>, sqlx::Error> {
    sqlx::query_as!(
        CryptoRow,
        r#"SELECT current_key_revision,
                  kdf_json as "kdf_json: Json<serde_json::Value>",
                  verifier_alg, verifier_nonce, verifier_ciphertext,
                  rotation_status,
                  from_key_revision, to_key_revision,
                  pending_kdf_json as "pending_kdf_json: Json<serde_json::Value>",
                  pending_verifier_alg, pending_verifier_nonce, pending_verifier_ciphertext,
                  rotation_started_at
           FROM user_crypto WHERE user_id = $1"#,
        user_id
    )
    .fetch_optional(pool)
    .await
}

pub async fn upsert_crypto_first(
    pool: &PgPool,
    user_id: i64,
    key_revision: i32,
    kdf: Json<serde_json::Value>,
    verifier_alg: &str,
    verifier_nonce: &[u8],
    verifier_ciphertext: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO user_crypto
            (user_id, current_key_revision, kdf_json, verifier_alg, verifier_nonce, verifier_ciphertext, rotation_status)
         VALUES ($1, $2, $3, $4, $5, $6, 'idle')",
        user_id,
        key_revision,
        kdf as Json<serde_json::Value>,
        verifier_alg,
        verifier_nonce,
        verifier_ciphertext
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn start_rotation(
    pool: &PgPool,
    user_id: i64,
    from_rev: i32,
    to_rev: i32,
    pending_kdf: Json<serde_json::Value>,
    pending_alg: &str,
    pending_nonce: &[u8],
    pending_ct: &[u8],
) -> Result<i64, sqlx::Error> {
    let updated = sqlx::query!(
        r#"UPDATE user_crypto SET
            rotation_status = 'in_progress',
            from_key_revision = $2,
            to_key_revision = $3,
            pending_kdf_json = $4,
            pending_verifier_alg = $5,
            pending_verifier_nonce = $6,
            pending_verifier_ciphertext = $7,
            rotation_started_at = now()
         WHERE user_id = $1"#,
        user_id,
        from_rev,
        to_rev,
        pending_kdf as Json<serde_json::Value>,
        pending_alg,
        pending_nonce,
        pending_ct
    )
    .execute(pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(sqlx::Error::RowNotFound);
    }
    Ok(i64::from(to_rev))
}

pub async fn complete_rotation(pool: &PgPool, user_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE user_crypto SET
            current_key_revision = to_key_revision,
            kdf_json = pending_kdf_json,
            verifier_alg = pending_verifier_alg,
            verifier_nonce = pending_verifier_nonce,
            verifier_ciphertext = pending_verifier_ciphertext,
            rotation_status = 'idle',
            from_key_revision = NULL,
            to_key_revision = NULL,
            pending_kdf_json = NULL,
            pending_verifier_alg = NULL,
            pending_verifier_nonce = NULL,
            pending_verifier_ciphertext = NULL,
            rotation_started_at = NULL
         WHERE user_id = $1 AND rotation_status = 'in_progress'",
        user_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn count_stale_crypto_items(pool: &PgPool, user_id: i64, to_rev: i32) -> Result<i64, sqlx::Error> {
    let n = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "count!" FROM user_items
           WHERE user_id = $1 AND key_revision < $2 AND octet_length(ciphertext) > 0"#,
        user_id,
        to_rev
    )
    .fetch_one(pool)
    .await?;
    Ok(n)
}

pub async fn rotation_items(
    pool: &PgPool,
    user_id: i64,
    to_rev: i32,
    after_id: Option<i64>,
    limit: i64,
) -> Result<Vec<ItemRow>, sqlx::Error> {
    sqlx::query_as!(
        ItemRow,
        r#"SELECT item_id, sync_key, item_type, rev, deleted, seq, updated_at, modified_timestamp, key_revision,
                  alg, nonce, ciphertext
           FROM user_items
           WHERE user_id = $1 AND key_revision < $2 AND octet_length(ciphertext) > 0
             AND ($3::bigint IS NULL OR item_id > $3)
           ORDER BY item_id
           LIMIT $4"#,
        user_id,
        to_rev,
        after_id,
        limit
    )
    .fetch_all(pool)
    .await
}

pub async fn audit(
    pool: &PgPool,
    actor: &str,
    action: &str,
    target: Option<&str>,
    request_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO admin_audit (actor, action, target_username, request_id) VALUES ($1, $2, $3, $4)",
        actor,
        action,
        target,
        request_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn count_users(pool: &PgPool) -> Result<(i64, i64), sqlx::Error> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) as "total!",
                  COUNT(*) FILTER (WHERE enabled) as "enabled!"
           FROM users"#
    )
    .fetch_one(pool)
    .await?;
    Ok((row.total, row.enabled))
}
