use web_misc::db::{
    DBConfig,
    DBPool,
};

pub fn load_dotenv() {
    let crate_env = concat!(env!("CARGO_MANIFEST_DIR"), "/.env");
    let _ = dotenvy::from_filename(crate_env);
    let _ = dotenvy::dotenv();
}

pub async fn pool(cfg: &DBConfig) -> anyhow::Result<DBPool> {
    let pool = DBPool::init(cfg).await?;
    sqlx::migrate!("db/migrations/postgres").run(&pool.pg_pool).await?;
    Ok(pool)
}
