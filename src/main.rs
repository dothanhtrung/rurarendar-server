#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
use tikv_jemallocator::Jemalloc;

#[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

mod api;
mod auth;
mod cli;
mod config;
mod db;
mod handlers;
mod serve;
mod setup;
mod ui;
mod util;

use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "rurarendar-server", version)]
struct Args {
    #[arg(short, long, default_value = "rurarendar-server.ron")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::load_dotenv();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_thread_ids(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = config::Config::load(&Args::parse().config)?;
    serve::run(config).await
}
