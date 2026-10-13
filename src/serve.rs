use actix_web::middleware::Logger;
use actix_web::web::JsonConfig;
use actix_web::{
    App,
    HttpServer,
    web,
};

use crate::cli::pool;
use crate::handlers;
use crate::ui;

pub async fn run(config: crate::config::Config) -> anyhow::Result<()> {
    let pool = pool(&config.db).await?;
    let bind = config.bind;

    let json_cfg = JsonConfig::default().limit(256 * 1024).error_handler(|err, _| {
        actix_web::error::InternalError::from_response(
            err,
            crate::api::json_err(actix_web::http::StatusCode::BAD_REQUEST, "Bad JSON."),
        )
        .into()
    });

    tracing::info!("listening on {bind}");
    let pool = web::Data::new(pool);
    let tera = web::Data::new(ui::tera());
    HttpServer::new(move || {
        App::new()
            .app_data(pool.clone())
            .app_data(tera.clone())
            .app_data(json_cfg.clone())
            .wrap(Logger::default())
            .configure(crate::setup::configure)
            .configure(ui::configure)
            .service(
                web::scope("/v1")
                    .configure(handlers::v1_public)
                    .configure(handlers::v1_user)
                    .configure(handlers::v1_admin),
            )
    })
    .bind(&bind)?
    .run()
    .await?;
    Ok(())
}
