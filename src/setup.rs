use actix_web::cookie::{Cookie, SameSite};
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use serde::Deserialize;
use tera::Tera;
use web_misc::db::DBPool;

use crate::{db, ui, util};

#[derive(Deserialize)]
struct SetupForm {
    username: String,
    display_name: String,
    password: String,
    confirm_password: String,
    csrf_token: String,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.app_data(web::FormConfig::default().limit(8192))
        .service(setup_page)
        .service(setup_submit);
}

fn form_response(tmpl: &Tera, req: &HttpRequest, error: Option<&str>) -> HttpResponse {
    let token = util::temporary_password();
    let mut context = tera::Context::new();
    context.insert("csrf_token", &token);
    context.insert("error", &error);
    let mut response = ui::render_context(tmpl, "setup.html", context);
    if error.is_some() {
        *response.status_mut() = actix_web::http::StatusCode::UNPROCESSABLE_ENTITY;
    }
    let cookie = Cookie::build("rurarendar.setup", token)
        .path("/setup")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(req.connection_info().scheme() == "https")
        .finish();
    let _ = response.add_cookie(&cookie);
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static("no-store"),
    );
    response
}

#[get("/setup")]
async fn setup_page(db: web::Data<DBPool>, tmpl: web::Data<Tera>, req: HttpRequest) -> HttpResponse {
    match db::setup_needed(&db.pg_pool).await {
        Ok(true) => form_response(&tmpl, &req, None),
        Ok(false) => ui::redirect("/login"),
        Err(_) => HttpResponse::ServiceUnavailable().body("Service unavailable."),
    }
}

#[post("/setup")]
async fn setup_submit(
    db: web::Data<DBPool>,
    tmpl: web::Data<Tera>,
    req: HttpRequest,
    form: web::Form<SetupForm>,
) -> HttpResponse {
    match db::setup_needed(&db.pg_pool).await {
        Ok(false) => return HttpResponse::Forbidden().body("Setup is already complete."),
        Err(_) => return HttpResponse::ServiceUnavailable().body("Service unavailable."),
        Ok(true) => {}
    }
    if !req.cookie("rurarendar.setup").is_some_and(|cookie| cookie.value() == form.csrf_token) {
        return HttpResponse::Forbidden().body("Invalid setup request.");
    }
    let username = form.username.trim();
    let error = if !util::valid_username(username) {
        Some("Username must be 3-32 ASCII letters, digits, dots, underscores or hyphens, and cannot start or end with a dot or hyphen.")
    } else if !(8..=128).contains(&form.password.len()) {
        Some("Password must be 8-128 bytes.")
    } else if form.password != form.confirm_password {
        Some("Passwords do not match.")
    } else if form.display_name.len() > 128 {
        Some("Display name must be at most 128 bytes.")
    } else {
        None
    };
    if let Some(error) = error {
        return form_response(&tmpl, &req, Some(error));
    }
    let Ok(hash) = util::hash_password(&form.password) else {
        return HttpResponse::InternalServerError().body("Could not create account.");
    };
    let display_name = form.display_name.trim();
    match db::initialize_admin(
        &db.pg_pool,
        username,
        (!display_name.is_empty()).then_some(display_name),
        &hash,
    ).await {
        Ok(true) => HttpResponse::SeeOther().append_header(("Location", "/login")).finish(),
        Ok(false) => HttpResponse::Forbidden().body("Setup is already complete."),
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
            form_response(&tmpl, &req, Some("Username is already taken."))
        }
        Err(error) => {
            tracing::error!(%error, "initial admin setup failed");
            HttpResponse::ServiceUnavailable().body("Service unavailable.")
        }
    }
}