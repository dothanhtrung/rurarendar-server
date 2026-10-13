use actix_web::{
    HttpResponse,
    get,
    web,
};
use tera::Tera;
use web_misc::db::DBPool;

pub fn tera() -> Tera {
    let mut tera = Tera::new();
    tera.add_raw_templates([
        ("base.html", include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/base.html"))),
        ("login.html", include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/login.html"))),
        ("setup.html", include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/setup.html"))),
        ("account.html", include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/account.html"))),
        ("users.html", include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/users.html"))),
    ])
    .expect("admin templates");
    tera
}

fn render(tera: &Tera, name: &str) -> HttpResponse {
    render_context(tera, name, tera::Context::new())
}

pub(crate) fn render_context(tera: &Tera, name: &str, mut ctx: tera::Context) -> HttpResponse {
    ctx.insert("version", env!("CARGO_PKG_VERSION"));
    match tera.render(name, &ctx) {
        Ok(body) => HttpResponse::Ok().content_type("text/html; charset=utf-8").body(body),
        Err(e) => {
            tracing::error!(error = %e, template = name, "admin template render failed");
            HttpResponse::InternalServerError().body("Template error.")
        }
    }
}

pub(crate) fn redirect(to: &str) -> HttpResponse {
    HttpResponse::Found().append_header(("Location", to)).finish()
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(root)
        .service(login)
        .service(account)
        .service(admin_root)
        .service(admin_root_slash)
        .service(admin_css)
        .service(admin_login)
        .service(admin_users);
}

#[get("/")]
async fn root(db: web::Data<DBPool>) -> HttpResponse {
    match crate::db::setup_needed(&db.pg_pool).await {
        Ok(true) => redirect("/setup"),
        Ok(false) => redirect("/login"),
        Err(_) => HttpResponse::ServiceUnavailable().body("Service unavailable."),
    }
}

async fn render_ready(db: &DBPool, tmpl: &Tera, name: &str) -> HttpResponse {
    match crate::db::setup_needed(&db.pg_pool).await {
        Ok(true) => redirect("/setup"),
        Ok(false) => render(tmpl, name),
        Err(_) => HttpResponse::ServiceUnavailable().body("Service unavailable."),
    }
}

#[get("/login")]
async fn login(db: web::Data<DBPool>, tmpl: web::Data<Tera>) -> HttpResponse {
    render_ready(&db, &tmpl, "login.html").await
}

#[get("/account")]
async fn account(db: web::Data<DBPool>, tmpl: web::Data<Tera>) -> HttpResponse {
    render_ready(&db, &tmpl, "account.html").await
}

#[get("/admin")]
async fn admin_root() -> HttpResponse {
    redirect("/admin/users")
}

#[get("/admin/")]
async fn admin_root_slash() -> HttpResponse {
    redirect("/admin/users")
}

#[get("/admin/static/tailwind_output.min.css")]
async fn admin_css() -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-cache"))
        .content_type("text/css; charset=utf-8")
        .body(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/css/tailwind_output.min.css"
        )))
}

#[get("/admin/login")]
async fn admin_login() -> HttpResponse {
    redirect("/login")
}

#[get("/admin/users")]
async fn admin_users(db: web::Data<DBPool>, tmpl: web::Data<Tera>) -> HttpResponse {
    render_ready(&db, &tmpl, "users.html").await
}
