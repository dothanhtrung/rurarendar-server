use std::future::Future;
use std::pin::Pin;

use actix_web::dev::Payload;
use actix_web::http::StatusCode;
use actix_web::http::header::AUTHORIZATION;
use actix_web::{
    Error,
    FromRequest,
    HttpRequest,
    web,
};
use time::OffsetDateTime;
use web_misc::db::DBPool;

use crate::api::json_err;
use crate::db::{
    self,
    UserRow,
};
use crate::util;

#[derive(Clone)]
pub struct AuthUser {
    pub user: UserRow,
    pub token_id: i64,
    pub expires_at: Option<OffsetDateTime>,
    pub app_token: bool,
}

impl AuthUser {
    pub fn is_admin(&self) -> bool {
        self.user.role == "admin"
    }

    pub fn user_id(&self) -> i64 {
        self.user.id
    }
}

fn unauthorized() -> Error {
    actix_web::error::InternalError::from_response("unauthorized", json_err(StatusCode::UNAUTHORIZED, "Unauthorized."))
        .into()
}

fn disabled() -> Error {
    actix_web::error::InternalError::from_response("disabled", json_err(StatusCode::FORBIDDEN, "Account disabled.")).into()
}

fn accept(
    user: UserRow,
    username: &str,
    token_id: i64,
    expires_at: Option<OffsetDateTime>,
    app_token: bool,
) -> Result<AuthUser, Error> {
    if user.username != username {
        return Err(unauthorized());
    }
    if !user.enabled {
        return Err(disabled());
    }
    Ok(AuthUser {
        user,
        token_id,
        expires_at,
        app_token,
    })
}

impl FromRequest for AuthUser {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Error>>>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            let header = req.headers().get(AUTHORIZATION).ok_or_else(unauthorized)?;
            let header = header.to_str().map_err(|_| unauthorized())?;
            let token = header.strip_prefix("Bearer ").ok_or_else(unauthorized)?;
            let username = req
                .headers()
                .get("X-Username")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(unauthorized)?;
            let hash = util::token_hash_from_header(token).ok_or_else(unauthorized)?;
            let pool = req.app_data::<web::Data<DBPool>>().ok_or_else(unauthorized)?;
            if let Some((user, token_row)) = db::lookup_token(&pool.pg_pool, &hash).await.ok().flatten() {
                return accept(user, username, token_row.id, Some(token_row.expires_at), false);
            }
            if let Some((user, app)) = db::lookup_app_token(&pool.pg_pool, &hash).await.ok().flatten() {
                return accept(user, username, app.id, app.expires_at, true);
            }
            Err(unauthorized())
        })
    }
}

pub struct AdminUser(pub AuthUser);

impl FromRequest for AdminUser {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = AuthUser::from_request(req, payload);
        Box::pin(async move {
            let auth = fut.await?;
            if auth.is_admin() {
                Ok(AdminUser(auth))
            } else {
                Err(actix_web::error::InternalError::from_response(
                    "forbidden",
                    json_err(StatusCode::FORBIDDEN, "Forbidden."),
                )
                .into())
            }
        })
    }
}
