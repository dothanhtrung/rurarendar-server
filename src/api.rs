use actix_web::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::TryRng;
use actix_web::{
    HttpRequest,
    HttpResponse,
};
use serde_json::{
    Value,
    json,
};

pub fn json_ok(mut body: Value) -> HttpResponse {
    if let Some(obj) = body.as_object_mut() {
        obj.entry("err").or_insert(Value::Null);
    }
    HttpResponse::Ok().json(body)
}

pub fn json_created(mut body: Value) -> HttpResponse {
    if let Some(obj) = body.as_object_mut() {
        obj.entry("err").or_insert(Value::Null);
    }
    HttpResponse::Created().json(body)
}

pub fn json_err(status: StatusCode, msg: &str) -> HttpResponse {
    HttpResponse::build(status).json(json!({ "err": msg }))
}

pub fn json_status(status: StatusCode, mut body: Value) -> HttpResponse {
    if let Some(obj) = body.as_object_mut() {
        obj.entry("err").or_insert(Value::Null);
    }
    HttpResponse::build(status).json(body)
}

pub fn request_id(req: &HttpRequest) -> String {
    req.headers()
        .get("X-Request-Id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            let mut random = [0u8; 16];
            rand::rngs::SysRng.try_fill_bytes(&mut random).expect("os rng");
            URL_SAFE_NO_PAD.encode(random)
        })
}
