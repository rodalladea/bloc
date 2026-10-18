//! bloc's HTTP application. Identity protocols are planned, not implemented.

pub mod operator;
pub mod storage;

use axum::{
    Router,
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, Response},
    routing::get,
};

/// Build the application without opening a socket.
pub fn app() -> Router {
    Router::new()
        .route("/", get(|| async { Html(include_str!("../templates/index.html")) }))
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/fragments/status", get(|| async {
            Html("<p role=\"status\">bloc is running. Identity protocols are not implemented yet.</p>")
        }))
        .route("/assets/app.css", get(|| async {
            ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], include_str!("../assets/app.css"))
        }))
        .route("/assets/htmx.min.js", get(|| async {
            ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], include_str!("../assets/vendor/htmx-2.0.8.min.js"))
        }))
        .fallback(|| async { (StatusCode::NOT_FOUND, "Not found") })
        .layer(middleware::from_fn(security_headers))
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    for (name, value) in [
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
        ("x-frame-options", "DENY"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
}
