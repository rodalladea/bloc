//! bloc's HTTP application. Identity protocols are planned, not implemented.

#[cfg(test)]
extern crate self as bloc;

pub mod administrator;
pub mod config;
pub mod credentials;
mod directory;
mod directory_storage;
pub mod operator;
pub mod request_security;
pub mod storage;

use axum::{Router, extract::Request, http::HeaderValue, middleware::Next, response::Response};

/// Build the configured production application without opening a socket.
pub fn app(application: administrator::Application) -> Router {
    administrator::router(application)
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    for (name, value) in [
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "same-origin"),
        ("cache-control", "no-store"),
        ("x-frame-options", "DENY"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
}
