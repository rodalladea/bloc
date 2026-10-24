async fn application() -> axum::Router {
    let path = std::env::temp_dir().join(format!(
        "bloc-http-ca-{}.crt",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, b"synthetic CA placeholder").unwrap();
    let storage =
        bloc::storage::Storage::lazy("postgres://127.0.0.1:1/unavailable", &path).unwrap();
    std::fs::remove_file(path).unwrap();
    let config =
        bloc::config::Config::new("https://bloc.example.test", "127.0.0.1/32", [7; 32]).unwrap();
    bloc::app(
        bloc::administrator::Application::new(storage, config)
            .await
            .unwrap(),
    )
}

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[tokio::test]
async fn serves_local_assets_and_health() {
    for (path, content_type, expected) in [
        ("/healthz", "text/plain", "ok\n"),
        ("/assets/admin.css", "text/css", ".workspace"),
        ("/assets/ui.css", "text/css", "--ui-accent"),
        ("/assets/ui.js", "text/javascript", "data-ui-theme-control"),
        ("/assets/htmx.min.js", "text/javascript", "htmx"),
    ] {
        let response = application()
            .await
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert!(
            response.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with(content_type)
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "same-origin");
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
        let body = to_bytes(response.into_body(), 100_000).await.unwrap();
        assert!(
            std::str::from_utf8(&body).unwrap().contains(expected),
            "{path}"
        );
    }
}

#[tokio::test]
async fn unimplemented_protocol_endpoints_are_not_exposed() {
    for path in [
        "/.well-known/openid-configuration",
        "/oauth/token",
        "/saml",
        "/missing",
    ] {
        let response = application()
            .await
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    }
}
