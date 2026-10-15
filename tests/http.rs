use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[tokio::test]
async fn serves_local_assets_health_and_htmx_fragment() {
    for (path, content_type, expected) in [
        ("/", "text/html", "Authentication, token issuance"),
        ("/healthz", "text/plain", "ok\n"),
        ("/fragments/status", "text/html", "role=\"status\""),
        ("/assets/app.css", "text/css", ":root"),
        ("/assets/htmx.min.js", "text/javascript", "htmx"),
    ] {
        let response = bloc::app()
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
        let response = bloc::app()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    }
}
