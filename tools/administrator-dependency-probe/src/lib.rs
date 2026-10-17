//! Compilation probe only. No authentication endpoints or persistence implementation.

#[cfg(test)]
mod tests {
    use axum::{Router, extract::State, routing::get};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    use sqlx::{
        PgPool,
        postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
    };
    use subtle::ConstantTimeEq;

    #[test]
    fn keyed_digest_matches_library_documentation_vector() {
        let mut mac = Hmac::<Sha256>::new_from_slice(b"my secret and secure key")
            .expect("fixed synthetic fixture key is accepted by HMAC");
        mac.update(b"input message");
        let expected = [
            0x97, 0xd2, 0xa5, 0x69, 0x05, 0x9b, 0xbc, 0xd8, 0xea, 0xd4, 0x44, 0x4f, 0xf9, 0x90,
            0x71, 0xf4, 0xc0, 0x1d, 0x00, 0x5b, 0xce, 0xfe, 0x0d, 0x35, 0x67, 0xe1, 0xbe, 0x62,
            0x8e, 0x5f, 0xdc, 0xd9,
        ];
        assert!(mac.clone().verify_slice(&expected).is_ok());
        let mut modified = expected;
        modified[0] ^= 1;
        assert!(mac.verify_slice(&modified).is_err());
    }

    #[test]
    fn token_primitives_match_known_digest_and_reject_modified_digest() {
        let digest: [u8; 32] = Sha256::digest(b"hello world").into();
        let expected = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d,
            0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac,
            0xe2, 0xef, 0xcd, 0xe9,
        ];
        assert!(bool::from(digest.ct_eq(&expected)));
        let mut modified = digest;
        modified[31] ^= 1;
        assert!(!bool::from(digest.ct_eq(&modified)));
    }

    #[test]
    fn os_randomness_api_fills_a_token_without_logging_it() {
        let mut token = [0_u8; 32];
        getrandom::fill(&mut token).expect("OS randomness must be available in this probe");
        // Availability check only; this is not a statistical randomness assessment.
        assert_eq!(Sha256::digest(token).len(), 32);
    }

    #[tokio::test]
    async fn axum_accepts_sqlx_pool_with_explicit_verify_full_options() {
        async fn handler(State(_pool): State<PgPool>) -> &'static str {
            "dependency probe"
        }
        let options = PgConnectOptions::new()
            .host("database.example.test")
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert("/not-opened-by-lazy-pool/ca.crt");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_lazy_with(options);
        let _router: Router = Router::new()
            .route("/probe", get(handler))
            .with_state(pool.clone());
        pool.close().await;
    }
}
