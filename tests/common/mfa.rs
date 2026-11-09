use super::Fixture;
use base64::Engine;
use std::{io::Write, path::Path};
impl Fixture {
    pub async fn mfa_service_keyring(&self, directory: &Path) {
        const ID: &str = "77777777-7777-4777-8777-777777777777";
        let material = base64::engine::general_purpose::STANDARD.encode([17u8; 32]);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("mfa-keyring"))
            .unwrap();
        write!(
            file,
            "{{\"format_version\":1,\"keys\":[{{\"id\":\"{ID}\",\"key\":\"{material}\"}}]}}"
        )
        .unwrap();
        let operator = self.pool("operator_user").await;
        let active: Option<String> =
            sqlx::query_scalar("SELECT active_key_id FROM bloc.mfa_key_status() LIMIT 1")
                .fetch_one(&operator)
                .await
                .unwrap();
        if let Some(active) = active {
            assert_eq!(
                active, ID,
                "serving fixture must mount all explicitly initialized keys"
            );
        } else {
            let status: String = sqlx::query_scalar(
                "SELECT bloc.mfa_key_change('initialize',$1::text::uuid,0,false)",
            )
            .bind(ID)
            .fetch_one(&operator)
            .await
            .unwrap();
            assert_eq!(status, "ok");
        }
    }
}
