#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Disabled,
    Optional,
    Required,
}
impl Mode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "disabled" => Some(Self::Disabled),
            "optional" => Some(Self::Optional),
            "required" => Some(Self::Required),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }
}
#[derive(Clone)]
pub(crate) struct Policy {
    pub mode: Mode,
    pub methods: Vec<String>,
    pub preferred: Option<String>,
    pub codes: bool,
    pub assisted: bool,
    pub ttl: i32,
    pub recovery_ttl: i32,
}
impl Policy {
    pub fn values(&self) -> Vec<String> {
        vec![
            self.mode.as_str().into(),
            self.methods.join(","),
            self.preferred.clone().unwrap_or_default(),
            self.codes.to_string(),
            self.assisted.to_string(),
            self.ttl.to_string(),
            self.recovery_ttl.to_string(),
        ]
    }
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: Mode::Optional,
            methods: vec!["totp".into(), "webauthn".into()],
            preferred: Some("webauthn".into()),
            codes: true,
            assisted: true,
            ttl: 300,
            recovery_ttl: 1800,
        }
    }
}
impl Policy {
    pub fn allows(&self, method: &str) -> bool {
        self.methods.iter().any(|m| m == method)
    }
}
