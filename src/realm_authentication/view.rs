use super::*;
pub(super) struct Field {
    pub(super) name: String,
    pub(super) label: String,
    pub(super) kind: &'static str,
    pub(super) value: String,
    pub(super) help: String,
    pub(super) error: String,
    pub(super) autocomplete: &'static str,
}
pub(super) struct Toggle {
    pub(super) name: &'static str,
    pub(super) label: &'static str,
    pub(super) checked: bool,
}
pub(super) struct Lifetime {
    pub(super) name: &'static str,
    pub(super) label: &'static str,
    pub(super) value: String,
    pub(super) unit: &'static str,
    pub(super) help: &'static str,
    pub(super) error: String,
}
pub(super) struct Page {
    pub(super) workspace: crate::workspace::Workspace,
    pub(super) title: String,
    pub(super) intro: String,
    pub(super) state: &'static str,
    pub(super) realm: String,
    pub(super) name: String,
    pub(super) path: String,
    pub(super) base: String,
    pub(super) account: Account,
    pub(super) admin: bool,
    pub(super) protected: bool,
    pub(super) csrf: String,
    pub(super) fields: Vec<Field>,
    pub(super) toggles: Vec<Toggle>,
    pub(super) lifetimes: Vec<Lifetime>,
    pub(super) feedback: String,
    pub(super) error: bool,
    pub(super) hidden: bool,
    pub(super) action: &'static str,
    pub(super) version: i64,
    pub(super) registration: bool,
    pub(super) sessions: Vec<Session>,
    pub(super) confirm: String,
    pub(super) confirm_values: Vec<(String, String)>,
    pub(super) hidden_fields: Vec<(String, String)>,
    pub(super) secret: String,
    pub(super) link: String,
    pub(super) expiry: String,
    pub(super) purpose: String,
}
impl Page {
    pub(super) fn new(r: &str, path: &str) -> Self {
        Self {
            workspace: crate::workspace::Workspace::default(),
            title: String::new(),
            intro: String::new(),
            state: "login",
            realm: r.into(),
            name: String::new(),
            path: path.into(),
            base: format!("/realms/{r}"),
            account: Account::default(),
            admin: false,
            protected: false,
            csrf: String::new(),
            fields: vec![],
            toggles: vec![],
            lifetimes: vec![],
            feedback: String::new(),
            error: false,
            hidden: false,
            action: "Continue",
            version: 0,
            registration: false,
            sessions: vec![],
            confirm: String::new(),
            confirm_values: vec![],
            hidden_fields: vec![],
            secret: String::new(),
            link: String::new(),
            expiry: String::new(),
            purpose: String::new(),
        }
    }
    pub(super) fn field(
        &mut self,
        name: &str,
        label: &str,
        kind: &'static str,
        value: &str,
        help: &str,
    ) {
        self.fields.push(Field {
            name: name.into(),
            label: label.into(),
            kind,
            value: if kind == "password" {
                String::new()
            } else {
                value.into()
            },
            help: help.into(),
            error: String::new(),
            autocomplete: if name == "current_password"
                || name == "password" && self.state == "login"
            {
                "current-password"
            } else if kind == "password" {
                "new-password"
            } else if name == "email" {
                "username"
            } else {
                "off"
            },
        })
    }
    pub(super) fn invalid(&mut self, name: &str, message: &str) {
        self.error = true;
        self.feedback = "Check the highlighted field.".into();
        if let Some(f) = self.fields.iter_mut().find(|x| x.name == name) {
            f.error = message.into()
        }
        if let Some(t) = self.lifetimes.iter_mut().find(|x| x.name == name) {
            t.error = message.into();
        }
    }
    pub(super) fn passwords(&mut self, p: &Policy) {
        self.field(
            "password",
            if self.state == "password" {
                "New password"
            } else {
                "Password"
            },
            "password",
            "",
            &p.requirements(),
        );
        self.field(
            "password_confirmation",
            "Confirm password",
            "password",
            "",
            "",
        );
    }
}
#[derive(Template)]
#[template(path = "realm.html")]
pub(super) struct Full<'a> {
    pub(super) p: &'a Page,
}
#[derive(Template)]
#[template(path = "realm_content.html")]
pub(super) struct Fragment<'a> {
    pub(super) p: &'a Page,
}
pub(super) fn render(p: &Page, status: StatusCode, hx: bool) -> Response {
    let html = if hx {
        Fragment { p }.render()
    } else {
        Full { p }.render()
    };
    let mut r = match html {
        Ok(h) => (status, Html(h)).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    r.headers_mut()
        .insert(header::VARY, HeaderValue::from_static("HX-Request"));
    r.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    r
}
