//! Email/password configuration switches, sign-in guards and username flows.
use super::auth_probe::{fast_password, raw};
use super::*;
use crate::snapshot::Trace;
use alibi::AuthResult;
use alibi::hooks::RequestHookContext;
use alibi::plugins::{EmailVerificationConfig, EmailVerificationPlugin, SendVerificationEmail};
use alibi::user_validation::{UserInfoValidator, UserValidationData, UserValidationRejection};
use alibi::utils::username::UsernameConfig;
use alibi::wire::UserView;
use async_trait::async_trait;

backend_tests!(
    email_password_switches_and_sign_in_guards,
    email_password_signup_without_session_hides_rejections,
    email_password_username_and_verification_flows,
    signup_and_signin_crypto_errors_precede_principal_publication,
    missing_credential_signin_hashes_once_without_verifier_or_session
);

struct Deny;
#[async_trait]
impl UserInfoValidator for Deny {
    async fn validate(
        &self,
        data: &mut UserValidationData,
        _: &RequestHookContext,
    ) -> AuthResult<Option<UserValidationRejection>> {
        Ok(data
            .user
            .email
            .as_deref()
            .is_some_and(|email| email.starts_with("denied"))
            .then(|| UserValidationRejection {
                error: "DENIED".into(),
                error_description: None,
            }))
    }
}

#[derive(Default)]
struct Verifications(Mutex<Vec<String>>);
#[async_trait]
impl SendVerificationEmail for Verifications {
    async fn send(&self, user: &UserView, _: &str, _: &str) -> AuthResult<()> {
        self.0.lock().unwrap().push(user.email.clone().unwrap());
        Ok(())
    }
}

async fn email_password_switches_and_sign_in_guards<B: Backend>(db: Db) -> TestResult {
    let mut trace = Trace::default();
    for (mode, plugin) in [
        ("disabled", fast_password().enabled(false)),
        ("no signup", fast_password().enable_signup(false)),
        (
            "short limits",
            fast_password()
                .password_min_length(12)
                .password_max_length(20),
        ),
        ("default", fast_password()),
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(plugin)
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?;
        let mut send = async |label: &str, path: &str, text: String, cookie: &str| {
            let mut input = raw(path, &text, cookie);
            if !text.starts_with('{') {
                _ = input.headers.insert(
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                );
            }
            let response = Box::pin(auth.handle_request(input)).await.unwrap();
            trace.response(&format!("{mode}: {label}"), &response);
            response
        };
        let account = json!({"email":"Guard@Example.test","password":PASSWORD,"name":"Guard"});
        let signup = send("sign up", "/sign-up/email", account.to_string(), "").await;
        let _ = send(
            "sign up remember me false",
            "/sign-up/email",
            json!({"email":"later@example.test","password":PASSWORD,"name":"L","rememberMe":false})
                .to_string(),
            "",
        )
        .await;
        let _ = send(
            "sign up form",
            "/sign-up/email",
            "email=form%40example.test&password=a-native-password-123&name=Form".into(),
            "",
        )
        .await;
        for (label, input) in [
            ("invalid email", json!({"email":"nope","password":PASSWORD})),
            (
                "long password",
                json!({"email":"guard@example.test","password":"p".repeat(300)}),
            ),
            (
                "unknown user",
                json!({"email":"nobody@example.test","password":PASSWORD}),
            ),
            (
                "wrong password",
                json!({"email":"guard@example.test","password":"wrong-password-1"}),
            ),
            (
                "remember me false with callback",
                json!({"email":"guard@example.test","password":PASSWORD,"rememberMe":false,"callbackURL":"/home"}),
            ),
        ] {
            let _ = send(label, "/sign-in/email", input.to_string(), "").await;
        }
        if mode == "default" {
            assert_eq!(body(&signup)["user"]["email"], "guard@example.test");
            let _ = send(
                "credential-less user",
                "/sign-in/email",
                json!({"email":"guard@example.test","password":PASSWORD}).to_string(),
                "",
            )
            .await;
            _ = db
                .execute("DELETE FROM accounts WHERE provider_id = 'credential'", &[])
                .await?;
            let _ = send(
                "after credential removal",
                "/sign-in/email",
                json!({"email":"guard@example.test","password":PASSWORD}).to_string(),
                "",
            )
            .await;
        }
        B::close(connection).await?;
    }
    trace.assert("email-password/switches-and-guards");
    Ok(())
}

async fn email_password_signup_without_session_hides_rejections<B: Backend>(db: Db) -> TestResult {
    let mut trace = Trace::default();
    for (mode, plugin) in [
        ("no auto sign-in", fast_password().auto_sign_in(false)),
        (
            "verification required",
            fast_password().require_email_verification(true),
        ),
        ("auto sign-in", fast_password()),
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.user_validation = Some(Arc::new(Deny));
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(plugin)
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?;
        for (label, email) in [
            ("new", "fresh@example.test"),
            ("duplicate", "fresh@example.test"),
            ("denied", "denied@example.test"),
        ] {
            let response = Box::pin(auth.handle_request(raw(
                "/sign-up/email",
                &json!({"email":email,"password":PASSWORD,"name":"Hidden"}).to_string(),
                "",
            )))
            .await?;
            trace.response(&format!("{mode}: {label}"), &response);
        }
        trace.value(
            &format!("{mode}: rows"),
            json!([
                db.count("users").await?,
                db.count("accounts").await?,
                db.count("sessions").await?
            ]),
        );
        B::close(connection).await?;
    }
    trace.assert("email-password/signup-without-session");
    Ok(())
}

async fn email_password_username_and_verification_flows<B: Backend>(db: Db) -> TestResult {
    let mut trace = Trace::default();
    for mode in ["display-only", "no-display", "verification", "sender"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let sender = Arc::new(Verifications::default());
        let policy = UsernameConfig {
            include_display_username: mode != "no-display",
            ..Default::default()
        };
        let mut plugin = fast_password().username_config(policy);
        if matches!(mode, "verification" | "sender") {
            plugin = plugin.require_email_verification(true);
        }
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let mut auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(plugin)
            .plugin(SessionManagementPlugin::new());
        if mode == "sender" {
            auth = auth.plugin(EmailVerificationPlugin::with_config(
                EmailVerificationConfig {
                    send_on_sign_in: true,
                    send_verification_email: Some(sender.clone()),
                    ..Default::default()
                },
            ));
        }
        let auth = auth.build().await?;
        let mut send = async |label: &str, path: &str, input: Value| {
            let response = Box::pin(auth.handle_request(raw(path, &input.to_string(), "")))
                .await
                .unwrap();
            trace.response(&format!("{mode}: {label}"), &response);
        };
        send(
            "signup display only",
            "/sign-up/email",
            json!({"email":"user@example.test","password":PASSWORD,"name":"User","displayUsername":"Fancy_Name"}),
        )
        .await;
        send(
            "signup both",
            "/sign-up/email",
            json!({"email":"both@example.test","password":PASSWORD,"name":"Both","username":"both_user","displayUsername":"Both User"}),
        )
        .await;
        send(
            "signup taken",
            "/sign-up/email",
            json!({"email":"taken@example.test","password":PASSWORD,"name":"Taken","username":"both_user"}),
        )
        .await;
        for (label, username, password) in [
            ("empty", "", PASSWORD),
            ("invalid characters", "bad name!", PASSWORD),
            ("unknown", "nobody", PASSWORD),
            ("wrong password", "both_user", "wrong-password-1"),
            ("valid", "both_user", PASSWORD),
            ("display as username", "fancy_name", PASSWORD),
        ] {
            send(
                &format!("sign in {label}"),
                "/sign-in/username",
                json!({"username":username,"password":password,"callbackURL":"/home","rememberMe":false}),
            )
            .await;
        }
        send(
            "availability empty",
            "/is-username-available",
            json!({"username":""}),
        )
        .await;
        send(
            "availability invalid",
            "/is-username-available",
            json!({"username":"x"}),
        )
        .await;
        trace.value(
            &format!("{mode}: sent"),
            json!(sender.0.lock().unwrap().len()),
        );
        B::close(connection).await?;
    }
    trace.assert("email-password/username-and-verification");
    Ok(())
}

async fn signup_and_signin_crypto_errors_precede_principal_publication<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::{AuthError, PasswordHasher};
    struct Crypto {
        mode: Mutex<u8>,
        seen: Mutex<Vec<(bool, String, String)>>,
    }
    impl Crypto {
        fn fail(&self) -> AuthResult<()> {
            match *self.mode.lock().unwrap() {
                1 => Err(AuthError::internal("configured crypto outage")),
                2 => Err(AuthError::Api {
                    status: 403,
                    code: Some("CRYPTO_REJECTED".into()),
                    message: "Configured crypto rejected".into(),
                }),
                _ => Ok(()),
            }
        }
    }
    #[async_trait]
    impl PasswordHasher for Crypto {
        async fn hash(&self, p: &str) -> AuthResult<String> {
            self.seen
                .lock()
                .unwrap()
                .push((false, p.into(), String::new()));
            self.fail()?;
            super::auth_probe::FastHasher.hash(p).await
        }
        async fn verify(&self, h: &str, p: &str) -> AuthResult<bool> {
            self.seen.lock().unwrap().push((true, p.into(), h.into()));
            self.fail()?;
            super::auth_probe::FastHasher.verify(h, p).await
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let crypto = Arc::new(Crypto {
        mode: Mutex::new(0),
        seen: Mutex::new(Vec::new()),
    });
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new().password_hasher(crypto.clone()))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "crypto-fail-owner@example.test").await;
    let foreign = signup(&auth, "crypto-fail-foreign@example.test").await;
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    let physical_hash = db
        .text(
            "SELECT password FROM accounts WHERE user_id=$1 AND provider_id=$2",
            &[body(&owner)["user"]["id"].as_str().unwrap(), "credential"],
        )
        .await?
        .unwrap();
    for signin in [false, true] {
        for mode in [1, 2] {
            *crypto.mode.lock().unwrap() = mode;
            crypto.seen.lock().unwrap().clear();
            let denied=call(&auth,request(if signin{"/sign-in/email"}else{"/sign-up/email"},Some(json!({"email":if signin{"crypto-fail-owner@example.test"}else{"crypto-fail-new@example.test"},"password":PASSWORD,"name":"New"})),""),if mode==1{500}else{403}).await;
            if mode == 1 {
                assert!(denied.body.is_empty());
            } else {
                assert_eq!(
                    body(&denied),
                    json!({"code":"CRYPTO_REJECTED","message":"Configured crypto rejected"})
                );
            }
            assert!(!denied.headers.contains_key("set-cookie"));
            assert_eq!(
                *crypto.seen.lock().unwrap(),
                [(
                    signin,
                    PASSWORD.into(),
                    if signin {
                        physical_hash.clone()
                    } else {
                        String::new()
                    }
                )]
            );
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "verifications"])
                    .await?,
                before
            );
        }
    }
    *crypto.mode.lock().unwrap() = 0;
    _ = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"crypto-fail-owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    authenticated(
        &auth,
        &cookies(&foreign),
        "crypto-fail-foreign@example.test",
    )
    .await;
    B::close(connection).await
}

async fn missing_credential_signin_hashes_once_without_verifier_or_session<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::PasswordHasher;
    struct Crypto(Mutex<Vec<(bool, String)>>);
    #[async_trait]
    impl PasswordHasher for Crypto {
        async fn hash(&self, p: &str) -> AuthResult<String> {
            self.0.lock().unwrap().push((false, p.into()));
            super::auth_probe::FastHasher.hash(p).await
        }
        async fn verify(&self, h: &str, p: &str) -> AuthResult<bool> {
            self.0.lock().unwrap().push((true, p.into()));
            super::auth_probe::FastHasher.verify(h, p).await
        }
    }
    for mode in ["unknown", "null", "empty", "removed"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let crypto = Arc::new(Crypto(Mutex::new(Vec::new())));
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().password_hasher(crypto.clone()))
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?;
        let owner = signup(&auth, "dummy-owner@example.test").await;
        let foreign = signup(&auth, "dummy-foreign@example.test").await;
        let id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
        match mode {
            "null" => {
                _ = db
                    .execute("UPDATE accounts SET password=NULL WHERE user_id=$1", &[&id])
                    .await?;
            }
            "empty" => {
                _ = db
                    .execute("UPDATE accounts SET password='' WHERE user_id=$1", &[&id])
                    .await?;
            }
            "removed" => {
                _ = db
                    .execute("DELETE FROM accounts WHERE user_id=$1", &[&id])
                    .await?;
            }
            _ => {}
        }
        let before = db
            .tables(&["users", "accounts", "sessions", "verifications"])
            .await?;
        crypto.0.lock().unwrap().clear();
        let denied=call(&auth,request("/sign-in/email",Some(json!({"email":if mode=="unknown"{"dummy-missing@example.test"}else{"dummy-owner@example.test"},"password":"short"})),""),401).await;
        assert_eq!(body(&denied)["code"], "INVALID_EMAIL_OR_PASSWORD");
        assert!(!denied.headers.contains_key("set-cookie"));
        assert_eq!(*crypto.0.lock().unwrap(), [(false, "short".into())]);
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
        authenticated(&auth, &cookies(&owner), "dummy-owner@example.test").await;
        authenticated(&auth, &cookies(&foreign), "dummy-foreign@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}
