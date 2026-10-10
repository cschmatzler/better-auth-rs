//! Configured codecs must process actual issued, delivered and consumed proofs.
use super::*;
use alibi::plugins::email_otp::*;
use alibi::{AuthError, AuthResult, CallbackContext};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};

backend_tests!(
    email_otp_custom_codec_controls_reuse_and_failure_consumption,
    email_otp_verification_override_owns_signup_transaction_and_direct_delivery,
    delegated_otp_issuance_retains_original_request_and_live_proof
);
postgres_tests!(
    email_otp_custom_codec_controls_reuse_and_failure_consumption,
    email_otp_verification_override_owns_signup_transaction_and_direct_delivery
);

struct Codec {
    reversible: bool,
    failure: Mutex<&'static str>,
    generated: AtomicUsize,
    delivered: Mutex<Vec<EmailOtpDelivery>>,
}
impl Codec {
    fn representation(&self, input: &str) -> String {
        if self.reversible {
            format!("reversible-{}", URL_SAFE_NO_PAD.encode(input))
        } else {
            format!(
                "digest-{}",
                URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
            )
        }
    }
    fn check(&self, phase: &str) -> AuthResult<()> {
        if *self.failure.lock().unwrap() == phase {
            Err(AuthError::internal(format!("{phase} codec failure")))
        } else {
            Ok(())
        }
    }
    fn last(&self) -> String {
        self.delivered.lock().unwrap().last().unwrap().otp.clone()
    }
}
#[async_trait]
impl EmailOtpCodec for Codec {
    async fn store(&self, otp: &str) -> AuthResult<String> {
        self.check("store")?;
        Ok(self.representation(otp))
    }
    async fn verify(&self, stored: &str, otp: &str) -> AuthResult<bool> {
        self.check("verify")?;
        Ok(stored == self.representation(otp))
    }
    async fn retrieve(&self, stored: &str) -> AuthResult<Option<String>> {
        self.check("retrieve")?;
        if self.reversible {
            Ok(Some(
                String::from_utf8(
                    URL_SAFE_NO_PAD
                        .decode(stored.strip_prefix("reversible-").unwrap())
                        .unwrap(),
                )
                .unwrap(),
            ))
        } else {
            Ok(None)
        }
    }
}
#[async_trait]
impl EmailOtpGenerator for Codec {
    async fn generate(
        &self,
        _: &str,
        _: EmailOtpType,
        _: &CallbackContext,
    ) -> AuthResult<Option<String>> {
        Ok(Some(format!(
            "{:06}",
            self.generated.fetch_add(1, Ordering::SeqCst) + 1
        )))
    }
}
#[async_trait]
impl SendEmailOtp for Codec {
    async fn send(&self, delivery: &EmailOtpDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.delivered.lock().unwrap().push(delivery.clone());
        Ok(())
    }
}
async fn email_otp_custom_codec_controls_reuse_and_failure_consumption<B: Backend>(
    db: Db,
) -> TestResult {
    for reversible in [true, false] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let codec = Arc::new(Codec {
            reversible,
            failure: Mutex::new("store"),
            generated: AtomicUsize::new(0),
            delivered: Mutex::new(Vec::new()),
        });
        let plugin = EmailOtpPlugin::new(EmailOtpConfig {
            storage: EmailOtpStorage::Custom(codec.clone()),
            resend_strategy: OtpResendStrategy::Reuse,
            generate_otp: Some(codec.clone()),
            send_verification_otp: Some(codec.clone()),
            ..Default::default()
        });
        let auth = builder::<B>(&connection)
            .plugin(plugin.clone())
            .build()
            .await?;
        let send = || {
            request(
                "/email-otp/send-verification-otp",
                Some(json!({"email":"codec@example.test","type":"sign-in"})),
                "",
            )
        };
        let _ = call(&auth, send(), 500).await;
        assert_eq!(db.count("verifications").await?, 0);
        assert!(codec.delivered.lock().unwrap().is_empty());
        *codec.failure.lock().unwrap() = "";
        let _ = call(&auth, send(), 200).await;
        let first = codec.last();
        let stored = db.table("verifications").await?;
        assert!(!stored.contains(&first));
        *codec.failure.lock().unwrap() = "retrieve";
        let _ = call(&auth, send(), 500).await;
        assert_eq!(db.table("verifications").await?, stored);
        assert_eq!(codec.delivered.lock().unwrap().len(), 1);
        *codec.failure.lock().unwrap() = "";
        let recovered = plugin
            .get_verification_otp(auth.context(), "codec@example.test", EmailOtpType::SignIn)
            .await;
        if reversible {
            assert_eq!(recovered?, Some(first.clone()));
        } else {
            assert!(
                matches!(recovered, Err(AuthError::BadRequest(message)) if message == "OTP is hashed, cannot return the plain text OTP")
            );
        }
        let _ = call(&auth, send(), 200).await;
        assert_eq!(codec.last() == first, reversible);
        *codec.failure.lock().unwrap() = "verify";
        let _ = call(
            &auth,
            request(
                "/sign-in/email-otp",
                Some(json!({"email":"codec@example.test","otp":codec.last()})),
                "",
            ),
            500,
        )
        .await;
        for table in ["users", "accounts", "sessions", "verifications"] {
            assert_eq!(db.count(table).await?, 0);
        }
        *codec.failure.lock().unwrap() = "";
        let _ = call(&auth, send(), 200).await;
        let _ = call(
            &auth,
            request(
                "/sign-in/email-otp",
                Some(json!({"email":"codec@example.test","otp":"999999"})),
                "",
            ),
            400,
        )
        .await;
        assert_eq!(db.count("verifications").await?, 1);
        assert_eq!(db.count("sessions").await?, 0);
        let accepted = call(
            &auth,
            request(
                "/sign-in/email-otp",
                Some(json!({"email":"codec@example.test","otp":codec.last()})),
                "",
            ),
            200,
        )
        .await;
        authenticated(&auth, &cookies(&accepted), "codec@example.test").await;
        assert_eq!(db.count("verifications").await?, 0);
        assert_eq!(db.count("sessions").await?, 1);
        B::close(connection).await?;
    }
    Ok(())
}

#[derive(Default)]
struct VerificationDelivery {
    otp: Mutex<Vec<EmailOtpDelivery>>,
    tokens: Mutex<Vec<String>>,
    fail: std::sync::atomic::AtomicBool,
}
#[async_trait]
impl SendEmailOtp for VerificationDelivery {
    async fn send(&self, delivery: &EmailOtpDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.otp.lock().unwrap().push(delivery.clone());
        if self.fail.load(Ordering::SeqCst) {
            Err(AuthError::internal("delivery failed"))
        } else {
            Ok(())
        }
    }
}
#[async_trait]
impl alibi::plugins::SendVerificationEmail for VerificationDelivery {
    async fn send(&self, _: &alibi::UserView, _: &str, token: &str) -> AuthResult<()> {
        self.tokens.lock().unwrap().push(token.to_owned());
        Ok(())
    }
}

async fn email_otp_verification_override_owns_signup_transaction_and_direct_delivery<B: Backend>(
    parent: Db,
) -> TestResult {
    use alibi::plugins::{EmailVerificationConfig, EmailVerificationPlugin};
    for explicit_sender in [false, true] {
        let db = parent.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let sender = Arc::new(VerificationDelivery::default());
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().require_email_verification(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(EmailVerificationPlugin::with_config(
                EmailVerificationConfig {
                    send_on_sign_up: Some(true),
                    send_verification_email: explicit_sender
                        .then(|| sender.clone() as Arc<dyn alibi::plugins::SendVerificationEmail>),
                    ..Default::default()
                },
            ))
            .plugin(EmailOtpPlugin::new(EmailOtpConfig {
                override_default_email_verification: true,
                send_verification_on_sign_up: true,
                send_verification_otp: Some(sender.clone()),
                ..Default::default()
            }))
            .build()
            .await?;
        let signup_request = || {
            request(
                "/sign-up/email",
                Some(
                    json!({"email":"override@example.test","password":PASSWORD,"name":"Override"}),
                ),
                "",
            )
        };
        if !explicit_sender {
            sender.fail.store(true, Ordering::SeqCst);
            let _ = call(&auth, signup_request(), 500).await;
            assert_eq!(sender.otp.lock().unwrap().len(), 1);
            for table in ["users", "accounts", "sessions", "verifications"] {
                assert_eq!(db.count(table).await?, 0);
            }
            sender.otp.lock().unwrap().clear();
            sender.fail.store(false, Ordering::SeqCst);
        }
        let created = call(&auth, signup_request(), 200).await;
        assert!(body(&created)["token"].is_null());
        assert!(cookies(&created).is_empty());
        assert_eq!(db.count("users").await?, 1);
        assert_eq!(db.count("accounts").await?, 1);
        assert_eq!(db.count("sessions").await?, 0);
        assert_eq!(
            sender.tokens.lock().unwrap().len(),
            usize::from(explicit_sender)
        );
        assert_eq!(
            sender.otp.lock().unwrap().len(),
            usize::from(!explicit_sender)
        );
        let _ = call(
            &auth,
            request(
                "/send-verification-email",
                Some(json!({"email":"override@example.test"})),
                "",
            ),
            200,
        )
        .await;
        if explicit_sender {
            assert!(sender.otp.lock().unwrap().is_empty());
            let token = sender.tokens.lock().unwrap().last().unwrap().clone();
            let mut verify = request("/verify-email", None, "");
            drop(verify.query.insert("token".into(), token));
            let _ = call(&auth, verify, 200).await;
        } else {
            assert!(sender.tokens.lock().unwrap().is_empty());
            assert_eq!(
                sender.otp.lock().unwrap().len(),
                2,
                "one signup delivery plus one direct delivery"
            );
            let delivery = sender.otp.lock().unwrap().last().unwrap().clone();
            assert_eq!(delivery.otp_type, EmailOtpType::EmailVerification);
            let _ = call(
                &auth,
                request(
                    "/email-otp/verify-email",
                    Some(json!({"email":delivery.email,"otp":delivery.otp})),
                    "",
                ),
                200,
            )
            .await;
            assert_eq!(db.count("verifications").await?, 0);
        }
        assert_eq!(
            db.count_where("SELECT COUNT(*) FROM users WHERE email_verified=true", &[])
                .await?,
            1
        );
        let logged = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"override@example.test","password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        authenticated(&auth, &cookies(&logged), "override@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn delegated_otp_issuance_retains_original_request_and_live_proof<B: Backend>(
    db: Db,
) -> TestResult {
    struct Application {
        raw: crate::storage::Raw,
        generated: Mutex<Vec<AuthRequest>>,
        sent: Mutex<Vec<(EmailOtpDelivery, AuthRequest)>>,
    }
    #[async_trait]
    impl EmailOtpGenerator for Application {
        async fn generate(
            &self,
            _: &str,
            _: EmailOtpType,
            c: &CallbackContext,
        ) -> AuthResult<Option<String>> {
            self.generated
                .lock()
                .unwrap()
                .push(c.request.clone().unwrap());
            Ok(Some("246810".into()))
        }
    }
    #[async_trait]
    impl SendEmailOtp for Application {
        async fn send(&self, d: &EmailOtpDelivery, c: &CallbackContext) -> AuthResult<()> {
            assert_eq!(
                self.raw
                    .count_where(
                        "SELECT COUNT(*) FROM verifications WHERE value=$1",
                        &[&format!("{}:0", d.otp)]
                    )
                    .await
                    .map_err(|e| AuthError::internal(e.to_string()))?,
                1
            );
            self.sent
                .lock()
                .unwrap()
                .push((d.clone(), c.request.clone().unwrap()));
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let application = Arc::new(Application {
        raw: db.raw.clone(),
        generated: Mutex::new(Vec::new()),
        sent: Mutex::new(Vec::new()),
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(EmailOtpPlugin::new(EmailOtpConfig {
            generate_otp: Some(application.clone()),
            send_verification_otp: Some(application.clone()),
            override_default_email_verification: true,
            change_email_enabled: true,
            verify_current_email: true,
            ..Default::default()
        }))
        .plugin(alibi::plugins::EmailVerificationPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "delegated-owner@example.test").await;
    for (path, input, recipient, kind) in [
        (
            "/send-verification-email",
            json!({"email":"delegated-owner@example.test"}),
            "delegated-owner@example.test",
            EmailOtpType::EmailVerification,
        ),
        (
            "/email-otp/request-email-change",
            json!({"newEmail":"delegated-target@example.test","otp":"246810"}),
            "delegated-target@example.test",
            EmailOtpType::ChangeEmail,
        ),
        (
            "/email-otp/request-password-reset",
            json!({"email":"delegated-target@example.test"}),
            "delegated-target@example.test",
            EmailOtpType::ForgetPassword,
        ),
    ] {
        let mut request = super::request(path, Some(input.clone()), &cookies(&owner)).with_url(
            url::Url::parse(&format!("{ORIGIN}/api/auth{path}?probe=207"))?,
        );
        request.set_query_pairs([("probe", "207")]);
        _ = request
            .headers
            .insert("x-callback-probe".into(), "issue207".into());
        _ = call(&auth, request.clone(), 200).await;
        let generated = application
            .generated
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        let (delivery, sent) = application.sent.lock().unwrap().last().unwrap().clone();
        assert_eq!(delivery.email, recipient);
        assert_eq!(delivery.otp_type, kind);
        for actual in [generated, sent] {
            assert_eq!(actual.url(), request.url());
            assert_eq!(actual.method, HttpMethod::Post);
            assert_eq!(actual.body, request.body);
            assert_eq!(actual.headers["x-callback-probe"], "issue207");
            assert_eq!(actual.query["probe"], "207");
        }
        if kind == EmailOtpType::ChangeEmail {
            _ = call(
                &auth,
                super::request(
                    "/email-otp/change-email",
                    Some(json!({"newEmail":recipient,"otp":delivery.otp})),
                    &cookies(&owner),
                ),
                200,
            )
            .await;
        }
    }
    _=call(&auth,request("/email-otp/reset-password",Some(json!({"email":"delegated-target@example.test","otp":"246810","password":"new-delegated-password"})),""),200).await;
    assert_eq!(db.count("verifications").await?, 0);
    assert_eq!(db.count("sessions").await?, 1);
    authenticated(&auth, &cookies(&owner), "delegated-target@example.test").await;
    _=call(&auth,request("/sign-in/email",Some(json!({"email":"delegated-target@example.test","password":"new-delegated-password"})),""),200).await;
    B::close(connection).await
}
