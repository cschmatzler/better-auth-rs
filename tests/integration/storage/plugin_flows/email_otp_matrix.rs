//! Email OTP issuance limits, request validation, reset and change-email policy.
use super::auth_probe::{fast_builder, raw};
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::email_otp::{
    EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, OtpResendStrategy,
};
use alibi::plugins::{EmailVerificationConfig, EmailVerificationPlugin};
use alibi::{AuthError, AuthResult, CallbackContext};

backend_tests!(
    email_otp_issuance_and_request_validation,
    email_otp_change_email_policy,
    email_otp_hooks_and_reset_edges,
    email_otp_configured_quota_blocks_delivery_and_resets_at_configured_window,
    disabled_email_change_preserves_live_proofs_for_enabled_instance,
    after_email_change_rejection_retains_verified_owner_and_consumed_proof,
    verification_otp_transformed_owner,
    verification_otp_creation_retry,
    verification_otp_cache_set_failure
);

#[derive(Default)]
struct Mailbox(Mutex<Vec<EmailOtpDelivery>>);
impl Mailbox {
    fn take(&self) -> EmailOtpDelivery {
        self.0.lock().unwrap().pop().unwrap()
    }
    fn drain(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .drain(..)
            .map(|sent| sent.otp)
            .collect()
    }
}
#[async_trait::async_trait]
impl alibi::plugins::email_otp::SendEmailOtp for Mailbox {
    async fn send(&self, delivery: &EmailOtpDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.0.lock().unwrap().push(delivery.clone());
        Ok(())
    }
}

fn plugin(mailbox: &Arc<Mailbox>, config: EmailOtpConfig) -> EmailOtpPlugin {
    EmailOtpPlugin::new(EmailOtpConfig {
        send_verification_otp: Some(mailbox.clone()),
        ..config
    })
}

async fn email_otp_issuance_and_request_validation<B: Backend>(db: Db) -> TestResult {
    let mut trace = Trace::default();
    let paths = [
        "/email-otp/send-verification-otp",
        "/email-otp/check-verification-otp",
        "/email-otp/verify-email",
        "/sign-in/email-otp",
        "/email-otp/request-password-reset",
        "/forget-password/email-otp",
        "/email-otp/reset-password",
        "/email-otp/request-email-change",
        "/email-otp/change-email",
    ];
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mailbox = Arc::new(Mailbox::default());
    let auth = fast_builder::<B>(&connection)
        .plugin(plugin(
            &mailbox,
            EmailOtpConfig {
                change_email_enabled: true,
                ..Default::default()
            },
        ))
        .build()
        .await?;
    let owner = cookies(&signup(&auth, "owner@example.test").await);
    for path in paths {
        for text in [
            "[]",
            "null",
            "{}",
            r#"{"email":5,"otp":5,"type":5,"newEmail":5,"password":5}"#,
            r#"{"email":"not-an-email","otp":"123456","type":"sign-in","newEmail":"x","password":"a-native-password-123"}"#,
            r#"{"email":"nobody@example.test","otp":"123456","type":"sign-in","newEmail":"other@example.test","password":"a-native-password-123"}"#,
            r#"{"email":"owner@example.test","otp":"123456","type":"change-email","newEmail":"owner@example.test","password":"short"}"#,
        ] {
            for (who, cookie) in [("anonymous", ""), ("owner", owner.as_str())] {
                trace.response(
                    &format!("{path} {who} {text}"),
                    &Box::pin(auth.handle_request(raw(path, text, cookie))).await?,
                );
            }
        }
    }
    B::close(connection).await?;

    for (mode, config) in [
        (
            "reuse",
            EmailOtpConfig {
                resend_strategy: OtpResendStrategy::Reuse,
                ..Default::default()
            },
        ),
        (
            "invalid expiry",
            EmailOtpConfig {
                expires_in: f64::INFINITY,
                ..Default::default()
            },
        ),
        (
            "nonpositive length",
            EmailOtpConfig {
                otp_length: 0.0,
                ..Default::default()
            },
        ),
        (
            "zero attempts",
            EmailOtpConfig {
                allowed_attempts: 0.0,
                ..Default::default()
            },
        ),
        (
            "sign-up disabled",
            EmailOtpConfig {
                disable_sign_up: true,
                ..Default::default()
            },
        ),
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mailbox = Arc::new(Mailbox::default());
        let auth = fast_builder::<B>(&connection)
            .plugin(plugin(&mailbox, config))
            .build()
            .await?;
        let send = r#"{"email":"Fresh@Example.test","type":"sign-in"}"#;
        for label in ["first", "second"] {
            trace.response(
                &format!("{mode}: send {label}"),
                &Box::pin(auth.handle_request(raw("/email-otp/send-verification-otp", send, "")))
                    .await?,
            );
        }
        let delivered = mailbox.drain();
        trace.value(&format!("{mode}: deliveries"), json!(delivered.len()));
        if mode == "reuse" {
            assert_eq!(delivered.len(), 2);
            assert_eq!(delivered[0], delivered[1]);
        }
        trace.value(
            &format!("{mode}: verifications"),
            json!(db.count("verifications").await?),
        );
        if let Some(otp) = delivered.first() {
            for wrong in ["wrong-1", "wrong-2", "wrong-3", "wrong-4"] {
                trace.response(
                    &format!("{mode}: sign in {wrong}"),
                    &Box::pin(auth.handle_request(raw(
                        "/sign-in/email-otp",
                        &json!({"email":"fresh@example.test","otp":wrong}).to_string(),
                        "",
                    )))
                    .await?,
                );
            }
            trace.response(
                &format!("{mode}: sign in after budget"),
                &Box::pin(auth.handle_request(raw(
                    "/sign-in/email-otp",
                    &json!({"email":"fresh@example.test","otp":otp}).to_string(),
                    "",
                )))
                .await?,
            );
        }
        B::close(connection).await?;
    }
    trace.assert("email-otp/issuance-and-validation");
    Ok(())
}

async fn email_otp_change_email_policy<B: Backend>(db: Db) -> TestResult {
    let mut trace = Trace::default();
    for mode in ["disabled", "enabled", "verify-current"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mailbox = Arc::new(Mailbox::default());
        let auth = fast_builder::<B>(&connection)
            .plugin(plugin(
                &mailbox,
                EmailOtpConfig {
                    change_email_enabled: mode != "disabled",
                    verify_current_email: mode == "verify-current",
                    ..Default::default()
                },
            ))
            .build()
            .await?;
        let owner = cookies(&signup(&auth, "owner@example.test").await);
        let _ = signup(&auth, "taken@example.test").await;
        let mut send = async |label: &str, path: &str, input: Value| {
            let response = Box::pin(auth.handle_request(raw(path, &input.to_string(), &owner)))
                .await
                .unwrap();
            trace.response(&format!("{mode}: {label}"), &response);
        };
        send(
            "request same",
            "/email-otp/request-email-change",
            json!({"newEmail":"owner@example.test"}),
        )
        .await;
        send(
            "request missing current proof",
            "/email-otp/request-email-change",
            json!({"newEmail":"next@example.test"}),
        )
        .await;
        send(
            "request to taken",
            "/email-otp/request-email-change",
            json!({"newEmail":"taken@example.test","otp":"000000"}),
        )
        .await;
        send(
            "confirm same",
            "/email-otp/change-email",
            json!({"newEmail":"owner@example.test","otp":"123456"}),
        )
        .await;
        send(
            "confirm unknown",
            "/email-otp/change-email",
            json!({"newEmail":"next@example.test","otp":"123456"}),
        )
        .await;
        trace.value(
            &format!("{mode}: verifications"),
            json!(db.count("verifications").await?),
        );
        B::close(connection).await?;
    }
    trace.assert("email-otp/change-email-policy");
    Ok(())
}

async fn email_otp_hooks_and_reset_edges<B: Backend>(db: Db) -> TestResult {
    use alibi::wire::UserView;
    let mut trace = Trace::default();
    for mode in ["passes", "api error", "internal"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mailbox = Arc::new(Mailbox::default());
        let hook =
            |kind: &'static str| -> alibi::plugins::email_verification::EmailVerificationHook {
                Arc::new(move |_: &UserView| {
                    Box::pin(async move {
                        match kind {
                            "api error" => Err(AuthError::forbidden("hook says no")),
                            "internal" => Err(AuthError::internal("hook crashed")),
                            _ => Ok(()),
                        }
                    })
                })
            };
        let auth = fast_builder::<B>(&connection)
            .plugin(plugin(
                &mailbox,
                EmailOtpConfig {
                    change_email_enabled: true,
                    before_email_verification: (mode != "passes").then(|| hook(mode)),
                    after_email_verification: (mode == "passes").then(|| hook(mode)),
                    ..Default::default()
                },
            ))
            .plugin(EmailVerificationPlugin::with_config(
                EmailVerificationConfig::default(),
            ))
            .build()
            .await?;
        let owner = cookies(&signup(&auth, "owner@example.test").await);
        let issue = async |kind: &str, input: Value| -> AuthResult<String> {
            let _ = Box::pin(auth.handle_request(raw(
                "/email-otp/send-verification-otp",
                &input.to_string(),
                "",
            )))
            .await?;
            let _ = kind;
            Ok(mailbox.take().otp)
        };
        let otp = issue(
            "verify",
            json!({"email":"owner@example.test","type":"email-verification"}),
        )
        .await?;
        trace.response(
            &format!("{mode}: verify email"),
            &Box::pin(auth.handle_request(raw(
                "/email-otp/verify-email",
                &json!({"email":"owner@example.test","otp":otp}).to_string(),
                "",
            )))
            .await?,
        );
        let _ = Box::pin(auth.handle_request(raw(
            "/email-otp/request-email-change",
            r#"{"newEmail":"moved@example.test"}"#,
            &owner,
        )))
        .await?;
        let otp = mailbox.take().otp;
        trace.response(
            &format!("{mode}: change email"),
            &Box::pin(auth.handle_request(raw(
                "/email-otp/change-email",
                &json!({"newEmail":"moved@example.test","otp":otp}).to_string(),
                &owner,
            )))
            .await?,
        );
        trace.value(
            &format!("{mode}: email"),
            json!(db.text("SELECT email FROM users", &[]).await?),
        );
        B::close(connection).await?;
    }
    trace.assert("email-otp/hooks-and-edges");
    Ok(())
}

async fn email_otp_configured_quota_blocks_delivery_and_resets_at_configured_window<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::store::SchemaMigrator;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let ledger = B::rate_limit(&connection);
    ledger.migrate().await?;
    let outbox = Arc::new(Mailbox::default());
    let auth = fast_builder::<B>(&connection)
        .rate_limit(
            alibi::middleware::RateLimitConfig::new()
                .enabled(true)
                .storage(Arc::new(ledger)),
        )
        .plugin(plugin(
            &outbox,
            EmailOtpConfig {
                rate_limit: alibi::EndpointRateLimit {
                    window_seconds: 120.0,
                    max_requests: 2.0,
                },
                ..Default::default()
            },
        ))
        .build()
        .await?;
    for index in 0..2 {
        _ = call(
            &auth,
            request(
                "/email-otp/send-verification-otp",
                Some(json!({"email":format!("quota-{index}@example.test"),"type":"sign-in"})),
                "",
            ),
            200,
        )
        .await;
    }
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    assert_eq!(outbox.0.lock().unwrap().len(), 2);
    // Crossing the default window must still respect this plugin's longer window.
    _ = db
        .execute(
            "UPDATE rate_limit SET last_request = last_request - 61000",
            &[],
        )
        .await?;
    let index = 2;
    let denied = call(
        &auth,
        request(
            "/email-otp/send-verification-otp",
            Some(json!({"email":format!("quota-{index}@example.test"),"type":"sign-in"})),
            "",
        ),
        429,
    )
    .await;
    assert_eq!(denied.status, 429);
    assert_eq!(outbox.0.lock().unwrap().len(), 2);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before
    );
    _ = db
        .execute(
            "UPDATE rate_limit SET last_request = last_request - 61000",
            &[],
        )
        .await?;
    _ = call(
        &auth,
        request(
            "/email-otp/send-verification-otp",
            Some(json!({"email":format!("quota-{index}@example.test"),"type":"sign-in"})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(outbox.0.lock().unwrap().len(), 3);
    assert_eq!(db.count("verifications").await?, 3);
    assert_eq!(db.count("sessions").await?, 0);
    B::close(connection).await
}

async fn disabled_email_change_preserves_live_proofs_for_enabled_instance<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mailbox = Arc::new(Mailbox::default());
    let enabled = fast_builder::<B>(&connection)
        .plugin(plugin(
            &mailbox,
            EmailOtpConfig {
                change_email_enabled: true,
                ..Default::default()
            },
        ))
        .build()
        .await?;
    let disabled = fast_builder::<B>(&connection)
        .plugin(plugin(
            &mailbox,
            EmailOtpConfig {
                change_email_enabled: false,
                verify_current_email: true,
                ..Default::default()
            },
        ))
        .build()
        .await?;
    let owner = signup(&enabled, "disabled-owner@example.test").await;
    _ = call(
        &enabled,
        request(
            "/email-otp/request-email-change",
            Some(json!({"newEmail":"disabled-target@example.test"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let target = mailbox.take();
    _ = call(
        &enabled,
        request(
            "/email-otp/send-verification-otp",
            Some(json!({"email":"disabled-owner@example.test","type":"email-verification"})),
            "",
        ),
        200,
    )
    .await;
    let current = mailbox.take();
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    let deliveries = mailbox.0.lock().unwrap().len();
    for (path, otp) in [
        ("/email-otp/request-email-change", current.otp.as_str()),
        ("/email-otp/change-email", target.otp.as_str()),
    ] {
        let input = json!({"newEmail":"disabled-target@example.test","otp":otp});
        let denied = call(
            &disabled,
            request(path, Some(input.clone()), &cookies(&owner)),
            400,
        )
        .await;
        assert_eq!(
            body(&denied)["message"],
            "Change email with OTP is disabled"
        );
        assert!(body(&denied).get("code").is_none());
        assert_eq!(
            body(&call(&disabled, request(path, Some(input), ""), 401).await)["code"],
            "UNAUTHORIZED"
        );
        _ = call(
            &disabled,
            request(path, Some(json!({"newEmail":55,"otp":otp})), ""),
            400,
        )
        .await;
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
        assert_eq!(mailbox.0.lock().unwrap().len(), deliveries);
    }
    _ = call(
        &enabled,
        request(
            "/email-otp/change-email",
            Some(json!({"newEmail":"disabled-target@example.test","otp":target.otp})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert_eq!(db.count_where("SELECT COUNT(*) FROM verifications WHERE identifier='email-verification-otp-disabled-owner@example.test'",&[]).await?,1);
    assert_eq!(db.count("verifications").await?, 1);
    authenticated(&disabled, &cookies(&owner), "disabled-target@example.test").await;
    let stable = db.tables(&["users", "accounts", "sessions"]).await?;
    _ = call(
        &enabled,
        request(
            "/email-otp/change-email",
            Some(json!({"newEmail":"disabled-target@example.test","otp":target.otp})),
            &cookies(&owner),
        ),
        400,
    )
    .await;
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, stable);
    B::close(connection).await
}

async fn after_email_change_rejection_retains_verified_owner_and_consumed_proof<B: Backend>(
    db: Db,
) -> TestResult {
    for coded in [false, true] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mailbox = Arc::new(Mailbox::default());
        let failure = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let hook: alibi::plugins::email_verification::EmailVerificationHook = {
            let failure = failure.clone();
            let seen = seen.clone();
            Arc::new(move |user| {
                let context = alibi::hooks::current_request_hook_context().unwrap();
                seen.lock()
                    .unwrap()
                    .push((serde_json::to_value(user).unwrap(), context.request));
                let failure = failure.clone();
                Box::pin(async move {
                    if !failure.load(std::sync::atomic::Ordering::SeqCst) {
                        return Ok(());
                    }
                    if coded {
                        Err(AuthError::Upstream {
                            status: 403,
                            code: "EMAIL_CHANGE_HOOK_VETO",
                            message: "Application verification hook rejected",
                        })
                    } else {
                        Err(AuthError::internal("Private after hook failure"))
                    }
                })
            })
        };
        let auth = fast_builder::<B>(&connection)
            .plugin(plugin(
                &mailbox,
                EmailOtpConfig {
                    change_email_enabled: true,
                    after_email_verification: Some(hook),
                    ..Default::default()
                },
            ))
            .build()
            .await?;
        let owner = signup(&auth, "after-change-owner@example.test").await;
        let foreign = signup(&auth, "after-change-foreign@example.test").await;
        let id = body(&owner)["user"]["id"].clone();
        _ = call(
            &auth,
            request(
                "/email-otp/request-email-change",
                Some(json!({"newEmail":"after-change-target@example.test"})),
                &cookies(&owner),
            ),
            200,
        )
        .await;
        let proof = mailbox.take();
        let protected = db.tables(&["accounts", "sessions"]).await?;
        let mut input = request(
            "/email-otp/change-email",
            Some(json!({"newEmail":proof.email,"otp":proof.otp})),
            &cookies(&owner),
        );
        _ = input
            .headers
            .insert("x-email-change-marker".into(), "actual-change".into());
        let denied = call(&auth, input.clone(), if coded { 403 } else { 500 }).await;
        assert!(!denied.headers.contains_key("set-cookie"));
        if coded {
            assert_eq!(body(&denied)["code"], "EMAIL_CHANGE_HOOK_VETO");
        } else {
            assert!(denied.body.is_empty());
        }
        assert_eq!(db.count("verifications").await?, 0);
        assert_eq!(db.tables(&["accounts", "sessions"]).await?, protected);
        let events = seen.lock().unwrap().clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0["id"], id);
        assert_eq!(events[0].0["email"], "after-change-target@example.test");
        assert_eq!(events[0].0["emailVerified"], true);
        assert_eq!(events[0].1.path, "/api/auth/email-otp/change-email");
        assert_eq!(
            events[0].1.headers["x-email-change-marker"],
            "actual-change"
        );
        authenticated(&auth, &cookies(&owner), "after-change-target@example.test").await;
        authenticated(
            &auth,
            &cookies(&foreign),
            "after-change-foreign@example.test",
        )
        .await;
        let stable = db.tables(&["users", "accounts", "sessions"]).await?;
        _ = call(&auth, input, 400).await;
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, stable);
        failure.store(false, std::sync::atomic::Ordering::SeqCst);
        _ = call(
            &auth,
            request(
                "/email-otp/request-email-change",
                Some(json!({"newEmail":"after-change-recovered@example.test"})),
                &cookies(&owner),
            ),
            200,
        )
        .await;
        let fresh = mailbox.take();
        _ = call(
            &auth,
            request(
                "/email-otp/change-email",
                Some(json!({"newEmail":fresh.email,"otp":fresh.otp})),
                &cookies(&owner),
            ),
            200,
        )
        .await;
        authenticated(
            &auth,
            &cookies(&owner),
            "after-change-recovered@example.test",
        )
        .await;
        assert_eq!(db.tables(&["accounts", "sessions"]).await?, protected);
        B::close(connection).await?;
    }
    Ok(())
}

async fn verification_otp_transformed_owner<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{CacheAdapter, MemoryCacheAdapter};
    use alibi::verification::{VerificationIdentifierHasher, VerificationIdentifierStrategy};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest as _, Sha256};
    struct Transform;
    #[async_trait::async_trait]
    impl VerificationIdentifierHasher for Transform {
        async fn hash(&self, s: &str) -> AuthResult<String> {
            Ok(format!("application:{s}"))
        }
    }
    for (custom, physical) in [(false, false), (false, true), (true, false), (true, true)] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let cache = Arc::new(MemoryCacheAdapter::new());
        let mailbox = Arc::new(Mailbox::default());
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.verification.store_identifier.default = if custom {
            VerificationIdentifierStrategy::Custom(Arc::new(Transform))
        } else {
            VerificationIdentifierStrategy::Hashed
        };
        config.verification.secondary_storage = Some(cache.clone());
        config.verification.store_in_database = physical;
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(plugin(&mailbox, EmailOtpConfig::default()))
            .build()
            .await?;
        let foreign = signup(&auth, "foreign@example.test").await;
        let baseline = db.tables(&["users", "accounts", "sessions"]).await?;
        let email = "new@example.test";
        let logical = format!("sign-in-otp-{email}");
        let stored = if custom {
            format!("application:{logical}")
        } else {
            URL_SAFE_NO_PAD.encode(Sha256::digest(logical.as_bytes()))
        };
        let key = format!("verification:{stored}");
        _ = call(
            &auth,
            request(
                "/email-otp/send-verification-otp",
                Some(json!({"email":email,"type":"sign-in"})),
                "",
            ),
            200,
        )
        .await;
        let delivered = mailbox.take();
        assert_eq!(delivered.email, email);
        let initial: Value = serde_json::from_str(&cache.get(&key).await?.unwrap())?;
        assert_eq!(initial["identifier"], stored);
        assert_eq!(initial["value"], format!("{}:0", delivered.otp));
        assert_eq!(db.count("verifications").await?, i64::from(physical));
        for (route, target) in [
            ("/sign-in/email-otp", "foreign-mailbox@example.test"),
            ("/email-otp/verify-email", email),
        ] {
            let denied = call(
                &auth,
                request(route, Some(json!({"email":target,"otp":delivered.otp})), ""),
                400,
            )
            .await;
            assert_eq!(body(&denied)["code"], "INVALID_OTP");
            assert_eq!(
                serde_json::from_str::<Value>(&cache.get(&key).await?.unwrap())?,
                initial
            );
        }
        let wrong = call(
            &auth,
            request(
                "/sign-in/email-otp",
                Some(json!({"email":email,"otp":"wrong"})),
                "",
            ),
            400,
        )
        .await;
        assert_eq!(body(&wrong)["code"], "INVALID_OTP");
        let retry: Value = serde_json::from_str(&cache.get(&key).await?.unwrap())?;
        assert_eq!(retry["value"], format!("{}:1", delivered.otp));
        assert_eq!(retry["expiresAt"], initial["expiresAt"]);
        let done = call(
            &auth,
            request(
                "/sign-in/email-otp",
                Some(json!({"email":email,"otp":delivered.otp,"name":"Actual Proof Owner"})),
                "",
            ),
            200,
        )
        .await;
        assert_eq!(body(&done)["user"]["emailVerified"], true);
        let current = body(&call(&auth, request("/get-session", None, &cookies(&done)), 200).await);
        assert_eq!(current["user"]["id"], body(&done)["user"]["id"]);
        assert_eq!(current["session"]["token"], body(&done)["token"]);
        assert!(cache.get(&key).await?.is_none());
        assert_eq!(db.count("verifications").await?, 0);
        let after = db.tables(&["users", "accounts", "sessions"]).await?;
        let replay = call(
            &auth,
            request(
                "/sign-in/email-otp",
                Some(json!({"email":email,"otp":delivered.otp})),
                "",
            ),
            400,
        )
        .await;
        assert_eq!(body(&replay)["code"], "INVALID_OTP");
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, after);
        for (before, now) in baseline.iter().zip(after.iter()) {
            let before: Vec<Value> = serde_json::from_str(before)?;
            let now: Vec<Value> = serde_json::from_str(now)?;
            assert!(before.iter().all(|r| now.contains(r)));
        }
        authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn verification_otp_creation_retry<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{DatabaseHookContext, DatabaseHooks, HookControl};
    use alibi::verification::{
        VerificationCreation, VerificationIdentifierStrategy, VerificationSnapshot,
    };

    #[derive(Clone)]
    struct Hook {
        events: Arc<Mutex<Vec<Value>>>,
        mailbox: Arc<Mailbox>,
    }
    #[async_trait::async_trait]
    impl<S: AuthSchema, H: alibi::store::HookBackend> DatabaseHooks<S, H> for Hook {
        async fn before_create_verification_record(
            &self,
            c: &mut VerificationCreation,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            assert!(self.mailbox.0.lock().unwrap().is_empty());
            let mut events = self.events.lock().unwrap();
            events.push(json!({"stage":"before","identifier":c.identifier,"value":c.value,"expiresAt":c.expires_at}));
            if events.len() == 1 {
                Err(AuthError::internal("first creation rejected"))
            } else {
                Ok(HookControl::Continue)
            }
        }
        async fn after_create_verification_record(
            &self,
            c: &VerificationSnapshot,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<()> {
            assert!(self.mailbox.0.lock().unwrap().is_empty());
            self.events
                .lock()
                .unwrap()
                .push(json!({"stage":"after","identifier":c.identifier()?,"value":c.value()?}));
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mailbox = Arc::new(Mailbox::default());
    let hook = Hook {
        events: Arc::new(Mutex::new(Vec::new())),
        mailbox: mailbox.clone(),
    };
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.verification.store_identifier.default = VerificationIdentifierStrategy::Hashed;
    let auth = AuthBuilder::new(config.clone())
        .store(B::hook(
            B::store(Arc::new(config), &connection),
            hook.clone(),
        ))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(plugin(&mailbox, EmailOtpConfig::default()))
        .build()
        .await?;
    let foreign = signup(&auth, "foreign@example.test").await;
    let baseline = db.tables(&["users", "accounts", "sessions"]).await?;
    let email = "retry@example.test";
    _ = call(
        &auth,
        request(
            "/email-otp/send-verification-otp",
            Some(json!({"email":email,"type":"sign-in"})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(mailbox.0.lock().unwrap().len(), 1);
    let delivery = mailbox.take();
    let events = hook.events.lock().unwrap().clone();
    assert_eq!(events.len(), 3);
    assert_eq!(
        events
            .iter()
            .map(|e| e["stage"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["before", "before", "after"]
    );
    assert_eq!(events[0]["value"], events[1]["value"]);
    assert_eq!(events[1]["value"], format!("{}:0", delivery.otp));
    assert_eq!(events[0]["identifier"], events[1]["identifier"]);
    assert!(events[1]["expiresAt"].as_str().unwrap() >= events[0]["expiresAt"].as_str().unwrap());
    assert_eq!(db.count("verifications").await?, 1);
    let proof = auth
        .context()
        .verifications()
        .find(&format!("sign-in-otp-{email}"))
        .await?
        .unwrap();
    assert_eq!(proof.value()?, format!("{}:0", delivery.otp));
    let done = call(
        &auth,
        request(
            "/sign-in/email-otp",
            Some(json!({"email":email,"otp":delivery.otp})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&done)["user"]["emailVerified"], true);
    authenticated(&auth, &cookies(&done), email).await;
    assert_eq!(db.count("verifications").await?, 0);
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    _ = call(
        &auth,
        request(
            "/sign-in/email-otp",
            Some(json!({"email":email,"otp":delivery.otp})),
            "",
        ),
        400,
    )
    .await;
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, after);
    for (before, now) in baseline.iter().zip(after.iter()) {
        let before: Vec<Value> = serde_json::from_str(before)?;
        let now: Vec<Value> = serde_json::from_str(now)?;
        assert!(before.iter().all(|r| now.contains(r)));
    }
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn verification_otp_cache_set_failure<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{
        CacheAdapter, DatabaseHookContext, DatabaseHooks, HookControl, MemoryCacheAdapter,
    };
    use alibi::verification::{
        VerificationCreation, VerificationIdentifierStrategy, VerificationSnapshot,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Cache {
        memory: MemoryCacheAdapter,
        fail_set: AtomicBool,
        fail_get: AtomicBool,
    }
    #[async_trait::async_trait]
    impl CacheAdapter for Cache {
        async fn set(&self, k: &str, v: &str, t: chrono::Duration) -> AuthResult<()> {
            if self.fail_set.load(Ordering::SeqCst) {
                return Err(AuthError::internal("configured cache outage"));
            }
            self.memory.set(k, v, t).await
        }
        async fn get(&self, k: &str) -> AuthResult<Option<String>> {
            if self.fail_get.load(Ordering::SeqCst) {
                return Err(AuthError::internal("configured cache outage"));
            }
            self.memory.get(k).await
        }
        async fn get_and_delete(&self, k: &str) -> AuthResult<Option<String>> {
            self.memory.get_and_delete(k).await
        }
        async fn delete(&self, k: &str) -> AuthResult<()> {
            self.memory.delete(k).await
        }
        async fn exists(&self, k: &str) -> AuthResult<bool> {
            self.memory.exists(k).await
        }
        async fn expire(&self, k: &str, t: chrono::Duration) -> AuthResult<()> {
            self.memory.expire(k, t).await
        }
        async fn clear(&self) -> AuthResult<()> {
            self.memory.clear().await
        }
    }

    #[derive(Clone)]
    struct Hook(Arc<Mutex<Vec<&'static str>>>);
    #[async_trait::async_trait]
    impl<S: AuthSchema, H: alibi::store::HookBackend> DatabaseHooks<S, H> for Hook {
        async fn before_create_verification_record(
            &self,
            _: &mut VerificationCreation,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            self.0.lock().unwrap().push("before");
            Ok(HookControl::Continue)
        }
        async fn after_create_verification_record(
            &self,
            _: &VerificationSnapshot,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<()> {
            self.0.lock().unwrap().push("after");
            Ok(())
        }
    }
    for physical in [false, true] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let cache = Arc::new(Cache {
            memory: MemoryCacheAdapter::new(),
            fail_set: AtomicBool::new(true),
            fail_get: AtomicBool::new(false),
        });
        let hook = Hook(Arc::new(Mutex::new(Vec::new())));
        let mailbox = Arc::new(Mailbox::default());
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.verification.secondary_storage = Some(cache.clone());
        config.verification.store_in_database = physical;
        config.verification.store_identifier.default = VerificationIdentifierStrategy::Hashed;
        let auth = AuthBuilder::new(config.clone())
            .store(B::hook(
                B::store(Arc::new(config), &connection),
                hook.clone(),
            ))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(plugin(&mailbox, EmailOtpConfig::default()))
            .build()
            .await?;
        let foreign = signup(&auth, "foreign@example.test").await;
        let baseline = db.tables(&["users", "accounts", "sessions"]).await?;
        let failed = call(
            &auth,
            request(
                "/email-otp/send-verification-otp",
                Some(json!({"email":"undelivered@example.test","type":"sign-in"})),
                "",
            ),
            500,
        )
        .await;
        assert!(failed.headers.get_all("set-cookie").next().is_none());
        assert!(mailbox.0.lock().unwrap().is_empty());
        assert_eq!(*hook.0.lock().unwrap(), ["before", "before"]);
        assert_eq!(db.count("verifications").await?, i64::from(physical));
        assert_eq!(
            db.tables(&["users", "accounts", "sessions"]).await?,
            baseline
        );
        cache.fail_set.store(false, Ordering::SeqCst);
        let denied = call(
            &auth,
            request(
                "/sign-in/email-otp",
                Some(json!({"email":"undelivered@example.test","otp":"undelivered-proof"})),
                "",
            ),
            400,
        )
        .await;
        assert_eq!(body(&denied)["code"], "INVALID_OTP");
        assert_eq!(
            db.tables(&["users", "accounts", "sessions"]).await?,
            baseline
        );
        assert!(mailbox.0.lock().unwrap().is_empty());
        authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}
