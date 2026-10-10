//! Magic-link issuance policy, callback validation and redemption outcomes.
use super::auth_probe::{Probe, fast_builder};
use super::*;
use alibi::hooks::RequestHookContext;
use alibi::plugins::magic_link::{
    MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin, MagicLinkTokenGenerator,
    MagicLinkTokenHasher, MagicLinkTokenStorage, SendMagicLink,
};
use alibi::user_validation::{UserInfoValidator, UserValidationData, UserValidationRejection};
use alibi::{AuthError, AuthResult, CallbackContext};
use async_trait::async_trait;

backend_tests!(
    magic_link_request_matrix,
    magic_link_issuance_policies,
    magic_link_redemption_matrix,
    magic_link_configured_quota_blocks_delivery_and_resets_at_configured_window,
    magic_link_returning_verified_owner_retains_credentials_oauth_and_browser_sessions,
    magic_link_redemption_hasher_failure,
    magic_link_fresh_empty_callback
);

#[derive(Default)]
struct Outbox {
    sent: Mutex<Vec<MagicLinkDelivery>>,
    failure: Mutex<Option<&'static str>>,
}
#[async_trait]
impl SendMagicLink for Outbox {
    async fn send(&self, delivery: &MagicLinkDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.sent.lock().unwrap().push(delivery.clone());
        match *self.failure.lock().unwrap() {
            Some("internal") => Err(AuthError::internal("mail down")),
            Some("api") => Err(AuthError::forbidden("mail refused")),
            _ => Ok(()),
        }
    }
}

struct Generator(&'static str);
#[async_trait]
impl MagicLinkTokenGenerator for Generator {
    async fn generate(&self, email: &str) -> AuthResult<String> {
        match self.0 {
            "fail" => Err(AuthError::internal("generator down")),
            _ => Ok(format!("token-for-{}", email.replace(['@', '.'], "-"))),
        }
    }
}

struct Hasher(&'static str);
#[async_trait]
impl MagicLinkTokenHasher for Hasher {
    async fn hash(&self, token: &str) -> AuthResult<String> {
        match self.0 {
            "internal" => Err(AuthError::internal("hasher down")),
            "api" => Err(AuthError::forbidden("hasher refused")),
            _ => Ok(format!("hashed-{token}")),
        }
    }
}

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
                error_description: Some("Closed community".into()),
            }))
    }
}

fn redeem(delivery: &MagicLinkDelivery, extra: &[(&str, &str)]) -> AuthRequest {
    let link = url::Url::parse(&delivery.url).unwrap();
    let mut request = AuthRequest::new(HttpMethod::Get, link.path());
    request.query.extend(link.query_pairs().into_owned());
    for (key, value) in extra {
        _ = request.query.insert((*key).into(), (*value).into());
    }
    request
}

async fn magic_link_request_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let auth = fast_builder::<B>(&connection)
        .plugin(MagicLinkPlugin::new(MagicLinkConfig {
            send_magic_link: Some(outbox.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    for text in [
        "[]",
        "null",
        "{}",
        r#"{"email":5}"#,
        r#"{"email":"not-an-email"}"#,
        r#"{"email":"a@example.test","name":5}"#,
        r#"{"email":"a@example.test","callbackURL":5,"newUserCallbackURL":5,"errorCallbackURL":5}"#,
        r#"{"email":"a@example.test","metadata":[]}"#,
        r#"{"email":"a@example.test","metadata":"text"}"#,
        r#"{"email":"a@example.test","metadata":{"campaign":"spring"},"newUserCallbackURL":"/welcome","errorCallbackURL":"/oops","callbackURL":"/home","name":"Ann"}"#,
        r#"{"email":"b@example.test","callbackURL":"","newUserCallbackURL":"","errorCallbackURL":""}"#,
    ] {
        let _ = probe.post(text, "/sign-in/magic-link", text, "").await;
    }
    let delivered: Vec<_> = outbox.sent.lock().unwrap().drain(..).collect();
    probe.trace.value(
        "deliveries",
        json!(delivered
            .iter()
            .map(|sent| {
                let link = url::Url::parse(&sent.url).unwrap();
                json!({
                    "email": sent.email,
                    "metadata": sent.metadata.as_ref().map(|value| value.to_json_value().unwrap()),
                    "query": link
                        .query_pairs()
                        .filter(|(key, _)| key != "token")
                        .map(|(key, value)| format!("{key}={value}"))
                        .collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>()),
    );
    probe.trace.assert("magic-link/request-matrix");
    B::close(connection).await
}

async fn magic_link_issuance_policies<B: Backend>(db: Db) -> TestResult {
    let mut trace = crate::snapshot::Trace::default();
    for mode in [
        "no sender",
        "internal sender failure",
        "api sender failure",
        "generator failure",
        "custom generator",
        "hashed",
        "custom hasher",
        "hasher internal failure",
        "hasher api failure",
        "invalid expiry",
        "zero expiry",
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let outbox = Arc::new(Outbox::default());
        *outbox.failure.lock().unwrap() = match mode {
            "internal sender failure" => Some("internal"),
            "api sender failure" => Some("api"),
            _ => None,
        };
        let config = MagicLinkConfig {
            send_magic_link: (mode != "no sender").then(|| outbox.clone() as _),
            generate_token: match mode {
                "generator failure" => Some(Arc::new(Generator("fail"))),
                "custom generator" => Some(Arc::new(Generator("ok"))),
                _ => None,
            },
            storage: match mode {
                "hashed" => MagicLinkTokenStorage::Hashed,
                "custom hasher" => MagicLinkTokenStorage::Custom(Arc::new(Hasher("ok"))),
                "hasher internal failure" => {
                    MagicLinkTokenStorage::Custom(Arc::new(Hasher("internal")))
                }
                "hasher api failure" => MagicLinkTokenStorage::Custom(Arc::new(Hasher("api"))),
                _ => MagicLinkTokenStorage::Plain,
            },
            expires_in: match mode {
                "invalid expiry" => f64::INFINITY,
                "zero expiry" => 0.0,
                _ => 300.0,
            },
            ..Default::default()
        };
        let auth = fast_builder::<B>(&connection)
            .plugin(MagicLinkPlugin::new(config))
            .build()
            .await?;
        let mut probe = Probe::new(&auth);
        probe.trace = trace;
        probe.prefix = format!("{mode}: ");
        let _ = probe
            .post(
                "request",
                "/sign-in/magic-link",
                r#"{"email":"Issue@Example.test"}"#,
                "",
            )
            .await;
        let token = outbox
            .sent
            .lock()
            .unwrap()
            .last()
            .map(|sent| sent.token.clone())
            .unwrap_or_default();
        let identifiers = db
            .text("SELECT identifier FROM verifications", &[])
            .await?
            .map(|identifier| {
                if token.is_empty() {
                    "<undelivered>".to_owned()
                } else {
                    identifier.replace(&token, "<token>")
                }
            });
        probe.trace.value("stored", json!(identifiers));
        let sent = outbox.sent.lock().unwrap().last().cloned();
        if let Some(sent) = sent {
            let response = Box::pin(auth.handle_request(redeem(&sent, &[]))).await?;
            probe.trace.response("redeem", &response);
        }
        trace = probe.trace;
        B::close(connection).await?;
    }
    trace.assert("magic-link/issuance-policies");
    Ok(())
}

async fn magic_link_redemption_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.user_validation = Some(Arc::new(Deny));
    let auth = alibi::AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(MagicLinkPlugin::new(MagicLinkConfig {
            send_magic_link: Some(outbox.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    let issue = async |probe: &mut Probe<'_, B::Schema>, email: &str| {
        let _ = probe
            .post(
                &format!("issue {email}"),
                "/sign-in/magic-link",
                &json!({"email":email,"name":"Link User","callbackURL":"/home","newUserCallbackURL":"/welcome","errorCallbackURL":"/oops"}).to_string(),
                "",
            )
            .await;
        outbox.sent.lock().unwrap().pop().unwrap()
    };
    let verify = async |probe: &mut Probe<'_, B::Schema>, label: &str, input: AuthRequest| {
        let response = Box::pin(auth.handle_request(input)).await.unwrap();
        probe.trace.response(label, &response);
        response
    };
    let sent = issue(&mut probe, "fresh@example.test").await;
    let _ = verify(&mut probe, "new user", redeem(&sent, &[])).await;
    let sent = issue(&mut probe, "fresh@example.test").await;
    let _ = verify(&mut probe, "returning user", redeem(&sent, &[])).await;
    let sent = issue(&mut probe, "fresh@example.test").await;
    let _ = verify(
        &mut probe,
        "no callback returns session json",
        redeem(&sent, &[("callbackURL", "")]),
    )
    .await;
    let sent = issue(&mut probe, "denied@example.test").await;
    let _ = verify(&mut probe, "denied by policy", redeem(&sent, &[])).await;
    let _ = signup(&auth, "unverified@example.test").await;
    let sent = issue(&mut probe, "unverified@example.test").await;
    let _ = verify(&mut probe, "unverified owner", redeem(&sent, &[])).await;
    let sent = issue(&mut probe, "bad@example.test").await;
    for (label, extra) in [
        ("missing token", vec![("token", "")]),
        (
            "untrusted callback",
            vec![("callbackURL", "https://evil.example")],
        ),
        (
            "untrusted new user callback",
            vec![("newUserCallbackURL", "https://evil.example")],
        ),
        (
            "untrusted error callback",
            vec![("errorCallbackURL", "https://evil.example")],
        ),
        ("malformed escape", vec![("callbackURL", "/a%2")]),
        ("malformed escape pair", vec![("errorCallbackURL", "/a%zz")]),
        ("encoded callback", vec![("callbackURL", "%2Fhome%3Fx%3D1")]),
        ("unknown token", vec![("token", "unknown")]),
    ] {
        let _ = verify(&mut probe, label, redeem(&sent, &extra)).await;
    }
    let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/magic-link/verify");
    request.headers.extend([("origin".into(), ORIGIN.into())]);
    let _ = verify(&mut probe, "query without token", request).await;
    probe.trace.value(
        "rows",
        json!([db.count("users").await?, db.count("sessions").await?]),
    );
    probe.trace.assert("magic-link/redemption-matrix");
    B::close(connection).await
}

async fn magic_link_configured_quota_blocks_delivery_and_resets_at_configured_window<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::store::SchemaMigrator;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let ledger = B::rate_limit(&connection);
    ledger.migrate().await?;
    let outbox = Arc::new(Outbox::default());
    let auth = fast_builder::<B>(&connection)
        .rate_limit(
            alibi::middleware::RateLimitConfig::new()
                .enabled(true)
                .storage(Arc::new(ledger)),
        )
        .plugin(MagicLinkPlugin::new(MagicLinkConfig {
            send_magic_link: Some(outbox.clone()),
            rate_limit: alibi::EndpointRateLimit {
                window_seconds: 120.0,
                max_requests: 2.0,
            },
            ..Default::default()
        }))
        .build()
        .await?;
    for index in 0..2 {
        _ = call(
            &auth,
            request(
                "/sign-in/magic-link",
                Some(json!({"email":format!("quota-{index}@example.test")})),
                "",
            ),
            200,
        )
        .await;
    }
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    assert_eq!(outbox.sent.lock().unwrap().len(), 2);
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
            "/sign-in/magic-link",
            Some(json!({"email":format!("quota-{index}@example.test")})),
            "",
        ),
        429,
    )
    .await;
    assert_eq!(denied.status, 429);
    assert_eq!(outbox.sent.lock().unwrap().len(), 2);
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
            "/sign-in/magic-link",
            Some(json!({"email":format!("quota-{index}@example.test")})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(outbox.sent.lock().unwrap().len(), 3);
    assert_eq!(db.count("verifications").await?, 3);
    assert_eq!(db.count("sessions").await?, 0);
    B::close(connection).await
}

async fn magic_link_returning_verified_owner_retains_credentials_oauth_and_browser_sessions<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let auth = fast_builder::<B>(&connection)
        .plugin(MagicLinkPlugin::new(MagicLinkConfig {
            send_magic_link: Some(outbox.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "verified@example.test").await;
    let id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    _ = auth
        .store()
        .update_user(
            &id,
            alibi::UpdateUser {
                email_verified: Some(true),
                ..Default::default()
            },
        )
        .await?;
    _ = auth
        .store()
        .create_account(alibi::CreateAccount {
            user_id: id.clone(),
            account_id: "linked-provider-owner".into(),
            provider_id: "github".into(),
            access_token: Some("durable-access".into()),
            refresh_token: Some("durable-refresh".into()),
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: Some("profile".into()),
            password: None,
            additional_fields: Default::default(),
        })
        .await?;
    let second = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"verified@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let accounts = db.table("accounts").await?;
    _ = call(
        &auth,
        request(
            "/sign-in/magic-link",
            Some(json!({"email":"VERIFIED@EXAMPLE.TEST","name":"must-not-replace"})),
            "",
        ),
        200,
    )
    .await;
    let delivery = outbox.sent.lock().unwrap().last().unwrap().clone();
    let response = call(&auth, redeem(&delivery, &[]), 302).await;
    assert_eq!(db.table("accounts").await?, accounts);
    assert_eq!(
        db.text("SELECT name FROM users WHERE id=$1", &[&id])
            .await?
            .as_deref(),
        Some("Native owner")
    );
    assert_eq!(db.count("verifications").await?, 0);
    for cookie in [cookies(&owner), cookies(&second), cookies(&response)] {
        authenticated(&auth, &cookie, "verified@example.test").await;
    }
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    let login = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"verified@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&login)["user"]["id"], id);
    assert_eq!(db.table("accounts").await?, accounts);
    B::close(connection).await
}

async fn magic_link_redemption_hasher_failure<B: Backend>(db: Db) -> TestResult {
    struct Switched(std::sync::atomic::AtomicU8);
    #[async_trait]
    impl MagicLinkTokenHasher for Switched {
        async fn hash(&self, token: &str) -> AuthResult<String> {
            match self.0.load(std::sync::atomic::Ordering::SeqCst) {
                1 => Err(AuthError::Upstream {
                    status: 403,
                    code: "MAGIC_HASH_REJECTED",
                    message: "Application hasher rejected",
                }),
                2 => Err(AuthError::internal("private hasher rejection")),
                _ => Ok(format!("application:{token}")),
            }
        }
    }
    for failure in [1, 2] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let hasher = Arc::new(Switched(std::sync::atomic::AtomicU8::new(0)));
        let outbox = Arc::new(Outbox::default());
        let auth = fast_builder::<B>(&connection)
            .plugin(MagicLinkPlugin::new(MagicLinkConfig {
                storage: MagicLinkTokenStorage::Custom(hasher.clone()),
                send_magic_link: Some(outbox.clone()),
                ..Default::default()
            }))
            .build()
            .await?;
        _ = call(
            &auth,
            request(
                "/sign-in/magic-link",
                Some(json!({"email":"hash-retry@example.test"})),
                "",
            ),
            200,
        )
        .await;
        let delivery = outbox.sent.lock().unwrap().last().unwrap().clone();
        let before = db
            .tables(&["users", "accounts", "sessions", "verifications"])
            .await?;
        assert_eq!(
            db.text("SELECT identifier FROM verifications", &[])
                .await?
                .as_deref(),
            Some(format!("magic-link:application:{}", delivery.token).as_str())
        );
        hasher.0.store(failure, std::sync::atomic::Ordering::SeqCst);
        let denied = call(
            &auth,
            redeem(&delivery, &[("callbackURL", "")]),
            if failure == 1 { 403 } else { 500 },
        )
        .await;
        assert!(cookies(&denied).is_empty());
        if failure == 1 {
            assert_eq!(body(&denied)["code"], "MAGIC_HASH_REJECTED");
        } else {
            assert!(denied.body.is_empty());
        }
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
        hasher.0.store(0, std::sync::atomic::Ordering::SeqCst);
        let accepted = call(&auth, redeem(&delivery, &[("callbackURL", "")]), 200).await;
        assert_eq!(body(&accepted)["user"]["email"], "hash-retry@example.test");
        authenticated(&auth, &cookies(&accepted), "hash-retry@example.test").await;
        assert_eq!(db.count("verifications").await?, 0);
        assert_eq!(db.count("sessions").await?, 1);
        let after = db.tables(&["users", "accounts", "sessions"]).await?;
        let replay = call(&auth, redeem(&delivery, &[("callbackURL", "")]), 302).await;
        let location = url::Url::parse(replay.headers.get("location").unwrap())?;
        assert_eq!(
            location
                .query_pairs()
                .find(|(key, _)| key == "error")
                .unwrap()
                .1,
            "INVALID_TOKEN"
        );
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, after);
        B::close(connection).await?;
    }
    Ok(())
}

async fn magic_link_fresh_empty_callback<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let auth = fast_builder::<B>(&connection)
        .plugin(MagicLinkPlugin::new(MagicLinkConfig {
            send_magic_link: Some(outbox.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    _ = call(
        &auth,
        request(
            "/sign-in/magic-link",
            Some(json!({"email":"fresh-json@example.test","name":"JSON owner"})),
            "",
        ),
        200,
    )
    .await;
    let delivery = outbox.sent.lock().unwrap().last().unwrap().clone();
    assert_eq!(db.count("users").await?, 0);
    assert_eq!(db.count("verifications").await?, 1);
    let input = redeem(
        &delivery,
        &[("callbackURL", ""), ("newUserCallbackURL", "/welcome")],
    );
    let accepted = call(&auth, input.clone(), 200).await;
    assert!(!accepted.headers.contains_key("location"));
    assert_eq!(body(&accepted)["user"]["name"], "JSON owner");
    assert_eq!(body(&accepted)["user"]["emailVerified"], true);
    assert!(body(&accepted)["token"].is_string());
    authenticated(&auth, &cookies(&accepted), "fresh-json@example.test").await;
    assert_eq!(db.count("sessions").await?, 1);
    assert_eq!(db.count("verifications").await?, 0);
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let replay = call(&auth, input, 302).await;
    let location = url::Url::parse(replay.headers.get("location").unwrap())?;
    assert_eq!(
        location
            .query_pairs()
            .find(|(key, _)| key == "error")
            .unwrap()
            .1,
        "INVALID_TOKEN"
    );
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    B::close(connection).await
}
