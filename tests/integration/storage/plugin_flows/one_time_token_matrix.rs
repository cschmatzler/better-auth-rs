//! One-time token generation policy, storage failures and redemption of damaged sessions.
use super::auth_probe::{Probe, fast_builder};
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::one_time_token::{
    GenerateOneTimeToken, HashOneTimeToken, OneTimeTokenConfig, OneTimeTokenPlugin,
    OneTimeTokenSession, OneTimeTokenStorage,
};
use alibi::{AuthError, AuthResult, CookieCacheConfig, CookieCacheStrategy};
use async_trait::async_trait;
use chrono::Duration;

backend_tests!(
    one_time_token_issuance_and_redemption_policies,
    one_time_token_server_endpoints_publish_cached_identity,
    ott_new_session_callback_failures_preserve_committed_authentication,
    ott_redemption_hasher_retry,
    ott_generator_real_endpoint_context,
    ott_verification_cancellation_result
);

struct Generator(&'static str);
#[async_trait]
impl GenerateOneTimeToken for Generator {
    async fn generate(
        &self,
        _: &OneTimeTokenSession,
        _: Option<&AuthRequest>,
    ) -> AuthResult<String> {
        match self.0 {
            "api" => Err(AuthError::forbidden("generation vetoed")),
            "internal" => Err(AuthError::internal("generator down")),
            _ => Ok("custom-generated-token".into()),
        }
    }
}

struct Hasher(&'static str);
#[async_trait]
impl HashOneTimeToken for Hasher {
    async fn hash(&self, token: &str) -> AuthResult<String> {
        match self.0 {
            "api" => Err(AuthError::forbidden("hash vetoed")),
            "internal" => Err(AuthError::internal("hasher down")),
            _ => Ok(format!("hashed-{token}")),
        }
    }
}

async fn one_time_token_issuance_and_redemption_policies<B: Backend>(db: Db) -> TestResult {
    let mut trace = crate::snapshot::Trace::default();
    for mode in [
        "default",
        "generator vetoes",
        "generator fails",
        "custom generator",
        "hasher vetoes",
        "hasher fails",
        "hashed",
        "client requests disabled",
        "cookie disabled",
        "short lived",
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let config = OneTimeTokenConfig {
            generator: match mode {
                "generator vetoes" => Some(Arc::new(Generator("api"))),
                "generator fails" => Some(Arc::new(Generator("internal"))),
                "custom generator" => Some(Arc::new(Generator("ok"))),
                _ => None,
            },
            storage: match mode {
                "hasher vetoes" => OneTimeTokenStorage::Custom(Arc::new(Hasher("api"))),
                "hasher fails" => OneTimeTokenStorage::Custom(Arc::new(Hasher("internal"))),
                "hashed" => OneTimeTokenStorage::Hashed,
                "custom generator" => OneTimeTokenStorage::Custom(Arc::new(Hasher("ok"))),
                _ => OneTimeTokenStorage::Plain,
            },
            disable_client_request: mode == "client requests disabled",
            disable_set_session_cookie: mode == "cookie disabled",
            expires_in: if mode == "short lived" {
                Duration::seconds(-5)
            } else {
                Duration::minutes(3)
            },
            ..Default::default()
        };
        let auth = fast_builder::<B>(&connection)
            .plugin(OneTimeTokenPlugin::with_config(config))
            .build()
            .await?;
        let mut probe = Probe::new(&auth);
        probe.trace = trace;
        probe.prefix = format!("{mode}: ");
        let owner = signup(&auth, "owner@example.test").await;
        let cookie = cookies(&owner);
        let generated = probe
            .send(
                "generate",
                request("/one-time-token/generate", None, &cookie),
            )
            .await;
        let token = serde_json::from_slice::<Value>(&generated.body)
            .ok()
            .and_then(|value| value["token"].as_str().map(str::to_owned));
        for text in [
            "[]",
            "null",
            "{}",
            r#"{"token":5}"#,
            r#"{"token":"unknown"}"#,
        ] {
            let _ = probe.post(text, "/one-time-token/verify", text, "").await;
        }
        if let Some(token) = token {
            let remember = format!(
                "better-auth.dont_remember={}",
                alibi::utils::cookie_utils::sign_cookie_value("true", SECRET)
            );
            let _ = probe
                .post(
                    "redeem",
                    "/one-time-token/verify",
                    &json!({"token":token}).to_string(),
                    &remember,
                )
                .await;
            probe
                .trace
                .value("sessions", json!(db.count("sessions").await?));
        }
        trace = probe.trace;
        B::close(connection).await?;
    }

    for mode in ["session removed", "session expired", "dont remember"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = fast_builder::<B>(&connection)
            .plugin(OneTimeTokenPlugin::new())
            .build()
            .await?;
        let mut probe = Probe::new(&auth);
        probe.trace = trace;
        probe.prefix = format!("{mode}: ");
        let owner = signup(&auth, "owner@example.test").await;
        let generated = probe
            .send(
                "generate",
                request("/one-time-token/generate", None, &cookies(&owner)),
            )
            .await;
        let token = body(&generated)["token"].as_str().unwrap().to_owned();
        match mode {
            "session removed" => {
                _ = db.execute("DELETE FROM sessions", &[]).await?;
            }
            "session expired" => {
                db.set_timestamp(
                    "sessions",
                    "expires_at",
                    ("user_id", body(&owner)["user"]["id"].as_str().unwrap()),
                    chrono::Utc::now() - Duration::hours(1),
                )
                .await?;
            }
            _ => {}
        }
        let remember = format!(
            "better-auth.dont_remember={}",
            alibi::utils::cookie_utils::sign_cookie_value("true", SECRET)
        );
        let _ = probe
            .post(
                "redeem",
                "/one-time-token/verify",
                &json!({"token":token}).to_string(),
                if mode == "dont remember" {
                    &remember
                } else {
                    ""
                },
            )
            .await;
        trace = probe.trace;
        B::close(connection).await?;
    }
    trace.assert("one-time-token/policies");
    Ok(())
}

async fn one_time_token_server_endpoints_publish_cached_identity<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            strategy: CookieCacheStrategy::Compact,
            max_age: 300.0,
            version: None,
        });
    let auth = alibi::AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(OneTimeTokenPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "cached@example.test").await;
    let cookie = cookies(&owner);
    assert!(cookie.contains("session_data"));
    let with_cookie = || EndpointOptions {
        headers: Some([("cookie".to_owned(), cookie.clone())].into()),
        ..Default::default()
    };
    let issued = auth
        .dispatch_endpoint(OneTimeTokenPlugin::generate_endpoint(), with_cookie())
        .await?
        .decode()?;
    let redeemed = auth
        .dispatch_endpoint(
            OneTimeTokenPlugin::verify_endpoint(issued.token),
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    assert_eq!(redeemed.user.email.as_deref(), Some("cached@example.test"));
    let denied = auth
        .dispatch_endpoint(
            OneTimeTokenPlugin::generate_endpoint(),
            EndpointOptions::default(),
        )
        .await;
    assert!(
        denied.is_err(),
        "anonymous server generation is unauthorized"
    );
    B::close(connection).await
}

async fn ott_new_session_callback_failures_preserve_committed_authentication<B: Backend>(
    db: Db,
) -> TestResult {
    struct Callbacks {
        next: std::sync::atomic::AtomicUsize,
        mode: Mutex<&'static str>,
        seen: Mutex<Vec<(OneTimeTokenSession, AuthRequest)>>,
    }
    #[async_trait]
    impl GenerateOneTimeToken for Callbacks {
        async fn generate(
            &self,
            session: &OneTimeTokenSession,
            request: Option<&AuthRequest>,
        ) -> AuthResult<String> {
            self.seen
                .lock()
                .unwrap()
                .push((session.clone(), request.unwrap().clone()));
            match *self.mode.lock().unwrap() {
                "generate internal" => Err(AuthError::internal("generator down")),
                "generate api" => Err(AuthError::Upstream {
                    status: 403,
                    code: "OTT_VETO",
                    message: "OTT callback veto",
                }),
                _ => Ok(format!(
                    "new-session-ott-{}",
                    self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                )),
            }
        }
    }
    #[async_trait]
    impl HashOneTimeToken for Callbacks {
        async fn hash(&self, token: &str) -> AuthResult<String> {
            match *self.mode.lock().unwrap() {
                "hash internal" => Err(AuthError::internal("hasher down")),
                "hash api" => Err(AuthError::Upstream {
                    status: 403,
                    code: "OTT_VETO",
                    message: "OTT callback veto",
                }),
                _ => Ok(format!("digest-{token}")),
            }
        }
    }
    for signup_flow in [true, false] {
        for mode in [
            "generate internal",
            "generate api",
            "hash internal",
            "hash api",
        ] {
            let db = db.fresh().await?;
            let (connection, _) = db.migrated::<B>(SECRET).await?;
            let callbacks = Arc::new(Callbacks {
                next: std::sync::atomic::AtomicUsize::new(0),
                mode: Mutex::new("success"),
                seen: Mutex::new(Vec::new()),
            });
            let auth = fast_builder::<B>(&connection)
                .plugin(OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
                    generator: Some(callbacks.clone()),
                    storage: OneTimeTokenStorage::Custom(callbacks.clone()),
                    set_ott_header_on_new_session: true,
                    ..Default::default()
                }))
                .build()
                .await?;
            let foreign = signup(&auth, "foreign@example.test").await;
            if !signup_flow {
                _ = signup(&auth, "owner@example.test").await;
            }
            let proofs = db.table("verifications").await?;
            callbacks.seen.lock().unwrap().clear();
            *callbacks.mode.lock().unwrap() = mode;
            let path = if signup_flow {
                "/sign-up/email"
            } else {
                "/sign-in/email"
            };
            let mut input = request(
                path,
                Some(json!({"email":"owner@example.test","password":PASSWORD,"name":"OTT owner"})),
                "",
            );
            _ = input.headers.insert("x-ott-marker".into(), mode.into());
            let failed = call(&auth, input, if mode.ends_with("api") { 403 } else { 500 }).await;
            assert!(failed.headers.get("set-ott").is_none());
            if mode.ends_with("internal") {
                assert!(failed.body.is_empty());
            }
            let (session, seen_request) = callbacks.seen.lock().unwrap().last().unwrap().clone();
            assert_eq!(seen_request.path(), path);
            assert_eq!(
                seen_request.headers.get("x-ott-marker").map(String::as_str),
                Some(mode)
            );
            assert_eq!(session.user.email.as_deref(), Some("owner@example.test"));
            assert_eq!(session.session.user_id, session.user.id);
            assert!(
                auth.store()
                    .get_session(&session.session.token)
                    .await?
                    .is_some()
            );
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM sessions WHERE user_id=$1",
                    &[&session.user.id]
                )
                .await?,
                if signup_flow { 1 } else { 2 }
            );
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM accounts WHERE user_id=$1",
                    &[&session.user.id]
                )
                .await?,
                1
            );
            assert_eq!(db.table("verifications").await?, proofs);
            authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
            *callbacks.mode.lock().unwrap() = "success";
            let restored = call(
                &auth,
                request(
                    "/sign-in/email",
                    Some(json!({"email":"owner@example.test","password":PASSWORD})),
                    "",
                ),
                200,
            )
            .await;
            assert_eq!(body(&restored)["user"]["id"], session.user.id);
            let token = restored.headers.get("set-ott").unwrap();
            let consumed = call(
                &auth,
                request("/one-time-token/verify", Some(json!({"token":token})), ""),
                200,
            )
            .await;
            assert_eq!(
                body(&consumed)["session"]["token"],
                body(&restored)["token"]
            );
            _ = call(
                &auth,
                request("/one-time-token/verify", Some(json!({"token":token})), ""),
                400,
            )
            .await;
            B::close(connection).await?;
        }
    }
    Ok(())
}

async fn ott_redemption_hasher_retry<B: Backend>(db: Db) -> TestResult {
    struct Hash(Mutex<u8>);
    #[async_trait]
    impl HashOneTimeToken for Hash {
        async fn hash(&self, token: &str) -> AuthResult<String> {
            match *self.0.lock().unwrap() {
                1 => Err(AuthError::internal("private hashing outage")),
                2 => Err(AuthError::Upstream {
                    status: 403,
                    code: "OTT_VETO",
                    message: "OTT callback veto",
                }),
                _ => Ok(format!("digest-{token}")),
            }
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let hash = Arc::new(Hash(Mutex::new(0)));
    let auth = fast_builder::<B>(&connection)
        .plugin(OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
            storage: OneTimeTokenStorage::Custom(hash.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "retry-owner@example.test").await;
    let foreign = signup(&auth, "retry-foreign@example.test").await;
    let generated = call(
        &auth,
        request("/one-time-token/generate", None, &cookies(&owner)),
        200,
    )
    .await;
    let token = body(&generated)["token"].as_str().unwrap().to_owned();
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    assert_eq!(
        db.text(
            "SELECT value FROM verifications WHERE identifier=$1",
            &[&format!("one-time-token:digest-{token}")]
        )
        .await?,
        Some(body(&owner)["token"].as_str().unwrap().to_owned())
    );
    for mode in [1, 2] {
        *hash.0.lock().unwrap() = mode;
        let denied = call(
            &auth,
            request(
                "/one-time-token/verify",
                Some(json!({"token":token})),
                &cookies(&foreign),
            ),
            if mode == 1 { 500 } else { 403 },
        )
        .await;
        if mode == 1 {
            assert!(denied.body.is_empty());
        } else {
            assert_eq!(
                body(&denied),
                json!({"code":"OTT_VETO","message":"OTT callback veto"})
            );
        }
        assert!(!denied.headers.contains_key("set-cookie"));
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
    }
    *hash.0.lock().unwrap() = 0;
    let accepted = call(
        &auth,
        request(
            "/one-time-token/verify",
            Some(json!({"token":token})),
            &cookies(&foreign),
        ),
        200,
    )
    .await;
    assert_eq!(body(&accepted)["session"]["token"], body(&owner)["token"]);
    authenticated(&auth, &cookies(&accepted), "retry-owner@example.test").await;
    assert_eq!(db.count("verifications").await?, 0);
    let replay = call(
        &auth,
        request("/one-time-token/verify", Some(json!({"token":token})), ""),
        400,
    )
    .await;
    assert_eq!(body(&replay)["message"], "Invalid token");
    assert_eq!(db.table("sessions").await?, before[2]);
    authenticated(&auth, &cookies(&foreign), "retry-foreign@example.test").await;
    B::close(connection).await
}

async fn ott_generator_real_endpoint_context<B: Backend>(db: Db) -> TestResult {
    struct Generator(Mutex<Vec<(OneTimeTokenSession, Option<AuthRequest>)>>);
    #[async_trait]
    impl GenerateOneTimeToken for Generator {
        async fn generate(
            &self,
            s: &OneTimeTokenSession,
            r: Option<&AuthRequest>,
        ) -> AuthResult<String> {
            self.0.lock().unwrap().push((s.clone(), r.cloned()));
            Ok(if r.is_some() {
                "physical-transfer"
            } else {
                "server-transfer"
            }
            .into())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let generator = Arc::new(Generator(Mutex::new(Vec::new())));
    let auth = fast_builder::<B>(&connection)
        .plugin(OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
            generator: Some(generator.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "context-owner@example.test").await;
    let foreign = signup(&auth, "context-foreign@example.test").await;
    let sessions = db.table("sessions").await?;
    let mut input =
        request("/one-time-token/generate", None, &cookies(&owner)).with_url(url::Url::parse(
            &format!("{ORIGIN}/api/auth/one-time-token/generate?physical=1"),
        )?);
    _ = input
        .headers
        .insert("x-ott-marker".into(), "callback-http".into());
    let physical = call(&auth, input, 200).await;
    assert_eq!(body(&physical)["token"], "physical-transfer");
    let server = auth
        .dispatch_endpoint(
            OneTimeTokenPlugin::generate_endpoint(),
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into()),
                ..Default::default()
            },
        )
        .await?
        .decode()?;
    assert_eq!(server.token, "server-transfer");
    let receipts = generator.0.lock().unwrap().clone();
    assert_eq!(receipts.len(), 2);
    for (s, _) in &receipts {
        assert_eq!(s.user.id, body(&owner)["user"]["id"].as_str().unwrap());
        assert_eq!(s.session.token, body(&owner)["token"].as_str().unwrap());
    }
    let physical = receipts[0].1.as_ref().unwrap();
    assert_eq!(physical.method, HttpMethod::Get);
    assert!(physical.path.ends_with("/one-time-token/generate"));
    assert_eq!(physical.headers["x-ott-marker"], "callback-http");
    assert_eq!(
        physical.url().unwrap().path(),
        "/api/auth/one-time-token/generate"
    );
    assert!(receipts[1].1.is_none());
    for token in ["physical-transfer", "server-transfer"] {
        assert_eq!(
            db.text(
                "SELECT value FROM verifications WHERE identifier=$1",
                &[&format!("one-time-token:{token}")]
            )
            .await?
            .as_deref(),
            Some(receipts[0].0.session.token.as_str())
        );
        let redeemed = call(
            &auth,
            request(
                "/one-time-token/verify",
                Some(json!({"token":token})),
                &cookies(&foreign),
            ),
            200,
        )
        .await;
        assert_eq!(body(&redeemed)["session"]["token"], body(&owner)["token"]);
    }
    assert_eq!(db.table("sessions").await?, sessions);
    assert_eq!(db.count("verifications").await?, 0);
    B::close(connection).await
}

async fn ott_verification_cancellation_result<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
    use std::sync::atomic::{AtomicBool, Ordering};
    #[derive(Clone)]
    struct Veto {
        cancel: Arc<AtomicBool>,
        seen: Arc<Mutex<Vec<(String, String)>>>,
    }
    #[async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for Veto {
        async fn before_create_verification(
            &self,
            v: &mut alibi::CreateVerification,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            if v.identifier.starts_with("one-time-token:") {
                self.seen
                    .lock()
                    .unwrap()
                    .push((v.identifier.clone(), v.value.clone()));
                if self.cancel.load(Ordering::SeqCst) {
                    return Ok(HookControl::Cancel);
                }
            }
            Ok(HookControl::Continue)
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let veto = Arc::new(Veto {
        cancel: Arc::new(AtomicBool::new(true)),
        seen: Arc::new(Mutex::new(Vec::new())),
    });
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::hook(
            B::store(Arc::new(config), &connection),
            veto.as_ref().clone(),
        ))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(OneTimeTokenPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "cancel-owner@example.test").await;
    let foreign = signup(&auth, "cancel-foreign@example.test").await;
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    let issued = call(
        &auth,
        request("/one-time-token/generate", None, &cookies(&owner)),
        200,
    )
    .await;
    let token = body(&issued)["token"].as_str().unwrap().to_owned();
    assert!(!token.is_empty());
    assert_eq!(
        *veto.seen.lock().unwrap(),
        [(
            format!("one-time-token:{token}"),
            body(&owner)["token"].as_str().unwrap().to_owned()
        )]
    );
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before
    );
    let denied = call(
        &auth,
        request(
            "/one-time-token/verify",
            Some(json!({"token":token})),
            &cookies(&foreign),
        ),
        400,
    )
    .await;
    assert_eq!(body(&denied)["message"], "Invalid token");
    assert!(!denied.headers.contains_key("set-cookie"));
    veto.cancel.store(false, Ordering::SeqCst);
    let live = call(
        &auth,
        request("/one-time-token/generate", None, &cookies(&owner)),
        200,
    )
    .await;
    let live = body(&live)["token"].as_str().unwrap().to_owned();
    assert_eq!(db.count("verifications").await?, 1);
    let accepted = call(
        &auth,
        request("/one-time-token/verify", Some(json!({"token":live})), ""),
        200,
    )
    .await;
    assert_eq!(body(&accepted)["session"]["token"], body(&owner)["token"]);
    _ = call(
        &auth,
        request("/one-time-token/verify", Some(json!({"token":live})), ""),
        400,
    )
    .await;
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before
    );
    B::close(connection).await
}
