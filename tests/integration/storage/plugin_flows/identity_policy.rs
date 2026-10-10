//! Application admission must run with the real request and before persistence.
use super::*;
mod verification_modes;
use alibi::hooks::RequestHookContext;
use alibi::user_validation::{
    UserInfoValidator, UserValidationAction, UserValidationData, UserValidationRejection,
};
use alibi::verification::{VerificationIdentifierHasher, VerificationIdentifierStrategy};
use alibi::{AuthError, AuthResult, CreateUser, CreateVerification, UpdateVerification};
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};

backend_tests!(
    identity_policy_admits_mutations_and_isolates_concurrent_requests,
    provider_admission_distinguishes_creation_returning_and_linking,
    verification_identifier_policy_preserves_logical_access_and_failure_atomicity,
    verification_trusted_create_cache_key,
    verification_expired_transformed_fallback,
    verification_cache_before_veto,
    verification_reservation_logical_primary,
    verification_find_cleanup_snapshot,
    verification_update_sibling_authority,
    verification_publication_transaction_rollback,
    verification_retirement_cache_delete_failure
);
postgres_tests!(
    identity_policy_admits_mutations_and_isolates_concurrent_requests,
    provider_admission_distinguishes_creation_returning_and_linking,
    verification_identifier_policy_preserves_logical_access_and_failure_atomicity
);

#[derive(Default)]
struct Admission(Mutex<Vec<(String, String)>>);
#[async_trait]
impl UserInfoValidator for Admission {
    async fn validate(
        &self,
        data: &mut UserValidationData,
        context: &RequestHookContext,
    ) -> AuthResult<Option<UserValidationRejection>> {
        assert_eq!(data.source.method, "email-password");
        assert_eq!(data.source.action, UserValidationAction::CreateUser);
        assert!(data.source.oauth.is_none());
        assert!(context.path.ends_with("/sign-up/email"));
        let body: Value = serde_json::from_slice(context.body.as_ref().unwrap()).unwrap();
        assert_eq!(data.user.email.as_deref(), body["email"].as_str());
        let policy = context.headers["x-admission"].clone();
        // Yield inside the callback so concurrently admitted requests interleave.
        tokio::task::yield_now().await;
        let actual = alibi::hooks::current_request_hook_context().unwrap();
        assert_eq!(actual.headers["x-admission"], policy);
        assert_eq!(actual.body, context.body);
        self.0
            .lock()
            .unwrap()
            .push((policy.clone(), data.user.email.clone().unwrap()));
        data.user.name = Some(format!("Admitted {policy}"));
        match policy.as_str() {
            "reject" => Ok(Some(UserValidationRejection {
                error: "TENANT_CLOSED".into(),
                error_description: Some("Tenant is closed".into()),
            })),
            "fallback" => Ok(Some(UserValidationRejection {
                error: "INVITATION_REQUIRED".into(),
                error_description: Some(String::new()),
            })),
            "exception" => Err(AuthError::internal("private application failure")),
            "empty" => Ok(Some(UserValidationRejection {
                error: String::new(),
                error_description: Some("not a rejection".into()),
            })),
            _ => Ok(None),
        }
    }
}

async fn identity_policy_admits_mutations_and_isolates_concurrent_requests<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(Admission::default());
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.user_validation = Some(policy.clone());
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let signup_request = |mode: &str| {
        let mut req = request(
            "/sign-up/email",
            Some(
                json!({"email":format!("{mode}@policy.test"),"password":PASSWORD,"name":"Untrusted name", "source":{"method":"admin","action":"sign-in"}}),
            ),
            "",
        );
        drop(req.headers.insert("x-admission".into(), mode.into()));
        req
    };
    for (mode, code, message) in [
        ("reject", "TENANT_CLOSED", "Tenant is closed"),
        ("fallback", "INVITATION_REQUIRED", "INVITATION_REQUIRED"),
        ("exception", "validation_failed", "User validation failed"),
    ] {
        let denied = call(&auth, signup_request(mode), 403).await;
        assert_eq!(body(&denied), json!({"code":code,"message":message}));
        assert!(cookies(&denied).is_empty());
        for table in ["users", "accounts", "sessions"] {
            assert_eq!(db.count(table).await?, 0);
        }
    }
    let (left, right) = tokio::join!(
        call(&auth, signup_request("left"), 200),
        call(&auth, signup_request("right"), 200)
    );
    for (response, mode) in [(&left, "left"), (&right, "right")] {
        assert_eq!(body(response)["user"]["name"], format!("Admitted {mode}"));
        authenticated(&auth, &cookies(response), &format!("{mode}@policy.test")).await;
        assert_eq!(
            db.text(
                "SELECT name FROM users WHERE email=$1",
                &[&format!("{mode}@policy.test")]
            )
            .await?
            .as_deref(),
            Some(format!("Admitted {mode}").as_str())
        );
    }
    let _ = call(&auth, signup_request("empty"), 200).await;
    assert_eq!(policy.0.lock().unwrap().len(), 6);
    let _ = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"left@policy.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(
        policy.0.lock().unwrap().len(),
        6,
        "returning password login must not re-admit existing identity"
    );
    // Direct store creation cannot borrow a completed request's task-local authority.
    assert!(
        auth.store()
            .create_user(CreateUser::new().with_email("outside@policy.test"))
            .await
            .is_err()
    );
    assert_eq!(db.count("users").await?, 3);
    assert!(alibi::hooks::current_request_hook_context().is_none());
    B::close(connection).await
}

struct IdentifierHasher(Arc<AtomicBool>);
#[async_trait]
impl VerificationIdentifierHasher for IdentifierHasher {
    async fn hash(&self, identifier: &str) -> AuthResult<String> {
        if self.0.load(Ordering::SeqCst) {
            return Err(AuthError::bad_request("Identifier policy rejected"));
        }
        Ok(format!("application:{identifier}"))
    }
}
async fn verification_identifier_policy_preserves_logical_access_and_failure_atomicity<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest as _, Sha256};
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let failed = Arc::new(AtomicBool::new(false));
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.verification.store_identifier.default = VerificationIdentifierStrategy::Hashed;
    config.verification.store_identifier.overrides = [
        ("12".into(), VerificationIdentifierStrategy::Plain),
        (
            "1".into(),
            VerificationIdentifierStrategy::Custom(Arc::new(IdentifierHasher(failed.clone()))),
        ),
        ("plain:".into(), VerificationIdentifierStrategy::Plain),
        (
            "custom:".into(),
            VerificationIdentifierStrategy::Custom(Arc::new(IdentifierHasher(failed.clone()))),
        ),
    ]
    .into_iter()
    .collect();
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .build()
        .await?;
    let values = auth.context().verifications();
    let proof = |identifier: &str| CreateVerification {
        identifier: identifier.into(),
        value: "first-proof".into(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
    };
    for (logical, physical) in [
        (
            "email@example.test",
            URL_SAFE_NO_PAD.encode(Sha256::digest(b"email@example.test")),
        ),
        ("plain:email", "plain:email".into()),
        ("custom:email", "application:custom:email".into()),
        ("123-prefix", "application:123-prefix".into()),
    ] {
        let _ = values.create(proof(logical)).await?;
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
                &[&physical]
            )
            .await?,
            1
        );
        assert!(values.find(logical).await?.is_some());
        let _ = values
            .update(
                logical,
                UpdateVerification {
                    value: Some("updated-proof".into()),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(
            db.text(
                "SELECT value FROM verifications WHERE identifier=$1",
                &[&physical]
            )
            .await?
            .as_deref(),
            Some("updated-proof")
        );
        assert!(values.consume(logical).await?.is_some());
        assert!(values.consume(logical).await?.is_none());
    }
    // Existing untransformed proofs remain readable and single-use after enabling hashing.
    let _ = auth.store().create_verification(proof("legacy-id")).await?;
    assert!(values.find("legacy-id").await?.is_some());
    assert!(values.consume("legacy-id").await?.is_some());
    assert_eq!(db.count("verifications").await?, 0);
    assert!(values.reserve(proof("custom:reservation")).await?);
    assert!(!values.reserve(proof("custom:reservation")).await?);
    let original = db.table("verifications").await?;
    failed.store(true, Ordering::SeqCst);
    assert!(values.create(proof("custom:reservation")).await.is_err());
    assert!(values.find("custom:reservation").await.is_err());
    assert!(values.consume("custom:reservation").await.is_err());
    assert!(values.delete("custom:reservation").await.is_err());
    assert!(
        values
            .update(
                "custom:reservation",
                UpdateVerification {
                    value: Some("overwrite".into()),
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    assert!(values.reserve(proof("custom:reservation")).await.is_err());
    assert_eq!(db.table("verifications").await?, original);
    failed.store(false, Ordering::SeqCst);
    values.delete("custom:reservation").await?;
    assert_eq!(db.count("verifications").await?, 0);
    verification_modes::exercise::<B>(&db).await?;
    B::close(connection).await
}

struct ProviderAdmission {
    expected: Mutex<(UserValidationAction, Option<String>, String, bool)>,
    seen: Mutex<Vec<UserValidationAction>>,
}
#[async_trait]
impl UserInfoValidator for ProviderAdmission {
    async fn validate(
        &self,
        data: &mut UserValidationData,
        context: &RequestHookContext,
    ) -> AuthResult<Option<UserValidationRejection>> {
        if data.source.method == "email-password" {
            return Ok(None);
        }
        let (action, owner, profile_name, deny) = self.expected.lock().unwrap().clone();
        assert_eq!(data.source.method, "oauth");
        assert_eq!(data.source.action, action);
        assert_eq!(data.user.id, owner);
        let source = data.source.oauth.as_ref().unwrap();
        assert_eq!(source.provider_id, "policy-provider");
        assert_eq!(source.profile.as_ref().unwrap()["name"], profile_name);
        assert_eq!(data.user.name.as_deref(), Some(profile_name.as_str()));
        assert!(context.path.ends_with("/callback/policy-provider"));
        self.seen.lock().unwrap().push(action);
        data.user.name = Some("Policy accepted creation".into());
        if action != UserValidationAction::CreateUser {
            data.user.id = Some("forged-copy-owner".into());
            data.user.email = Some("forged-copy@example.test".into());
        }
        Ok(deny.then(|| UserValidationRejection {
            error: "PROVIDER_POLICY_DENIED".into(),
            error_description: Some("Provider admission denied".into()),
        }))
    }
}

async fn provider_admission_distinguishes_creation_returning_and_linking<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::{OAuthPlugin, oauth::GenericOAuthConfig};
    use std::collections::HashMap;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let peer = Provider::start("application/json", "{}").await;
    let mut provider = GenericOAuthConfig::new("client", "secret");
    provider.authorization_url = Some(peer.url.join("authorize")?.into());
    provider.token_url = Some(peer.url.join("token")?.into());
    provider.user_info_url = Some(peer.url.join("profile")?.into());
    let provider = provider.resolve().await?.unwrap().provider;
    let policy = Arc::new(ProviderAdmission {
        expected: Mutex::new((
            UserValidationAction::CreateUser,
            None,
            "Initial profile".into(),
            false,
        )),
        seen: Mutex::new(Vec::new()),
    });
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.user_validation = Some(policy.clone());
    config.account.update_account_on_sign_in = true;
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(OAuthPlugin::new().add_provider("policy-provider", provider))
        .build()
        .await?;
    peer.respond_at(
        "/token",
        200,
        json!({"access_token":"first-access","refresh_token":"first-refresh","expires_in":3600}),
    );
    peer.respond_at("/profile",200,json!({"id":"remote-created","email":"provider-created@example.test","email_verified":true,"name":"Initial profile"}));
    let (authorization, cookie) = super::oauth_profiles::begin(&auth, "policy-provider").await;
    let created =
        super::oauth_profiles::complete(&auth, "policy-provider", &authorization, &cookie).await;
    authenticated(&auth, &cookies(&created), "provider-created@example.test").await;
    let created_id = db
        .text(
            "SELECT id FROM users WHERE email=$1",
            &["provider-created@example.test"],
        )
        .await?
        .unwrap();
    assert_eq!(
        db.text("SELECT name FROM users WHERE id=$1", &[&created_id])
            .await?
            .as_deref(),
        Some("Policy accepted creation")
    );
    let local = signup(&auth, "provider-local@example.test").await;
    let local_id = body(&local)["user"]["id"].as_str().unwrap().to_owned();
    drop(
        auth.store()
            .update_user(
                &local_id,
                alibi::UpdateUser {
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await?,
    );
    for (action, explicit, owner, remote_id, email) in [
        (
            UserValidationAction::SignIn,
            false,
            &created_id,
            "remote-created",
            "provider-created@example.test",
        ),
        (
            UserValidationAction::LinkAccount,
            false,
            &local_id,
            "remote-implicit",
            "provider-local@example.test",
        ),
        (
            UserValidationAction::LinkAccount,
            true,
            &local_id,
            "remote-explicit",
            "provider-local@example.test",
        ),
    ] {
        for deny in [true, false] {
            let profile_name = format!("Fresh {remote_id}");
            *policy.expected.lock().unwrap() =
                (action, Some(owner.clone()), profile_name.clone(), deny);
            let access = format!("rotated-{remote_id}");
            peer.respond_at(
                "/token",
                200,
                json!({"access_token":access,"refresh_token":"rotated-refresh","expires_in":3600}),
            );
            peer.respond_at(
                "/profile",
                200,
                json!({"id":remote_id,"email":email,"email_verified":true,"name":profile_name}),
            );
            let before = db.tables(&["users", "accounts", "sessions"]).await?;
            let (authorization, cookie) = if explicit {
                let start=call(&auth,request("/link-social",Some(json!({"provider":"policy-provider","callbackURL":format!("{ORIGIN}/done"),"errorCallbackURL":format!("{ORIGIN}/failed"),"disableRedirect":true})),&cookies(&local)),200).await;
                let url = url::Url::parse(body(&start)["url"].as_str().unwrap())?;
                (
                    url.query_pairs()
                        .into_owned()
                        .collect::<HashMap<String, String>>(),
                    cookies(&start),
                )
            } else {
                super::oauth_profiles::begin(&auth, "policy-provider").await
            };
            let completed =
                super::oauth_profiles::complete(&auth, "policy-provider", &authorization, &cookie)
                    .await;
            let target = url::Url::parse(completed.headers.get("location").unwrap())?;
            if deny {
                assert!(
                    target
                        .query_pairs()
                        .any(|(k, v)| k == "error" && v == "PROVIDER_POLICY_DENIED")
                );
                assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
                assert!(!cookies(&completed).contains("session_token="));
            } else {
                assert_eq!(target.path(), "/done");
                assert_eq!(db.text("SELECT user_id FROM accounts WHERE provider_id='policy-provider' AND account_id=$1",&[remote_id]).await?.as_deref(),Some(owner.as_str()));
                assert_eq!(db.text("SELECT access_token FROM accounts WHERE provider_id='policy-provider' AND account_id=$1",&[remote_id]).await?.as_deref(),Some(access.as_str()));
                assert_eq!(
                    db.table("users").await?,
                    before[0],
                    "signin/link validation mutates only a copy"
                );
                if explicit {
                    assert_eq!(db.table("sessions").await?, before[2]);
                } else {
                    authenticated(&auth, &cookies(&completed), email).await;
                }
            }
        }
    }
    assert_eq!(
        *policy.seen.lock().unwrap(),
        vec![
            UserValidationAction::CreateUser,
            UserValidationAction::SignIn,
            UserValidationAction::SignIn,
            UserValidationAction::LinkAccount,
            UserValidationAction::LinkAccount,
            UserValidationAction::LinkAccount,
            UserValidationAction::LinkAccount
        ]
    );
    B::close(connection).await
}

async fn verification_trusted_create_cache_key<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{
        CacheAdapter, DatabaseHookContext, DatabaseHooks, HookBackend, HookControl,
        MemoryCacheAdapter,
    };
    use alibi::verification::{VerificationCreation, VerificationSnapshot};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    struct Mutation {
        events: Arc<Mutex<Vec<Value>>>,
        cache: Arc<MemoryCacheAdapter>,
        key: String,
    }
    #[async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for Mutation {
        async fn before_create_verification_record(
            &self,
            v: &mut VerificationCreation,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            self.events
                .lock()
                .unwrap()
                .push(serde_json::to_value(v.snapshot().data())?);
            v.id = Some("trusted-storage-primary".into());
            v.identifier = "trusted-stored-identifier".into();
            v.value = "trusted-proof".into();
            v.created_at = chrono::DateTime::parse_from_rfc3339("2010-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc);
            v.updated_at = chrono::DateTime::parse_from_rfc3339("2011-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc);
            Ok(HookControl::Continue)
        }
        async fn after_create_verification_record(
            &self,
            v: &VerificationSnapshot,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<()> {
            let actual = serde_json::to_value(v.data())?;
            let published: Value =
                serde_json::from_str(&self.cache.get(&self.key).await?.unwrap())?;
            assert_eq!(published, actual);
            self.events.lock().unwrap().push(actual);
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let cache = Arc::new(MemoryCacheAdapter::new());
    let events = Arc::new(Mutex::new(Vec::new()));
    let key = format!(
        "verification:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(b"original-logical-identifier"))
    );
    let mut config = AuthConfig::new(SECRET);
    config.verification.secondary_storage = Some(cache.clone());
    config.verification.store_in_database = true;
    config.verification.store_identifier.default = VerificationIdentifierStrategy::Hashed;
    let auth = AuthBuilder::new(config.clone())
        .store(B::hook(
            B::store(Arc::new(config), &connection),
            Mutation {
                events: events.clone(),
                cache: cache.clone(),
                key: key.clone(),
            },
        ))
        .build()
        .await?;
    let created = auth
        .context()
        .verifications()
        .create(VerificationCreation {
            id: None,
            identifier: "original-logical-identifier".into(),
            value: "original-proof".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            created_at: chrono::DateTime::parse_from_rfc3339("2020-01-02T03:04:05Z")?
                .with_timezone(&chrono::Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339("2021-02-03T04:05:06Z")?
                .with_timezone(&chrono::Utc),
        })
        .await?
        .unwrap();
    let actual = serde_json::to_value(created.data())?;
    assert_eq!(actual["id"], "trusted-storage-primary");
    assert_eq!(actual["identifier"], "trusted-stored-identifier");
    assert_eq!(actual["value"], "trusted-proof");
    assert_eq!(actual["createdAt"], "2010-01-01T00:00:00.000Z");
    assert_eq!(actual["updatedAt"], "2011-01-01T00:00:00.000Z");
    assert_eq!(
        db.text(
            "SELECT identifier FROM verifications WHERE id=$1",
            &["trusted-storage-primary"]
        )
        .await?
        .as_deref(),
        Some("trusted-stored-identifier")
    );
    assert_eq!(
        db.text(
            "SELECT value FROM verifications WHERE id=$1",
            &["trusted-storage-primary"]
        )
        .await?
        .as_deref(),
        Some("trusted-proof")
    );
    assert_eq!(db.count("verifications").await?, 1);
    assert_eq!(
        serde_json::from_str::<Value>(&cache.get(&key).await?.unwrap())?,
        actual
    );
    assert!(
        cache
            .get("verification:trusted-stored-identifier")
            .await?
            .is_none()
    );
    let found = auth
        .context()
        .verifications()
        .find("original-logical-identifier")
        .await?
        .unwrap();
    assert_eq!(serde_json::to_value(found.data())?, actual);
    let receipts = events.lock().unwrap().clone();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0]["value"], "original-proof");
    assert_eq!(receipts[0]["createdAt"], "2020-01-02T03:04:05.000Z");
    assert_eq!(
        receipts[0]["identifier"],
        key.strip_prefix("verification:").unwrap()
    );
    assert_eq!(receipts[1], actual);
    B::close(connection).await
}

async fn verification_expired_transformed_fallback<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{CacheAdapter, MemoryCacheAdapter};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    for mode in [0, 1, 2] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let cache = Arc::new(MemoryCacheAdapter::new());
        let mut config = AuthConfig::new(SECRET);
        config.verification.store_identifier.default = VerificationIdentifierStrategy::Hashed;
        if mode > 0 {
            config.verification.secondary_storage = Some(cache.clone());
        }
        config.verification.store_in_database = mode == 1;
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .build()
            .await?;
        let transformed = URL_SAFE_NO_PAD.encode(Sha256::digest(b"fallback-owner"));
        let foreign = auth
            .store()
            .create_verification(CreateVerification {
                identifier: "foreign-proof".into(),
                value: "unchanged".into(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            })
            .await?;
        use alibi::AuthVerification;
        let foreign_id = foreign.id().into_owned();
        for (identifier, value, expired) in [
            (transformed.as_str(), "expired-transformed", true),
            ("fallback-owner", "live-plain", false),
        ] {
            let expiry = if expired {
                "2000-01-01T00:00:00Z"
            } else {
                "2100-01-01T00:00:00Z"
            };
            if mode == 2 {
                cache
                    .set(
                        &format!("verification:{identifier}"),
                        &json!({"identifier":identifier,"value":value,"expiresAt":expiry})
                            .to_string(),
                        chrono::Duration::minutes(5),
                    )
                    .await?;
            } else {
                _ = auth
                    .store()
                    .create_verification(CreateVerification {
                        identifier: identifier.into(),
                        value: value.into(),
                        expires_at: chrono::DateTime::parse_from_rfc3339(expiry)?
                            .with_timezone(&chrono::Utc),
                    })
                    .await?;
            }
        }
        assert!(
            auth.context()
                .verifications()
                .consume("fallback-owner")
                .await?
                .is_none()
        );
        assert_eq!(
            db.count("verifications").await?,
            if mode == 2 { 1 } else { 2 }
        );
        if mode == 2 {
            assert!(cache.get("verification:fallback-owner").await?.is_none());
            assert!(
                cache
                    .get(&format!("verification:{transformed}"))
                    .await?
                    .is_none()
            );
        } else {
            assert_eq!(
                db.text(
                    "SELECT value FROM verifications WHERE identifier=$1",
                    &["fallback-owner"]
                )
                .await?
                .as_deref(),
                Some("live-plain")
            );
        }
        let next = auth
            .context()
            .verifications()
            .consume("fallback-owner")
            .await?;
        if mode == 2 {
            assert!(next.is_none());
        } else {
            assert_eq!(next.unwrap().value()?, "live-plain");
        }
        assert_eq!(db.count("verifications").await?, 1);
        assert_eq!(
            db.text(
                "SELECT value FROM verifications WHERE id=$1",
                &[&foreign_id]
            )
            .await?
            .as_deref(),
            Some("unchanged")
        );
        B::close(connection).await?;
    }
    Ok(())
}

async fn verification_cache_before_veto<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{
        CacheAdapter, DatabaseHookContext, DatabaseHooks, HookBackend, HookControl,
        MemoryCacheAdapter,
    };
    struct Veto {
        cache: Arc<MemoryCacheAdapter>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }
    #[async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for Veto {
        async fn before_update_verification(
            &self,
            _: &str,
            _: &mut UpdateVerification,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            let cached: Value = serde_json::from_str(
                &self
                    .cache
                    .get("verification:application:owner")
                    .await?
                    .unwrap(),
            )?;
            assert_eq!(cached["value"], "cached-patch");
            self.events.lock().unwrap().push("update");
            Ok(HookControl::Cancel)
        }
        async fn before_delete_verification(
            &self,
            _: &S::Verification,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            assert!(
                self.cache
                    .get("verification:application:owner")
                    .await?
                    .is_none()
            );
            self.events.lock().unwrap().push("delete");
            Ok(HookControl::Cancel)
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let cache = Arc::new(MemoryCacheAdapter::new());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut config = AuthConfig::new(SECRET);
    config.verification.secondary_storage = Some(cache.clone());
    config.verification.store_in_database = true;
    config.verification.store_identifier.default = VerificationIdentifierStrategy::Custom(
        Arc::new(IdentifierHasher(Arc::new(AtomicBool::new(false)))),
    );
    let auth = AuthBuilder::new(config.clone())
        .store(B::hook(
            B::store(Arc::new(config), &connection),
            Veto {
                cache: cache.clone(),
                events: events.clone(),
            },
        ))
        .build()
        .await?;
    _ = auth
        .context()
        .verifications()
        .create(CreateVerification {
            identifier: "owner".into(),
            value: "original".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        })
        .await?;
    _ = auth
        .store()
        .create_verification(CreateVerification {
            identifier: "owner".into(),
            value: "legacy-plain".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        })
        .await?;
    let before = db.table("verifications").await?;
    assert!(
        auth.context()
            .verifications()
            .update(
                "owner",
                UpdateVerification {
                    value: Some("cached-patch".into()),
                    ..Default::default()
                }
            )
            .await?
            .is_none()
    );
    assert_eq!(db.table("verifications").await?, before);
    auth.context().verifications().delete("owner").await?;
    assert_eq!(db.table("verifications").await?, before);
    assert!(cache.get("verification:application:owner").await?.is_none());
    assert_eq!(*events.lock().unwrap(), ["update", "delete"]);
    B::close(connection).await
}

async fn verification_reservation_logical_primary<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{
        CacheAdapter, DatabaseHookContext, DatabaseHooks, HookBackend, HookControl,
        MemoryCacheAdapter,
    };
    use alibi::verification::{VerificationCreation, VerificationSnapshot};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    struct Calls(Arc<std::sync::atomic::AtomicUsize>);
    #[async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for Calls {
        async fn before_create_verification_record(
            &self,
            _: &mut VerificationCreation,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            _ = self.0.fetch_add(1, Ordering::SeqCst);
            Ok(HookControl::Continue)
        }
        async fn after_create_verification_record(
            &self,
            _: &VerificationSnapshot,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<()> {
            _ = self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let cache = Arc::new(MemoryCacheAdapter::new());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut config = AuthConfig::new(SECRET);
    config.verification.secondary_storage = Some(cache.clone());
    config.verification.store_in_database = true;
    config.verification.store_identifier.default = VerificationIdentifierStrategy::Hashed;
    let auth = AuthBuilder::new(config.clone())
        .store(B::hook(
            B::store(Arc::new(config.clone()), &connection),
            Calls(calls.clone()),
        ))
        .build()
        .await?;
    let expiry = chrono::Utc::now() + chrono::Duration::minutes(5);
    let candidate = || CreateVerification {
        identifier: "logical-reservation".into(),
        value: "reservation-proof".into(),
        expires_at: expiry,
    };
    assert!(auth.context().verifications().reserve(candidate()).await?);
    config.verification.store_identifier.default = VerificationIdentifierStrategy::Plain;
    let alternate = AuthBuilder::new(config.clone())
        .store(B::hook(
            B::store(Arc::new(config.clone()), &connection),
            Calls(calls.clone()),
        ))
        .build()
        .await?;
    assert!(
        !alternate
            .context()
            .verifications()
            .reserve(candidate())
            .await?
    );
    let id = URL_SAFE_NO_PAD.encode(Sha256::digest(b"reserve:logical-reservation"));
    let identifier = URL_SAFE_NO_PAD.encode(Sha256::digest(b"logical-reservation"));
    assert_eq!(db.count("verifications").await?, 1);
    assert_eq!(
        db.text("SELECT identifier FROM verifications WHERE id=$1", &[&id])
            .await?,
        Some(identifier.clone())
    );
    let key = format!("verification:{identifier}");
    let raw = cache.get(&key).await?.unwrap();
    let actual: Value = serde_json::from_str(&raw)?;
    assert_eq!(
        actual,
        json!({"id":id,"identifier":identifier,"value":"reservation-proof","expiresAt":expiry.to_rfc3339_opts(chrono::SecondsFormat::Millis,true)})
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let before = db.table("verifications").await?;
    config.verification.store_in_database = false;
    let cache_only = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .build()
        .await?;
    assert!(
        cache_only
            .context()
            .verifications()
            .reserve(candidate())
            .await
            .is_err()
    );
    assert_eq!(db.table("verifications").await?, before);
    assert_eq!(cache.get(&key).await?.unwrap(), raw);
    B::close(connection).await
}

async fn verification_find_cleanup_snapshot<B: Backend>(db: Db) -> TestResult {
    use alibi::AuthVerification;
    use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
    use alibi::verification::VerificationCreation;
    struct Events(Arc<Mutex<Vec<(bool, String)>>>);
    #[async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for Events {
        async fn before_delete_verification(
            &self,
            row: &S::Verification,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            self.0.lock().unwrap().push((false, row.id().into_owned()));
            Ok(HookControl::Continue)
        }
        async fn after_delete_verification(
            &self,
            row: &S::Verification,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<()> {
            self.0.lock().unwrap().push((true, row.id().into_owned()));
            Ok(())
        }
    }
    for mode in [0, 1, 2] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut config = AuthConfig::new(SECRET);
        config.verification.disable_cleanup = mode == 1;
        if mode == 2 {
            config.advanced.database.default_find_many_limit = 2;
        }
        let auth = AuthBuilder::new(config.clone())
            .store(B::hook(
                B::store(Arc::new(config), &connection),
                Events(events.clone()),
            ))
            .build()
            .await?;
        for index in 0..4 {
            _ = auth
                .context()
                .verifications()
                .create(VerificationCreation {
                    id: Some(format!("expired-{index}")),
                    identifier: if index < 2 {
                        "cleanup-owner".into()
                    } else {
                        format!("expired-other-{index}")
                    },
                    value: format!("proof-{index}"),
                    expires_at: chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00Z")?
                        .with_timezone(&chrono::Utc),
                    created_at: chrono::DateTime::parse_from_rfc3339(&format!(
                        "2020-01-0{}T00:00:00Z",
                        index + 1
                    ))?
                    .with_timezone(&chrono::Utc),
                    updated_at: chrono::Utc::now(),
                })
                .await?;
        }
        _ = auth
            .store()
            .create_verification(CreateVerification {
                identifier: "live-other".into(),
                value: "untouched".into(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            })
            .await?;
        let before = db.table("verifications").await?;
        let selected = auth
            .context()
            .verifications()
            .find("cleanup-owner")
            .await?
            .unwrap();
        assert_eq!(selected.id(), Some("expired-1"));
        assert_eq!(selected.value()?, "proof-1");
        assert!(selected.is_expired());
        assert_eq!(
            db.count("verifications").await?,
            if mode == 1 { 5 } else { 1 }
        );
        if mode == 1 {
            assert_eq!(db.table("verifications").await?, before);
            assert!(events.lock().unwrap().is_empty());
        } else {
            let receipts = events.lock().unwrap().clone();
            let count = if mode == 2 { 2 } else { 4 };
            assert_eq!(receipts.iter().filter(|(after, _)| !after).count(), count);
            assert_eq!(receipts.iter().filter(|(after, _)| *after).count(), count);
        }
        assert_eq!(
            db.text(
                "SELECT value FROM verifications WHERE identifier=$1",
                &["live-other"]
            )
            .await?
            .as_deref(),
            Some("untouched")
        );
        B::close(connection).await?;
    }
    Ok(())
}

async fn verification_update_sibling_authority<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{
        CacheAdapter, DatabaseHookContext, DatabaseHooks, HookBackend, HookControl,
        MemoryCacheAdapter,
    };
    use alibi::verification::{VerificationCreation, VerificationSnapshot};
    struct Mutation(Arc<Mutex<Vec<Value>>>);
    #[async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for Mutation {
        async fn before_update_verification(
            &self,
            id: &str,
            patch: &mut UpdateVerification,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            self.0
                .lock()
                .unwrap()
                .push(json!({"before":id,"value":patch.value}));
            patch.value = Some("trusted-update".into());
            Ok(HookControl::Continue)
        }
        async fn after_update_verification_record(
            &self,
            row: Option<&VerificationSnapshot>,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<()> {
            let value = row
                .map(|v| serde_json::to_value(v.data()))
                .transpose()?
                .unwrap_or(Value::Null);
            self.0.lock().unwrap().push(json!({"after":value}));
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let cache = Arc::new(MemoryCacheAdapter::new());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut config = AuthConfig::new(SECRET);
    config.verification.secondary_storage = Some(cache.clone());
    config.verification.store_in_database = true;
    config.verification.store_identifier.default = VerificationIdentifierStrategy::Custom(
        Arc::new(IdentifierHasher(Arc::new(AtomicBool::new(false)))),
    );
    let auth = AuthBuilder::new(config.clone())
        .store(B::hook(
            B::store(Arc::new(config), &connection),
            Mutation(events.clone()),
        ))
        .build()
        .await?;
    let old =
        chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")?.with_timezone(&chrono::Utc);
    for index in 0..2 {
        _ = auth
            .context()
            .verifications()
            .create(VerificationCreation {
                id: Some(format!("sibling-{index}")),
                identifier: "owner".into(),
                value: format!("old-{index}"),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
                created_at: old,
                updated_at: old,
            })
            .await?;
    }
    _ = auth
        .store()
        .create_verification(CreateVerification {
            identifier: "owner".into(),
            value: "legacy-plain".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        })
        .await?;
    let before = db.table("verifications").await?;
    let changed = auth
        .context()
        .verifications()
        .update(
            "owner",
            UpdateVerification {
                value: Some("original-patch".into()),
                ..Default::default()
            },
        )
        .await?
        .unwrap();
    assert_eq!(changed.value()?, "trusted-update");
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM verifications WHERE identifier=$1 AND value=$2",
            &["application:owner", "trusted-update"]
        )
        .await?,
        2
    );
    for id in ["sibling-0", "sibling-1"] {
        let row = auth
            .store()
            .get_latest_verification_by_identifier("application:owner")
            .await?
            .unwrap();
        use alibi::AuthVerification;
        assert!(row.updated_at() > old);
        assert_eq!(
            db.text("SELECT value FROM verifications WHERE id=$1", &[id])
                .await?
                .as_deref(),
            Some("trusted-update")
        );
    }
    let before: Value = serde_json::from_str(&before)?;
    let after: Value = serde_json::from_str(&db.table("verifications").await?)?;
    assert_eq!(
        before
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["identifier"] == "owner"),
        after
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["identifier"] == "owner")
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            &cache.get("verification:application:owner").await?.unwrap()
        )?["value"],
        "original-patch"
    );
    let absent = auth
        .context()
        .verifications()
        .update(
            "absent",
            UpdateVerification {
                value: Some("absent-patch".into()),
                ..Default::default()
            },
        )
        .await?;
    assert!(absent.is_none());
    let receipts = events.lock().unwrap().clone();
    assert_eq!(receipts.len(), 4);
    assert_eq!(
        receipts[0],
        json!({"before":"application:owner","value":"original-patch"})
    );
    assert_eq!(receipts[1]["after"]["value"], "trusted-update");
    assert_eq!(receipts[3], json!({"after":null}));
    assert_eq!(db.count("verifications").await?, 3);
    assert!(
        cache
            .get("verification:application:absent")
            .await?
            .is_none()
    );
    B::close(connection).await
}

async fn verification_publication_transaction_rollback<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{
        CacheAdapter, DatabaseHookContext, DatabaseHooks, HookBackend, MemoryCacheAdapter,
    };
    use alibi::verification::VerificationSnapshot;
    struct After(Arc<std::sync::atomic::AtomicUsize>);
    #[async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for After {
        async fn after_create_verification_record(
            &self,
            _: &VerificationSnapshot,
            c: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<()> {
            assert!(c.tx.is_none());
            _ = self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    for rollback in [false, true] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let cache = Arc::new(MemoryCacheAdapter::new());
        let after = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let published = Arc::new(Mutex::new(None));
        let mut config = AuthConfig::new(SECRET);
        config.verification.secondary_storage = Some(cache.clone());
        config.verification.store_in_database = true;
        config.verification.store_identifier.default = VerificationIdentifierStrategy::Custom(
            Arc::new(IdentifierHasher(Arc::new(AtomicBool::new(false)))),
        );
        let auth = Arc::new(
            AuthBuilder::new(config.clone())
                .store(B::hook(
                    B::store(Arc::new(config), &connection),
                    After(after.clone()),
                ))
                .build()
                .await?,
        );
        let inner = auth.clone();
        let inner_cache = cache.clone();
        let inner_after = after.clone();
        let inner_published = published.clone();
        let result = auth
            .store()
            .transaction_boxed(Box::new(move |tx| {
                Box::pin(async move {
                    let actual = inner
                        .context()
                        .verifications()
                        .create_in_transaction(
                            tx,
                            CreateVerification {
                                identifier: "transaction-owner".into(),
                                value: "transaction-proof".into(),
                                expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
                            },
                        )
                        .await?
                        .unwrap();
                    let raw = inner_cache
                        .get("verification:application:transaction-owner")
                        .await?
                        .unwrap();
                    assert_eq!(
                        serde_json::from_str::<Value>(&raw)?,
                        serde_json::to_value(actual.data())?
                    );
                    assert_eq!(inner_after.load(Ordering::SeqCst), 0);
                    *inner_published.lock().unwrap() = Some(raw);
                    if rollback {
                        return Err(AuthError::internal("deliberate rollback after publication"));
                    }
                    Ok(Box::new(()) as Box<dyn std::any::Any + Send>)
                })
            }))
            .await;
        assert_eq!(result.is_err(), rollback);
        assert_eq!(db.count("verifications").await?, i64::from(!rollback));
        assert_eq!(after.load(Ordering::SeqCst), usize::from(!rollback));
        assert_eq!(
            cache
                .get("verification:application:transaction-owner")
                .await?,
            *published.lock().unwrap()
        );
        let replay = auth
            .context()
            .verifications()
            .consume("transaction-owner")
            .await?;
        assert_eq!(replay.is_some(), !rollback);
        assert_eq!(db.count("verifications").await?, 0);
        if rollback {
            assert!(
                cache
                    .get("verification:application:transaction-owner")
                    .await?
                    .is_some()
            );
        }
        B::close(connection).await?;
    }
    Ok(())
}

async fn verification_retirement_cache_delete_failure<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{
        CacheAdapter, DatabaseHookContext, DatabaseHooks, HookBackend, MemoryCacheAdapter,
    };
    struct Cache {
        inner: MemoryCacheAdapter,
        fail: AtomicBool,
        deleted: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl CacheAdapter for Cache {
        async fn get(&self, k: &str) -> AuthResult<Option<String>> {
            self.inner.get(k).await
        }
        async fn set(&self, k: &str, v: &str, t: chrono::Duration) -> AuthResult<()> {
            self.inner.set(k, v, t).await
        }
        async fn get_and_delete(&self, k: &str) -> AuthResult<Option<String>> {
            self.inner.get_and_delete(k).await
        }
        async fn delete(&self, k: &str) -> AuthResult<()> {
            self.deleted.lock().unwrap().push(k.into());
            if self.fail.load(Ordering::SeqCst) {
                return Err(AuthError::internal("application cache delete failed"));
            }
            self.inner.delete(k).await
        }
        async fn exists(&self, k: &str) -> AuthResult<bool> {
            self.inner.exists(k).await
        }
        async fn expire(&self, k: &str, t: chrono::Duration) -> AuthResult<()> {
            self.inner.expire(k, t).await
        }
        async fn clear(&self) -> AuthResult<()> {
            self.inner.clear().await
        }
    }
    struct After {
        raw: super::super::Raw,
        events: Arc<Mutex<Vec<&'static str>>>,
    }
    #[async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for After {
        async fn after_delete_verification(
            &self,
            _: &S::Verification,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<()> {
            let count = self
                .raw
                .count_where(
                    "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
                    &["application:retire-owner"],
                )
                .await
                .map_err(|e| AuthError::internal(e.to_string()))?;
            assert_eq!(count, 0);
            self.events.lock().unwrap().push("retired");
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let cache = Arc::new(Cache {
        inner: MemoryCacheAdapter::new(),
        fail: AtomicBool::new(false),
        deleted: Mutex::new(Vec::new()),
    });
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut config = AuthConfig::new(SECRET);
    config.verification.secondary_storage = Some(cache.clone());
    config.verification.store_in_database = true;
    config.verification.store_identifier.default = VerificationIdentifierStrategy::Custom(
        Arc::new(IdentifierHasher(Arc::new(AtomicBool::new(false)))),
    );
    let auth = AuthBuilder::new(config.clone())
        .store(B::hook(
            B::store(Arc::new(config), &connection),
            After {
                raw: db.raw.clone(),
                events: events.clone(),
            },
        ))
        .build()
        .await?;
    _ = auth
        .context()
        .verifications()
        .create(CreateVerification {
            identifier: "retire-owner".into(),
            value: "actual-proof".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        })
        .await?;
    let key = "verification:application:retire-owner";
    let raw = cache.get(key).await?.unwrap();
    cache
        .set(
            "verification:retire-owner",
            &raw,
            chrono::Duration::minutes(10),
        )
        .await?;
    _ = auth
        .store()
        .create_verification(CreateVerification {
            identifier: "foreign".into(),
            value: "untouched".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        })
        .await?;
    cache.fail.store(true, Ordering::SeqCst);
    assert!(
        auth.context()
            .verifications()
            .consume("retire-owner")
            .await
            .is_err()
    );
    assert_eq!(db.count("verifications").await?, 1);
    assert_eq!(*events.lock().unwrap(), ["retired"]);
    assert_eq!(cache.get(key).await?.as_deref(), Some(raw.as_str()));
    assert_eq!(
        cache.get("verification:retire-owner").await?.as_deref(),
        Some(raw.as_str())
    );
    let mut attempts = cache.deleted.lock().unwrap().clone();
    attempts.sort();
    assert_eq!(
        attempts,
        [
            "verification:application:retire-owner",
            "verification:retire-owner"
        ]
    );
    cache.fail.store(false, Ordering::SeqCst);
    assert!(
        auth.context()
            .verifications()
            .consume("retire-owner")
            .await?
            .is_none()
    );
    assert_eq!(cache.get(key).await?.as_deref(), Some(raw.as_str()));
    assert_eq!(cache.deleted.lock().unwrap().len(), 2);
    assert_eq!(
        db.text(
            "SELECT value FROM verifications WHERE identifier=$1",
            &["foreign"]
        )
        .await?
        .as_deref(),
        Some("untouched")
    );
    B::close(connection).await
}
