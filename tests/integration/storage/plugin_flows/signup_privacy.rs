//! Duplicate signup may return a synthetic public user, but cannot expose the
//! stored identity, publish a session, or persist application customization.
use super::*;
use alibi::plugins::phone_number::{PhoneNumberConfig, PhoneNumberPlugin};
use alibi::plugins::{AdminPlugin, AnonymousPlugin, LastLoginMethodPlugin, TwoFactorPlugin};

backend_tests!(
    duplicate_signup_preserves_identity_and_filters_synthetic_output,
    duplicate_privacy_hashes_before_notification_without_replacing_credentials,
    existing_signup_notification_waits_or_remains_owned_in_background,
    synthetic_callback_failures_keep_public_error_boundary_and_principals,
    signup_privacy_never_synthesizes_creation_cancellation_or_ordinary_error,
    synthetic_duplicate_identity_uses_application_id_policy,
    synthetic_customization_retains_declared_application_fields
);
postgres_tests!(duplicate_signup_preserves_identity_and_filters_synthetic_output);

async fn duplicate_signup_preserves_identity_and_filters_synthetic_output<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let original_auth = builder::<B>(&connection).build().await?;
    let owner = signup(&original_auth, "duplicate@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let original = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    let input = json!({"email":"duplicate@example.test","password":"different-password-456","name":"Submitted Name","image":"https://images.test/submitted"});
    let _ = call(
        &original_auth,
        request("/sign-up/email", Some(input.clone()), ""),
        422,
    )
    .await;
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        original
    );
    for mode in [
        "verification",
        "no-auto-signin",
        "plugins",
        "custom",
        "custom-error",
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let observed = events.clone();
        let expected_owner = owner_id.clone();
        let mut plugin = EmailPasswordPlugin::new()
            .enable_username(matches!(mode, "plugins" | "custom"))
            .require_email_verification(mode != "no-auto-signin")
            .auto_sign_in(mode != "no-auto-signin")
            .on_existing_user_signup(Arc::new(move |user, request| {
                let observed = observed.clone();
                let expected_owner = expected_owner.clone();
                Box::pin(async move {
                    assert_eq!(user.id, expected_owner);
                    assert_eq!(user.name.as_deref(), Some("Native owner"));
                    assert_eq!(request.path, "/sign-up/email");
                    assert_eq!(request.body_as_json::<Value>()?["name"], "Submitted Name");
                    observed.lock().unwrap().push("existing");
                    Err(alibi::AuthError::bad_request(
                        "notification failure must not enumerate identity",
                    ))
                })
            }));
        if matches!(mode, "custom" | "custom-error") {
            let observed = events.clone();
            plugin=plugin.custom_synthetic_user(Arc::new(move |context| {
                observed.lock().unwrap().push("synthetic");
                assert_eq!(context.core_fields["name"],"Submitted Name");
                assert_eq!(context.core_fields["email"],"duplicate@example.test");
                assert!(context.additional_fields.is_empty());
                assert!(!context.id.is_empty());
                if mode=="custom-error" {return Err(alibi::AuthError::bad_request("synthetic customization rejected"));}
                Ok(json!({"id":"synthetic-application-id","name":"Synthetic display","email":"public@example.test","username":"synthetic_username","displayUsername":"Synthetic Username","role":"synthetic-role","privateApplicationSecret":"must-not-escape","accessToken":"must-not-escape"}).as_object().unwrap().clone())
            }));
        }
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let mut builder = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .plugin(plugin);
        if matches!(mode, "plugins" | "custom") {
            builder = builder
                .plugin(AdminPlugin::new())
                .plugin(AnonymousPlugin::new())
                .plugin(TwoFactorPlugin::new())
                .plugin(PhoneNumberPlugin::new(PhoneNumberConfig::default()))
                .plugin(LastLoginMethodPlugin::with_config(
                    alibi::plugins::last_login_method::LastLoginMethodConfig {
                        store_in_database: true,
                        ..Default::default()
                    },
                ));
        }
        let auth = builder.build().await?;
        let response = call(
            &auth,
            request("/sign-up/email", Some(input.clone()), ""),
            if mode == "custom-error" { 400 } else { 200 },
        )
        .await;
        assert!(!cookies(&response).contains("session_token="));
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            original,
            "{mode} must not mutate the physical identity"
        );
        let expected_events = if matches!(mode, "custom" | "custom-error") {
            vec!["existing", "synthetic"]
        } else {
            vec!["existing"]
        };
        assert_eq!(*events.lock().unwrap(), expected_events);
        if mode == "custom-error" {
            continue;
        }
        let response = body(&response);
        assert!(response["token"].is_null());
        let user = &response["user"];
        assert_ne!(user["id"], owner_id);
        assert_eq!(user["emailVerified"], false);
        for secret in ["password", "accessToken", "privateApplicationSecret"] {
            assert!(user.get(secret).is_none());
        }
        if mode == "custom" {
            assert_eq!(user["id"], "synthetic-application-id");
            assert_eq!(user["name"], "Synthetic display");
            assert_eq!(user["email"], "public@example.test");
            assert_eq!(user["role"], "synthetic-role");
            assert_eq!(user["username"], "synthetic_username");
        } else {
            assert_eq!(user["name"], "Submitted Name");
            assert_eq!(user["email"], "duplicate@example.test");
            assert_eq!(user["image"], "https://images.test/submitted");
        }
        if matches!(mode, "plugins" | "custom") {
            for field in [
                "username",
                "displayUsername",
                "twoFactorEnabled",
                "role",
                "banned",
                "banReason",
                "banExpires",
                "isAnonymous",
                "phoneNumber",
                "phoneNumberVerified",
                "lastLoginMethod",
            ] {
                assert!(user.get(field).is_some(), "{mode}: {field}");
            }
            assert_eq!(user["isAnonymous"], false);
            assert_eq!(user["twoFactorEnabled"], false);
            assert_eq!(user["banned"], false);
        } else {
            for field in [
                "username",
                "displayUsername",
                "role",
                "isAnonymous",
                "phoneNumber",
                "twoFactorEnabled",
                "lastLoginMethod",
            ] {
                assert!(user.get(field).is_none(), "{mode}: {field}");
            }
        }
    }
    authenticated(&original_auth, &cookies(&owner), "duplicate@example.test").await;
    B::close(connection).await
}

async fn duplicate_privacy_hashes_before_notification_without_replacing_credentials<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::{AuthResult, PasswordHasher};
    struct Crypto(Arc<Mutex<Vec<String>>>);
    #[async_trait::async_trait]
    impl PasswordHasher for Crypto {
        async fn hash(&self, p: &str) -> AuthResult<String> {
            self.0.lock().unwrap().push(format!("hash:{p}"));
            super::auth_probe::FastHasher.hash(p).await
        }
        async fn verify(&self, h: &str, p: &str) -> AuthResult<bool> {
            super::auth_probe::FastHasher.verify(h, p).await
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let setup = super::auth_probe::fast_builder::<B>(&connection)
        .build()
        .await?;
    let owner = signup(&setup, "crypto-owner@example.test").await;
    let foreign = signup(&setup, "crypto-foreign@example.test").await;
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for generic in [false, true] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let notification = events.clone();
        let customization = events.clone();
        let expected = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
        let plugin = EmailPasswordPlugin::new()
            .password_hasher(Arc::new(Crypto(events.clone())))
            .auto_sign_in(!generic)
            .on_existing_user_signup(Arc::new(move |user, r| {
                let events = notification.clone();
                let id = expected.clone();
                Box::pin(async move {
                    assert_eq!(user.id, id);
                    assert_eq!(user.name.as_deref(), Some("Native owner"));
                    assert_eq!(r.headers["x-privacy-marker"], "original-request");
                    assert_eq!(
                        r.body_as_json::<Value>()?["password"],
                        "different-password456"
                    );
                    events.lock().unwrap().push("existing".into());
                    Ok(())
                })
            }))
            .custom_synthetic_user(Arc::new(move |c| {
                customization.lock().unwrap().push("synthetic".into());
                let mut fields = c.core_fields;
                _ = fields.insert("id".into(), json!(c.id));
                Ok(fields)
            }));
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(plugin)
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?;
        let mut input = request(
            "/sign-up/email",
            Some(
                json!({"email":"CRYPTO-OWNER@EXAMPLE.TEST","password":"different-password456","name":"Synthetic incoming"}),
            ),
            "",
        );
        _ = input
            .headers
            .insert("x-privacy-marker".into(), "original-request".into());
        let response = call(&auth, input, if generic { 200 } else { 422 }).await;
        if generic {
            assert_eq!(
                *events.lock().unwrap(),
                ["hash:different-password456", "existing", "synthetic"]
            );
            assert_eq!(body(&response)["token"], Value::Null);
            let synthetic = body(&response)["user"]["id"].as_str().unwrap().to_owned();
            assert_ne!(synthetic, body(&owner)["user"]["id"].as_str().unwrap());
            assert_eq!(
                db.count_where("SELECT COUNT(*) FROM users WHERE id=$1", &[&synthetic])
                    .await?,
                0
            );
        } else {
            assert!(events.lock().unwrap().is_empty());
        }
        assert!(!response.headers.contains_key("set-cookie"));
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
    }
    _ = call(
        &setup,
        request(
            "/sign-in/email",
            Some(json!({"email":"crypto-owner@example.test","password":"different-password456"})),
            "",
        ),
        401,
    )
    .await;
    authenticated(&setup, &cookies(&owner), "crypto-owner@example.test").await;
    authenticated(&setup, &cookies(&foreign), "crypto-foreign@example.test").await;
    B::close(connection).await
}

async fn existing_signup_notification_waits_or_remains_owned_in_background<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::{AuthError, AuthResult, BackgroundTaskCompletion, BackgroundTaskHandler};
    struct Observer(u8);
    impl BackgroundTaskHandler for Observer {
        fn handle(&self, completion: BackgroundTaskCompletion) -> AuthResult<()> {
            drop(completion);
            match self.0 {
                1 => Err(AuthError::internal("observer unavailable")),
                2 => Err(AuthError::forbidden("observer veto")),
                _ => Ok(()),
            }
        }
    }
    for observer in [None, Some(0), Some(1), Some(2)] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let setup = super::auth_probe::fast_builder::<B>(&connection)
            .build()
            .await?;
        let owner = signup(&setup, "notification-owner@example.test").await;
        let foreign = signup(&setup, "notification-foreign@example.test").await;
        let before = db
            .tables(&["users", "accounts", "sessions", "verifications"])
            .await?;
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let completed = Arc::new(tokio::sync::Notify::new());
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (e, r, c, f) = (
            entered.clone(),
            release.clone(),
            completed.clone(),
            finished.clone(),
        );
        let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
        let plugin = super::auth_probe::fast_password()
            .auto_sign_in(false)
            .on_existing_user_signup(Arc::new(move |u, request| {
                let (e, r, c, f) = (e.clone(), r.clone(), c.clone(), f.clone());
                let owner_id = owner_id.clone();
                Box::pin(async move {
                    assert_eq!(u.id, owner_id);
                    assert_eq!(request.headers["x-notification-marker"], "owned-request");
                    e.notify_one();
                    r.notified().await;
                    assert_eq!(
                        alibi::hooks::current_request_hook_context()
                            .unwrap()
                            .headers["x-notification-marker"],
                        "owned-request"
                    );
                    f.store(true, std::sync::atomic::Ordering::SeqCst);
                    c.notify_one();
                    Err(AuthError::internal("notification failure remains private"))
                })
            }));
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        if let Some(mode) = observer {
            config.background_tasks = Some(Arc::new(Observer(mode)));
        }
        let auth = Arc::new(
            AuthBuilder::new(config.clone())
                .store(B::store(Arc::new(config), &connection))
                .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
                .plugin(plugin)
                .plugin(SessionManagementPlugin::new())
                .build()
                .await?,
        );
        let mut input = request(
            "/sign-up/email",
            Some(
                json!({"email":"notification-owner@example.test","password":PASSWORD,"name":"Incoming"}),
            ),
            "",
        );
        _ = input
            .headers
            .insert("x-notification-marker".into(), "owned-request".into());
        let inner = auth.clone();
        let mut pending = tokio::spawn(async move { call(&inner, input, 200).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified()).await?;
        assert!(!finished.load(std::sync::atomic::Ordering::SeqCst));
        if observer.is_none() {
            assert!(!pending.is_finished());
            release.notify_one();
            let response = pending.await?;
            assert_eq!(body(&response)["token"], Value::Null);
        } else {
            let response =
                tokio::time::timeout(std::time::Duration::from_secs(5), &mut pending).await??;
            assert_eq!(body(&response)["token"], Value::Null);
            assert!(!finished.load(std::sync::atomic::Ordering::SeqCst));
            release.notify_one();
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), completed.notified()).await?;
        assert!(finished.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
        authenticated(&auth, &cookies(&owner), "notification-owner@example.test").await;
        authenticated(
            &auth,
            &cookies(&foreign),
            "notification-foreign@example.test",
        )
        .await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn synthetic_callback_failures_keep_public_error_boundary_and_principals<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::{AuthError, AuthResult, PasswordHasher};
    struct Crypto(Arc<Mutex<Vec<&'static str>>>);
    #[async_trait::async_trait]
    impl PasswordHasher for Crypto {
        async fn hash(&self, p: &str) -> AuthResult<String> {
            self.0.lock().unwrap().push("hash");
            super::auth_probe::FastHasher.hash(p).await
        }
        async fn verify(&self, h: &str, p: &str) -> AuthResult<bool> {
            super::auth_probe::FastHasher.verify(h, p).await
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let setup = super::auth_probe::fast_builder::<B>(&connection)
        .build()
        .await?;
    let owner = signup(&setup, "synthetic-error-owner@example.test").await;
    let foreign = signup(&setup, "synthetic-error-foreign@example.test").await;
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for api in [false, true] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let notification = events.clone();
        let customization = events.clone();
        let plugin = EmailPasswordPlugin::new()
            .password_hasher(Arc::new(Crypto(events.clone())))
            .auto_sign_in(false)
            .on_existing_user_signup(Arc::new(move |_, _| {
                let events = notification.clone();
                Box::pin(async move {
                    events.lock().unwrap().push("existing");
                    Ok(())
                })
            }))
            .custom_synthetic_user(Arc::new(move |c| {
                assert_eq!(c.core_fields["name"], "Submitted");
                assert_eq!(c.core_fields["email"], "synthetic-error-owner@example.test");
                customization.lock().unwrap().push("synthetic");
                if api {
                    Err(AuthError::Api {
                        status: 403,
                        code: Some("SYNTHETIC_REJECTED".into()),
                        message: "Configured synthetic-user rejected".into(),
                    })
                } else {
                    Err(AuthError::internal("Actual synthetic-user callback failed"))
                }
            }));
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(plugin)
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?;
        let response=call(&auth,request("/sign-up/email",Some(json!({"email":"synthetic-error-owner@example.test","password":PASSWORD,"name":"Submitted"})),""),if api{403}else{500}).await;
        if api {
            assert_eq!(
                body(&response),
                json!({"code":"SYNTHETIC_REJECTED","message":"Configured synthetic-user rejected"})
            );
        } else {
            assert!(response.body.is_empty());
        }
        assert!(!response.headers.contains_key("set-cookie"));
        assert_eq!(*events.lock().unwrap(), ["hash", "existing", "synthetic"]);
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
    }
    authenticated(
        &setup,
        &cookies(&owner),
        "synthetic-error-owner@example.test",
    )
    .await;
    authenticated(
        &setup,
        &cookies(&foreign),
        "synthetic-error-foreign@example.test",
    )
    .await;
    B::close(connection).await
}

async fn signup_privacy_never_synthesizes_creation_cancellation_or_ordinary_error<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
    use alibi::{AuthError, AuthResult, PasswordHasher};
    struct Crypto(Arc<Mutex<Vec<&'static str>>>);
    #[async_trait::async_trait]
    impl PasswordHasher for Crypto {
        async fn hash(&self, p: &str) -> AuthResult<String> {
            self.0.lock().unwrap().push("hash");
            super::auth_probe::FastHasher.hash(p).await
        }
        async fn verify(&self, h: &str, p: &str) -> AuthResult<bool> {
            super::auth_probe::FastHasher.verify(h, p).await
        }
    }
    struct Hook {
        events: Arc<Mutex<Vec<&'static str>>>,
        cancel: bool,
    }
    #[async_trait::async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for Hook {
        async fn before_create_user(
            &self,
            _: &mut alibi::CreateUser,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            self.events.lock().unwrap().push("hook");
            if self.cancel {
                Ok(HookControl::Cancel)
            } else {
                Err(AuthError::CallbackFailure(Box::new(AuthError::internal(
                    "actual creation policy outage",
                ))))
            }
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let setup = super::auth_probe::fast_builder::<B>(&connection)
        .build()
        .await?;
    let owner = signup(&setup, "creation-existing@example.test").await;
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for generic in [false, true] {
        for cancel in [false, true] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let config = AuthConfig::new(SECRET).base_url(ORIGIN);
            let plugin = EmailPasswordPlugin::new()
                .password_hasher(Arc::new(Crypto(events.clone())))
                .auto_sign_in(!generic)
                .custom_synthetic_user(Arc::new(|_| {
                    panic!("new creation failures must not become synthetic duplicates")
                }));
            let auth = AuthBuilder::new(config.clone())
                .store(B::hook(
                    B::store(Arc::new(config), &connection),
                    Hook {
                        events: events.clone(),
                        cancel,
                    },
                ))
                .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
                .plugin(plugin)
                .plugin(SessionManagementPlugin::new())
                .build()
                .await?;
            let denied=call(&auth,request("/sign-up/email",Some(json!({"email":"creation-new@example.test","password":PASSWORD,"name":"New identity"})),""),if cancel{400}else{422}).await;
            assert_eq!(body(&denied)["code"], "FAILED_TO_CREATE_USER");
            assert!(!denied.headers.contains_key("set-cookie"));
            assert_eq!(*events.lock().unwrap(), ["hash", "hook"]);
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "verifications"])
                    .await?,
                before
            );
        }
    }
    authenticated(&setup, &cookies(&owner), "creation-existing@example.test").await;
    B::close(connection).await
}

async fn synthetic_duplicate_identity_uses_application_id_policy<B: Backend>(db: Db) -> TestResult {
    use alibi::config::DatabaseIdStrategy;
    use std::sync::atomic::{AtomicBool, Ordering};
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let setup = super::auth_probe::fast_builder::<B>(&connection)
        .build()
        .await?;
    let owner = signup(&setup, "synthetic-id-owner@example.test").await;
    let foreign = signup(&setup, "synthetic-id-foreign@example.test").await;
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for custom in [false, true] {
        let fail = Arc::new(AtomicBool::new(false));
        let events = Arc::new(Mutex::new(Vec::<Value>::new()));
        let observed = events.clone();
        let rejected = fail.clone();
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.advanced.database.generate_id = Some(DatabaseIdStrategy::Custom(Arc::new(
            move |model: &str, size: Option<usize>| {
                observed
                    .lock()
                    .unwrap()
                    .push(json!({"stage":"id-generation", "model":model,"size":size}));
                if rejected.load(Ordering::SeqCst) {
                    return Err(alibi::AuthError::internal("application ID failed"));
                }
                Ok(Some("synthetic_application_1".into()))
            },
        )));
        let mut plugin = super::auth_probe::fast_password().auto_sign_in(false);
        if custom {
            let observed = events.clone();
            plugin = plugin.custom_synthetic_user(Arc::new(move |input| {
                observed
                    .lock()
                    .unwrap()
                    .push(json!({"stage":"synthetic-user", "id":input.id}));
                assert_eq!(input.id, "synthetic_application_1");
                let mut fields = input.core_fields;
                _ = fields.insert("id".into(), json!(input.id));
                Ok(fields)
            }));
        }
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .plugin(plugin)
            .build()
            .await?;
        let input = json!({"email":"synthetic-id-owner@example.test","name":"Submitted name","password":PASSWORD});
        let response = call(
            &auth,
            request("/sign-up/email", Some(input.clone()), &cookies(&foreign)),
            200,
        )
        .await;
        assert_eq!(body(&response)["user"]["id"], "synthetic_application_1");
        assert_ne!(body(&response)["user"]["id"], body(&owner)["user"]["id"]);
        assert_eq!(body(&response)["user"]["name"], "Submitted name");
        assert!(body(&response)["token"].is_null());
        assert!(cookies(&response).is_empty());
        let mut expected = vec![json!({"stage":"id-generation","model":"user","size":null})];
        if custom {
            expected.push(json!({"stage":"synthetic-user","id":"synthetic_application_1"}));
        }
        assert_eq!(*events.lock().unwrap(), expected);
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
        events.lock().unwrap().clear();
        fail.store(true, Ordering::SeqCst);
        let rejected = call(
            &auth,
            request("/sign-up/email", Some(input), &cookies(&foreign)),
            500,
        )
        .await;
        assert!(cookies(&rejected).is_empty());
        assert_eq!(
            *events.lock().unwrap(),
            vec![json!({"stage":"id-generation","model":"user","size":null})]
        );
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
    }
    authenticated(&setup, &cookies(&owner), "synthetic-id-owner@example.test").await;
    authenticated(
        &setup,
        &cookies(&foreign),
        "synthetic-id-foreign@example.test",
    )
    .await;
    B::close(connection).await
}

async fn synthetic_customization_retains_declared_application_fields<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::field_policy::FieldConfig;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for column in [
        "synthetic_tier",
        "synthetic_secret",
        "synthetic_locale",
        "synthetic_note",
    ] {
        _ = db
            .execute(&format!("ALTER TABLE users ADD COLUMN {column} TEXT"), &[])
            .await?;
    }
    let setup = super::auth_probe::fast_builder::<B>(&connection)
        .build()
        .await?;
    let owner = signup(&setup, "synthetic-fields-owner@example.test").await;
    let foreign = signup(&setup, "synthetic-fields-foreign@example.test").await;
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for custom in [false, true] {
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        _ = config.user.additional_fields.insert(
            "syntheticTier".into(),
            FieldConfig::new(json!({"type":"string"}))
                .field_name("synthetic_tier")
                .validate(|value| {
                    value
                        .as_str()
                        .map(|v| {
                            alibi::utils::json::JsValue::String(format!(
                                "parsed:{}",
                                v.trim().to_lowercase()
                            ))
                        })
                        .ok_or_else(|| "tier must be a string".into())
                }),
        );
        _ = config.user.additional_fields.insert(
            "syntheticSecret".into(),
            FieldConfig::new(json!({"type":"string"}))
                .field_name("synthetic_secret")
                .hidden(),
        );
        _ = config.user.additional_fields.insert(
            "syntheticLocale".into(),
            FieldConfig::new(json!({"type":"string"}))
                .field_name("synthetic_locale")
                .default_value(json!("en")),
        );
        _ = config.user.additional_fields.insert(
            "syntheticNote".into(),
            FieldConfig::new(json!({"type":"string"})).field_name("synthetic_note"),
        );
        let seen = Arc::new(Mutex::new(Vec::<Value>::new()));
        let mut plugin = super::auth_probe::fast_password().auto_sign_in(false);
        if custom {
            let observed = seen.clone();
            plugin = plugin.custom_synthetic_user(Arc::new(move |input| {
                observed
                    .lock()
                    .unwrap()
                    .push(json!(input.additional_fields));
                assert!(!input.additional_fields.contains_key("name"));
                assert!(!input.additional_fields.contains_key("unknownApplication"));
                let mut fields = input.core_fields;
                _ = fields.insert("id".into(), json!(input.id));
                if let Some(tier) = input.additional_fields.get("syntheticTier") {
                    _ = fields.insert(
                        "syntheticTier".into(),
                        json!(format!("custom:{}", tier.as_str().unwrap())),
                    );
                }
                _ = fields.insert("syntheticSecret".into(), json!("custom-private"));
                _ = fields.insert("unknownApplication".into(), json!("must-not-escape"));
                Ok(fields)
            }));
        }
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .plugin(plugin)
            .build()
            .await?;
        for supplied in [true, false] {
            seen.lock().unwrap().clear();
            let mut input = json!({"name":"Submitted fields","email":"synthetic-fields-owner@example.test","password":PASSWORD,"unknownApplication":"unregistered"});
            if supplied {
                input["syntheticTier"] = json!(" GOLD ");
                input["syntheticSecret"] = json!("submitted-private");
            }
            let response = call(
                &auth,
                request("/sign-up/email", Some(input), &cookies(&foreign)),
                200,
            )
            .await;
            let returned = body(&response);
            assert!(returned["token"].is_null());
            assert!(cookies(&response).is_empty());
            assert_eq!(returned["user"]["name"], "Submitted fields");
            assert_ne!(returned["user"]["id"], body(&owner)["user"]["id"]);
            assert_eq!(
                returned["user"]["syntheticTier"],
                if supplied {
                    json!(if custom {
                        "custom:parsed:gold"
                    } else {
                        "parsed:gold"
                    })
                } else {
                    Value::Null
                }
            );
            assert_eq!(returned["user"]["syntheticLocale"], "en");
            assert!(
                returned["user"]
                    .as_object()
                    .unwrap()
                    .contains_key("syntheticNote")
            );
            assert!(returned["user"]["syntheticNote"].is_null());
            for secret in ["syntheticSecret", "unknownApplication", "password"] {
                assert!(returned["user"].get(secret).is_none());
            }
            let expected = if supplied {
                json!({"syntheticTier":"parsed:gold","syntheticSecret":"submitted-private","syntheticLocale":"en"})
            } else {
                json!({"syntheticLocale":"en"})
            };
            assert_eq!(
                *seen.lock().unwrap(),
                if custom {
                    vec![expected]
                } else {
                    Vec::<Value>::new()
                }
            );
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "verifications"])
                    .await?,
                before
            );
        }
    }
    authenticated(
        &setup,
        &cookies(&owner),
        "synthetic-fields-owner@example.test",
    )
    .await;
    authenticated(
        &setup,
        &cookies(&foreign),
        "synthetic-fields-foreign@example.test",
    )
    .await;
    B::close(connection).await
}
