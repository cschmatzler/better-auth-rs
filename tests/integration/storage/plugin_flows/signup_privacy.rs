//! Duplicate signup may return a synthetic public user, but cannot expose the
//! stored identity, publish a session, or persist application customization.
use super::*;
use alibi::plugins::phone_number::{PhoneNumberConfig, PhoneNumberPlugin};
use alibi::plugins::{AdminPlugin, AnonymousPlugin, LastLoginMethodPlugin, TwoFactorPlugin};

backend_tests!(
    duplicate_signup_preserves_identity_and_filters_synthetic_output,
    existing_signup_notification_waits_or_remains_owned_in_background
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
