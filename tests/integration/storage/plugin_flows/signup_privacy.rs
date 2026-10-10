//! Duplicate signup may return a synthetic public user, but cannot expose the
//! stored identity, publish a session, or persist application customization.
use super::*;
use alibi::plugins::phone_number::{PhoneNumberConfig, PhoneNumberPlugin};
use alibi::plugins::{AdminPlugin, AnonymousPlugin, LastLoginMethodPlugin, TwoFactorPlugin};

backend_tests!(
    duplicate_signup_preserves_identity_and_filters_synthetic_output,
    synthetic_duplicate_identity_uses_application_id_policy
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
