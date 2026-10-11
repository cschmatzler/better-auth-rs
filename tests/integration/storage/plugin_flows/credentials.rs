//! Identity mutations must preserve ownership and invalidate the intended proofs.
use super::passwordless::Mailbox;
use super::*;
use alibi::plugins::email_otp::{EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, EmailOtpType};

backend_tests!(
    username_signup_lookup_and_denials_share_normalized_identity,
    profile_update_publishes_accepted_fields_and_preserves_rejected_identity,
    password_change_verification_and_session_revocation_are_owner_scoped,
    email_otp_verification_reset_and_email_change_bind_owner_and_scope,
    password_length_limits_apply_to_every_new_password_endpoint,
    duplicate_canonical_credentials_keep_first_physical_row_authoritative,
    cookie_emission_failure_preserves_endpoint_commit_stage,
    username_unicode_identity_admission,
    username_readonly_registration_admission,
    application_id_policy_owns_signup_principals_and_verification,
    rate_storage_failures_preserve_signup_and_recovery_authority
);
postgres_tests!(
    username_signup_lookup_and_denials_share_normalized_identity,
    profile_update_publishes_accepted_fields_and_preserves_rejected_identity,
    password_change_verification_and_session_revocation_are_owner_scoped,
    email_otp_verification_reset_and_email_change_bind_owner_and_scope,
    password_length_limits_apply_to_every_new_password_endpoint
);

async fn username_signup_lookup_and_denials_share_normalized_identity<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new().enable_username(true))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let availability = request(
        "/is-username-available",
        Some(json!({"username":"Cool_User"})),
        "",
    );
    assert_eq!(
        body(&call(&auth, availability.clone(), 200).await)["available"],
        true
    );
    let owner = call(&auth, request("/sign-up/email", Some(json!({"email":"username@example.test","password":PASSWORD,"name":"Username User","username":"Cool_User","displayUsername":"Cool User"})), ""), 200).await;
    assert_eq!(body(&owner)["user"]["username"], "cool_user");
    assert_eq!(body(&owner)["user"]["displayUsername"], "Cool User");
    assert_eq!(
        db.text("SELECT username FROM users", &[]).await?.as_deref(),
        Some("cool_user")
    );
    assert_eq!(
        body(&call(&auth, availability, 200).await)["available"],
        false
    );
    let snapshot = db.tables(&["users", "accounts", "sessions"]).await?;
    for (username, password) in [("COOL_USER", "wrong-password"), ("no_such_user", PASSWORD)] {
        let denied = call(
            &auth,
            request(
                "/sign-in/username",
                Some(json!({"username":username,"password":password})),
                "",
            ),
            401,
        )
        .await;
        assert_eq!(body(&denied)["code"], "INVALID_USERNAME_OR_PASSWORD");
        assert!(cookies(&denied).is_empty());
        assert_eq!(
            db.tables(&["users", "accounts", "sessions"]).await?,
            snapshot
        );
    }
    let duplicate = call(&auth, request("/sign-up/email", Some(json!({"email":"different@example.test","password":PASSWORD,"name":"Different","username":"COOL_USER"})), ""), 400).await;
    assert_eq!(body(&duplicate)["code"], "USERNAME_IS_ALREADY_TAKEN");
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        snapshot
    );
    let login = call(
        &auth,
        request(
            "/sign-in/username",
            Some(json!({"username":"COOL_USER","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&login)["user"]["id"], body(&owner)["user"]["id"]);
    authenticated(&auth, &cookies(&login), "username@example.test").await;
    B::close(connection).await?;
    configured_username_policy::<B>(&db).await
}

async fn email_otp_verification_reset_and_email_change_bind_owner_and_scope<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mailbox = Arc::new(Mailbox::<EmailOtpDelivery>::default());
    let auth = builder::<B>(&connection)
        .plugin(EmailOtpPlugin::new(EmailOtpConfig {
            send_verification_otp: Some(mailbox.clone()),
            change_email_enabled: true,
            verify_current_email: true,
            revoke_sessions_on_password_reset: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "email-otp-owner@example.test").await;
    let foreign = signup(&auth, "email-otp-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let mut owner_cookie = cookies(&owner);
    let send_current = || {
        request(
            "/email-otp/send-verification-otp",
            Some(json!({"email":"email-otp-owner@example.test","type":"email-verification"})),
            "",
        )
    };
    let _ = call(&auth, send_current(), 200).await;
    let verification = mailbox.take();
    assert_eq!(verification.email, "email-otp-owner@example.test");
    assert_eq!(verification.otp_type, EmailOtpType::EmailVerification);
    let code_rows = db.table("verifications").await?;
    let check = call(&auth, request("/email-otp/check-verification-otp", Some(json!({"email":verification.email,"type":"email-verification","otp":verification.otp})), ""), 200).await;
    assert_eq!(body(&check)["success"], true);
    assert_eq!(
        db.table("verifications").await?,
        code_rows,
        "checking a proof must not consume it"
    );
    let _ = call(
        &auth,
        request(
            "/sign-in/email-otp",
            Some(json!({"email":verification.email,"otp":verification.otp})),
            "",
        ),
        400,
    )
    .await;
    assert_eq!(
        db.table("verifications").await?,
        code_rows,
        "verification scope cannot authenticate sign-in"
    );
    let verified = call(
        &auth,
        request(
            "/email-otp/verify-email",
            Some(json!({"email":verification.email,"otp":verification.otp})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&verified)["status"], true);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE id=$1 AND email_verified=true",
            &[&owner_id]
        )
        .await?,
        1
    );
    assert_eq!(db.count("verifications").await?, 0);
    let mut previous_password = PASSWORD.to_owned();
    for (route, replacement) in [
        ("/email-otp/request-password-reset", "first-reset-password"),
        ("/forget-password/email-otp", "second-reset-password"),
    ] {
        let _ = call(
            &auth,
            request(
                route,
                Some(json!({"email":"email-otp-owner@example.test"})),
                "",
            ),
            200,
        )
        .await;
        let delivery = mailbox.take();
        assert_eq!(delivery.otp_type, EmailOtpType::ForgetPassword);
        let reset = request(
            "/email-otp/reset-password",
            Some(json!({"email":delivery.email,"otp":delivery.otp,"password":replacement})),
            "",
        );
        assert_eq!(
            body(&call(&auth, reset.clone(), 200).await)["success"],
            true
        );
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM sessions WHERE user_id=$1",
                &[&owner_id]
            )
            .await?,
            0
        );
        let stored = db.tables(&["users", "accounts", "sessions"]).await?;
        let replay = call(&auth, reset, 400).await;
        assert_eq!(body(&replay)["code"], "INVALID_OTP");
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, stored);
        let _ = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"email-otp-owner@example.test","password":previous_password})),
                "",
            ),
            401,
        )
        .await;
        let logged = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"email-otp-owner@example.test","password":replacement})),
                "",
            ),
            200,
        )
        .await;
        owner_cookie = cookies(&logged);
        previous_password = replacement.into();
        authenticated(&auth, &cookies(&foreign), "email-otp-foreign@example.test").await;
    }
    let _ = call(
        &auth,
        request(
            "/email-otp/request-email-change",
            Some(json!({"newEmail":"changed@example.test"})),
            &owner_cookie,
        ),
        400,
    )
    .await;
    let _ = call(&auth, send_current(), 200).await;
    let current_proof = mailbox.take();
    let _ = call(
        &auth,
        request(
            "/email-otp/request-email-change",
            Some(json!({"newEmail":"changed@example.test","otp":current_proof.otp})),
            &owner_cookie,
        ),
        200,
    )
    .await;
    let new_proof = mailbox.take();
    assert_eq!(new_proof.email, "changed@example.test");
    assert_eq!(new_proof.otp_type, EmailOtpType::ChangeEmail);
    let identities = db.tables(&["users", "accounts", "sessions"]).await?;
    let change = json!({"newEmail":new_proof.email,"otp":new_proof.otp});
    let _ = call(
        &auth,
        request(
            "/email-otp/change-email",
            Some(change.clone()),
            &cookies(&foreign),
        ),
        400,
    )
    .await;
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        identities
    );
    let changed = call(
        &auth,
        request("/email-otp/change-email", Some(change), &owner_cookie),
        200,
    )
    .await;
    assert_eq!(body(&changed)["success"], true);
    assert_eq!(
        db.text("SELECT email FROM users WHERE id=$1", &[&owner_id])
            .await?
            .as_deref(),
        Some("changed@example.test")
    );
    authenticated(&auth, &cookies(&changed), "changed@example.test").await;
    authenticated(&auth, &cookies(&foreign), "email-otp-foreign@example.test").await;
    assert_eq!(db.count("verifications").await?, 0);
    B::close(connection).await
}

async fn profile_update_publishes_accepted_fields_and_preserves_rejected_identity<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::config::CookieCacheConfig;
    use alibi::utils::username::UsernameConfig;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for immutable in [false, true] {
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: true,
            ..Default::default()
        });
        drop(config.user.additional_fields.insert(
            "role".into(),
            alibi::field_policy::FieldConfig::new(json!({"type":"string"})).read_only(),
        ));
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .plugin(EmailPasswordPlugin::new().username_config(UsernameConfig {
                immutable_username: immutable,
                display_validator: Some(Arc::new(|value: String| async move {
                    Ok(value != "Forbidden Display")
                })),
                ..Default::default()
            }))
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?;
        let email = format!("profile-{immutable}@example.test");
        let username = format!("owner_{immutable}");
        let taken = format!("taken_{immutable}");
        let owner=call(&auth,request("/sign-up/email",Some(json!({"email":email,"password":PASSWORD,"name":"Original", "username":username})),""),200).await;
        let _=call(&auth,request("/sign-up/email",Some(json!({"email":format!("foreign-{immutable}@example.test"),"password":PASSWORD,"name":"Foreign", "username":taken})),""),200).await;
        let cookie = cookies(&owner);
        let original = db.tables(&["users", "accounts", "sessions"]).await?;
        for input in [
            json!({"email":"forged@example.test"}),
            json!({"username":taken}),
            json!({"username":"x"}),
            json!({"displayUsername":"Forbidden Display","name":"Must not save"}),
            json!({"role":"admin","name":"Must not save"}),
            json!({}),
            json!([]),
        ] {
            let _ = call(&auth, request("/update-user", Some(input), &cookie), 400).await;
            assert_eq!(
                db.tables(&["users", "accounts", "sessions"]).await?,
                original
            );
        }
        let _ = call(
            &auth,
            request(
                "/update-user",
                Some(json!({"name":"Unauthenticated overwrite"})),
                "",
            ),
            401,
        )
        .await;
        assert_eq!(
            db.tables(&["users", "accounts", "sessions"]).await?,
            original
        );
        if immutable {
            let denied = call(
                &auth,
                request(
                    "/update-user",
                    Some(json!({"username":"new_available_username"})),
                    &cookie,
                ),
                400,
            )
            .await;
            assert_eq!(body(&denied)["code"], "USERNAME_IS_IMMUTABLE");
            assert_eq!(
                db.tables(&["users", "accounts", "sessions"]).await?,
                original
            );
        }
        let response=call(&auth,request("/update-user",Some(json!({"name":"Updated Owner","image":"https://images.test/updated","username":username.to_uppercase(),"displayUsername":"Updated Display"})),&cookie),200).await;
        assert_eq!(
            db.text("SELECT name FROM users WHERE email=$1", &[&email])
                .await?
                .as_deref(),
            Some("Updated Owner")
        );
        let updated = cookies(&response);
        assert!(
            updated.contains("session_data="),
            "profile mutation must publish an updated cache cookie"
        );
        let session = call(&auth, request("/get-session", None, &updated), 200).await;
        assert_eq!(body(&session)["user"]["name"], "Updated Owner");
        assert_eq!(
            body(&session)["user"]["image"],
            "https://images.test/updated"
        );
        assert_eq!(body(&session)["user"]["displayUsername"], "Updated Display");
        assert_eq!(body(&session)["user"]["username"], username);
        assert_eq!(body(&session)["user"]["email"], email);
        let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
        auth.store().delete_user(&owner_id).await?;
        let physical = db.tables(&["users", "accounts", "sessions"]).await?;
        let snapshot_only = call(
            &auth,
            request(
                "/update-user",
                Some(json!({"name":"Cached-only name","image":"https://images.test/cached-only"})),
                &updated,
            ),
            200,
        )
        .await;
        assert_eq!(
            db.tables(&["users", "accounts", "sessions"]).await?,
            physical,
            "an authenticated cached snapshot must never recreate a deleted identity"
        );
        assert!(auth.store().get_user_by_id(&owner_id).await?.is_none());
        let cached = call(
            &auth,
            request("/get-session", None, &cookies(&snapshot_only)),
            200,
        )
        .await;
        assert_eq!(body(&cached)["user"]["id"], owner_id);
        assert_eq!(body(&cached)["user"]["name"], "Cached-only name");
        assert_eq!(
            body(&cached)["user"]["image"],
            "https://images.test/cached-only"
        );
    }
    B::close(connection).await
}

async fn password_change_verification_and_session_revocation_are_owner_scoped<B: Backend>(
    db: Db,
) -> TestResult {
    for revoke in [false, true] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = builder::<B>(&connection)
            .plugin(alibi::plugins::PasswordManagementPlugin::new())
            .build()
            .await?;
        let owner = signup(&auth, "password-owner@example.test").await;
        let foreign = signup(&auth, "password-foreign@example.test").await;
        let cookie = cookies(&owner);
        let peer = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"password-owner@example.test","password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        let snapshot = db.tables(&["users", "accounts", "sessions"]).await?;
        let _ = call(
            &auth,
            request("/verify-password", Some(json!({"password":PASSWORD})), ""),
            401,
        )
        .await;
        let _ = call(
            &auth,
            request(
                "/verify-password",
                Some(json!({"password":"wrong-password"})),
                &cookie,
            ),
            400,
        )
        .await;
        let valid = call(
            &auth,
            request(
                "/verify-password",
                Some(json!({"password":PASSWORD})),
                &cookie,
            ),
            200,
        )
        .await;
        assert_eq!(body(&valid)["status"], true);
        let _=call(&auth,request("/change-password",Some(json!({"currentPassword":"wrong-password","newPassword":"replacement-password123","revokeOtherSessions":revoke})),&cookie),400).await;
        assert_eq!(
            db.tables(&["users", "accounts", "sessions"]).await?,
            snapshot
        );
        let changed=call(&auth,request("/change-password",Some(json!({"currentPassword":PASSWORD,"newPassword":"replacement-password123","revokeOtherSessions":revoke})),&cookie),200).await;
        if revoke {
            authenticated(&auth, &cookies(&changed), "password-owner@example.test").await;
            for old in [&owner, &peer] {
                let read = call(&auth, request("/get-session", None, &cookies(old)), 200).await;
                assert_eq!(body(&read), Value::Null);
            }
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM sessions WHERE user_id=$1",
                    &[body(&owner)["user"]["id"].as_str().unwrap()]
                )
                .await?,
                1
            );
        } else {
            assert_eq!(body(&changed)["token"], Value::Null);
            assert!(cookies(&changed).is_empty());
            authenticated(&auth, &cookie, "password-owner@example.test").await;
            authenticated(&auth, &cookies(&peer), "password-owner@example.test").await;
            assert_eq!(db.table("sessions").await?, snapshot[2]);
        }
        authenticated(&auth, &cookies(&foreign), "password-foreign@example.test").await;
        let _ = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"password-owner@example.test","password":PASSWORD})),
                "",
            ),
            401,
        )
        .await;
        let login=call(&auth,request("/sign-in/email",Some(json!({"email":"password-owner@example.test","password":"replacement-password123"})),""),200).await;
        assert_eq!(body(&login)["user"]["id"], body(&owner)["user"]["id"]);
        authenticated(&auth, &cookies(&login), "password-owner@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn configured_username_policy<B: Backend>(parent: &Db) -> TestResult {
    use alibi::utils::username::{UsernameConfig, UsernameNormalization, UsernameValidationOrder};
    for post in [false, true] {
        let db = parent.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let order = if post {
            UsernameValidationOrder::PostNormalization
        } else {
            UsernameValidationOrder::PreNormalization
        };
        let policy = UsernameConfig {
            normalization: UsernameNormalization::Custom(Arc::new(|value: &str| {
                if value.contains("normalizer-error") {
                    return Err(alibi::AuthError::internal("private normalizer failure"));
                }
                Ok(value.trim_start_matches("raw-").to_ascii_lowercase())
            })),
            validator: Some(Arc::new(move |value: String| async move {
                if value.contains("validator-error") {
                    return Err(alibi::AuthError::internal("private validator failure"));
                }
                Ok(value == if post { "admitted" } else { "raw-ADMITTED" }
                    || value.contains("normalizer-error"))
            })),
            display_normalizer: Some(Arc::new(|value: &str| {
                if value.contains("display-error") {
                    return Err(alibi::AuthError::internal("private display failure"));
                }
                Ok(value.trim_start_matches("raw-").to_ascii_lowercase())
            })),
            display_validator: Some(Arc::new(move |value: String| async move {
                if value.contains("display-validator-error") {
                    return Err(alibi::AuthError::internal(
                        "private display validator failure",
                    ));
                }
                Ok(value == if post { "visible" } else { "raw-VISIBLE" }
                    || value.contains("display-error"))
            })),
            validation_order: Some(order),
            display_validation_order: Some(order),
            ..Default::default()
        };
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().username_config(policy))
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?;
        for (username, display, status) in [
            ("raw-denied", "raw-VISIBLE", 400),
            ("raw-ADMITTED", "raw-denied", 400),
            ("raw-validator-error", "raw-VISIBLE", 500),
            ("raw-ADMITTED", "raw-display-error", 500),
            ("raw-ADMITTED", "raw-display-validator-error", 500),
        ] {
            let _ = call(&auth, request("/sign-up/email", Some(json!({"email":"configured@example.test","password":PASSWORD,"name":"Configured", "username":username,"displayUsername":display})), ""), status).await;
            for table in ["users", "accounts", "sessions"] {
                assert_eq!(db.count(table).await?, 0);
            }
        }
        let created = call(&auth, request("/sign-up/email", Some(json!({"email":"configured@example.test","password":PASSWORD,"name":"Configured", "username":"raw-ADMITTED","displayUsername":"raw-VISIBLE"})), ""), 200).await;
        assert_eq!(body(&created)["user"]["username"], "admitted");
        assert_eq!(body(&created)["user"]["displayUsername"], "visible");
        assert_eq!(
            db.text("SELECT username FROM users", &[]).await?.as_deref(),
            Some("admitted")
        );
        assert_eq!(
            db.text("SELECT display_username FROM users", &[])
                .await?
                .as_deref(),
            Some("visible")
        );
        let available = call(
            &auth,
            request(
                "/is-username-available",
                Some(json!({"username":if post { "admitted" } else { "raw-ADMITTED" }})),
                "",
            ),
            200,
        )
        .await;
        assert_eq!(body(&available)["available"], false);
        // Sign-in's explicit PreNormalization setting validates the normalized
        // value; signup's setting validates the submitted value.
        let before_login = db.table("sessions").await?;
        let logged = call(&auth, request("/sign-in/username", Some(json!({"username":if post { "admitted" } else { "raw-ADMITTED" },"password":PASSWORD})), ""), if post {200} else {422}).await;
        if post {
            assert_eq!(body(&logged)["user"]["id"], body(&created)["user"]["id"]);
            authenticated(&auth, &cookies(&logged), "configured@example.test").await;
        } else {
            assert_eq!(body(&logged)["code"], "INVALID_USERNAME");
            assert_eq!(db.table("sessions").await?, before_login);
        }
        let snapshot = db.tables(&["users", "accounts", "sessions"]).await?;
        let _ = call(
            &auth,
            request(
                "/is-username-available",
                Some(json!({"username":"raw-normalizer-error"})),
                "",
            ),
            500,
        )
        .await;
        let _ = call(
            &auth,
            request(
                "/update-user",
                Some(json!({"displayUsername":"raw-denied","name":"must not save"})),
                &cookies(&created),
            ),
            400,
        )
        .await;
        assert_eq!(
            db.tables(&["users", "accounts", "sessions"]).await?,
            snapshot
        );
        B::close(connection).await?;
    }
    Ok(())
}

// The email/password plugin's limits, in UTF-16 units, govern every endpoint
// that accepts a new password.
async fn password_length_limits_apply_to_every_new_password_endpoint<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(
            EmailPasswordPlugin::new()
                .password_min_length(10)
                .password_max_length(24),
        )
        .plugin(SessionManagementPlugin::new())
        .plugin(alibi::plugins::AdminPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "limits@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    drop(
        auth.store()
            .update_user(
                &owner_id,
                alibi::UpdateUser {
                    role: Some("admin".into()),
                    ..Default::default()
                },
            )
            .await?,
    );
    let cookie = cookies(&owner);
    let snapshot = db.tables(&["users", "accounts"]).await?;
    // 9 and 25 UTF-16 units; their byte and character counts lie inside the limits.
    let too_short = "😀😀😀😀a";
    let too_long = format!("{}a", "😀".repeat(12));
    for (password, code) in [
        (too_short, "PASSWORD_TOO_SHORT"),
        (too_long.as_str(), "PASSWORD_TOO_LONG"),
    ] {
        for (path, input, credentials) in [
            (
                "/sign-up/email",
                json!({"email":"limits-other@example.test","password":password,"name":"Other"}),
                "",
            ),
            (
                "/change-password",
                json!({"currentPassword":PASSWORD,"newPassword":password}),
                cookie.as_str(),
            ),
            (
                "/admin/set-user-password",
                json!({"userId":owner_id,"newPassword":password}),
                cookie.as_str(),
            ),
        ] {
            let rejected = call(&auth, request(path, Some(input), credentials), 400).await;
            assert_eq!(body(&rejected)["code"], code, "{path}");
            assert_eq!(db.tables(&["users", "accounts"]).await?, snapshot, "{path}");
        }
    }
    // Ten UTF-16 units in five characters meets the minimum.
    let minimum = "😀😀😀😀😀";
    let _ = call(
        &auth,
        request(
            "/admin/set-user-password",
            Some(json!({"userId":owner_id,"newPassword":minimum})),
            &cookie,
        ),
        200,
    )
    .await;
    let _ = call(
        &auth,
        request(
            "/change-password",
            Some(json!({"currentPassword":minimum,"newPassword":PASSWORD})),
            &cookie,
        ),
        200,
    )
    .await;
    drop(auth);
    B::close(connection).await
}

async fn duplicate_canonical_credentials_keep_first_physical_row_authoritative<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(alibi::plugins::AccountManagementPlugin::new())
        .plugin(alibi::plugins::UserManagementPlugin::new().delete_user_enabled(true))
        .build()
        .await?;
    let owner = signup(&auth, "duplicate-owner@example.test").await;
    let foreign = signup(&auth, "duplicate-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let original = db
        .text("SELECT id FROM accounts WHERE user_id=$1", &[&owner_id])
        .await?
        .unwrap();
    _ = db.execute("INSERT INTO accounts (id,user_id,account_id,provider_id,password,created_at,updated_at) SELECT 'later-credential',user_id,account_id,provider_id,password,created_at,updated_at FROM accounts WHERE id=$1", &[&original]).await?;
    db.set_timestamp(
        "accounts",
        "created_at",
        ("id", "later-credential"),
        chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00Z")?.with_timezone(&chrono::Utc),
    )
    .await?;
    _ = db
        .execute(
            "UPDATE accounts SET password=NULL WHERE id=$1",
            &[&original],
        )
        .await?;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let listed = body(
        &call(
            &auth,
            request("/list-accounts", None, &cookies(&owner)),
            200,
        )
        .await,
    );
    assert_eq!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].clone())
            .collect::<Vec<_>>(),
        vec![json!(original), json!("later-credential")]
    );
    let denied = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"duplicate-owner@example.test","password":PASSWORD})),
            "",
        ),
        401,
    )
    .await;
    assert_eq!(body(&denied)["code"], "INVALID_EMAIL_OR_PASSWORD");
    assert!(cookies(&denied).is_empty());
    let denied = call(
        &auth,
        request(
            "/delete-user",
            Some(json!({"password":PASSWORD})),
            &cookies(&owner),
        ),
        400,
    )
    .await;
    assert_eq!(body(&denied)["code"], "CREDENTIAL_ACCOUNT_NOT_FOUND");
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_account = db
        .text("SELECT id FROM accounts WHERE user_id=$1", &[&foreign_id])
        .await?
        .unwrap();
    let rejected = call(
        &auth,
        request(
            "/unlink-account",
            Some(json!({"accountId":foreign_account})),
            &cookies(&owner),
        ),
        400,
    )
    .await;
    assert_eq!(body(&rejected)["code"], "ACCOUNT_NOT_FOUND");
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    assert_eq!(
        body(
            &call(
                &auth,
                request(
                    "/unlink-account",
                    Some(json!({"accountId":original})),
                    &cookies(&owner)
                ),
                200
            )
            .await
        )["status"],
        true
    );
    let accepted = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"duplicate-owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&accepted)["user"]["id"], owner_id);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM accounts WHERE user_id=$1",
            &[&owner_id]
        )
        .await?,
        1
    );
    assert_eq!(
        db.text("SELECT id FROM accounts WHERE user_id=$1", &[&owner_id])
            .await?
            .as_deref(),
        Some("later-credential")
    );
    authenticated(&auth, &cookies(&foreign), "duplicate-foreign@example.test").await;
    B::close(connection).await
}

async fn cookie_emission_failure_preserves_endpoint_commit_stage<B: Backend>(db: Db) -> TestResult {
    use alibi::config::{CookieAttributes, CookieOverride};
    for mode in ["age", "expiry", "cache"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let normal = super::auth_probe::fast_builder::<B>(&connection)
            .build()
            .await?;
        let owner = signup(&normal, "emission-owner@example.test").await;
        let foreign = signup(&normal, "emission-foreign@example.test").await;
        let principals = db.tables(&["users", "accounts"]).await?;
        let sessions = db.count("sessions").await?;
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        match mode {
            "age" => config.session.expires_in = chrono::Duration::seconds(34_560_001),
            "expiry" => {
                _ = config.advanced.cookies.insert(
                    "session_token".into(),
                    CookieOverride {
                        name: None,
                        attributes: CookieAttributes {
                            expires: Some(chrono::Utc::now() + chrono::Duration::days(401)),
                            ..Default::default()
                        },
                    },
                );
            }
            _ => {
                config.session.cookie_cache = Some(alibi::CookieCacheConfig {
                    enabled: true,
                    max_age: f64::INFINITY,
                    ..Default::default()
                })
            }
        }
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?;
        for signin in [false, true] {
            let failed=call(&auth,request(if signin{"/sign-in/email"}else{"/sign-up/email"},Some(json!({"email":if signin{"emission-owner@example.test"}else{"emission-new@example.test"},"password":PASSWORD,"name":"Incoming"})),""),500).await;
            assert!(failed.body.is_empty());
            assert!(!failed.headers.contains_key("set-cookie"));
            assert_eq!(db.tables(&["users", "accounts"]).await?, principals);
            assert_eq!(
                db.count("sessions").await?,
                sessions + if signin { 1 } else { 0 }
            );
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM users WHERE email=$1",
                    &["emission-new@example.test"]
                )
                .await?,
                0
            );
        }
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM sessions WHERE user_id=$1",
                &[body(&owner)["user"]["id"].as_str().unwrap()]
            )
            .await?,
            2
        );
        authenticated(&normal, &cookies(&owner), "emission-owner@example.test").await;
        authenticated(&normal, &cookies(&foreign), "emission-foreign@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn username_unicode_identity_admission<B: Backend>(db: Db) -> TestResult {
    use alibi::utils::username::UsernameConfig;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let receipt = observed.clone();
    let policy = UsernameConfig {
        min_length: 2,
        max_length: 4,
        validator: Some(Arc::new(move |v: String| {
            receipt.lock().unwrap().push(v.clone());
            async move { Ok(v.chars().all(|c| c.is_alphabetic() || c == '😀')) }
        })),
        ..Default::default()
    };
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(
            super::auth_probe::fast_password()
                .enable_username(true)
                .username_config(policy),
        )
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let rejected=call(&auth,request("/sign-up/email",Some(json!({"email":"unicode-rejected@example.test","password":PASSWORD,"name":"Rejected","username":"😀😀😀"})),""),400).await;
    assert_eq!(body(&rejected)["code"], "USERNAME_TOO_LONG");
    assert!(!rejected.headers.contains_key("set-cookie"));
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let owner=call(&auth,request("/sign-up/email",Some(json!({"email":"unicode-owner@example.test","password":PASSWORD,"name":"Unicode owner","username":"😀😀"})),""),200).await;
    assert_eq!(body(&owner)["user"]["username"], "😀😀");
    assert!(observed.lock().unwrap().iter().any(|v| v == "😀😀"));
    authenticated(&auth, &cookies(&owner), "unicode-owner@example.test").await;
    let accounts = db.table("accounts").await?;
    _ = call(
        &auth,
        request(
            "/update-user",
            Some(json!({"username":"ΟΣ"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert_eq!(
        db.text(
            "SELECT username FROM users WHERE id=$1",
            &[body(&owner)["user"]["id"].as_str().unwrap()]
        )
        .await?
        .as_deref(),
        Some("ος")
    );
    let signed = call(
        &auth,
        request(
            "/sign-in/username",
            Some(json!({"username":"ΟΣ","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&signed)["user"]["id"], body(&owner)["user"]["id"]);
    assert_eq!(db.table("accounts").await?, accounts);
    authenticated(&auth, &cookies(&signed), "unicode-owner@example.test").await;
    B::close(connection).await
}

async fn username_readonly_registration_admission<B: Backend>(db: Db) -> TestResult {
    use alibi::utils::username::UsernameConfig;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(
            super::auth_probe::fast_password()
                .enable_username(true)
                .username_config(UsernameConfig {
                    input: false,
                    ..Default::default()
                }),
        )
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let foreign = signup(&auth, "readonly-foreign@example.test").await;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let rejected=call(&auth,request("/sign-up/email",Some(json!({"email":"readonly-owner@example.test","password":PASSWORD,"name":"Owner","username":"owner_name"})),""),400).await;
    assert_eq!(body(&rejected)["code"], "FIELD_NOT_ALLOWED");
    assert!(!rejected.headers.contains_key("set-cookie"));
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    authenticated(&auth, &cookies(&foreign), "readonly-foreign@example.test").await;
    let owner = signup(&auth, "readonly-owner@example.test").await;
    assert_eq!(db.count("users").await?, 2);
    assert_eq!(db.count("accounts").await?, 2);
    assert_eq!(db.count("sessions").await?, 2);
    assert_eq!(body(&owner)["user"]["username"], Value::Null);
    authenticated(&auth, &cookies(&owner), "readonly-owner@example.test").await;
    B::close(connection).await
}

async fn application_id_policy_owns_signup_principals_and_verification<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::config::DatabaseIdStrategy;
    use alibi::plugins::PasswordManagementPlugin;
    use alibi::plugins::password_management::SendResetPassword;
    use alibi::{AuthError, AuthResult};
    struct Inbox(Mutex<Option<String>>);
    #[async_trait::async_trait]
    impl SendResetPassword for Inbox {
        async fn send(&self, _: &Value, _: &str, token: &str) -> AuthResult<()> {
            *self.0.lock().unwrap() = Some(token.into());
            Ok(())
        }
    }
    for mode in ["uuid", "custom", "none", "throws"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let setup = super::auth_probe::fast_builder::<B>(&connection)
            .build()
            .await?;
        let foreign = signup(&setup, "foreign@example.test").await;
        let baseline = db
            .tables(&["users", "accounts", "sessions", "verifications"])
            .await?;
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = calls.clone();
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.advanced.database.generate_id = Some(if mode == "uuid" {
            DatabaseIdStrategy::Uuid
        } else {
            DatabaseIdStrategy::Custom(Arc::new(
                move |model: &str, size: Option<usize>| -> AuthResult<Option<String>> {
                    assert!(size.is_none());
                    let mut calls = log.lock().unwrap();
                    calls.push(model.into());
                    match mode {
                        "none" => Ok(None),
                        "throws" => Err(AuthError::internal("configured ID refusal")),
                        _ => Ok(Some(format!("{model}_application_{}", calls.len()))),
                    }
                },
            ))
        });
        let inbox = Arc::new(Inbox(Mutex::new(None)));
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(PasswordManagementPlugin::new().send_reset_password(inbox.clone()))
            .build()
            .await?;
        let response=call(&auth,request("/sign-up/email",Some(json!({"email":"new@example.test","password":PASSWORD,"name":"Generated Owner"})),""),if matches!(mode,"none"|"throws"){422}else{200}).await;
        if matches!(mode, "none" | "throws") {
            assert!(response.headers.get_all("set-cookie").next().is_none());
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "verifications"])
                    .await?,
                baseline
            );
            assert_eq!(*calls.lock().unwrap(), ["user"]);
        } else {
            let id = body(&response)["user"]["id"].as_str().unwrap().to_owned();
            let current = body(
                &call(
                    &auth,
                    request("/get-session", None, &cookies(&response)),
                    200,
                )
                .await,
            );
            assert_eq!(current["user"]["id"], id);
            assert_eq!(current["session"]["userId"], id);
            _ = call(
                &auth,
                request(
                    "/request-password-reset",
                    Some(json!({"email":"new@example.test","redirectTo":"/reset"})),
                    "",
                ),
                200,
            )
            .await;
            let token = inbox.0.lock().unwrap().clone().unwrap();
            let proof = auth
                .context()
                .verifications()
                .find(&format!("reset-password:{token}"))
                .await?
                .unwrap();
            assert_eq!(proof.value()?, id);
            let mut ids = Vec::new();
            for (table, key) in [
                ("users", "id"),
                ("accounts", "user_id"),
                ("sessions", "user_id"),
            ] {
                ids.push(
                    db.text(&format!("SELECT id FROM {table} WHERE {key}=$1"), &[&id])
                        .await?
                        .unwrap(),
                );
            }
            ids.push(proof.id().unwrap().to_owned());
            if mode == "uuid" {
                for id in ids {
                    let id = uuid::Uuid::parse_str(&id)?;
                    assert_eq!(id.get_version_num(), 4);
                }
            } else {
                assert_eq!(
                    *calls.lock().unwrap(),
                    ["user", "account", "session", "verification"]
                );
                assert_eq!(
                    ids,
                    [
                        "user_application_1",
                        "account_application_2",
                        "session_application_3",
                        "verification_application_4"
                    ]
                );
            }
            let after = db
                .tables(&["users", "accounts", "sessions", "verifications"])
                .await?;
            for (before, now) in baseline.iter().zip(after.iter()) {
                let before: Vec<Value> = serde_json::from_str(before)?;
                let now: Vec<Value> = serde_json::from_str(now)?;
                assert!(before.iter().all(|r| now.contains(r)));
            }
        }
        authenticated(&setup, &cookies(&foreign), "foreign@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn rate_storage_failures_preserve_signup_and_recovery_authority<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::middleware::{
        CacheRateLimitStorage, EndpointRateLimit, RateLimitConfig, RateLimitResolver, RateLimitRule,
    };
    use alibi::store::{CacheAdapter, MemoryCacheAdapter};
    use alibi::{AuthError, AuthResult};
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Cache {
        memory: MemoryCacheAdapter,
        missing: bool,
        failing: AtomicBool,
        calls: Mutex<Vec<&'static str>>,
    }
    #[async_trait::async_trait]
    impl CacheAdapter for Cache {
        async fn set(&self, k: &str, v: &str, t: chrono::Duration) -> AuthResult<()> {
            self.calls.lock().unwrap().push("set");
            self.memory.set(k, v, t).await
        }
        async fn get(&self, k: &str) -> AuthResult<Option<String>> {
            self.calls.lock().unwrap().push("get");
            self.memory.get(k).await
        }
        async fn delete(&self, k: &str) -> AuthResult<()> {
            self.calls.lock().unwrap().push("delete");
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
        async fn increment(&self, k: &str, t: std::time::Duration) -> AuthResult<f64> {
            self.calls.lock().unwrap().push("increment");
            if self.missing || self.failing.load(Ordering::SeqCst) {
                return Err(AuthError::internal(if self.missing {
                    "atomic cache increment is not supported by this adapter"
                } else {
                    "atomic counter outage"
                }));
            }
            self.memory.increment(k, t).await
        }
    }

    struct Missing(Arc<Cache>);
    #[async_trait::async_trait]
    impl CacheAdapter for Missing {
        async fn set(&self, k: &str, v: &str, t: chrono::Duration) -> AuthResult<()> {
            self.0.set(k, v, t).await
        }
        async fn get(&self, k: &str) -> AuthResult<Option<String>> {
            self.0.get(k).await
        }
        async fn delete(&self, k: &str) -> AuthResult<()> {
            self.0.delete(k).await
        }
        async fn exists(&self, k: &str) -> AuthResult<bool> {
            self.0.exists(k).await
        }
        async fn expire(&self, k: &str, t: chrono::Duration) -> AuthResult<()> {
            self.0.expire(k, t).await
        }
        async fn clear(&self) -> AuthResult<()> {
            self.0.clear().await
        }
    }
    #[derive(Debug)]
    struct Resolver;
    #[async_trait::async_trait]
    impl RateLimitResolver for Resolver {
        async fn resolve(
            &self,
            r: &AuthRequest,
            _: &EndpointRateLimit,
        ) -> AuthResult<Option<EndpointRateLimit>> {
            Ok(
                (r.headers.get("x-rate-bypass").map(String::as_str) != Some("yes")).then_some(
                    EndpointRateLimit {
                        window_seconds: 60.0,
                        max_requests: 2.0,
                    },
                ),
            )
        }
    }
    for missing in [false, true] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let setup = super::auth_probe::fast_builder::<B>(&connection)
            .build()
            .await?;
        let foreign = signup(&setup, "foreign@example.test").await;
        let before = db
            .tables(&["users", "accounts", "sessions", "verifications"])
            .await?;
        let cache = Arc::new(Cache {
            memory: MemoryCacheAdapter::new(),
            missing,
            failing: AtomicBool::new(true),
            calls: Mutex::new(Vec::new()),
        });
        let unavailable: Arc<dyn CacheAdapter> = if missing {
            Arc::new(Missing(cache.clone()))
        } else {
            cache.clone()
        };
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(
                RateLimitConfig::new()
                    .storage(Arc::new(CacheRateLimitStorage::new(unavailable)))
                    .rule("/sign-up/email", RateLimitRule::Dynamic(Arc::new(Resolver)))
                    .rule("/get-session", RateLimitRule::Disabled),
            )
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?;
        let failed=auth.handle_request(request("/sign-up/email",Some(json!({"email":"failed@example.test","password":PASSWORD,"name":"No Authority"})),"")).await;
        assert!(failed.is_err());
        assert_eq!(
            *cache.calls.lock().unwrap(),
            if missing {
                Vec::new()
            } else {
                vec!["increment"]
            }
        );
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
        let mut bypass = request(
            "/sign-up/email",
            Some(
                json!({"email":"bypass@example.test","password":PASSWORD,"name":"Bypassed Owner"}),
            ),
            "",
        );
        _ = bypass.headers.insert("x-rate-bypass".into(), "yes".into());
        let owner = call(&auth, bypass, 200).await;
        assert_eq!(
            *cache.calls.lock().unwrap(),
            if missing {
                Vec::new()
            } else {
                vec!["increment"]
            }
        );
        authenticated(&auth, &cookies(&owner), "bypass@example.test").await;
        cache.failing.store(false, Ordering::SeqCst);
        let ready_cache = if missing {
            Arc::new(Cache {
                memory: MemoryCacheAdapter::new(),
                missing: false,
                failing: AtomicBool::new(false),
                calls: Mutex::new(Vec::new()),
            })
        } else {
            cache.clone()
        };
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let ready = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(
                RateLimitConfig::new()
                    .storage(Arc::new(CacheRateLimitStorage::new(ready_cache.clone())))
                    .rule("/sign-up/email", RateLimitRule::Dynamic(Arc::new(Resolver)))
                    .rule("/get-session", RateLimitRule::Disabled),
            )
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?;
        let first = signup(&ready, "first@example.test").await;
        let second = signup(&ready, "second@example.test").await;
        let committed = db
            .tables(&["users", "accounts", "sessions", "verifications"])
            .await?;
        let denied = call(
            &ready,
            request(
                "/sign-up/email",
                Some(json!({"email":"blocked@example.test","password":PASSWORD,"name":"Blocked"})),
                "",
            ),
            429,
        )
        .await;
        assert!(denied.headers.get_all("set-cookie").next().is_none());
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            committed
        );
        let calls = ready_cache.calls.lock().unwrap().clone();
        assert!(calls.iter().all(|c| *c == "increment"));
        assert_eq!(calls.len(), if missing { 3 } else { 4 });
        authenticated(&ready, &cookies(&owner), "bypass@example.test").await;
        authenticated(&ready, &cookies(&first), "first@example.test").await;
        authenticated(&ready, &cookies(&second), "second@example.test").await;
        authenticated(&setup, &cookies(&foreign), "foreign@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}
