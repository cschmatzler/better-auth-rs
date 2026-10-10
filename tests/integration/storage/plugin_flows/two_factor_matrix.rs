//! Two-factor input validation, factor state transitions, stored-secret damage
//! and forged trusted-device proofs.
use super::auth_probe::raw;
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::TwoFactorPlugin;
use alibi::plugins::two_factor::{SendTwoFactorOtp, TwoFactorBackupStorage, TwoFactorConfig};
use alibi::{AuthResult, UserView};
use async_trait::async_trait;

backend_tests!(
    two_factor_input_and_enrollment_matrix,
    two_factor_stored_backup_code_damage,
    two_factor_forged_trust_proofs,
    two_factor_otp_budget_and_session_choices,
    two_factor_numeric_options_and_damaged_factor,
    two_factor_otp_resends_are_consumed_once_across_real_requests,
    two_factor_reenrollment_retains_row_policy,
    two_factor_pending_unverified_totp_backup_recovery,
    two_factor_account_lock_pending_only_scope,
    two_factor_configured_account_lock_policy,
    two_factor_otp_account_budget_coupling,
    two_factor_pending_orphan_owner_proof_retention,
    two_factor_pending_newest_expired_snapshot,
    two_factor_backup_view_exact_truthy_projection,
    two_factor_backup_remainder_json_normalization,
    two_factor_pending_session_cancellation_retirement,
    two_factor_authenticated_totp_failed_rotation_retry,
    two_factor_expired_pending_factor_stage_policy,
    two_factor_configured_proof_cookie_lifetimes,
    two_factor_trust_syntax_before_cleanup,
    two_factor_trust_lookup_cleanup_policy,
    two_factor_trust_ignored_components,
    two_factor_factor_cookie_wire_aliases
);

#[derive(Default)]
struct Outbox(Mutex<Vec<String>>);
#[async_trait]
impl SendTwoFactorOtp for Outbox {
    async fn send(&self, _: &UserView, otp: &str) -> AuthResult<()> {
        self.0.lock().unwrap().push(otp.to_owned());
        Ok(())
    }
}

async fn enroll<S: AuthSchema>(auth: &Alibi<S>, cookie: &str) -> (totp_rs::Totp, Value, String) {
    let response = call(
        auth,
        request(
            "/two-factor/enable",
            Some(json!({"password":PASSWORD})),
            cookie,
        ),
        200,
    )
    .await;
    let session = cookies(&response);
    let body = body(&response);
    let totp = totp_rs::Totp::from_url(body["totpURI"].as_str().unwrap()).unwrap();
    (totp, body, session)
}

/// Create a user with an active authenticator and return its code generator.
async fn enabled_user<S: AuthSchema>(auth: &Alibi<S>, email: &str) -> totp_rs::Totp {
    let owner = cookies(&signup(auth, email).await);
    let (totp, _, _) = enroll(auth, &owner).await;
    let _ = call(
        auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":totp.generate_current().to_string()})),
            &owner,
        ),
        200,
    )
    .await;
    totp
}

async fn sign_in<S: AuthSchema>(
    auth: &Alibi<S>,
    email: &str,
    extra: Value,
    cookie: &str,
) -> AuthResponse {
    let mut input = json!({"email":email,"password":PASSWORD});
    input
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    call(auth, request("/sign-in/email", Some(input), cookie), 200).await
}

async fn two_factor_input_and_enrollment_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let auth = builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            send_otp: Some(outbox.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let owner = cookies(&signup(&auth, "matrix@example.test").await);
    for path in [
        "/two-factor/enable",
        "/two-factor/disable",
        "/two-factor/get-totp-uri",
        "/two-factor/generate-backup-codes",
        "/two-factor/verify-totp",
        "/two-factor/verify-otp",
        "/two-factor/verify-backup-code",
        "/two-factor/send-otp",
    ] {
        for text in [
            "[]",
            "null",
            r#"{"password":5,"code":5}"#,
            r#"{"password":"wrong-password","code":"1"}"#,
            "{",
        ] {
            trace.response(
                &format!("{path} {text}"),
                &Box::pin(auth.handle_request(raw(path, text, &owner))).await?,
            );
        }
        trace.response(
            &format!("{path} anonymous"),
            &Box::pin(auth.handle_request(raw(path, r#"{"password":"x","code":"1"}"#, ""))).await?,
        );
    }
    trace.response(
        "backup codes before enrollment",
        &Box::pin(auth.handle_request(raw(
            "/two-factor/generate-backup-codes",
            &json!({"password":PASSWORD}).to_string(),
            &owner,
        )))
        .await?,
    );
    trace.response(
        "otp enrollment",
        &Box::pin(auth.handle_request(raw(
            "/two-factor/enable",
            &json!({"password":PASSWORD,"method":"otp"}).to_string(),
            &owner,
        )))
        .await?,
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE two_factor_enabled = true",
            &[]
        )
        .await?,
        1
    );
    B::close(connection).await?;

    let db = db.fresh().await?;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig::default()))
        .build()
        .await?;
    let owner = cookies(&signup(&auth, "enroll@example.test").await);
    let (first, first_body, _) = enroll(&auth, &owner).await;
    let (second, second_body, _) = enroll(&auth, &owner).await;
    assert_ne!(first_body["totpURI"], second_body["totpURI"]);
    assert_ne!(first_body["backupCodes"], second_body["backupCodes"]);
    assert_eq!(db.count("two_factor").await?, 1);
    let stale = first.generate_current().to_string();
    let wrong = if stale == second.generate_current().to_string() {
        "x"
    } else {
        &stale
    };
    trace.response(
        "stale authenticator",
        &Box::pin(auth.handle_request(raw(
            "/two-factor/verify-totp",
            &json!({"code":wrong}).to_string(),
            &owner,
        )))
        .await?,
    );
    let activated = cookies(
        &call(
            &auth,
            request(
                "/two-factor/verify-totp",
                Some(json!({"code":second.generate_current().to_string()})),
                &owner,
            ),
            200,
        )
        .await,
    );
    trace.response(
        "enroll after activation",
        &Box::pin(auth.handle_request(raw(
            "/two-factor/enable",
            &json!({"password":PASSWORD}).to_string(),
            &activated,
        )))
        .await?,
    );
    trace.response(
        "pending verify without proof",
        &Box::pin(auth.handle_request(raw(
            "/two-factor/verify-backup-code",
            r#"{"code":"nope"}"#,
            "",
        )))
        .await?,
    );
    trace.assert("two-factor/input-enrollment-matrix");
    B::close(connection).await
}

async fn two_factor_stored_backup_code_damage<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            backup_storage: TwoFactorBackupStorage::Plain,
            skip_verification_on_enable: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let owner = cookies(&signup(&auth, "damage@example.test").await);
    let (_, enrolled, owner) = enroll(&auth, &owner).await;
    let user = db
        .text(
            "SELECT id FROM users WHERE email = 'damage@example.test'",
            &[],
        )
        .await?
        .unwrap();
    let stored = db
        .text("SELECT backup_codes FROM two_factor", &[])
        .await?
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&stored)?,
        enrolled["backupCodes"]
    );
    for (label, damaged) in [
        ("null", "null"),
        ("zero", "0"),
        ("empty string", r#""""#),
        ("object", r#"{"a":1}"#),
        ("text", "not json"),
        ("number", "7"),
        ("dated codes", r#"["2020-01-01T00:00:00Z","12345-67890"]"#),
    ] {
        _ = db
            .execute("UPDATE two_factor SET backup_codes = $1", &[damaged])
            .await?;
        let pending = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"damage@example.test","password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        trace.response(&format!("{label}: sign in"), &pending);
        let pending = cookies(&pending);
        for code in ["12345-67890", "2020-01-01T00:00:00Z"] {
            trace.response(
                &format!("{label}: verify {code}"),
                &Box::pin(auth.handle_request(raw(
                    "/two-factor/verify-backup-code",
                    &json!({"code":code}).to_string(),
                    &pending,
                )))
                .await?,
            );
        }
        let view = auth
            .dispatch_endpoint(
                TwoFactorPlugin::view_backup_codes_endpoint(&user),
                alibi::endpoint::EndpointOptions::default(),
            )
            .await;
        trace.value(
            &format!("{label}: view"),
            json!(match view {
                Ok(_) => "viewed".to_owned(),
                Err(error) => error.to_string(),
            }),
        );
    }
    trace.value("sessions", json!(db.count("sessions").await?));

    _ = db
        .execute(
            "UPDATE two_factor SET backup_codes = $1",
            &[r#"["11111-22222","33333-44444"]"#],
        )
        .await?;
    let pending = cookies(&sign_in(&auth, "damage@example.test", json!({}), "").await);
    let before = db.table("sessions").await?;
    let skipped = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":"11111-22222","disableSession":true})),
            &pending,
        ),
        200,
    )
    .await;
    assert!(body(&skipped).get("token").is_none_or(Value::is_null));
    assert_eq!(db.table("sessions").await?, before);
    let session = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":"33333-44444","disableSession":true})),
            &owner,
        ),
        200,
    )
    .await;
    assert!(body(&session)["token"].as_str().is_some());
    assert_eq!(db.table("sessions").await?, before);
    assert_eq!(
        db.text("SELECT backup_codes FROM two_factor", &[])
            .await?
            .as_deref(),
        Some("[]")
    );
    trace.assert("two-factor/stored-backup-code-damage");
    B::close(connection).await
}

async fn two_factor_forged_trust_proofs<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig::default()))
        .build()
        .await?;
    let mut trace = Trace::default();
    let email = "trust@example.test";
    let totp = enabled_user(&auth, email).await;
    let other = enabled_user(&auth, "other@example.test").await;
    let user = db
        .text("SELECT id FROM users WHERE email = $1", &[email])
        .await?
        .unwrap();
    let other_user = db
        .text(
            "SELECT id FROM users WHERE email = 'other@example.test'",
            &[],
        )
        .await?
        .unwrap();
    let trusted_cookie = async || -> TestResult<String> {
        let pending = cookies(&sign_in(&auth, email, json!({}), "").await);
        let done = call(
            &auth,
            request(
                "/two-factor/verify-totp",
                Some(json!({"code":totp.generate_current().to_string(),"trustDevice":true})),
                &pending,
            ),
            200,
        )
        .await;
        Ok(cookies(&done)
            .split("; ")
            .find(|cookie| cookie.starts_with("better-auth.trust_device="))
            .unwrap()
            .to_owned())
    };
    let name = "better-auth.trust_device";
    let forged = |payload: &str| {
        format!(
            "{name}={}",
            alibi::utils::cookie_utils::sign_cookie_value(payload, SECRET)
        )
    };
    for (label, cookie) in [
        ("unsigned", format!("{name}=plain")),
        ("empty token", forged("!trust-device-x")),
        ("empty identifier", forged("token!")),
        ("wrong token", forged("token!trust-device-x")),
    ] {
        trace.response(label, &sign_in(&auth, email, json!({}), &cookie).await);
    }
    let _ = other;

    let real = trusted_cookie().await?;
    _ = db
        .execute(
            "DELETE FROM verifications WHERE identifier LIKE 'trust-device-%'",
            &[],
        )
        .await?;
    trace.response(
        "missing record",
        &sign_in(&auth, email, json!({}), &real).await,
    );

    let real = trusted_cookie().await?;
    _ = db
        .execute(
            "UPDATE verifications SET value = $1 WHERE identifier LIKE 'trust-device-%'",
            &[other_user.as_str()],
        )
        .await?;
    trace.response(
        "foreign owner",
        &sign_in(&auth, email, json!({}), &real).await,
    );
    _ = db
        .execute(
            "DELETE FROM verifications WHERE identifier LIKE 'trust-device-%'",
            &[],
        )
        .await?;

    let real = trusted_cookie().await?;
    let identifier = db
        .text(
            "SELECT identifier FROM verifications WHERE identifier LIKE 'trust-device-%' AND value = $1",
            &[user.as_str()],
        )
        .await?
        .unwrap();
    db.set_timestamp(
        "verifications",
        "expires_at",
        ("identifier", &identifier),
        chrono::Utc::now() - chrono::Duration::seconds(5),
    )
    .await?;
    trace.response(
        "expired record",
        &sign_in(&auth, email, json!({}), &real).await,
    );
    trace.assert("two-factor/forged-trust-proofs");
    B::close(connection).await
}

async fn two_factor_otp_budget_and_session_choices<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let auth = builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            send_otp: Some(outbox.clone()),
            otp_allowed_attempts: 2.0,
            ..Default::default()
        }))
        .build()
        .await?;
    let email = "budget@example.test";
    let totp = enabled_user(&auth, email).await;
    let pending = cookies(&sign_in(&auth, email, json!({}), "").await);
    let _ = call(
        &auth,
        request("/two-factor/send-otp", Some(json!({})), &pending),
        200,
    )
    .await;
    let code = outbox.0.lock().unwrap().pop().unwrap();
    let wrong = if code == "000000" { "000001" } else { "000000" };
    for _ in 0..2 {
        let denied = call(
            &auth,
            request(
                "/two-factor/verify-otp",
                Some(json!({"code":wrong})),
                &pending,
            ),
            401,
        )
        .await;
        assert_eq!(body(&denied)["message"], "Invalid code");
    }
    let exhausted = call(
        &auth,
        request(
            "/two-factor/verify-otp",
            Some(json!({"code":code})),
            &pending,
        ),
        400,
    )
    .await;
    assert_eq!(
        body(&exhausted)["code"],
        "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"
    );
    assert_eq!(db.count("sessions").await?, 1);

    let remembered = sign_in(&auth, email, json!({"rememberMe":false}), "").await;
    let pending = cookies(&remembered);
    assert!(pending.contains("better-auth.dont_remember="));
    let done = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":totp.generate_current().to_string()})),
            &pending,
        ),
        200,
    )
    .await;
    assert!(cookies(&done).contains("better-auth.dont_remember="));
    let token = body(&done)["token"].as_str().unwrap().to_owned();
    let expires = db
        .text(
            "SELECT CAST(expires_at AS TEXT) FROM sessions WHERE token = $1",
            &[&token],
        )
        .await?
        .unwrap();
    assert!(!expires.is_empty());
    let plain = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"nobody@example.test","password":PASSWORD,"rememberMe":false})),
            "",
        ),
        401,
    )
    .await;
    assert!(cookies(&plain).is_empty());
    B::close(connection).await
}

async fn two_factor_numeric_options_and_damaged_factor<B: Backend>(db: Db) -> TestResult {
    let mut trace = crate::snapshot::Trace::default();
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for (label, period, digits, secret) in [
        ("defaults", 0.0, 0.0, "12345678901234567890"),
        ("nan period", f64::NAN, f64::NAN, "12345678901234567890"),
        ("negative period", -30.0, 4.0, "12345678901234567890"),
        (
            "infinite period",
            f64::INFINITY,
            8.0,
            "12345678901234567890",
        ),
        ("too many digits", 30.0, 9.0, "12345678901234567890"),
        ("empty secret", 30.0, 6.0, ""),
    ] {
        let auth = builder::<B>(&connection)
            .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                totp_period: period,
                totp_digits: digits,
                ..Default::default()
            }))
            .build()
            .await?;
        let result = auth
            .dispatch_endpoint(
                TwoFactorPlugin::generate_totp_endpoint(secret),
                alibi::endpoint::EndpointOptions::default(),
            )
            .await
            .and_then(|response| Ok(response.decode()?.code));
        trace.value(
            label,
            json!(result.map_or_else(
                |error| error.to_string(),
                |code| format!("{} digits", code.len())
            )),
        );
    }
    B::close(connection).await?;

    for (label, config) in [
        (
            "unbounded backup codes",
            TwoFactorConfig {
                backup_code_amount: f64::INFINITY,
                ..Default::default()
            },
        ),
        (
            "invalid otp digits",
            TwoFactorConfig {
                otp_digits: 0.0,
                send_otp: Some(Arc::new(Outbox::default())),
                ..Default::default()
            },
        ),
        (
            "default otp window and budget",
            TwoFactorConfig {
                otp_period_minutes: 0.0,
                otp_allowed_attempts: 0.0,
                send_otp: Some(Arc::new(Outbox::default())),
                ..Default::default()
            },
        ),
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = builder::<B>(&connection)
            .plugin(TwoFactorPlugin::with_config(config))
            .build()
            .await?;
        let owner = cookies(&signup(&auth, "numeric@example.test").await);
        let enable = Box::pin(auth.handle_request(raw(
            "/two-factor/enable",
            &json!({"password":PASSWORD}).to_string(),
            &owner,
        )))
        .await?;
        trace.response(&format!("{label}: enable"), &enable);
        if label != "unbounded backup codes" {
            _ = db
                .execute("UPDATE users SET two_factor_enabled = true", &[])
                .await?;
            _ = db
                .execute("UPDATE two_factor SET verified = false", &[])
                .await?;
            let pending = cookies(&sign_in(&auth, "numeric@example.test", json!({}), "").await);
            for path in [
                "/two-factor/send-otp",
                "/two-factor/verify-otp",
                "/two-factor/verify-totp",
            ] {
                trace.response(
                    &format!("{label}: {path}"),
                    &Box::pin(auth.handle_request(raw(path, r#"{"code":"000000"}"#, &pending)))
                        .await?,
                );
            }
            _ = db
                .execute(
                    "UPDATE two_factor SET verified = true, secret = 'damaged'",
                    &[],
                )
                .await?;
            trace.response(
                &format!("{label}: damaged secret"),
                &Box::pin(auth.handle_request(raw(
                    "/two-factor/verify-totp",
                    r#"{"code":"000000"}"#,
                    &pending,
                )))
                .await?,
            );
        }
        B::close(connection).await?;
    }
    trace.assert("two-factor/numeric-options-and-damage");
    Ok(())
}

async fn two_factor_otp_resends_are_consumed_once_across_real_requests<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            send_otp: Some(outbox.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let enabled = call(
        &auth,
        request(
            "/two-factor/enable",
            Some(json!({"password":PASSWORD,"method":"otp"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let cookie = cookies(&enabled);
    let current = body(&call(&auth, request("/get-session", None, &cookie), 200).await);
    let token = current["session"]["token"].as_str().unwrap().to_owned();
    assert_eq!(db.count("two_factor").await?, 0);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM sessions WHERE user_id=$1",
            &[&owner_id]
        )
        .await?,
        1
    );
    let stable = db
        .tables(&["users", "accounts", "sessions", "two_factor"])
        .await?;
    _ = call(
        &auth,
        request("/two-factor/send-otp", Some(json!({})), &cookie),
        200,
    )
    .await;
    let first: Vec<Value> = serde_json::from_str(&db.table("verifications").await?)?;
    assert_eq!(first.len(), 1);
    let identifier = first[0]["identifier"].as_str().unwrap().to_owned();
    _ = call(
        &auth,
        request("/two-factor/send-otp", Some(json!({})), &cookie),
        200,
    )
    .await;
    let generations: Vec<Value> = serde_json::from_str(&db.table("verifications").await?)?;
    assert_eq!(generations.len(), 2);
    assert!(generations.contains(&first[0]));
    assert!(
        generations
            .iter()
            .all(|row| row["identifier"] == identifier)
    );
    assert_ne!(generations[0]["id"], generations[1]["id"]);
    let delivered = outbox.0.lock().unwrap().clone();
    assert_eq!(delivered.len(), 2);
    let input = json!({"code":delivered[1]});
    let (left, right) = tokio::join!(
        Box::pin(auth.handle_request(request(
            "/two-factor/verify-otp",
            Some(input.clone()),
            &cookie
        ))),
        Box::pin(auth.handle_request(request("/two-factor/verify-otp", Some(input), &cookie)))
    );
    let mut responses = [left?, right?];
    responses.sort_by_key(|response| response.status);
    assert_eq!([responses[0].status, responses[1].status], [200, 400]);
    assert_eq!(body(&responses[0])["token"], token);
    assert_eq!(body(&responses[0])["user"]["id"], owner_id);
    assert_eq!(body(&responses[1])["code"], "OTP_HAS_EXPIRED");
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
            &[&identifier]
        )
        .await?,
        0
    );
    assert_eq!(db.count("verifications").await?, 0);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "two_factor"])
            .await?,
        stable
    );
    let replay = call(
        &auth,
        request(
            "/two-factor/verify-otp",
            Some(json!({"code":delivered[0]})),
            &cookie,
        ),
        400,
    )
    .await;
    assert_eq!(body(&replay)["code"], "OTP_HAS_EXPIRED");
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "two_factor"])
            .await?,
        stable
    );
    authenticated(&auth, &cookie, "owner@example.test").await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn two_factor_reenrollment_retains_row_policy<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(TwoFactorPlugin::new())
        .build()
        .await?;
    let signed = signup(&auth, "generation@example.test").await;
    let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
    let jar = cookies(&signed);
    let (_, first, _) = enroll(&auth, &jar).await;
    _ = db
        .execute(
            "UPDATE two_factor SET failed_verification_count = 0.5 WHERE user_id = $1",
            &[&id],
        )
        .await?;
    let original = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
    let principals = db.tables(&["users", "accounts", "sessions"]).await?;
    let (totp, second, _) = enroll(&auth, &jar).await;
    let next = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
    assert_eq!(next.id, original.id);
    assert_eq!(next.failed_verification_count, Some(0.5));
    assert_eq!(next.locked_until, original.locked_until);
    assert_eq!(next.verified, Some(false));
    assert_ne!(next.secret, original.secret);
    assert_ne!(first["backupCodes"], second["backupCodes"]);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        principals
    );
    let activated = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":totp.generate_current().to_string()})),
            &jar,
        ),
        200,
    )
    .await;
    let verified = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
    assert_eq!(verified.id, original.id);
    assert_eq!(verified.secret, next.secret);
    assert_eq!(verified.backup_codes, next.backup_codes);
    assert_eq!(verified.failed_verification_count, Some(0.5));
    assert_eq!(verified.verified, Some(true));
    let before = db.table("two_factor").await?;
    let denied = call(
        &auth,
        request(
            "/two-factor/enable",
            Some(json!({"password":PASSWORD})),
            &cookies(&activated),
        ),
        400,
    )
    .await;
    assert_eq!(body(&denied)["code"], "TOTP_ALREADY_ENABLED");
    assert_eq!(db.table("two_factor").await?, before);
    B::close(connection).await
}

async fn two_factor_pending_unverified_totp_backup_recovery<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            send_otp: Some(outbox),
            ..Default::default()
        }))
        .build()
        .await?;
    let signed = signup(&auth, "unverified@example.test").await;
    let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
    let (totp, enrollment, _) = enroll(&auth, &cookies(&signed)).await;
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":totp.generate_current().to_string()})),
            &cookies(&signed),
        ),
        200,
    )
    .await;
    _ = db.execute("UPDATE two_factor SET verified = false, failed_verification_count = 2.5 WHERE user_id = $1", &[&id]).await?;
    let pending = sign_in(&auth, "unverified@example.test", json!({}), "").await;
    assert_eq!(body(&pending)["twoFactorMethods"], json!(["otp"]));
    let before = db
        .tables(&[
            "two_factor",
            "verifications",
            "sessions",
            "users",
            "accounts",
        ])
        .await?;
    let denied = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":totp.generate_current().to_string()})),
            &cookies(&pending),
        ),
        400,
    )
    .await;
    assert_eq!(body(&denied)["code"], "TOTP_NOT_ENABLED");
    assert_eq!(
        db.tables(&[
            "two_factor",
            "verifications",
            "sessions",
            "users",
            "accounts"
        ])
        .await?,
        before
    );
    let completed = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":enrollment["backupCodes"][0]})),
            &cookies(&pending),
        ),
        200,
    )
    .await;
    assert_eq!(body(&completed)["user"]["id"], id);
    authenticated(&auth, &cookies(&completed), "unverified@example.test").await;
    let factor = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
    assert_eq!(factor.verified, Some(false));
    assert_eq!(factor.failed_verification_count, Some(0.0));
    let stable = db
        .tables(&["two_factor", "verifications", "sessions"])
        .await?;
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":enrollment["backupCodes"][0]})),
            &cookies(&pending),
        ),
        401,
    )
    .await;
    assert_eq!(
        db.tables(&["two_factor", "verifications", "sessions"])
            .await?,
        stable
    );
    B::close(connection).await
}

async fn two_factor_account_lock_pending_only_scope<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(TwoFactorPlugin::new())
        .build()
        .await?;
    let signed = signup(&auth, "locked@example.test").await;
    let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
    let (totp, enrollment, _) = enroll(&auth, &cookies(&signed)).await;
    let active = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":totp.generate_current().to_string()})),
            &cookies(&signed),
        ),
        200,
    )
    .await;
    let foreign = signup(&auth, "unlocked@example.test").await;
    let (other, _, _) = enroll(&auth, &cookies(&foreign)).await;
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":other.generate_current().to_string()})),
            &cookies(&foreign),
        ),
        200,
    )
    .await;
    let pending = sign_in(&auth, "locked@example.test", json!({}), "").await;
    _ = db
        .execute(
            "UPDATE two_factor SET failed_verification_count = 10 WHERE user_id = $1",
            &[&id],
        )
        .await?;
    let factor = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
    _ = auth
        .store()
        .set_two_factor_lock_if_count_at_least(
            &factor.id,
            10.0,
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .await?;
    let before = db
        .tables(&[
            "two_factor",
            "verifications",
            "sessions",
            "users",
            "accounts",
        ])
        .await?;
    for (path, code) in [
        (
            "/two-factor/verify-totp",
            json!(totp.generate_current().to_string()),
        ),
        (
            "/two-factor/verify-backup-code",
            enrollment["backupCodes"][0].clone(),
        ),
    ] {
        let denied = call(
            &auth,
            request(path, Some(json!({"code":code})), &cookies(&pending)),
            429,
        )
        .await;
        assert_eq!(body(&denied)["code"], "ACCOUNT_TEMPORARILY_LOCKED");
        assert_eq!(
            db.tables(&[
                "two_factor",
                "verifications",
                "sessions",
                "users",
                "accounts"
            ])
            .await?,
            before
        );
    }
    let confirmed = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":totp.generate_current().to_string()})),
            &cookies(&active),
        ),
        200,
    )
    .await;
    assert_eq!(
        body(&confirmed)["token"],
        body(&call(&auth, request("/get-session", None, &cookies(&active)), 200).await)["session"]
            ["token"]
    );
    assert_eq!(
        db.tables(&[
            "two_factor",
            "verifications",
            "sessions",
            "users",
            "accounts"
        ])
        .await?,
        before
    );
    let independent = sign_in(&auth, "unlocked@example.test", json!({}), "").await;
    let completed = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":other.generate_current().to_string()})),
            &cookies(&independent),
        ),
        200,
    )
    .await;
    authenticated(&auth, &cookies(&completed), "unlocked@example.test").await;
    assert_eq!(db.table("two_factor").await?, *before.first().unwrap());
    // The foreign completion cannot spend the locked owner's pending proof.
    let denied = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":totp.generate_current().to_string()})),
            &cookies(&pending),
        ),
        429,
    )
    .await;
    assert_eq!(body(&denied)["code"], "ACCOUNT_TEMPORARILY_LOCKED");
    authenticated(&auth, &cookies(&active), "locked@example.test").await;
    B::close(connection).await
}

async fn two_factor_configured_account_lock_policy<B: Backend>(db: Db) -> TestResult {
    use alibi::plugins::two_factor::AccountLockoutConfig;
    for mode in 0..3 {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                account_lockout: AccountLockoutConfig {
                    enabled: mode != 2,
                    max_failed_attempts: if mode == 1 { 0.0 } else { 2.5 },
                    duration_seconds: if mode == 1 { 0.0 } else { 600.25 },
                },
                ..Default::default()
            }))
            .build()
            .await?;
        let signed = signup(&auth, "policy@example.test").await;
        let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
        let (totp, enrollment, _) = enroll(&auth, &cookies(&signed)).await;
        let _ = call(
            &auth,
            request(
                "/two-factor/verify-totp",
                Some(json!({"code":totp.generate_current().to_string()})),
                &cookies(&signed),
            ),
            200,
        )
        .await;
        let pending = sign_in(&auth, "policy@example.test", json!({}), "").await;
        _ = db
            .execute(
                if mode == 1 {
                    "UPDATE two_factor SET failed_verification_count = NULL"
                } else {
                    "UPDATE two_factor SET failed_verification_count = 0.5"
                },
                &[],
            )
            .await?;
        let original = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
        let mut started = chrono::Utc::now();
        for _ in 0..if mode == 0 { 2 } else { 1 } {
            started = chrono::Utc::now();
            let _ = call(
                &auth,
                request(
                    "/two-factor/verify-totp",
                    Some(json!({"code":"invalid-code"})),
                    &cookies(&pending),
                ),
                401,
            )
            .await;
        }
        let finished = chrono::Utc::now();
        let failed = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
        assert_eq!(
            failed.failed_verification_count,
            match mode {
                0 => Some(2.5),
                1 => None,
                _ => Some(0.5),
            }
        );
        if mode == 0 {
            let until = failed.locked_until.unwrap().timestamp_millis();
            assert!(
                (started.timestamp_millis() + 600_250..=finished.timestamp_millis() + 600_250)
                    .contains(&until)
            );
            let before = db
                .tables(&["two_factor", "verifications", "sessions"])
                .await?;
            let _ = call(
                &auth,
                request(
                    "/two-factor/verify-backup-code",
                    Some(json!({"code":enrollment["backupCodes"][0]})),
                    &cookies(&pending),
                ),
                429,
            )
            .await;
            assert_eq!(
                db.tables(&["two_factor", "verifications", "sessions"])
                    .await?,
                before
            );
            _ = auth
                .store()
                .set_two_factor_lock_if_count_at_least(
                    &failed.id,
                    2.5,
                    chrono::Utc::now() - chrono::Duration::seconds(1),
                )
                .await?;
        } else {
            assert!(failed.locked_until.is_none());
        }
        let completed = call(
            &auth,
            request(
                "/two-factor/verify-totp",
                Some(json!({"code":totp.generate_current().to_string()})),
                &cookies(&pending),
            ),
            200,
        )
        .await;
        assert_eq!(body(&completed)["user"]["id"], id);
        let recovered = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
        assert_eq!(
            recovered.failed_verification_count,
            if mode == 2 { Some(0.5) } else { Some(0.0) }
        );
        assert!(recovered.locked_until.is_none());
        assert_eq!(
            (recovered.id, recovered.secret, recovered.backup_codes),
            (original.id, original.secret, original.backup_codes)
        );
        if mode == 1 {
            let next = sign_in(&auth, "policy@example.test", json!({}), "").await;
            let from = chrono::Utc::now().timestamp_millis();
            let _ = call(
                &auth,
                request(
                    "/two-factor/verify-totp",
                    Some(json!({"code":"invalid-code"})),
                    &cookies(&next),
                ),
                401,
            )
            .await;
            let until = auth
                .store()
                .get_two_factor_by_user_id(&id)
                .await?
                .unwrap()
                .locked_until
                .unwrap()
                .timestamp_millis();
            assert!((from..=chrono::Utc::now().timestamp_millis()).contains(&until));
            let _ = call(
                &auth,
                request(
                    "/two-factor/verify-totp",
                    Some(json!({"code":totp.generate_current().to_string()})),
                    &cookies(&next),
                ),
                200,
            )
            .await;
            let cleared = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
            assert_eq!(cleared.failed_verification_count, Some(0.0));
            assert!(cleared.locked_until.is_none());
        }
        B::close(connection).await?;
    }
    Ok(())
}

async fn two_factor_otp_account_budget_coupling<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            send_otp: Some(outbox.clone()),
            account_lockout: alibi::plugins::two_factor::AccountLockoutConfig {
                max_failed_attempts: 2.5,
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    let signed = signup(&auth, "coupled@example.test").await;
    let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
    let (totp, _, _) = enroll(&auth, &cookies(&signed)).await;
    let active = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":totp.generate_current().to_string()})),
            &cookies(&signed),
        ),
        200,
    )
    .await;
    _ = db
        .execute("UPDATE two_factor SET failed_verification_count=1.5", &[])
        .await?;
    let original = db.table("two_factor").await?;
    let _ = call(
        &auth,
        request("/two-factor/send-otp", Some(json!({})), &cookies(&active)),
        200,
    )
    .await;
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-otp",
            Some(json!({"code":"invalid-code"})),
            &cookies(&active),
        ),
        401,
    )
    .await;
    assert_eq!(db.table("two_factor").await?, original);
    let pending = sign_in(&auth, "coupled@example.test", json!({}), "").await;
    let _ = call(
        &auth,
        request("/two-factor/send-otp", Some(json!({})), &cookies(&pending)),
        200,
    )
    .await;
    let actual = outbox.0.lock().unwrap().last().unwrap().clone();
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-otp",
            Some(json!({"code":"invalid-code"})),
            &cookies(&pending),
        ),
        401,
    )
    .await;
    let factor = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
    assert_eq!(factor.failed_verification_count, Some(2.5));
    assert!(factor.locked_until.unwrap() > chrono::Utc::now());
    let before = db
        .tables(&["two_factor", "verifications", "sessions"])
        .await?;
    for (path, code) in [
        ("/two-factor/verify-otp", actual.clone()),
        (
            "/two-factor/verify-totp",
            totp.generate_current().to_string(),
        ),
    ] {
        let denied = call(
            &auth,
            request(path, Some(json!({"code":code})), &cookies(&pending)),
            429,
        )
        .await;
        assert_eq!(body(&denied)["code"], "ACCOUNT_TEMPORARILY_LOCKED");
        assert_eq!(
            db.tables(&["two_factor", "verifications", "sessions"])
                .await?,
            before
        );
    }
    _ = auth
        .store()
        .set_two_factor_lock_if_count_at_least(
            &factor.id,
            2.5,
            chrono::Utc::now() - chrono::Duration::seconds(1),
        )
        .await?;
    let completed = call(
        &auth,
        request(
            "/two-factor/verify-otp",
            Some(json!({"code":actual})),
            &cookies(&pending),
        ),
        200,
    )
    .await;
    authenticated(&auth, &cookies(&completed), "coupled@example.test").await;
    let final_factor = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
    assert_eq!(final_factor.failed_verification_count, Some(0.0));
    assert!(final_factor.locked_until.is_none());
    assert_eq!(
        (
            final_factor.id,
            final_factor.secret,
            final_factor.backup_codes
        ),
        (factor.id, factor.secret, factor.backup_codes)
    );
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-otp",
            Some(json!({"code":actual})),
            &cookies(&pending),
        ),
        401,
    )
    .await;
    B::close(connection).await
}

async fn two_factor_pending_orphan_owner_proof_retention<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            skip_verification_on_enable: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let signed = signup(&auth, "orphan@example.test").await;
    let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
    let (_, enrollment, _) = enroll(&auth, &cookies(&signed)).await;
    let pending = sign_in(&auth, "orphan@example.test", json!({}), "").await;
    let key=db.text("SELECT identifier FROM verifications WHERE value=$1 AND identifier LIKE '2fa-%' AND identifier NOT LIKE '2fa-attempts-%'",&[&id]).await?.unwrap();
    _ = db
        .execute(
            "UPDATE verifications SET value='missing-physical-owner' WHERE identifier=$1",
            &[&key],
        )
        .await?;
    let before = db
        .tables(&[
            "two_factor",
            "verifications",
            "users",
            "accounts",
            "sessions",
        ])
        .await?;
    let denied = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":enrollment["backupCodes"][0]})),
            &cookies(&pending),
        ),
        401,
    )
    .await;
    assert_eq!(body(&denied)["code"], "INVALID_TWO_FACTOR_COOKIE");
    assert_eq!(
        db.tables(&[
            "two_factor",
            "verifications",
            "users",
            "accounts",
            "sessions"
        ])
        .await?,
        before
    );
    _ = db
        .execute(
            "UPDATE verifications SET value=$1 WHERE identifier=$2",
            &[&id, &key],
        )
        .await?;
    let done = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":enrollment["backupCodes"][0]})),
            &cookies(&pending),
        ),
        200,
    )
    .await;
    assert_eq!(body(&done)["user"]["id"], id);
    authenticated(&auth, &cookies(&done), "orphan@example.test").await;
    let stable = db
        .tables(&[
            "two_factor",
            "verifications",
            "users",
            "accounts",
            "sessions",
        ])
        .await?;
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":enrollment["backupCodes"][0]})),
            &cookies(&pending),
        ),
        401,
    )
    .await;
    assert_eq!(
        db.tables(&[
            "two_factor",
            "verifications",
            "users",
            "accounts",
            "sessions"
        ])
        .await?,
        stable
    );
    B::close(connection).await
}

async fn two_factor_pending_newest_expired_snapshot<B: Backend>(db: Db) -> TestResult {
    use alibi::entity::AuthVerification;
    for disabled in [false, true] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.verification.disable_cleanup = disabled;
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                skip_verification_on_enable: true,
                ..Default::default()
            }))
            .build()
            .await?;
        let signed = signup(&auth, "shadow@example.test").await;
        let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
        let (_, enrollment, _) = enroll(&auth, &cookies(&signed)).await;
        let pending = sign_in(&auth, "shadow@example.test", json!({}), "").await;
        let key=db.text("SELECT identifier FROM verifications WHERE value=$1 AND identifier LIKE '2fa-%' AND identifier NOT LIKE '2fa-attempts-%'",&[&id]).await?.unwrap();
        let shadow = auth
            .store()
            .create_verification(alibi::CreateVerification {
                identifier: key.clone(),
                value: "missing-shadow-owner".into(),
                expires_at: chrono::Utc::now() - chrono::Duration::hours(1),
            })
            .await?;
        db.set_timestamp(
            "verifications",
            "created_at",
            ("id", shadow.id().as_ref()),
            "2030-01-01T00:00:00Z".parse()?,
        )
        .await?;
        let principals = db
            .tables(&["two_factor", "users", "accounts", "sessions"])
            .await?;
        let denied = call(
            &auth,
            request(
                "/two-factor/verify-backup-code",
                Some(json!({"code":enrollment["backupCodes"][0]})),
                &cookies(&pending),
            ),
            401,
        )
        .await;
        assert_eq!(body(&denied)["code"], "INVALID_TWO_FACTOR_COOKIE");
        assert_eq!(
            db.tables(&["two_factor", "users", "accounts", "sessions"])
                .await?,
            principals
        );
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM verifications WHERE id=$1",
                &[shadow.id().as_ref()]
            )
            .await?,
            i64::from(disabled)
        );
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM verifications WHERE identifier=$1 AND value=$2",
                &[&key, &id]
            )
            .await?,
            1
        );
        assert_eq!(
            db.text(
                "SELECT value FROM verifications WHERE identifier=$1",
                &[&format!("2fa-attempts-{key}")]
            )
            .await?
            .as_deref(),
            Some("0")
        );
        if disabled {
            let before = db.table("verifications").await?;
            let _ = call(
                &auth,
                request(
                    "/two-factor/verify-backup-code",
                    Some(json!({"code":enrollment["backupCodes"][0]})),
                    &cookies(&pending),
                ),
                401,
            )
            .await;
            assert_eq!(db.table("verifications").await?, before);
            _ = db
                .execute(
                    "DELETE FROM verifications WHERE id=$1",
                    &[shadow.id().as_ref()],
                )
                .await?;
        }
        let done = call(
            &auth,
            request(
                "/two-factor/verify-backup-code",
                Some(json!({"code":enrollment["backupCodes"][0]})),
                &cookies(&pending),
            ),
            200,
        )
        .await;
        assert_eq!(body(&done)["user"]["id"], id);
        authenticated(&auth, &cookies(&done), "shadow@example.test").await;
        let _ = call(
            &auth,
            request(
                "/two-factor/verify-backup-code",
                Some(json!({"code":enrollment["backupCodes"][0]})),
                &cookies(&pending),
            ),
            401,
        )
        .await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn two_factor_backup_view_exact_truthy_projection<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            backup_storage: TwoFactorBackupStorage::Plain,
            skip_verification_on_enable: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let signed = signup(&auth, "projection@example.test").await;
    let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
    let _ = enroll(&auth, &cookies(&signed)).await;
    for (stored, expected) in [
        (
            r#"{"nested":["2025-02-30T00:00:00Z",1e400],"__proto__":{"keep":true}}"#,
            json!({"nested":["2025-03-02T00:00:00.000Z",null],"__proto__":{"keep":true}}),
        ),
        ("true", json!(true)),
        ("42", json!(42.0)),
        (r#""present""#, json!("present")),
        ("1e400", Value::Null),
        ("[]", json!([])),
    ] {
        _ = db
            .execute(
                "UPDATE two_factor SET backup_codes=$1 WHERE user_id=$2",
                &[stored, &id],
            )
            .await?;
        let before = db
            .tables(&["two_factor", "users", "accounts", "sessions"])
            .await?;
        let view = auth
            .dispatch_endpoint(
                TwoFactorPlugin::view_backup_codes_endpoint(&id),
                alibi::endpoint::EndpointOptions::default(),
            )
            .await?
            .decode()?;
        assert!(view.status);
        assert_eq!(view.backup_codes, expected);
        assert_eq!(
            db.tables(&["two_factor", "users", "accounts", "sessions"])
                .await?,
            before
        );
    }
    for stored in ["[", "null", "false", "0", "-0", r#""""#] {
        _ = db
            .execute(
                "UPDATE two_factor SET backup_codes=$1 WHERE user_id=$2",
                &[stored, &id],
            )
            .await?;
        let before = db
            .tables(&["two_factor", "users", "accounts", "sessions"])
            .await?;
        let error = auth
            .dispatch_endpoint(
                TwoFactorPlugin::view_backup_codes_endpoint(&id),
                alibi::endpoint::EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Invalid backup code"));
        assert_eq!(
            db.tables(&["two_factor", "users", "accounts", "sessions"])
                .await?,
            before
        );
    }
    B::close(connection).await
}

async fn two_factor_backup_remainder_json_normalization<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            backup_storage: TwoFactorBackupStorage::Plain,
            skip_verification_on_enable: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let signed = signup(&auth, "remainder@example.test").await;
    let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
    let initial_jar = cookies(&signed);
    let (_, enrollment, jar) = enroll(&auth, &initial_jar).await;
    let issued = enrollment["backupCodes"][0].as_str().unwrap();
    let stored = format!(
        r#"[{0},{0},{{"keep":"2025-02-30T00:00:00Z"}},"9999-12-31T24:00:00Z","2025-01-02T03:04:05.123456Z",1e400,-1e400,9007199254740993,"+275760-09-13T00:00:00.000Z","2025-02-32T00:00:00Z","2025-01-02T03:04:60Z"]"#,
        serde_json::to_string(issued)?
    );
    _ = db
        .execute(
            "UPDATE two_factor SET backup_codes=$1 WHERE user_id=$2",
            &[&stored, &id],
        )
        .await?;
    let factor = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
    let principals = db.tables(&["users", "accounts", "sessions"]).await?;
    let before = db.table("two_factor").await?;
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":"9999-12-31T24:00:00Z"})),
            &jar,
        ),
        401,
    )
    .await;
    assert_eq!(db.table("two_factor").await?, before);
    let done = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":issued})),
            &jar,
        ),
        200,
    )
    .await;
    assert_eq!(body(&done)["user"]["id"], id);
    let next = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
    assert_eq!(
        next.backup_codes,
        r#"[{"keep":"2025-03-02T00:00:00.000Z"},"+010000-01-01T00:00:00.000Z","2025-01-02T03:04:05.123Z",null,null,9007199254740992,"+275760-09-13T00:00:00.000Z","2025-02-32T00:00:00Z","2025-01-02T03:04:60Z"]"#
    );
    assert_eq!(
        (
            next.id,
            next.secret,
            next.failed_verification_count,
            next.verified
        ),
        (
            factor.id,
            factor.secret,
            factor.failed_verification_count,
            factor.verified
        )
    );
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        principals
    );
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":issued})),
            &jar,
        ),
        401,
    )
    .await;
    let expanded = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":"+275760-09-13T00:00:00.000Z"})),
            &jar,
        ),
        200,
    )
    .await;
    assert_eq!(body(&expanded)["user"]["id"], id);
    assert_eq!(
        auth.store()
            .get_two_factor_by_user_id(&id)
            .await?
            .unwrap()
            .backup_codes,
        r#"[{"keep":"2025-03-02T00:00:00.000Z"},"+010000-01-01T00:00:00.000Z","2025-01-02T03:04:05.123Z",null,null,9007199254740992,"2025-02-32T00:00:00Z","2025-01-02T03:04:60Z"]"#
    );
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        principals
    );
    B::close(connection).await
}

async fn two_factor_pending_session_cancellation_retirement<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Debug)]
    struct Reject {
        mode: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for Reject {
        async fn before_create_session(
            &self,
            _: &mut alibi::CreateSession,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            match self.mode.load(Ordering::SeqCst) {
                0 => Ok(HookControl::Continue),
                1 => {
                    _ = self.calls.fetch_add(1, Ordering::SeqCst);
                    Ok(HookControl::Cancel)
                }
                _ => {
                    _ = self.calls.fetch_add(1, Ordering::SeqCst);
                    Err(alibi::AuthError::forbidden(
                        "session creation cancelled by database hook",
                    ))
                }
            }
        }
    }

    for mode in [1, 2] {
        for kind in ["totp", "otp", "backup"] {
            let db = db.fresh().await?;
            let (connection, _) = db.migrated::<B>(SECRET).await?;
            let gate = Arc::new(AtomicUsize::new(0));
            let calls = Arc::new(AtomicUsize::new(0));
            let outbox = Arc::new(Outbox::default());
            let config = AuthConfig::new(SECRET).base_url(ORIGIN);
            let auth = super::auth_probe::fast_builder::<B>(&connection)
                .store(B::hook(
                    B::store(Arc::new(config), &connection),
                    Reject {
                        mode: gate.clone(),
                        calls: calls.clone(),
                    },
                ))
                .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                    skip_verification_on_enable: true,
                    backup_storage: TwoFactorBackupStorage::Plain,
                    send_otp: Some(outbox.clone()),
                    ..Default::default()
                }))
                .build()
                .await?;
            let signed = signup(&auth, "cancel@example.test").await;
            let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
            let foreign = signup(&auth, "other@example.test").await;
            let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
            let (totp, enrollment, active) = enroll(&auth, &cookies(&signed)).await;
            let _ = call(&auth, request("/sign-out", Some(json!({})), &active), 200).await;
            _ = db
                .execute(
                    "UPDATE two_factor SET failed_verification_count=0.5 WHERE user_id=$1",
                    &[&id],
                )
                .await?;
            let initial = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
            let pending = sign_in(&auth, "cancel@example.test", json!({}), "").await;
            let key=db.text("SELECT identifier FROM verifications WHERE value=$1 AND identifier LIKE '2fa-%' AND identifier NOT LIKE '2fa-attempts-%'",&[&id]).await?.unwrap();
            let code = match kind {
                "totp" => totp.generate_current().to_string(),
                "backup" => enrollment["backupCodes"][0].as_str().unwrap().to_owned(),
                _ => {
                    let _ = call(
                        &auth,
                        request("/two-factor/send-otp", Some(json!({})), &cookies(&pending)),
                        200,
                    )
                    .await;
                    outbox.0.lock().unwrap().last().unwrap().clone()
                }
            };
            let path = format!(
                "/two-factor/verify-{}",
                if kind == "backup" {
                    "backup-code"
                } else {
                    kind
                }
            );
            let before_sessions = db.table("sessions").await?;
            let principals = db.tables(&["users", "accounts"]).await?;
            gate.store(mode, Ordering::SeqCst);
            let denied = call(
                &auth,
                request(
                    &path,
                    Some(json!({"code":code,"trustDevice":true})),
                    &cookies(&pending),
                ),
                if mode == 1 { 500 } else { 403 },
            )
            .await;
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(denied.headers.get_all("set-cookie").count(), 0);
            if mode == 1 {
                assert_eq!(
                    body(&denied),
                    json!({"code":"FAILED_TO_CREATE_SESSION","message":"failed to create session"})
                );
            } else {
                assert_eq!(
                    body(&denied),
                    json!({"message":"session creation cancelled by database hook"})
                );
            }
            assert_eq!(db.table("sessions").await?, before_sessions);
            assert_eq!(db.tables(&["users", "accounts"]).await?, principals);
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
                    &[&key]
                )
                .await?,
                0
            );
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
                    &[&format!("2fa-attempts-{key}")]
                )
                .await?,
                i64::from(kind == "otp")
            );
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM verifications WHERE identifier LIKE 'trust-device-%'",
                    &[]
                )
                .await?,
                0
            );
            let factor = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
            assert_eq!(factor.secret, initial.secret);
            assert_eq!(factor.verified, Some(true));
            assert_eq!(factor.failed_verification_count, Some(0.0));
            assert!(factor.locked_until.is_none());
            if kind == "backup" {
                let remaining: Value = serde_json::from_str(&factor.backup_codes)?;
                assert!(!remaining.as_array().unwrap().contains(&json!(code)));
            } else {
                assert_eq!(factor.backup_codes, initial.backup_codes);
            }
            let stable = db
                .tables(&[
                    "two_factor",
                    "verifications",
                    "users",
                    "accounts",
                    "sessions",
                ])
                .await?;
            let replay = call(
                &auth,
                request(
                    &path,
                    Some(json!({"code":code,"trustDevice":true})),
                    &cookies(&pending),
                ),
                401,
            )
            .await;
            assert_eq!(body(&replay)["code"], "INVALID_TWO_FACTOR_COOKIE");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                db.tables(&[
                    "two_factor",
                    "verifications",
                    "users",
                    "accounts",
                    "sessions"
                ])
                .await?,
                stable
            );
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM sessions WHERE user_id=$1",
                    &[&foreign_id]
                )
                .await?,
                1
            );
            authenticated(&auth, &cookies(&foreign), "other@example.test").await;
            B::close(connection).await?;
        }
    }
    Ok(())
}

async fn two_factor_authenticated_totp_failed_rotation_retry<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Debug)]
    struct Reject {
        mode: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for Reject {
        async fn before_create_session(
            &self,
            _: &mut alibi::CreateSession,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            match self.mode.load(Ordering::SeqCst) {
                0 => Ok(HookControl::Continue),
                1 => {
                    _ = self.calls.fetch_add(1, Ordering::SeqCst);
                    Ok(HookControl::Cancel)
                }
                _ => {
                    _ = self.calls.fetch_add(1, Ordering::SeqCst);
                    Err(alibi::AuthError::forbidden(
                        "session creation cancelled by database hook",
                    ))
                }
            }
        }
    }

    for mode in [1, 2] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let gate = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .store(B::hook(
                B::store(Arc::new(config), &connection),
                Reject {
                    mode: gate.clone(),
                    calls: calls.clone(),
                },
            ))
            .plugin(TwoFactorPlugin::new())
            .build()
            .await?;
        let signed = signup(&auth, "retry@example.test").await;
        let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
        let jar = cookies(&signed);
        let (totp, _, _) = enroll(&auth, &jar).await;
        let original = db.table("two_factor").await?;
        let sessions = db.table("sessions").await?;
        gate.store(mode, Ordering::SeqCst);
        let _ = call(
            &auth,
            request(
                "/two-factor/verify-totp",
                Some(json!({"code":"invalid-code"})),
                &jar,
            ),
            401,
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(db.table("two_factor").await?, original);
        let denied = call(
            &auth,
            request(
                "/two-factor/verify-totp",
                Some(json!({"code":totp.generate_current().to_string(),"trustDevice":true})),
                &jar,
            ),
            if mode == 1 { 500 } else { 403 },
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(denied.headers.get_all("set-cookie").count(), 0);
        if mode == 1 {
            assert!(denied.body.is_empty());
        } else {
            assert_eq!(
                body(&denied)["message"],
                "session creation cancelled by database hook"
            );
        }
        assert_eq!(db.table("two_factor").await?, original);
        assert_eq!(db.table("sessions").await?, sessions);
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM users WHERE id=$1 AND two_factor_enabled=true",
                &[&id]
            )
            .await?,
            1
        );
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM verifications WHERE identifier LIKE 'trust-device-%'",
                &[]
            )
            .await?,
            0
        );
        gate.store(0, Ordering::SeqCst);
        let done = call(
            &auth,
            request(
                "/two-factor/verify-totp",
                Some(json!({"code":totp.generate_current().to_string()})),
                &jar,
            ),
            200,
        )
        .await;
        assert_eq!(body(&done)["token"], body(&signed)["token"]);
        assert_eq!(done.headers.get_all("set-cookie").count(), 0);
        let factor = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
        assert_eq!(factor.verified, Some(true));
        assert_eq!(db.table("sessions").await?, sessions);
        authenticated(&auth, &jar, "retry@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn two_factor_expired_pending_factor_stage_policy<B: Backend>(db: Db) -> TestResult {
    for disabled in [false, true] {
        for kind in ["totp", "otp", "backup"] {
            let db = db.fresh().await?;
            let (connection, _) = db.migrated::<B>(SECRET).await?;
            let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
            config.verification.disable_cleanup = disabled;
            let outbox = Arc::new(Outbox::default());
            let auth = AuthBuilder::new(config.clone())
                .store(B::store(Arc::new(config), &connection))
                .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
                .plugin(super::auth_probe::fast_password())
                .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                    skip_verification_on_enable: true,
                    send_otp: Some(outbox.clone()),
                    ..Default::default()
                }))
                .build()
                .await?;
            let signed = signup(&auth, "expired@example.test").await;
            let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
            let (totp, enrollment, _) = enroll(&auth, &cookies(&signed)).await;
            let pending = sign_in(&auth, "expired@example.test", json!({}), "").await;
            let key=db.text("SELECT identifier FROM verifications WHERE value=$1 AND identifier LIKE '2fa-%' AND identifier NOT LIKE '2fa-attempts-%'",&[&id]).await?.unwrap();
            _ = db
                .execute("UPDATE two_factor SET failed_verification_count=3", &[])
                .await?;
            let old = "2020-01-01T00:00:00Z".parse()?;
            db.set_timestamp("verifications", "expires_at", ("identifier", &key), old)
                .await?;
            db.set_timestamp(
                "verifications",
                "expires_at",
                ("identifier", &format!("2fa-attempts-{key}")),
                old,
            )
            .await?;
            let factor = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
            let sessions = db.tables(&["users", "accounts", "sessions"]).await?;
            let code = match kind {
                "totp" => totp.generate_current().to_string(),
                "backup" => enrollment["backupCodes"][0].as_str().unwrap().to_owned(),
                _ => {
                    let _ = call(
                        &auth,
                        request("/two-factor/send-otp", Some(json!({})), &cookies(&pending)),
                        200,
                    )
                    .await;
                    outbox.0.lock().unwrap().last().unwrap().clone()
                }
            };
            let path = format!(
                "/two-factor/verify-{}",
                if kind == "backup" {
                    "backup-code"
                } else {
                    kind
                }
            );
            let denied = call(
                &auth,
                request(&path, Some(json!({"code":code})), &cookies(&pending)),
                401,
            )
            .await;
            assert_eq!(body(&denied)["code"], "INVALID_TWO_FACTOR_COOKIE");
            assert_eq!(
                db.tables(&["users", "accounts", "sessions"]).await?,
                sessions
            );
            let next = auth.store().get_two_factor_by_user_id(&id).await?.unwrap();
            assert_eq!(
                (next.id, next.secret, next.backup_codes),
                (factor.id, factor.secret, factor.backup_codes)
            );
            assert_eq!(
                next.failed_verification_count,
                Some(if disabled && kind == "otp" { 0.0 } else { 3.0 })
            );
            for (identifier, remains) in [
                (&key, disabled && kind != "otp"),
                (&format!("2fa-attempts-{key}"), disabled && kind == "otp"),
                (&format!("2fa-otp-{key}"), !disabled && kind == "otp"),
            ] {
                assert_eq!(
                    db.count_where(
                        "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
                        &[identifier]
                    )
                    .await?,
                    i64::from(remains)
                );
            }
            let fresh = sign_in(&auth, "expired@example.test", json!({}), "").await;
            let done = call(
                &auth,
                request(
                    "/two-factor/verify-totp",
                    Some(json!({"code":totp.generate_current().to_string()})),
                    &cookies(&fresh),
                ),
                200,
            )
            .await;
            authenticated(&auth, &cookies(&done), "expired@example.test").await;
            B::close(connection).await?;
        }
    }
    Ok(())
}

async fn two_factor_configured_proof_cookie_lifetimes<B: Backend>(db: Db) -> TestResult {
    use alibi::entity::AuthVerification;
    for (challenge_age, challenge_ms, trust_age, trust_ms) in [
        (600.75, 600_750, 1200.875, 1_200_875),
        (0.0, 0, 1200.875, 1_200_875),
        (-0.25, -250, 1200.875, 1_200_875),
        (600.75, 600_750, 0.0, 0),
        (600.75, 600_750, -0.25, -250),
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                skip_verification_on_enable: true,
                two_factor_cookie_max_age: challenge_age,
                trust_device_max_age: trust_age,
                ..Default::default()
            }))
            .build()
            .await?;
        let signed = signup(&auth, "ttl@example.test").await;
        let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
        let (totp, _, _) = enroll(&auth, &cookies(&signed)).await;
        let from = chrono::Utc::now().timestamp_millis();
        let pending = sign_in(&auth, "ttl@example.test", json!({}), "").await;
        let to = chrono::Utc::now().timestamp_millis();
        let header = pending
            .headers
            .get_all("set-cookie")
            .find(|x| x.starts_with("better-auth.two_factor="))
            .unwrap();
        let expected = if challenge_ms < 0 {
            None
        } else {
            Some(format!("Max-Age={}", challenge_ms / 1000))
        };
        assert_eq!(header.contains("Max-Age="), expected.is_some());
        if let Some(x) = expected {
            assert!(header.contains(&x));
        }
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("SameSite=Lax"));
        assert!(!header.contains("Expires="));
        let key=db.text("SELECT identifier FROM verifications WHERE value=$1 AND identifier LIKE '2fa-%' AND identifier NOT LIKE '2fa-attempts-%'",&[&id]).await?.unwrap();
        let proof = auth
            .store()
            .get_latest_verification_by_identifier(&key)
            .await?
            .unwrap();
        let attempts = auth
            .store()
            .get_latest_verification_by_identifier(&format!("2fa-attempts-{key}"))
            .await?
            .unwrap();
        let expiry = proof.expires_at().timestamp_millis();
        assert!((from + challenge_ms..=to + challenge_ms).contains(&expiry));
        assert_eq!(attempts.expires_at(), proof.expires_at());
        if challenge_ms > 0 {
            let from = chrono::Utc::now().timestamp_millis();
            let done = call(
                &auth,
                request(
                    "/two-factor/verify-totp",
                    Some(json!({"code":totp.generate_current().to_string(),"trustDevice":true})),
                    &cookies(&pending),
                ),
                200,
            )
            .await;
            let to = chrono::Utc::now().timestamp_millis();
            let header = done
                .headers
                .get_all("set-cookie")
                .find(|x| x.starts_with("better-auth.trust_device="))
                .unwrap();
            assert_eq!(header.contains("Max-Age="), trust_ms >= 0);
            if trust_ms >= 0 {
                assert!(header.contains(&format!("Max-Age={}", trust_ms / 1000)));
            }
            let key=db.text("SELECT identifier FROM verifications WHERE identifier LIKE 'trust-device-%' AND value=$1",&[&id]).await?.unwrap();
            let trust = auth
                .store()
                .get_latest_verification_by_identifier(&key)
                .await?
                .unwrap();
            assert!(
                (from + trust_ms..=to + trust_ms).contains(&trust.expires_at().timestamp_millis())
            );
            let pair = header.split(';').next().unwrap();
            let from = chrono::Utc::now().timestamp_millis();
            let rotated = sign_in(&auth, "ttl@example.test", json!({}), pair).await;
            let to = chrono::Utc::now().timestamp_millis();
            if trust_ms > 0 {
                assert_eq!(body(&rotated)["user"]["id"], id);
                assert!(
                    auth.store()
                        .get_latest_verification_by_identifier(&key)
                        .await?
                        .is_none()
                );
                let next=db.text("SELECT identifier FROM verifications WHERE identifier LIKE 'trust-device-%' AND value=$1",&[&id]).await?.unwrap();
                assert_ne!(next, key);
                let expiry = auth
                    .store()
                    .get_latest_verification_by_identifier(&next)
                    .await?
                    .unwrap()
                    .expires_at()
                    .timestamp_millis();
                assert!((from + trust_ms..=to + trust_ms).contains(&expiry));
            } else {
                assert_eq!(body(&rotated)["twoFactorRedirect"], true);
            }
        }
        B::close(connection).await?;
    }
    Ok(())
}

async fn two_factor_trust_syntax_before_cleanup<B: Backend>(db: Db) -> TestResult {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use hkdf::hmac::{Hmac, KeyInit, Mac};
    let sign = |value: &str| {
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(value.as_bytes());
        url::form_urlencoded::byte_serialize(
            format!("{value}.{}", STANDARD.encode(mac.finalize().into_bytes())).as_bytes(),
        )
        .collect::<String>()
    };
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            skip_verification_on_enable: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let signed = signup(&auth, "syntax@example.test").await;
    let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
    let (totp, _, _) = enroll(&auth, &cookies(&signed)).await;
    let pending = sign_in(&auth, "syntax@example.test", json!({}), "").await;
    let done = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":totp.generate_current().to_string(),"trustDevice":true})),
            &cookies(&pending),
        ),
        200,
    )
    .await;
    let real = cookies(&done)
        .split("; ")
        .find(|x| x.starts_with("better-auth.trust_device="))
        .unwrap()
        .to_owned();
    let key = db
        .text(
            "SELECT identifier FROM verifications WHERE identifier LIKE 'trust-device-%'",
            &[],
        )
        .await?
        .unwrap();
    let _ = auth
        .store()
        .create_verification(alibi::CreateVerification {
            identifier: "unrelated-expired-syntax".into(),
            value: id.clone(),
            expires_at: chrono::Utc::now() - chrono::Duration::days(1),
        })
        .await?;
    let principals = db
        .tables(&["two_factor", "users", "accounts", "sessions"])
        .await?;
    let issued = db
        .text(
            "SELECT value FROM verifications WHERE identifier=$1",
            &[&key],
        )
        .await?;
    for (value, clear) in [
        ("plain".into(), false),
        (sign(""), false),
        (sign("unstructured"), true),
        (sign(&format!("wrong!{key}")), true),
        (sign(&format!("!{key}")), true),
        (sign("token!"), true),
    ] {
        let pending = sign_in(
            &auth,
            "syntax@example.test",
            json!({}),
            &format!("better-auth.trust_device={value}"),
        )
        .await;
        assert_eq!(body(&pending)["twoFactorRedirect"], true);
        assert_eq!(
            db.tables(&["two_factor", "users", "accounts", "sessions"])
                .await?,
            principals
        );
        assert_eq!(
            pending
                .headers
                .get_all("set-cookie")
                .any(|x| x.starts_with("better-auth.trust_device=") && x.contains("Max-Age=0")),
            clear
        );
        assert_eq!(
            db.text(
                "SELECT value FROM verifications WHERE identifier=$1",
                &[&key]
            )
            .await?,
            issued
        );
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM verifications WHERE identifier='unrelated-expired-syntax'",
                &[]
            )
            .await?,
            1
        );
    }
    let control = sign_in(&auth, "syntax@example.test", json!({}), &real).await;
    assert_eq!(body(&control)["user"]["id"], id);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM verifications WHERE identifier='unrelated-expired-syntax'",
            &[]
        )
        .await?,
        0
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
            &[&key]
        )
        .await?,
        0
    );
    B::close(connection).await
}

async fn two_factor_trust_lookup_cleanup_policy<B: Backend>(db: Db) -> TestResult {
    for disabled in [false, true] {
        for expired in [false, true] {
            let db = db.fresh().await?;
            let (connection, _) = db.migrated::<B>(SECRET).await?;
            let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
            config.verification.disable_cleanup = disabled;
            let auth = AuthBuilder::new(config.clone())
                .store(B::store(Arc::new(config), &connection))
                .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
                .plugin(super::auth_probe::fast_password())
                .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                    skip_verification_on_enable: true,
                    ..Default::default()
                }))
                .build()
                .await?;
            let signed = signup(&auth, "lookup@example.test").await;
            let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
            let (totp, _, _) = enroll(&auth, &cookies(&signed)).await;
            let pending = sign_in(&auth, "lookup@example.test", json!({}), "").await;
            let done = call(
                &auth,
                request(
                    "/two-factor/verify-totp",
                    Some(json!({"code":totp.generate_current().to_string(),"trustDevice":true})),
                    &cookies(&pending),
                ),
                200,
            )
            .await;
            let real = cookies(&done)
                .split("; ")
                .find(|x| x.starts_with("better-auth.trust_device="))
                .unwrap()
                .to_owned();
            let key = db
                .text(
                    "SELECT identifier FROM verifications WHERE identifier LIKE 'trust-device-%'",
                    &[],
                )
                .await?
                .unwrap();
            if expired {
                db.set_timestamp(
                    "verifications",
                    "expires_at",
                    ("identifier", &key),
                    "2020-01-01T00:00:00Z".parse()?,
                )
                .await?;
            } else {
                _ = db
                    .execute(
                        "UPDATE verifications SET value='changed-trust-owner' WHERE identifier=$1",
                        &[&key],
                    )
                    .await?;
            }
            let _ = auth
                .store()
                .create_verification(alibi::CreateVerification {
                    identifier: "unrelated-expired-lookup".into(),
                    value: id.clone(),
                    expires_at: chrono::Utc::now() - chrono::Duration::days(1),
                })
                .await?;
            let before = db
                .tables(&["two_factor", "users", "accounts", "sessions"])
                .await?;
            let rejected = sign_in(&auth, "lookup@example.test", json!({}), &real).await;
            assert_eq!(body(&rejected)["twoFactorRedirect"], true);
            assert_eq!(
                db.tables(&["two_factor", "users", "accounts", "sessions"])
                    .await?,
                before
            );
            assert_eq!(db.count_where("SELECT COUNT(*) FROM verifications WHERE identifier='unrelated-expired-lookup'",&[]).await?,i64::from(disabled));
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
                    &[&key]
                )
                .await?,
                i64::from(disabled || !expired)
            );
            if !expired {
                assert_eq!(
                    db.text(
                        "SELECT value FROM verifications WHERE identifier=$1",
                        &[&key]
                    )
                    .await?
                    .as_deref(),
                    Some("changed-trust-owner")
                );
            }
            let recovered = call(
                &auth,
                request(
                    "/two-factor/verify-totp",
                    Some(json!({"code":totp.generate_current().to_string()})),
                    &cookies(&rejected),
                ),
                200,
            )
            .await;
            authenticated(&auth, &cookies(&recovered), "lookup@example.test").await;
            B::close(connection).await?;
        }
    }
    Ok(())
}

async fn two_factor_trust_ignored_components<B: Backend>(db: Db) -> TestResult {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use hkdf::hmac::{Hmac, KeyInit, Mac};
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            skip_verification_on_enable: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let signed = signup(&auth, "components@example.test").await;
    let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
    let (totp, _, _) = enroll(&auth, &cookies(&signed)).await;
    let pending = sign_in(&auth, "components@example.test", json!({}), "").await;
    let done = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":totp.generate_current().to_string(),"trustDevice":true})),
            &cookies(&pending),
        ),
        200,
    )
    .await;
    let jar = cookies(&done);
    let encoded = jar
        .split("; ")
        .find_map(|x| x.strip_prefix("better-auth.trust_device="))
        .unwrap();
    let decoded = url::form_urlencoded::parse(format!("v={encoded}").as_bytes())
        .next()
        .unwrap()
        .1
        .into_owned();
    let payload = decoded.rsplit_once('.').unwrap().0;
    let key = payload.split('!').nth(1).unwrap();
    let preceding = sign_in(&auth, "components@example.test", json!({}), "").await;
    let pending_key=db.text("SELECT identifier FROM verifications WHERE value=$1 AND identifier LIKE '2fa-%' AND identifier NOT LIKE '2fa-attempts-%'",&[&id]).await?.unwrap();
    let extended = format!("{payload}!ignored!components");
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes())?;
    mac.update(extended.as_bytes());
    let wire = url::form_urlencoded::byte_serialize(
        format!(
            "{extended}.{}",
            STANDARD.encode(mac.finalize().into_bytes())
        )
        .as_bytes(),
    )
    .collect::<String>();
    let pair = format!("better-auth.trust_device={wire}");
    let rotated = sign_in(&auth, "components@example.test", json!({}), &pair).await;
    assert_eq!(body(&rotated)["user"]["id"], id);
    authenticated(&auth, &cookies(&rotated), "components@example.test").await;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
            &[key]
        )
        .await?,
        0
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM verifications WHERE identifier LIKE 'trust-device-%'",
            &[]
        )
        .await?,
        1
    );
    let next = db
        .text(
            "SELECT identifier FROM verifications WHERE identifier LIKE 'trust-device-%'",
            &[],
        )
        .await?
        .unwrap();
    assert_ne!(next, key);
    let replay = sign_in(&auth, "components@example.test", json!({}), &pair).await;
    assert_eq!(body(&replay)["twoFactorRedirect"], true);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM verifications WHERE identifier=$1 AND value=$2",
            &[&next, &id]
        )
        .await?,
        1
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM verifications WHERE identifier=$1 AND value=$2",
            &[&pending_key, &id]
        )
        .await?,
        1
    );
    let retained = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":totp.generate_current().to_string()})),
            &cookies(&preceding),
        ),
        200,
    )
    .await;
    assert_eq!(body(&retained)["user"]["id"], id);
    B::close(connection).await
}

async fn two_factor_factor_cookie_wire_aliases<B: Backend>(db: Db) -> TestResult {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use hkdf::hmac::{Hmac, KeyInit, Mac};
    let sign = |payload: &str| {
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        format!("{payload}.{}", STANDARD.encode(mac.finalize().into_bytes()))
    };
    let encode =
        |value: &str| url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
    for mode in 0..5 {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                skip_verification_on_enable: true,
                ..Default::default()
            }))
            .build()
            .await?;
        let signed = signup(&auth, "wire@example.test").await;
        let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
        let (_, enrollment, _) = enroll(&auth, &cookies(&signed)).await;
        let actual = sign_in(&auth, "wire@example.test", json!({}), "").await;
        let key = if mode == 0 {
            "2fa-雪-é.uri".to_owned()
        } else if mode == 1 {
            "2fa-%E9".to_owned()
        } else {
            db.text("SELECT identifier FROM verifications WHERE value=$1 AND identifier LIKE '2fa-%' AND identifier NOT LIKE '2fa-attempts-%'",&[&id]).await?.unwrap()
        };
        if mode < 2 {
            for (identifier, value) in [
                (key.clone(), id.clone()),
                (format!("2fa-attempts-{key}"), "0".into()),
            ] {
                let _ = auth
                    .store()
                    .create_verification(alibi::CreateVerification {
                        identifier,
                        value,
                        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                    })
                    .await?;
            }
        }
        let signed_key = sign(&key);
        let before = db
            .tables(&[
                "two_factor",
                "verifications",
                "users",
                "accounts",
                "sessions",
            ])
            .await?;
        let incomplete = signed_key.strip_suffix('=').unwrap();
        let bad = call(
            &auth,
            request(
                "/two-factor/verify-backup-code",
                Some(json!({"code":enrollment["backupCodes"][0]})),
                &format!("better-auth.two_factor={}", encode(incomplete)),
            ),
            401,
        )
        .await;
        assert_eq!(body(&bad)["code"], "INVALID_TWO_FACTOR_COOKIE");
        assert_eq!(
            db.tables(&[
                "two_factor",
                "verifications",
                "users",
                "accounts",
                "sessions"
            ])
            .await?,
            before
        );
        let wire = match mode {
            0 => encode(&signed_key)
                .replace("%C3", "%c3")
                .replace("%A9", "%a9")
                .replace('.', "%2e"),
            1 => signed_key.clone(),
            2 => format!("\"{}\"", encode(&signed_key)),
            3 => encode(&signed_key),
            _ => {
                let mut alias = signed_key.clone().into_bytes();
                let index = alias.len() - 2;
                let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                let position = alphabet
                    .iter()
                    .position(|x| x == alias.get(index).unwrap())
                    .unwrap();
                *alias.get_mut(index).unwrap() = *alphabet.get(position + 1).unwrap();
                let alias = String::from_utf8(alias)?;
                let permissive = base64::engine::general_purpose::GeneralPurpose::new(
                    &base64::alphabet::STANDARD,
                    base64::engine::general_purpose::GeneralPurposeConfig::new()
                        .with_decode_allow_trailing_bits(true),
                );
                assert_eq!(
                    permissive.decode(alias.rsplit_once('.').unwrap().1)?,
                    STANDARD.decode(signed_key.rsplit_once('.').unwrap().1)?
                );
                encode(&alias)
            }
        };
        let preference = encode(&sign("temporary"));
        let pair = if mode == 3 {
            format!(
                "better-auth.two_factor \t={wire}; better-auth.two_factor=invalid; better-auth.dont_remember \t={preference}; better-auth.dont_remember=invalid"
            )
        } else {
            format!("better-auth.two_factor={wire}; better-auth.dont_remember={preference}")
        };
        let done = call(
            &auth,
            request(
                "/two-factor/verify-backup-code",
                Some(json!({"code":enrollment["backupCodes"][0],"trustDevice":true})),
                &pair,
            ),
            200,
        )
        .await;
        assert_eq!(body(&done)["user"]["id"], id);
        let session = done
            .headers
            .get_all("set-cookie")
            .find(|x| x.starts_with("better-auth.session_token="))
            .unwrap();
        assert!(!session.contains("Max-Age="));
        assert!(!session.contains("Expires="));
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
                &[&key]
            )
            .await?,
            0
        );
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
                &[&format!("2fa-attempts-{key}")]
            )
            .await?,
            0
        );
        let mut active = cookies(&done);
        if mode == 2 {
            active = active
                .split("; ")
                .map(|x| {
                    x.split_once('=')
                        .map_or_else(|| x.to_owned(), |(k, v)| format!("{k}=\"{v}\""))
                })
                .collect::<Vec<_>>()
                .join("; ");
        }
        let disabled = call(
            &auth,
            request(
                "/two-factor/disable",
                Some(json!({"password":PASSWORD})),
                &active,
            ),
            200,
        )
        .await;
        assert!(body(&disabled)["status"].as_bool().unwrap());
        assert_eq!(db.count("two_factor").await?, 0);
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM verifications WHERE identifier LIKE 'trust-device-%'",
                &[]
            )
            .await?,
            0
        );
        let _ = actual;
        B::close(connection).await?;
    }
    Ok(())
}
