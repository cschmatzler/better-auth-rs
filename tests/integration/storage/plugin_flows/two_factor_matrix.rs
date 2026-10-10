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
    two_factor_configured_account_lock_policy
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
