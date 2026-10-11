//! Phone-number request validation, proof budgets, provider verification and reset effects.
use super::auth_probe::{Probe, fast_builder};
use super::*;
use alibi::plugins::PasswordManagementPlugin;
use alibi::plugins::password_management::PasswordManagementConfig;
use alibi::plugins::phone_number::{
    PhoneNumberConfig, PhoneNumberPlugin, PhoneNumberValidator, PhoneNumberVerification,
    PhoneOtpDelivery, PhoneOtpVerifier, PhoneSignupIdentity, PhoneVerificationHook, SendPhoneOtp,
};
use alibi::{AuthError, AuthResult, CallbackContext};
use async_trait::async_trait;

backend_tests!(
    phone_number_request_and_proof_matrix,
    phone_number_provider_and_sender_failures,
    phone_number_password_reset_effects,
    phone_number_signup_and_update_inputs,
    phone_signin_distinguishes_missing_null_and_empty_credentials,
    phone_self_update_consumes_proof_without_changing_owner_or_callbacks,
    phone_reset_callback_rejection_precedes_configured_session_revocation,
    phone_missing_otp_sender_precedes_application_validation,
    phone_external_verifier_cannot_authorize_local_password_reset,
    phone_verifier_rejection_preserves_local_proof_until_successful_retry,
    phone_callback_context_preserves_proof_consumption_and_committed_owner,
    revoked_compact_owner_consumes_local_phone_proof_without_recreating_browser,
    phone_background_notification_lifecycle,
    phone_trusted_device_completion_forwards_rotated_owned_proof
);

#[derive(Default)]
struct Outbox {
    sent: Mutex<Vec<PhoneOtpDelivery>>,
    failure: Mutex<Option<&'static str>>,
}
impl Outbox {
    fn last(&self) -> PhoneOtpDelivery {
        self.sent.lock().unwrap().last().cloned().unwrap()
    }
}
#[async_trait]
impl SendPhoneOtp for Outbox {
    async fn send(&self, delivery: &PhoneOtpDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.sent.lock().unwrap().push(delivery.clone());
        match *self.failure.lock().unwrap() {
            Some("internal") => Err(AuthError::internal("gateway down")),
            Some("api") => Err(AuthError::forbidden("gateway refused")),
            _ => Ok(()),
        }
    }
}

struct Validator;
#[async_trait]
impl PhoneNumberValidator for Validator {
    async fn is_valid(&self, phone_number: &str) -> AuthResult<bool> {
        match phone_number {
            "+000" => Ok(false),
            "+err" => Err(AuthError::internal("validator offline")),
            _ => Ok(true),
        }
    }
}

struct Identity;
impl PhoneSignupIdentity for Identity {
    fn temporary_email(&self, phone_number: &str) -> String {
        format!(
            "{}@phone.example.test",
            phone_number.trim_start_matches('+')
        )
    }
    fn temporary_name(&self, phone_number: &str) -> Option<String> {
        (phone_number != "+15550000003").then(|| format!("Phone {phone_number}"))
    }
}

struct Hook;
#[async_trait]
impl PhoneVerificationHook for Hook {
    async fn verified(
        &self,
        result: &PhoneNumberVerification,
        _: &CallbackContext,
    ) -> AuthResult<()> {
        if result.phone_number.ends_with('9') {
            return Err(AuthError::forbidden("hook rejected"));
        }
        Ok(())
    }
}

struct Provider(&'static str);
#[async_trait]
impl PhoneOtpVerifier for Provider {
    async fn verify(&self, delivery: &PhoneOtpDelivery, _: &CallbackContext) -> AuthResult<bool> {
        match self.0 {
            "accept" => Ok(delivery.code == "424242"),
            "api" => Err(AuthError::forbidden("provider denied")),
            _ => Err(AuthError::internal("provider offline")),
        }
    }
}

fn verify_body(number: &str, code: &str, extra: &Value) -> String {
    let mut input = json!({"phoneNumber":number,"code":code});
    input
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    input.to_string()
}

async fn send_code<S: AuthSchema>(
    probe: &mut Probe<'_, S>,
    outbox: &Outbox,
    number: &str,
) -> String {
    let _ = probe
        .post(
            &format!("send {number}"),
            "/phone-number/send-otp",
            &json!({"phoneNumber":number}).to_string(),
            "",
        )
        .await;
    outbox.last().code
}

async fn phone_number_request_and_proof_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let auth = fast_builder::<B>(&connection)
        .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
            send_otp: Some(outbox.clone()),
            send_password_reset_otp: Some(outbox.clone()),
            phone_number_validator: Some(Arc::new(Validator)),
            sign_up_on_verification: Some(Arc::new(Identity)),
            callback_on_verification: Some(Arc::new(Hook)),
            require_verification: true,
            allowed_attempts: 2.0,
            ..Default::default()
        }))
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    for path in [
        "/sign-in/phone-number",
        "/phone-number/send-otp",
        "/phone-number/verify",
        "/phone-number/request-password-reset",
        "/phone-number/reset-password",
    ] {
        for text in [
            "[]",
            "null",
            "{}",
            r#"{"phoneNumber":5,"password":5,"code":5,"otp":5,"newPassword":5}"#,
            r#"{"phoneNumber":"+000","password":"a-native-password-123","code":"1","otp":"1","newPassword":"a-native-password-123"}"#,
            r#"{"phoneNumber":"+err","password":"a-native-password-123","code":"1"}"#,
        ] {
            let _ = probe.post(&format!("{path} {text}"), path, text, "").await;
        }
    }
    let phone = "+15550000001";
    let verify = "/phone-number/verify";
    let _ = probe
        .post(
            "verify before send",
            verify,
            &verify_body(phone, "1", &json!({})),
            "",
        )
        .await;
    let _ = send_code(&mut probe, &outbox, phone).await;
    for wrong in ["wrong-1", "wrong-2", "wrong-3"] {
        let _ = probe
            .post(wrong, verify, &verify_body(phone, wrong, &json!({})), "")
            .await;
    }
    let code = send_code(&mut probe, &outbox, phone).await;
    let _ = probe
        .post(
            "verified input rejected",
            verify,
            &verify_body(phone, &code, &json!({"phoneNumberVerified":true})),
            "",
        )
        .await;
    let code = send_code(&mut probe, &outbox, phone).await;
    db.set_timestamp(
        "verifications",
        "expires_at",
        ("identifier", phone),
        chrono::Utc::now() - chrono::Duration::seconds(5),
    )
    .await?;
    let _ = probe
        .post(
            "expired",
            verify,
            &verify_body(phone, &code, &json!({})),
            "",
        )
        .await;
    let code = send_code(&mut probe, &outbox, phone).await;
    let _ = probe
        .post(
            "creates user without session",
            verify,
            &verify_body(phone, &code, &json!({"disableSession":true})),
            "",
        )
        .await;
    assert_eq!(db.count("users").await?, 1);
    assert_eq!(db.count("sessions").await?, 0);
    let code = send_code(&mut probe, &outbox, phone).await;
    let _ = probe
        .post(
            "existing user",
            verify,
            &verify_body(phone, &code, &json!({})),
            "",
        )
        .await;
    let hooked = "+15550000009";
    let code = send_code(&mut probe, &outbox, hooked).await;
    let _ = probe
        .post(
            "callback rejects",
            verify,
            &verify_body(hooked, &code, &json!({})),
            "",
        )
        .await;
    let nameless = "+15550000003";
    let code = send_code(&mut probe, &outbox, nameless).await;
    let _ = probe
        .post(
            "nameless signup",
            verify,
            &verify_body(
                nameless,
                &code,
                &json!({"username":"ignored","image":"https://img.example.test/a.png"}),
            ),
            "",
        )
        .await;
    for (label, number, password) in [
        ("unknown phone", "+15559999999", PASSWORD.to_owned()),
        ("long password", phone, "p".repeat(200)),
        ("unverified phone", phone, PASSWORD.to_owned()),
    ] {
        let _ = probe
            .post(
                &format!("sign in {label}"),
                "/sign-in/phone-number",
                &json!({"phoneNumber":number,"password":password}).to_string(),
                "",
            )
            .await;
    }
    _ = db
        .execute("UPDATE users SET phone_number_verified = false", &[])
        .await?;
    let _ = probe
        .post(
            "sign in without credential",
            "/sign-in/phone-number",
            &json!({"phoneNumber":phone,"password":PASSWORD}).to_string(),
            "",
        )
        .await;
    probe
        .trace
        .value("deliveries", json!(outbox.sent.lock().unwrap().len()));
    probe.trace.assert("phone-number/request-and-proof-matrix");
    B::close(connection).await
}

async fn phone_number_provider_and_sender_failures<B: Backend>(db: Db) -> TestResult {
    let mut trace = crate::snapshot::Trace::default();
    for mode in [
        "no sender",
        "internal sender",
        "api sender",
        "provider accepts",
        "provider api error",
        "provider internal error",
        "invalid expiry",
        "sign-up unavailable",
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let outbox = Arc::new(Outbox::default());
        *outbox.failure.lock().unwrap() = match mode {
            "internal sender" => Some("internal"),
            "api sender" => Some("api"),
            _ => None,
        };
        let provider = Arc::new(Provider(match mode {
            "provider api error" => "api",
            "provider internal error" => "internal",
            _ => "accept",
        }));
        let config = PhoneNumberConfig {
            send_otp: (mode != "no sender").then(|| outbox.clone() as _),
            verify_otp: mode.starts_with("provider").then(|| provider.clone() as _),
            sign_up_on_verification: (mode != "sign-up unavailable")
                .then(|| Arc::new(Identity) as _),
            expires_in: if mode == "invalid expiry" {
                f64::INFINITY
            } else {
                300.0
            },
            ..Default::default()
        };
        let auth = fast_builder::<B>(&connection)
            .plugin(PhoneNumberPlugin::new(config))
            .build()
            .await?;
        let mut probe = Probe::new(&auth);
        probe.trace = trace;
        probe.prefix = format!("{mode}: ");
        let phone = "+15550000002";
        let _ = probe
            .post(
                "send",
                "/phone-number/send-otp",
                &json!({"phoneNumber":phone}).to_string(),
                "",
            )
            .await;
        let code = if mode.starts_with("provider") {
            "424242".to_owned()
        } else {
            outbox
                .sent
                .lock()
                .unwrap()
                .last()
                .map_or_else(|| "000000".into(), |sent| sent.code.clone())
        };
        for (label, attempt) in [
            ("issued", code.as_str()),
            ("provider", "424242"),
            ("wrong", "000000"),
        ] {
            let _ = probe
                .post(
                    &format!("verify {label}"),
                    "/phone-number/verify",
                    &verify_body(phone, attempt, &json!({})),
                    "",
                )
                .await;
        }
        probe
            .trace
            .value(&format!("{mode}: users"), json!(db.count("users").await?));
        trace = probe.trace;
        B::close(connection).await?;
    }
    trace.assert("phone-number/provider-and-sender-failures");
    Ok(())
}

type ResetFuture = std::pin::Pin<Box<dyn std::future::Future<Output = AuthResult<()>> + Send>>;

async fn latest_reset_code(db: &Db, phone: &str) -> TestResult<String> {
    Ok(db
        .text(
            "SELECT value FROM verifications WHERE identifier = $1",
            &[&format!("{phone}-request-password-reset")],
        )
        .await?
        .unwrap()
        .split(':')
        .next()
        .unwrap()
        .to_owned())
}

async fn phone_number_password_reset_effects<B: Backend>(db: Db) -> TestResult {
    let mut trace = crate::snapshot::Trace::default();
    for mode in ["plain", "callback", "revoke", "callback fails"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let outbox = Arc::new(Outbox::default());
        let calls = Arc::new(Mutex::new(0_usize));
        let seen = calls.clone();
        let failing = mode == "callback fails";
        let auth = fast_builder::<B>(&connection)
            .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
                send_otp: Some(outbox.clone()),
                send_password_reset_otp: (mode != "plain").then(|| outbox.clone() as _),
                sign_up_on_verification: Some(Arc::new(Identity)),
                ..Default::default()
            }))
            .plugin(PasswordManagementPlugin::with_config(
                PasswordManagementConfig {
                    revoke_sessions_on_password_reset: mode == "revoke",
                    on_password_reset: mode.starts_with("callback").then(|| {
                        Arc::new(move |_: Value| -> ResetFuture {
                            *seen.lock().unwrap() += 1;
                            Box::pin(async move {
                                if failing {
                                    Err(AuthError::forbidden("reset hook refused"))
                                } else {
                                    Ok(())
                                }
                            })
                        }) as _
                    }),
                    ..Default::default()
                },
            ))
            .build()
            .await?;
        let mut probe = Probe::new(&auth);
        probe.trace = trace;
        probe.prefix = format!("{mode}: ");
        let phone = "+15550000004";
        let code = send_code(&mut probe, &outbox, phone).await;
        let created = probe
            .post(
                "verify",
                "/phone-number/verify",
                &verify_body(phone, &code, &json!({})),
                "",
            )
            .await;
        let session = cookies(&created);
        let _ = probe
            .post(
                "request unknown phone",
                "/phone-number/request-password-reset",
                r#"{"phoneNumber":"+15551111111"}"#,
                "",
            )
            .await;
        let _ = probe
            .post(
                "reset unknown phone",
                "/phone-number/reset-password",
                r#"{"phoneNumber":"+15551111111","otp":"1","newPassword":"a-native-password-123"}"#,
                "",
            )
            .await;
        for (label, password) in [("too short", "short"), ("accepted", "a-brand-new-password")] {
            let _ = probe
                .post(
                    "request",
                    "/phone-number/request-password-reset",
                    &json!({"phoneNumber":phone}).to_string(),
                    "",
                )
                .await;
            let otp = if mode == "plain" {
                latest_reset_code(&db, phone).await?
            } else {
                outbox.last().code
            };
            let _ = probe
                .post(
                    label,
                    "/phone-number/reset-password",
                    &json!({"phoneNumber":phone,"otp":otp,"newPassword":password}).to_string(),
                    "",
                )
                .await;
        }
        let credentials = db
            .count_where(
                "SELECT COUNT(*) FROM accounts WHERE provider_id = 'credential'",
                &[],
            )
            .await?;
        let hook_calls = *calls.lock().unwrap();
        let old_session = body(&call(&auth, request("/get-session", None, &session), 200).await);
        probe.trace.value(
            "effects",
            json!({"credentials": credentials, "hook calls": hook_calls, "old session cleared": old_session.is_null()}),
        );
        let _ = probe
            .post(
                "sign in with new password",
                "/sign-in/phone-number",
                &json!({"phoneNumber":phone,"password":"a-brand-new-password"}).to_string(),
                "",
            )
            .await;
        trace = probe.trace;
        B::close(connection).await?;
    }
    trace.assert("phone-number/password-reset-effects");
    Ok(())
}

async fn phone_number_signup_and_update_inputs<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = fast_builder::<B>(&connection)
        .plugin(PhoneNumberPlugin::new(PhoneNumberConfig::default()))
        .plugin(alibi::plugins::UserManagementPlugin::new())
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    let inputs = [
        r#""+15550001""#,
        "true",
        "false",
        "12345",
        "1.5",
        "1e400",
        "-0",
        "[]",
        r#"{"number":1}"#,
        "null",
    ];
    for (index, phone) in inputs.into_iter().enumerate() {
        let _ = probe
            .post(
                &format!("signup phone {phone}"),
                "/sign-up/email",
                &format!(
                    r#"{{"email":"p{index}@example.test","password":"{PASSWORD}","name":"P","phoneNumber":{phone}}}"#
                ),
                "",
            )
            .await;
    }
    for (index, verified) in ["true", "1", r#""yes""#, "[]", "false", "0", r#""""#, "null"]
        .into_iter()
        .enumerate()
    {
        let _ = probe
            .post(
                &format!("signup verified {verified}"),
                "/sign-up/email",
                &format!(
                    r#"{{"email":"v{index}@example.test","password":"{PASSWORD}","name":"P","phoneNumberVerified":{verified}}}"#
                ),
                "",
            )
            .await;
    }
    let owner = cookies(&signup(&auth, "updater@example.test").await);
    for text in [
        r#"{"phoneNumber":"+15557777777"}"#,
        r#"{"phoneNumber":null}"#,
        r#"{"phoneNumber":0}"#,
        r#"{"name":"Plain update"}"#,
    ] {
        let _ = probe
            .post(&format!("update {text}"), "/update-user", text, &owner)
            .await;
    }
    probe.trace.value("rows", json!(db.count("users").await?));
    probe.trace.assert("phone-number/signup-and-update-inputs");
    B::close(connection).await
}

async fn phone_signin_distinguishes_missing_null_and_empty_credentials<B: Backend>(
    parent: Db,
) -> TestResult {
    for state in ["missing", "null", "empty"] {
        let db = parent.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = fast_builder::<B>(&connection)
            .plugin(PhoneNumberPlugin::new(PhoneNumberConfig::default()))
            .build()
            .await?;
        let owner=call(&auth,request("/sign-up/email",Some(json!({"email":"phone-owner@example.test","password":PASSWORD,"name":"Phone Owner","phoneNumber":"+15550000101"})),""),200).await;
        let id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
        _ = call(
            &auth,
            request(
                "/sign-in/phone-number",
                Some(json!({"phoneNumber":"+15550000101","password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        let sql = match state {
            "missing" => "DELETE FROM accounts WHERE user_id=$1",
            "null" => "UPDATE accounts SET password=NULL WHERE user_id=$1",
            _ => "UPDATE accounts SET password='' WHERE user_id=$1",
        };
        _ = db.execute(sql, &[&id]).await?;
        let before = db
            .tables(&["users", "accounts", "sessions", "verifications"])
            .await?;
        let denied = call(
            &auth,
            request(
                "/sign-in/phone-number",
                Some(json!({"phoneNumber":"+15550000101","password":PASSWORD})),
                "",
            ),
            401,
        )
        .await;
        assert_eq!(
            body(&denied)["code"],
            if state == "missing" {
                "INVALID_PHONE_NUMBER_OR_PASSWORD"
            } else {
                "UNEXPECTED_ERROR"
            }
        );
        assert!(!denied.headers.contains_key("set-cookie"));
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
        authenticated(&auth, &cookies(&owner), "phone-owner@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn phone_self_update_consumes_proof_without_changing_owner_or_callbacks<B: Backend>(
    db: Db,
) -> TestResult {
    struct Count(std::sync::atomic::AtomicUsize);
    #[async_trait]
    impl PhoneVerificationHook for Count {
        async fn verified(
            &self,
            _: &PhoneNumberVerification,
            _: &CallbackContext,
        ) -> AuthResult<()> {
            _ = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let hook = Arc::new(Count(std::sync::atomic::AtomicUsize::new(0)));
    let auth = fast_builder::<B>(&connection)
        .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
            send_otp: Some(outbox.clone()),
            sign_up_on_verification: Some(Arc::new(Identity)),
            callback_on_verification: Some(hook.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let phone = "+15550000102";
    _ = call(
        &auth,
        request(
            "/phone-number/send-otp",
            Some(json!({"phoneNumber":phone})),
            "",
        ),
        200,
    )
    .await;
    let owner = call(
        &auth,
        request(
            "/phone-number/verify",
            Some(json!({"phoneNumber":phone,"code":outbox.last().code})),
            "",
        ),
        200,
    )
    .await;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    assert_eq!(hook.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    _ = call(
        &auth,
        request(
            "/phone-number/send-otp",
            Some(json!({"phoneNumber":phone})),
            "",
        ),
        200,
    )
    .await;
    let code = outbox.last().code;
    let input = json!({"phoneNumber":phone,"code":code,"updatePhoneNumber":true});
    let denied = call(
        &auth,
        request(
            "/phone-number/verify",
            Some(input.clone()),
            &cookies(&owner),
        ),
        400,
    )
    .await;
    assert_eq!(body(&denied)["code"], "PHONE_NUMBER_EXIST");
    assert_eq!(db.count("verifications").await?, 0);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    assert_eq!(hook.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    let replay = call(
        &auth,
        request("/phone-number/verify", Some(input), &cookies(&owner)),
        400,
    )
    .await;
    assert_eq!(body(&replay)["code"], "OTP_NOT_FOUND");
    let next = "+15550000103";
    _ = call(
        &auth,
        request(
            "/phone-number/send-otp",
            Some(json!({"phoneNumber":next})),
            "",
        ),
        200,
    )
    .await;
    let updated = call(
        &auth,
        request(
            "/phone-number/verify",
            Some(json!({"phoneNumber":next,"code":outbox.last().code,"updatePhoneNumber":true})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert_eq!(body(&updated)["user"]["id"], body(&owner)["user"]["id"]);
    assert_eq!(body(&updated)["token"], body(&owner)["token"]);
    assert_eq!(body(&updated)["user"]["phoneNumber"], next);
    assert_eq!(hook.0.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(db.count("sessions").await?, 1);
    B::close(connection).await
}

async fn phone_reset_callback_rejection_precedes_configured_session_revocation<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let reject = fail.clone();
    let auth = fast_builder::<B>(&connection)
        .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
            send_password_reset_otp: Some(outbox.clone()),
            ..Default::default()
        }))
        .plugin(PasswordManagementPlugin::with_config(
            PasswordManagementConfig {
                revoke_sessions_on_password_reset: true,
                on_password_reset: Some(Arc::new(move |_: Value| -> ResetFuture {
                    let failing = reject.load(std::sync::atomic::Ordering::SeqCst);
                    Box::pin(async move {
                        if failing {
                            Err(AuthError::forbidden("reset hook refused"))
                        } else {
                            Ok(())
                        }
                    })
                })),
                ..Default::default()
            },
        ))
        .build()
        .await?;
    let phone = "+15550000104";
    let owner=call(&auth,request("/sign-up/email",Some(json!({"email":"reset-phone@example.test","password":PASSWORD,"name":"Owner","phoneNumber":phone})),""),200).await;
    let sibling = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"reset-phone@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let sessions = db.table("sessions").await?;
    _ = call(
        &auth,
        request(
            "/phone-number/request-password-reset",
            Some(json!({"phoneNumber":phone})),
            "",
        ),
        200,
    )
    .await;
    _=call(&auth,request("/phone-number/reset-password",Some(json!({"phoneNumber":phone,"otp":outbox.last().code,"newPassword":"committed-phone-password"})),""),403).await;
    assert_eq!(db.count("verifications").await?, 0);
    assert_eq!(db.table("sessions").await?, sessions);
    authenticated(&auth, &cookies(&owner), "reset-phone@example.test").await;
    authenticated(&auth, &cookies(&sibling), "reset-phone@example.test").await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    _ = call(
        &auth,
        request(
            "/sign-in/phone-number",
            Some(json!({"phoneNumber":phone,"password":PASSWORD})),
            "",
        ),
        401,
    )
    .await;
    let login = call(
        &auth,
        request(
            "/sign-in/phone-number",
            Some(json!({"phoneNumber":phone,"password":"committed-phone-password"})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&login)["user"]["id"], body(&owner)["user"]["id"]);
    fail.store(false, std::sync::atomic::Ordering::SeqCst);
    _ = call(
        &auth,
        request(
            "/phone-number/request-password-reset",
            Some(json!({"phoneNumber":phone})),
            "",
        ),
        200,
    )
    .await;
    _=call(&auth,request("/phone-number/reset-password",Some(json!({"phoneNumber":phone,"otp":outbox.last().code,"newPassword":"successful-phone-password"})),""),200).await;
    assert_eq!(db.count("sessions").await?, 1);
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn phone_missing_otp_sender_precedes_application_validation<B: Backend>(
    db: Db,
) -> TestResult {
    struct Count(std::sync::atomic::AtomicUsize);
    #[async_trait]
    impl PhoneNumberValidator for Count {
        async fn is_valid(&self, _: &str) -> AuthResult<bool> {
            _ = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(AuthError::internal("validator must not run"))
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let validator = Arc::new(Count(std::sync::atomic::AtomicUsize::new(0)));
    let auth = fast_builder::<B>(&connection)
        .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
            phone_number_validator: Some(validator.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    let denied = call(
        &auth,
        request(
            "/phone-number/send-otp",
            Some(json!({"phoneNumber":"not-a-phone"})),
            "",
        ),
        501,
    )
    .await;
    assert_eq!(body(&denied)["code"], "SEND_OTP_NOT_IMPLEMENTED");
    assert_eq!(validator.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(!denied.headers.contains_key("set-cookie"));
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before
    );
    B::close(connection).await
}

async fn phone_external_verifier_cannot_authorize_local_password_reset<B: Backend>(
    db: Db,
) -> TestResult {
    struct ProviderCount(std::sync::atomic::AtomicUsize);
    #[async_trait]
    impl PhoneOtpVerifier for ProviderCount {
        async fn verify(&self, _: &PhoneOtpDelivery, _: &CallbackContext) -> AuthResult<bool> {
            _ = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(true)
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let provider = Arc::new(ProviderCount(std::sync::atomic::AtomicUsize::new(0)));
    let auth = fast_builder::<B>(&connection)
        .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
            send_otp: Some(outbox.clone()),
            send_password_reset_otp: Some(outbox.clone()),
            verify_otp: Some(provider.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let phone = "+15550000105";
    let owner=call(&auth,request("/sign-up/email",Some(json!({"email":"provider-reset@example.test","password":PASSWORD,"name":"Owner","phoneNumber":phone})),""),200).await;
    _ = call(
        &auth,
        request(
            "/phone-number/send-otp",
            Some(json!({"phoneNumber":phone})),
            "",
        ),
        200,
    )
    .await;
    _ = call(
        &auth,
        request(
            "/phone-number/verify",
            Some(json!({"phoneNumber":phone,"code":outbox.last().code,"disableSession":true})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert_eq!(provider.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    _ = call(
        &auth,
        request(
            "/phone-number/request-password-reset",
            Some(json!({"phoneNumber":phone})),
            "",
        ),
        200,
    )
    .await;
    let code = outbox.last().code;
    let identifier = format!("{phone}-request-password-reset");
    let proof = db
        .text(
            "SELECT expires_at FROM verifications WHERE identifier=$1",
            &[&identifier],
        )
        .await?;
    _ = call(
        &auth,
        request(
            "/phone-number/send-otp",
            Some(json!({"phoneNumber":phone})),
            "",
        ),
        200,
    )
    .await;
    let wrong = if code == "000000" { "999999" } else { "000000" };
    let denied = call(
        &auth,
        request(
            "/phone-number/reset-password",
            Some(json!({"phoneNumber":phone,"otp":wrong,"newPassword":"new-local-password"})),
            "",
        ),
        400,
    )
    .await;
    assert_eq!(body(&denied)["code"], "INVALID_OTP");
    assert_eq!(provider.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        db.text(
            "SELECT value FROM verifications WHERE identifier=$1",
            &[&identifier]
        )
        .await?
        .as_deref(),
        Some(format!("{code}:1").as_str())
    );
    assert_eq!(
        db.text(
            "SELECT expires_at FROM verifications WHERE identifier=$1",
            &[&identifier]
        )
        .await?,
        proof
    );
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    _ = call(
        &auth,
        request(
            "/phone-number/reset-password",
            Some(json!({"phoneNumber":phone,"otp":code,"newPassword":"new-local-password"})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(provider.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
            &[&identifier]
        )
        .await?,
        0
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
            &[phone]
        )
        .await?,
        1
    );
    authenticated(&auth, &cookies(&owner), "provider-reset@example.test").await;
    B::close(connection).await
}

async fn phone_verifier_rejection_preserves_local_proof_until_successful_retry<B: Backend>(
    parent: Db,
) -> TestResult {
    struct MutableProvider(std::sync::atomic::AtomicUsize);
    #[async_trait]
    impl PhoneOtpVerifier for MutableProvider {
        async fn verify(&self, _: &PhoneOtpDelivery, _: &CallbackContext) -> AuthResult<bool> {
            match self.0.load(std::sync::atomic::Ordering::SeqCst) {
                0 => Err(AuthError::Upstream {
                    status: 403,
                    code: "PHONE_VERIFIER_REJECTED",
                    message: "Application verifier rejected",
                }),
                1 => Err(AuthError::internal("provider offline")),
                _ => Ok(true),
            }
        }
    }
    for mode in [0, 1] {
        let db = parent.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let outbox = Arc::new(Outbox::default());
        let provider = Arc::new(MutableProvider(std::sync::atomic::AtomicUsize::new(mode)));
        let auth = fast_builder::<B>(&connection)
            .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
                send_otp: Some(outbox.clone()),
                verify_otp: Some(provider.clone()),
                ..Default::default()
            }))
            .build()
            .await?;
        let phone = "+15550000106";
        let owner=call(&auth,request("/sign-up/email",Some(json!({"email":"retry-phone@example.test","password":PASSWORD,"name":"Owner","phoneNumber":phone})),""),200).await;
        _ = call(
            &auth,
            request(
                "/phone-number/send-otp",
                Some(json!({"phoneNumber":phone})),
                "",
            ),
            200,
        )
        .await;
        let code = outbox.last().code;
        let before = db
            .tables(&["users", "accounts", "sessions", "verifications"])
            .await?;
        _ = call(
            &auth,
            request(
                "/phone-number/verify",
                Some(json!({"phoneNumber":phone,"code":code})),
                &cookies(&owner),
            ),
            if mode == 0 { 403 } else { 500 },
        )
        .await;
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
        provider.0.store(2, std::sync::atomic::Ordering::SeqCst);
        let accepted = call(
            &auth,
            request(
                "/phone-number/verify",
                Some(json!({"phoneNumber":phone,"code":code})),
                &cookies(&owner),
            ),
            200,
        )
        .await;
        assert_eq!(body(&accepted)["user"]["id"], body(&owner)["user"]["id"]);
        assert_eq!(body(&accepted)["user"]["phoneNumberVerified"], true);
        assert_eq!(db.count("verifications").await?, 0);
        assert_eq!(db.count("sessions").await?, 2);
        authenticated(&auth, &cookies(&owner), "retry-phone@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn phone_callback_context_preserves_proof_consumption_and_committed_owner<B: Backend>(
    db: Db,
) -> TestResult {
    struct Application {
        raw: crate::storage::Raw,
        sent: Mutex<Vec<PhoneOtpDelivery>>,
        events: Mutex<Vec<(&'static str, AuthRequest, bool)>>,
    }
    impl Application {
        async fn capture(
            &self,
            phase: &'static str,
            c: &CallbackContext,
            number: &str,
        ) -> AuthResult<bool> {
            let live = self
                .raw
                .count_where(
                    "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
                    &[number],
                )
                .await
                .map_err(|e| AuthError::internal(e.to_string()))?
                == 1;
            self.events
                .lock()
                .unwrap()
                .push((phase, c.request.clone().unwrap(), live));
            Ok(live)
        }
    }
    #[async_trait]
    impl SendPhoneOtp for Application {
        async fn send(&self, d: &PhoneOtpDelivery, c: &CallbackContext) -> AuthResult<()> {
            assert!(self.capture("sender", c, &d.phone_number).await?);
            self.sent.lock().unwrap().push(d.clone());
            Ok(())
        }
    }
    #[async_trait]
    impl PhoneOtpVerifier for Application {
        async fn verify(&self, d: &PhoneOtpDelivery, c: &CallbackContext) -> AuthResult<bool> {
            let live = self.capture("verifier", c, &d.phone_number).await?;
            Ok(live
                && self
                    .sent
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|sent| sent.phone_number == d.phone_number && sent.code == d.code))
        }
    }
    #[async_trait]
    impl PhoneVerificationHook for Application {
        async fn verified(
            &self,
            d: &PhoneNumberVerification,
            c: &CallbackContext,
        ) -> AuthResult<()> {
            assert!(!self.capture("completed", c, &d.phone_number).await?);
            assert_eq!(self.raw.count_where("SELECT COUNT(*) FROM users WHERE id=$1 AND phone_number=$2 AND phone_number_verified=1",&[&d.user.id,&d.phone_number]).await.map_err(|e| AuthError::internal(e.to_string()))?,1);
            assert_eq!(
                self.raw
                    .count_where("SELECT COUNT(*) FROM sessions", &[])
                    .await
                    .map_err(|e| AuthError::internal(e.to_string()))?,
                0
            );
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let application = Arc::new(Application {
        raw: db.raw.clone(),
        sent: Mutex::new(Vec::new()),
        events: Mutex::new(Vec::new()),
    });
    let auth = fast_builder::<B>(&connection)
        .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
            send_otp: Some(application.clone()),
            verify_otp: Some(application.clone()),
            callback_on_verification: Some(application.clone()),
            sign_up_on_verification: Some(Arc::new(Identity)),
            ..Default::default()
        }))
        .build()
        .await?;
    let marked = |path: &str, input: Value| {
        let mut request = super::request(path, Some(input), "")
            .with_url(url::Url::parse(&format!("{ORIGIN}/api/auth{path}")).unwrap());
        _ = request
            .headers
            .insert("x-callback-probe".into(), "issue207".into());
        request
    };
    let number = "+15550000207";
    let sent = marked("/phone-number/send-otp", json!({"phoneNumber":number}));
    _ = call(&auth, sent.clone(), 200).await;
    let delivery = application.sent.lock().unwrap().last().unwrap().clone();
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    _ = call(
        &auth,
        marked(
            "/phone-number/verify",
            json!({"phoneNumber":"+15550000208","code":delivery.code}),
        ),
        400,
    )
    .await;
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before
    );
    let verify = marked(
        "/phone-number/verify",
        json!({"phoneNumber":number,"code":delivery.code}),
    );
    let accepted = call(&auth, verify.clone(), 200).await;
    let events = application.events.lock().unwrap().clone();
    assert_eq!(
        events
            .iter()
            .map(|(phase, _, live)| (*phase, *live))
            .collect::<Vec<_>>(),
        [
            ("sender", true),
            ("verifier", false),
            ("verifier", true),
            ("completed", false)
        ]
    );
    for (index, (_, actual, _)) in events.iter().enumerate() {
        let expected = if index == 0 { &sent } else { &verify };
        assert_eq!(actual.url(), expected.url());
        assert_eq!(actual.method, HttpMethod::Post);
        assert_eq!(actual.headers["x-callback-probe"], "issue207");
        if index != 1 {
            assert_eq!(actual.body, expected.body);
        }
    }
    let current = body(
        &call(
            &auth,
            request("/get-session", None, &cookies(&accepted)),
            200,
        )
        .await,
    );
    assert_eq!(current["user"]["id"], body(&accepted)["user"]["id"]);
    assert_eq!(current["user"]["phoneNumber"], number);
    assert_eq!(current["user"]["phoneNumberVerified"], true);
    assert_eq!(db.count("accounts").await?, 0);
    assert_eq!(db.count("sessions").await?, 1);
    assert_eq!(db.count("verifications").await?, 0);
    let stable = db.tables(&["users", "accounts", "sessions"]).await?;
    _ = call(&auth, verify, 400).await;
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, stable);
    B::close(connection).await
}

async fn revoked_compact_owner_consumes_local_phone_proof_without_recreating_browser<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::{CookieCacheConfig, CookieCacheStrategy};
    struct Receipt(Mutex<Vec<Value>>);
    #[async_trait]
    impl PhoneVerificationHook for Receipt {
        async fn verified(
            &self,
            r: &PhoneNumberVerification,
            _: &CallbackContext,
        ) -> AuthResult<()> {
            self.0
                .lock()
                .unwrap()
                .push(json!({"user":r.user,"phone":r.phone_number}));
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            strategy: CookieCacheStrategy::Compact,
            ..Default::default()
        });
    let outbox = Arc::new(Outbox::default());
    let hook = Arc::new(Receipt(Mutex::new(Vec::new())));
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
            send_otp: Some(outbox.clone()),
            callback_on_verification: Some(hook.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let foreign = signup(&auth, "foreign@example.test").await;
    let baseline = db.tables(&["users", "accounts", "sessions"]).await?;
    let owner = signup(&auth, "owner@example.test").await;
    let id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let token = body(&owner)["token"].as_str().unwrap().to_owned();
    let jar = cookies(&owner);
    let phone = "+15550100001";
    _ = call(
        &auth,
        request(
            "/phone-number/send-otp",
            Some(json!({"phoneNumber":phone})),
            &jar,
        ),
        200,
    )
    .await;
    let delivery = outbox.last();
    assert_eq!(delivery.phone_number, phone);
    assert_eq!(
        db.text(
            "SELECT value FROM verifications WHERE identifier=$1",
            &[phone]
        )
        .await?
        .as_deref(),
        Some(format!("{}:0", delivery.code).as_str())
    );
    assert_eq!(
        db.execute("DELETE FROM sessions WHERE token=$1", &[&token])
            .await?,
        1
    );
    let verified = call(
        &auth,
        request(
            "/phone-number/verify",
            Some(json!({"phoneNumber":phone,"code":delivery.code,"updatePhoneNumber":true})),
            &jar,
        ),
        200,
    )
    .await;
    assert!(
        !verified
            .headers
            .get_all("set-cookie")
            .any(|x| x.starts_with("better-auth.session_token=") && !x.contains("Max-Age=0"))
    );
    assert_eq!(
        db.text("SELECT phone_number FROM users WHERE id=$1", &[&id])
            .await?
            .as_deref(),
        Some(phone)
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE id=$1 AND phone_number_verified=true",
            &[&id]
        )
        .await?,
        1
    );
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM sessions WHERE user_id=$1", &[&id])
            .await?,
        0
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
            &[phone]
        )
        .await?,
        0
    );
    let receipts = hook.0.lock().unwrap().clone();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["user"]["id"], id);
    assert_eq!(receipts[0]["phone"], phone);
    let after = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    _ = call(
        &auth,
        request(
            "/phone-number/verify",
            Some(json!({"phoneNumber":phone,"code":delivery.code,"updatePhoneNumber":true})),
            &jar,
        ),
        400,
    )
    .await;
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        after
    );
    assert_eq!(hook.0.lock().unwrap().len(), 1);
    for (before, now) in baseline.iter().zip(after.iter()) {
        let before: Vec<Value> = serde_json::from_str(before)?;
        let now: Vec<Value> = serde_json::from_str(now)?;
        assert!(before.iter().all(|x| now.contains(x)));
    }
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    let recovered = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&recovered)["user"]["id"], id);
    B::close(connection).await
}

async fn phone_background_notification_lifecycle<B: Backend>(db: Db) -> TestResult {
    use alibi::{BackgroundTaskCompletion, BackgroundTaskHandler};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::Notify;
    #[derive(Default)]
    struct Sender {
        armed: AtomicBool,
        deliveries: Mutex<Vec<(PhoneOtpDelivery, String, Option<String>)>>,
        received: Notify,
        entered: Notify,
        release: Notify,
        finished: Notify,
    }
    #[async_trait]
    impl SendPhoneOtp for Sender {
        async fn send(&self, d: &PhoneOtpDelivery, c: &CallbackContext) -> AuthResult<()> {
            let r = c.request.as_ref().unwrap();
            self.deliveries.lock().unwrap().push((
                d.clone(),
                r.path.clone(),
                r.headers.get("x-delivery-marker").cloned(),
            ));
            self.received.notify_one();
            if self.armed.load(Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
                assert_eq!(
                    r.headers.get("x-delivery-marker").map(String::as_str),
                    Some("owned-context")
                );
                self.finished.notify_one();
                return Err(AuthError::internal("application gateway unavailable"));
            }
            Ok(())
        }
    }
    struct Observer(bool);
    impl BackgroundTaskHandler for Observer {
        fn handle(&self, task: BackgroundTaskCompletion) -> AuthResult<()> {
            drop(task);
            if self.0 {
                Err(AuthError::internal("application observer refused"))
            } else {
                Ok(())
            }
        }
    }
    for observer_rejects in [false, true] {
        for route in [
            "/phone-number/send-otp",
            "/sign-in/phone-number",
            "/phone-number/request-password-reset",
        ] {
            let db = db.fresh().await?;
            let (connection, _) = db.migrated::<B>(SECRET).await?;
            let sender = Arc::new(Sender::default());
            let config = AuthConfig::new(SECRET)
                .base_url(ORIGIN)
                .background_tasks(Arc::new(Observer(observer_rejects)));
            let auth = AuthBuilder::new(config.clone())
                .store(B::store(Arc::new(config), &connection))
                .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
                .plugin(super::auth_probe::fast_password())
                .plugin(alibi::plugins::SessionManagementPlugin::new())
                .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
                    send_otp: Some(sender.clone()),
                    send_password_reset_otp: Some(sender.clone()),
                    require_verification: true,
                    ..Default::default()
                }))
                .build()
                .await?;
            let phone = "+15554443333";
            let signed = call(&auth,request("/sign-up/email",Some(json!({"email":"background-phone@example.test","name":"Phone owner","password":PASSWORD,"phoneNumber":phone})),""),200).await;
            let foreign = signup(&auth, "background-foreign@example.test").await;
            if route == "/phone-number/request-password-reset" {
                let _ = call(
                    &auth,
                    request(
                        "/phone-number/send-otp",
                        Some(json!({"phoneNumber":phone})),
                        "",
                    ),
                    200,
                )
                .await;
                tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    sender.received.notified(),
                )
                .await?;
                let code = sender
                    .deliveries
                    .lock()
                    .unwrap()
                    .last()
                    .unwrap()
                    .0
                    .code
                    .clone();
                let _ = call(
                    &auth,
                    request(
                        "/phone-number/verify",
                        Some(json!({"phoneNumber":phone,"code":code,"disableSession":true})),
                        "",
                    ),
                    200,
                )
                .await;
            }
            sender.deliveries.lock().unwrap().clear();
            sender.armed.store(true, Ordering::SeqCst);
            let before = db.tables(&["users", "accounts", "sessions"]).await?;
            let mut input = request(
                route,
                Some(json!({"phoneNumber":phone,"password":PASSWORD})),
                &cookies(&signed),
            );
            _ = input
                .headers
                .insert("x-delivery-marker".into(), "owned-context".into());
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                Box::pin(auth.handle_request(input)),
            )
            .await??;
            assert_eq!(
                result.status,
                if route == "/sign-in/phone-number" {
                    401
                } else {
                    200
                }
            );
            assert!(result.headers.get_all("set-cookie").next().is_none());
            if route == "/sign-in/phone-number" {
                assert_eq!(body(&result)["code"], "PHONE_NUMBER_NOT_VERIFIED");
            } else {
                assert_eq!(
                    body(&result),
                    if route == "/phone-number/send-otp" {
                        json!({"message":"code sent"})
                    } else {
                        json!({"status":true})
                    }
                );
            }
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                sender.entered.notified(),
            )
            .await?;
            let (delivery, path, marker) =
                sender.deliveries.lock().unwrap().last().unwrap().clone();
            assert_eq!(path, route);
            assert_eq!(marker.as_deref(), Some("owned-context"));
            assert_eq!(delivery.phone_number, phone);
            let identifier = if route == "/phone-number/request-password-reset" {
                format!("{phone}-request-password-reset")
            } else {
                phone.to_owned()
            };
            let proof = db.tables(&["verifications"]).await?;
            assert_eq!(
                db.text(
                    "SELECT value FROM verifications WHERE identifier=$1",
                    &[&identifier]
                )
                .await?
                .unwrap(),
                if route == "/sign-in/phone-number" {
                    delivery.code.clone()
                } else {
                    format!("{}:0", delivery.code)
                }
            );
            assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
            sender.release.notify_one();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                sender.finished.notified(),
            )
            .await?;
            assert_eq!(db.tables(&["verifications"]).await?, proof);
            let (path, input) = if route == "/phone-number/request-password-reset" {
                (
                    "/phone-number/reset-password",
                    json!({"phoneNumber":phone,"otp":delivery.code,"newPassword":"changed-phone-password-123"}),
                )
            } else {
                (
                    "/phone-number/verify",
                    json!({"phoneNumber":phone,"code":delivery.code,"disableSession":true}),
                )
            };
            let _ = call(&auth, request(path, Some(input.clone()), ""), 200).await;
            assert!(
                db.text(
                    "SELECT value FROM verifications WHERE identifier=$1",
                    &[&identifier]
                )
                .await?
                .is_none()
            );
            let _ = call(&auth, request(path, Some(input), ""), 400).await;
            assert_eq!(sender.deliveries.lock().unwrap().len(), 1);
            authenticated(&auth, &cookies(&foreign), "background-foreign@example.test").await;
            B::close(connection).await?;
        }
    }
    Ok(())
}

async fn phone_trusted_device_completion_forwards_rotated_owned_proof<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::{
        TwoFactorPlugin,
        two_factor::{SendTwoFactorOtp, TwoFactorConfig},
    };
    #[derive(Default)]
    struct Factor(Mutex<Vec<String>>);
    #[async_trait]
    impl SendTwoFactorOtp for Factor {
        async fn send(&self, _: &alibi::UserView, code: &str) -> AuthResult<()> {
            self.0.lock().unwrap().push(code.into());
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let factor = Arc::new(Factor::default());
    let auth = fast_builder::<B>(&connection)
        .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
            send_otp: Some(outbox.clone()),
            require_verification: true,
            ..Default::default()
        }))
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            send_otp: Some(factor.clone()),
            skip_verification_on_enable: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let number = "+15556667777";
    let signed = call(&auth,request("/sign-up/email",Some(json!({"email":"trusted-phone@example.test","name":"Phone owner","password":PASSWORD,"phoneNumber":number})),""),200).await;
    let id = body(&signed)["user"]["id"].as_str().unwrap().to_owned();
    let foreign = signup(&auth, "trusted-phone-foreign@example.test").await;
    let _ = call(
        &auth,
        request(
            "/phone-number/send-otp",
            Some(json!({"phoneNumber":number})),
            "",
        ),
        200,
    )
    .await;
    let _ = call(
        &auth,
        request(
            "/phone-number/verify",
            Some(json!({"phoneNumber":number,"code":outbox.last().code,"disableSession":true})),
            "",
        ),
        200,
    )
    .await;
    let _ = call(
        &auth,
        request(
            "/two-factor/enable",
            Some(json!({"password":PASSWORD,"method":"otp"})),
            &cookies(&signed),
        ),
        200,
    )
    .await;
    let pending = call(
        &auth,
        request(
            "/sign-in/phone-number",
            Some(json!({"phoneNumber":number,"password":PASSWORD,"rememberMe":false})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&pending)["twoFactorRedirect"], true);
    assert!(body(&pending).get("token").is_none());
    let _ = call(
        &auth,
        request("/two-factor/send-otp", Some(json!({})), &cookies(&pending)),
        200,
    )
    .await;
    let code = factor.0.lock().unwrap().last().unwrap().clone();
    let done = call(
        &auth,
        request(
            "/two-factor/verify-otp",
            Some(json!({"code":code,"trustDevice":true})),
            &cookies(&pending),
        ),
        200,
    )
    .await;
    assert_eq!(body(&done)["user"]["id"], id);
    authenticated(&auth, &cookies(&done), "trusted-phone@example.test").await;
    let original = cookies(&done)
        .split("; ")
        .find(|h| h.starts_with("better-auth.trust_device="))
        .unwrap()
        .to_owned();
    let old_key = db.text("SELECT identifier FROM verifications WHERE identifier LIKE 'trust-device-%' AND value=$1",&[&id]).await?.unwrap();
    let foreign_state = db
        .text(
            "SELECT token FROM sessions WHERE user_id=$1",
            &[body(&foreign)["user"]["id"].as_str().unwrap()],
        )
        .await?;
    let trusted = call(
        &auth,
        request(
            "/sign-in/phone-number",
            Some(json!({"phoneNumber":number,"password":PASSWORD})),
            &original,
        ),
        200,
    )
    .await;
    assert_eq!(body(&trusted)["user"]["id"], id);
    assert_ne!(body(&trusted)["token"], body(&done)["token"]);
    assert!(body(&trusted).get("twoFactorRedirect").is_none());
    let rotated = cookies(&trusted)
        .split("; ")
        .find(|h| h.starts_with("better-auth.trust_device="))
        .unwrap()
        .to_owned();
    assert_ne!(rotated, original);
    assert!(
        auth.store()
            .get_latest_verification_by_identifier(&old_key)
            .await?
            .is_none()
    );
    let next_key = db.text("SELECT identifier FROM verifications WHERE identifier LIKE 'trust-device-%' AND value=$1",&[&id]).await?.unwrap();
    assert_ne!(old_key, next_key);
    authenticated(&auth, &cookies(&trusted), "trusted-phone@example.test").await;
    let count = db.count("sessions").await?;
    let replay = call(
        &auth,
        request(
            "/sign-in/phone-number",
            Some(json!({"phoneNumber":number,"password":PASSWORD})),
            &original,
        ),
        200,
    )
    .await;
    assert_eq!(body(&replay)["twoFactorRedirect"], true);
    assert_eq!(db.count("sessions").await?, count);
    assert!(
        auth.store()
            .get_latest_verification_by_identifier(&next_key)
            .await?
            .is_some()
    );
    let fresh = call(
        &auth,
        request(
            "/sign-in/phone-number",
            Some(json!({"phoneNumber":number,"password":PASSWORD})),
            &rotated,
        ),
        200,
    )
    .await;
    assert_eq!(body(&fresh)["user"]["id"], id);
    assert!(body(&fresh).get("twoFactorRedirect").is_none());
    authenticated(&auth, &cookies(&fresh), "trusted-phone@example.test").await;
    assert_eq!(
        db.text(
            "SELECT token FROM sessions WHERE user_id=$1",
            &[body(&foreign)["user"]["id"].as_str().unwrap()]
        )
        .await?,
        foreign_state
    );
    B::close(connection).await
}
