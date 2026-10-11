//! Passkey registration ownership, application hooks, challenge reuse and
//! session freshness.
use super::passkey_attestation::{Shape, Signature, client};
use super::passkey_matrix::{
    ATTESTED, Authenticator, BACKUP_ELIGIBLE, USER_PRESENT, USER_VERIFIED,
};
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::PasskeyPlugin;
use alibi::plugins::passkey::{
    PasskeyAuthenticationAfterVerification, PasskeyAuthenticationConfig,
    PasskeyAuthenticationContext, PasskeyRegistrationAfterVerification, PasskeyRegistrationConfig,
    PasskeyRegistrationContext, PasskeyRegistrationOverride, PasskeyRegistrationUser,
    PasskeyUserResolver, VerifiedPasskeyAuthentication, VerifiedPasskeyRegistration,
};
use alibi::utils::json::JsValue;
use alibi::{AuthError, AuthResult};

backend_tests!(
    passkey_registration_ownership,
    passkey_authentication_hooks,
    passkey_session_freshness,
    passkey_input_types,
    passkey_auth_callback_reassignment_keeps_verified_owner,
    passkey_registration_forces_credential_properties_over_static_false,
    passkey_verification_freshness_retains_issued_proof
);

type Observed = (usize, u32, bool, bool, bool);

#[derive(Default)]
struct Policy {
    mode: Mutex<&'static str>,
    resolved: Mutex<String>,
    other: Mutex<String>,
    registered: Mutex<Vec<(String, u64, bool)>>,
    authenticated: Mutex<Vec<Observed>>,
    url: Mutex<String>,
}

#[async_trait::async_trait]
impl PasskeyUserResolver for Policy {
    async fn resolve_user(
        &self,
        _: &PasskeyRegistrationContext<'_>,
        context: Option<&str>,
    ) -> AuthResult<Option<PasskeyRegistrationUser>> {
        assert_eq!(context, Some("signup"));
        Ok(Some(PasskeyRegistrationUser {
            id: self.resolved.lock().unwrap().clone(),
            name: "resolved".into(),
            display_name: None,
        }))
    }
}

#[async_trait::async_trait]
impl PasskeyRegistrationAfterVerification for Policy {
    async fn after_verification(
        &self,
        _: &PasskeyRegistrationContext<'_>,
        verification: &VerifiedPasskeyRegistration,
        _: &PasskeyRegistrationUser,
        _: &JsValue,
        stored_context: Option<&str>,
    ) -> AuthResult<Option<PasskeyRegistrationOverride>> {
        self.registered.lock().unwrap().push((
            verification.credential_id.clone(),
            verification.counter,
            verification.backed_up,
        ));
        assert_eq!(stored_context, Some("signup"));
        match *self.mode.lock().unwrap() {
            "other" => Ok(Some(PasskeyRegistrationOverride {
                user_id: Some(self.other.lock().unwrap().clone()),
                name: Some("  Override name  ".into()),
            })),
            "empty" => Ok(Some(PasskeyRegistrationOverride {
                user_id: Some(String::new()),
                name: Some(String::new()),
            })),
            "api" => Err(AuthError::forbidden("registration denied")),
            "internal" => Err(AuthError::internal("registration unavailable")),
            _ => Ok(None),
        }
    }
}

#[async_trait::async_trait]
impl PasskeyAuthenticationAfterVerification for Policy {
    async fn after_verification(
        &self,
        _: &PasskeyAuthenticationContext<'_>,
        verification: &VerifiedPasskeyAuthentication,
        _: &JsValue,
    ) -> AuthResult<()> {
        let result = &verification.result;
        self.authenticated.lock().unwrap().push((
            result.cred_id().as_slice().len(),
            result.counter(),
            result.user_verified(),
            result.backup_eligible(),
            result.backup_state(),
        ));
        assert_eq!(verification.origin, ORIGIN);
        assert_eq!(verification.rp_id, "localhost");
        let mode = *self.mode.lock().unwrap();
        match mode {
            "api" => Err(AuthError::forbidden("authentication denied")),
            "internal" => Err(AuthError::internal("authentication unavailable")),
            "delete" => {
                let url = self.url.lock().unwrap().clone();
                let pool = alibi::sqlx::sqlx::SqlitePool::connect(&url).await.unwrap();
                _ = alibi::sqlx::sqlx::query("DELETE FROM passkeys")
                    .execute(&pool)
                    .await
                    .unwrap();
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

fn plugin(policy: &Arc<Policy>) -> PasskeyPlugin {
    PasskeyPlugin::new()
        .origins(vec![ORIGIN.into()])
        .registration(PasskeyRegistrationConfig {
            require_session: false,
            resolve_user: Some(policy.clone()),
            after_verification: Some(policy.clone()),
            ..Default::default()
        })
        .authentication(PasskeyAuthenticationConfig {
            extensions: None,
            after_verification: Some(policy.clone()),
        })
}

fn proof(key: &Authenticator, shape: &Shape, challenge: &Value) -> Value {
    let client = client(challenge);
    let bytes = serde_json::to_vec(&client).unwrap();
    key.registration(&client, &shape.build(key, &bytes), false)
}

fn keyed(seed: u8) -> (Authenticator, Shape) {
    (
        Authenticator::new(seed, &format!("hook-key-{seed}")),
        Shape {
            flags: USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | ATTESTED,
            ..Default::default()
        },
    )
}

async fn passkey_registration_ownership<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(Policy::default());
    let auth = builder::<B>(&connection)
        .plugin(plugin(&policy))
        .build()
        .await?;
    let mut trace = Trace::default();
    let first = signup(&auth, "passkey-first@example.com").await;
    let second = signup(&auth, "passkey-second@example.com").await;
    let (first_id, second_id) = (
        body(&first)["user"]["id"].as_str().unwrap().to_owned(),
        body(&second)["user"]["id"].as_str().unwrap().to_owned(),
    );
    trace.mask(&first_id);
    trace.mask(&second_id);
    *policy.resolved.lock().unwrap() = second_id.clone();
    *policy.other.lock().unwrap() = first_id.clone();
    let session = cookies(&first);

    let options = async |cookie: &str| {
        call(
            &auth,
            {
                let mut request = request("/passkey/generate-register-options", None, cookie);
                request.set_query_pairs([("context", "signup")]);
                request
            },
            200,
        )
        .await
    };
    let verify = async |trace: &mut Trace,
                        label: &str,
                        options: &AuthResponse,
                        cookie: &str,
                        seed: u8,
                        extra: Value| {
        let (key, shape) = keyed(seed);
        let mut input = json!({"response": proof(&key, &shape, &body(options)["challenge"])});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let response = Box::pin(auth.handle_request(request(
            "/passkey/verify-registration",
            Some(input),
            &format!("{cookie}; {}", cookies(options)),
        )))
        .await
        .unwrap();
        trace.response(label, &response);
        response
    };

    let issued = options("").await;
    _ = verify(
        &mut trace,
        "someone else finishes the challenge",
        &issued,
        &session,
        70,
        json!({}),
    )
    .await;
    let issued = options("").await;
    let finished = verify(&mut trace, "resolved user", &issued, "", 71, json!({})).await;
    assert_eq!(body(&finished)["userId"], second_id);
    _ = verify(&mut trace, "replayed challenge", &issued, "", 71, json!({})).await;
    let mut request_without_cookie = request(
        "/passkey/verify-registration",
        Some(json!({"response": {}})),
        "",
    );
    request_without_cookie.method = HttpMethod::Post;
    trace.response(
        "missing challenge cookie",
        &Box::pin(auth.handle_request(request_without_cookie)).await?,
    );
    let authentication = call(
        &auth,
        request("/passkey/generate-authenticate-options", None, ""),
        200,
    )
    .await;
    _ = verify(
        &mut trace,
        "authentication challenge",
        &authentication,
        "",
        72,
        json!({}),
    )
    .await;
    let issued = options("").await;
    let (key, shape) = keyed(73);
    let mut cross = request(
        "/passkey/verify-authentication",
        Some(json!({"response": key.assertion(
            &json!({"type": "webauthn.get", "challenge": body(&issued)["challenge"], "origin": ORIGIN}),
            "localhost",
            USER_PRESENT,
            1,
        )})),
        &cookies(&issued),
    );
    cross.method = HttpMethod::Post;
    trace.response(
        "registration challenge for authentication",
        &Box::pin(auth.handle_request(cross)).await?,
    );
    drop(shape);

    for (index, mode) in ["other", "empty", "api", "internal"]
        .into_iter()
        .enumerate()
    {
        *policy.mode.lock().unwrap() = mode;
        *policy.other.lock().unwrap() = first_id.clone();
        let seed = 80 + 2 * u8::try_from(index)?;
        let issued = options("").await;
        _ = verify(
            &mut trace,
            &format!("anonymous hook {mode}"),
            &issued,
            "",
            seed,
            json!({}),
        )
        .await;
        *policy.other.lock().unwrap() = second_id.clone();
        let issued = options(&session).await;
        _ = verify(
            &mut trace,
            &format!("session hook {mode}"),
            &issued,
            &session,
            seed + 1,
            json!({"name": "  Given  "}),
        )
        .await;
    }
    *policy.mode.lock().unwrap() = "other";
    let issued = options("").await;
    let created = verify(
        &mut trace,
        "override with session creation",
        &issued,
        "",
        90,
        json!({"createSession": true}),
    )
    .await;
    assert!(cookies(&created).contains("session_token"));
    *policy.mode.lock().unwrap() = "";
    _ = db
        .execute(
            "CREATE TRIGGER fail_session_insert BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'forced'); END",
            &[],
        )
        .await?;
    let issued = options("").await;
    _ = verify(
        &mut trace,
        "session creation storage failure",
        &issued,
        "",
        91,
        json!({"createSession": true}),
    )
    .await;
    _ = db.execute("DROP TRIGGER fail_session_insert", &[]).await?;

    let shapes: Vec<(&str, Shape)> = vec![
        (
            "core packed corrupt signature",
            Shape {
                fmt: "packed",
                signature: Signature::Corrupt,
                ..keyed(0).1
            },
        ),
        (
            "core packed algorithm mismatch",
            Shape {
                fmt: "packed",
                statement_alg: Some(-7),
                ..keyed(0).1
            },
        ),
        (
            "core packed on another curve",
            Shape {
                fmt: "packed",
                curve: 7,
                ..keyed(0).1
            },
        ),
        (
            "core packed valid",
            Shape {
                fmt: "packed",
                ..keyed(0).1
            },
        ),
    ];
    for (index, (label, shape)) in shapes.into_iter().enumerate() {
        let issued = options("").await;
        let key = Authenticator::new(100 + u8::try_from(index)?, &format!("packed-{index}"));
        let response = Box::pin(auth.handle_request(request(
            "/passkey/verify-registration",
            Some(json!({"response": proof(&key, &shape, &body(&issued)["challenge"])})),
            &cookies(&issued),
        )))
        .await?;
        trace.response(label, &response);
    }
    assert!(!policy.registered.lock().unwrap().is_empty());
    trace.assert("passkey/registration-ownership");
    B::close(connection).await
}

async fn passkey_authentication_hooks<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(Policy::default());
    *policy.url.lock().unwrap() = db.url.clone();
    let auth = builder::<B>(&connection)
        .plugin(plugin(&policy))
        .build()
        .await?;
    let mut trace = Trace::default();
    let owner = signup(&auth, "hooks-owner@example.com").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    trace.mask(&owner_id);
    let session = cookies(&owner);
    *policy.resolved.lock().unwrap() = owner_id;
    let core = Authenticator::new(7, "hooks-core");
    let raw = Authenticator::new(9, "hooks-raw");
    for (key, shape) in [
        (
            &core,
            Shape {
                flags: USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | ATTESTED,
                ..Default::default()
            },
        ),
        (
            &raw,
            Shape {
                fmt: "packed",
                alg: -7,
                flags: USER_PRESENT | BACKUP_ELIGIBLE | ATTESTED,
                ..Default::default()
            },
        ),
    ] {
        let options = call(
            &auth,
            {
                let mut request = request("/passkey/generate-register-options", None, &session);
                request.set_query_pairs([("context", "signup")]);
                request
            },
            200,
        )
        .await;
        _ = call(
            &auth,
            request(
                "/passkey/verify-registration",
                Some(json!({"response": proof(key, &shape, &body(&options)["challenge"])})),
                &format!("{session}; {}", cookies(&options)),
            ),
            200,
        )
        .await;
    }
    let mut counter = 1;
    for (label, key, mode, flags) in [
        (
            "core hook denies",
            &core,
            "api",
            USER_PRESENT | USER_VERIFIED,
        ),
        ("core hook fails", &core, "internal", USER_PRESENT),
        ("raw hook denies", &raw, "api", USER_PRESENT),
        ("raw hook fails", &raw, "internal", USER_PRESENT),
        (
            "raw hook observes",
            &raw,
            "",
            USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE,
        ),
        (
            "core hook observes",
            &core,
            "",
            USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE,
        ),
        ("raw hook removes the row", &raw, "delete", USER_PRESENT),
    ] {
        *policy.mode.lock().unwrap() = mode;
        counter += 1;
        let options = call(
            &auth,
            request("/passkey/generate-authenticate-options", None, ""),
            200,
        )
        .await;
        let client = json!({"type": "webauthn.get", "challenge": body(&options)["challenge"], "origin": ORIGIN});
        let response = Box::pin(auth.handle_request(request(
            "/passkey/verify-authentication",
            Some(json!({"response": key.assertion(&client, "localhost", flags, counter)})),
            &cookies(&options),
        )))
        .await?;
        trace.response(label, &response);
    }
    trace.value(
        "observed",
        json!(policy.authenticated.lock().unwrap().clone()),
    );
    trace.value("rows left", json!(db.count("passkeys").await?));
    trace.assert("passkey/authentication-hooks");
    B::close(connection).await
}

async fn passkey_session_freshness<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(PasskeyPlugin::new())
        .build()
        .await?;
    let signed_up = signup(&auth, "stale-passkey@example.com").await;
    let user_id = body(&signed_up)["user"]["id"].as_str().unwrap().to_owned();
    let cookie = cookies(&signed_up);
    _ = call(
        &auth,
        request("/passkey/generate-register-options", None, &cookie),
        200,
    )
    .await;
    db.set_timestamp(
        "sessions",
        "created_at",
        ("user_id", &user_id),
        chrono::Utc::now() - chrono::Duration::days(3),
    )
    .await?;
    let stale = call(
        &auth,
        request("/passkey/generate-register-options", None, &cookie),
        403,
    )
    .await;
    assert_eq!(body(&stale)["code"], "SESSION_NOT_FRESH");
    B::close(connection).await
}

async fn passkey_input_types<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(PasskeyPlugin::new())
        .build()
        .await?;
    let owner = cookies(&signup(&auth, "passkey-types@example.com").await);
    let mut trace = Trace::default();
    for (label, text) in [
        ("missing response", r#"{}"#),
        (
            "session flag null",
            r#"{"response":{},"createSession":null}"#,
        ),
        (
            "session flag array",
            r#"{"response":{},"createSession":[]}"#,
        ),
        (
            "session flag object",
            r#"{"response":{},"createSession":{}}"#,
        ),
        (
            "session flag string",
            r#"{"response":{},"createSession":"yes"}"#,
        ),
        (
            "session flag number",
            r#"{"response":{},"createSession":5}"#,
        ),
        ("name number", r#"{"response":{},"name":5}"#),
        ("name boolean", r#"{"response":{},"name":true}"#),
        ("name object", r#"{"response":{},"name":{}}"#),
        ("name array", r#"{"response":{},"name":[]}"#),
        ("name null", r#"{"response":{},"name":null}"#),
    ] {
        let mut register = request("/passkey/verify-registration", None, &owner);
        register.method = HttpMethod::Post;
        register.body = Some(text.as_bytes().to_vec());
        trace.response(
            &format!("registration {label}"),
            &Box::pin(auth.handle_request(register)).await?,
        );
    }
    for (label, text) in [
        ("missing", r#"{}"#),
        ("null", r#"{"response":null}"#),
        ("array", r#"{"response":[]}"#),
        ("string", r#"{"response":"x"}"#),
        ("number", r#"{"response":5}"#),
        ("boolean", r#"{"response":true}"#),
    ] {
        let mut authenticate = request("/passkey/verify-authentication", None, "");
        authenticate.method = HttpMethod::Post;
        authenticate.body = Some(text.as_bytes().to_vec());
        trace.response(
            &format!("authentication response {label}"),
            &Box::pin(auth.handle_request(authenticate)).await?,
        );
    }
    trace.assert("passkey/input-types");
    B::close(connection).await
}

async fn passkey_auth_callback_reassignment_keeps_verified_owner<B: Backend>(db: Db) -> TestResult {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    struct Reassign {
        raw: crate::storage::Raw,
        foreign: Mutex<String>,
        seen: Mutex<Vec<Value>>,
    }
    #[async_trait::async_trait]
    impl PasskeyAuthenticationAfterVerification for Reassign {
        async fn after_verification(
            &self,
            context: &PasskeyAuthenticationContext<'_>,
            verification: &VerifiedPasskeyAuthentication,
            _: &JsValue,
        ) -> AuthResult<()> {
            let credential = URL_SAFE_NO_PAD.encode(verification.result.cred_id().as_slice());
            let foreign = self.foreign.lock().unwrap().clone();
            self.seen.lock().unwrap().push(json!({"credential":credential,"counter":verification.result.counter(),"origin":verification.origin,"rpId":verification.rp_id,"path":context.request.path}));
            let changed=self.raw.execute("UPDATE passkeys SET user_id=$1, name='Application updated', backed_up=1, device_type='application-updated' WHERE credential_id=$2",&[&foreign,&credential]).await.map_err(|error|AuthError::internal(error.to_string()))?;
            assert_eq!(changed, 1);
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(Reassign {
        raw: db.raw.clone(),
        foreign: Mutex::new(String::new()),
        seen: Mutex::new(Vec::new()),
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(
            PasskeyPlugin::new()
                .origins(vec![ORIGIN.into()])
                .authentication(PasskeyAuthenticationConfig {
                    extensions: None,
                    after_verification: Some(policy.clone()),
                }),
        )
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    *policy.foreign.lock().unwrap() = foreign_id.clone();
    let (key, shape) = keyed(31);
    let registration = call(
        &auth,
        request("/passkey/generate-register-options", None, &cookies(&owner)),
        200,
    )
    .await;
    _=call(&auth,request("/passkey/verify-registration",Some(json!({"response":proof(&key,&shape,&body(&registration)["challenge"]),"name":"Original"})),&format!("{}; {}",cookies(&owner),cookies(&registration))),200).await;
    let before: Vec<Value> = serde_json::from_str(&db.table("passkeys").await?)?;
    let before_sessions: Vec<Value> = serde_json::from_str(&db.table("sessions").await?)?;
    let stable = db.tables(&["users", "accounts"]).await?;
    let options = call(
        &auth,
        request(
            "/passkey/generate-authenticate-options",
            None,
            &cookies(&foreign),
        ),
        200,
    )
    .await;
    let challenge_cookie = format!("{}; {}", cookies(&foreign), cookies(&options));
    let client =
        json!({"type":"webauthn.get","challenge":body(&options)["challenge"],"origin":ORIGIN});
    let assertion = key.assertion(
        &client,
        "localhost",
        USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE,
        2,
    );
    let input = json!({"response":assertion,"userId":foreign_id});
    let verified = call(
        &auth,
        request(
            "/passkey/verify-authentication",
            Some(input.clone()),
            &challenge_cookie,
        ),
        200,
    )
    .await;
    assert_eq!(body(&verified)["user"]["id"], body(&owner)["user"]["id"]);
    assert_eq!(
        body(&verified)["session"]["userId"],
        body(&owner)["user"]["id"]
    );
    let current = body(
        &call(
            &auth,
            request("/get-session", None, &cookies(&verified)),
            200,
        )
        .await,
    );
    assert_eq!(current["user"]["id"], body(&owner)["user"]["id"]);
    let after: Vec<Value> = serde_json::from_str(&db.table("passkeys").await?)?;
    assert_eq!(after.len(), 1);
    assert_eq!(after[0]["id"], before[0]["id"]);
    assert_eq!(after[0]["credential_id"], assertion["id"]);
    assert_eq!(after[0]["user_id"], foreign_id);
    assert_eq!(after[0]["counter"], 2);
    assert_eq!(after[0]["backed_up"], 1);
    assert_eq!(after[0]["device_type"], "application-updated");
    assert_eq!(after[0]["name"], "Application updated");
    assert_eq!(after[0]["created_at"], before[0]["created_at"]);
    let seen = policy.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["credential"], assertion["id"]);
    assert_eq!(seen[0]["counter"], 2);
    assert_eq!(seen[0]["origin"], ORIGIN);
    assert_eq!(seen[0]["rpId"], "localhost");
    let owner_passkeys = body(
        &call(
            &auth,
            request("/passkey/list-user-passkeys", None, &cookies(&verified)),
            200,
        )
        .await,
    );
    assert_eq!(owner_passkeys, json!([]));
    let foreign_passkeys = body(
        &call(
            &auth,
            request("/passkey/list-user-passkeys", None, &cookies(&foreign)),
            200,
        )
        .await,
    );
    assert_eq!(foreign_passkeys.as_array().unwrap().len(), 1);
    assert_eq!(foreign_passkeys[0]["userId"], foreign_id);
    let sessions: Vec<Value> = serde_json::from_str(&db.table("sessions").await?)?;
    assert_eq!(sessions.len(), before_sessions.len() + 1);
    assert!(before_sessions.iter().all(|row| sessions.contains(row)));
    assert_eq!(db.tables(&["users", "accounts"]).await?, stable);
    let replay = call(
        &auth,
        request(
            "/passkey/verify-authentication",
            Some(input),
            &challenge_cookie,
        ),
        400,
    )
    .await;
    assert_eq!(body(&replay)["code"], "CHALLENGE_NOT_FOUND");
    assert_eq!(policy.seen.lock().unwrap().len(), 1);
    assert_eq!(
        serde_json::from_str::<Vec<Value>>(&db.table("passkeys").await?)?,
        after
    );
    assert_eq!(
        serde_json::from_str::<Vec<Value>>(&db.table("sessions").await?)?,
        sessions
    );
    authenticated(&auth, &cookies(&owner), "owner@example.test").await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn passkey_registration_forces_credential_properties_over_static_false<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::passkey::PasskeyExtensions;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(
            PasskeyPlugin::new()
                .origins(vec![ORIGIN.into()])
                .registration(PasskeyRegistrationConfig {
                    extensions: Some(PasskeyExtensions::Static(json!({"credProps":false}))),
                    ..Default::default()
                })
                .authentication(PasskeyAuthenticationConfig {
                    extensions: Some(PasskeyExtensions::Static(
                        json!({"appid":"https://extensions.fixture.test/static"}),
                    )),
                    after_verification: None,
                }),
        )
        .build()
        .await?;
    let owner = signup(&auth, "extension-owner@example.test").await;
    let owner_id = body(&owner)["user"]["id"].clone();
    let options = call(
        &auth,
        request("/passkey/generate-register-options", None, &cookies(&owner)),
        200,
    )
    .await;
    assert_eq!(body(&options)["extensions"], json!({"credProps":true}));
    let (key, shape) = keyed(205);
    let registered = call(&auth,request("/passkey/verify-registration",Some(json!({"response":proof(&key,&shape,&body(&options)["challenge"]),"name":"Extension key"})),&format!("{}; {}",cookies(&owner),cookies(&options))),200).await;
    assert_eq!(body(&registered)["userId"], owner_id);
    _ = call(
        &auth,
        request("/sign-out", Some(json!({})), &cookies(&owner)),
        200,
    )
    .await;
    let authentication = call(
        &auth,
        request("/passkey/generate-authenticate-options", None, ""),
        200,
    )
    .await;
    assert_eq!(
        body(&authentication)["extensions"],
        json!({"appid":"https://extensions.fixture.test/static"})
    );
    let client = json!({"type":"webauthn.get","challenge":body(&authentication)["challenge"],"origin":ORIGIN});
    let signed_in = call(&auth,request("/passkey/verify-authentication",Some(json!({"response":key.assertion(&client,"localhost",USER_PRESENT|USER_VERIFIED|BACKUP_ELIGIBLE,2)})),&cookies(&authentication)),200).await;
    let current = body(
        &call(
            &auth,
            request("/get-session", None, &cookies(&signed_in)),
            200,
        )
        .await,
    );
    assert_eq!(current["user"]["id"], owner_id);
    assert_eq!(current["user"]["email"], "extension-owner@example.test");
    assert_eq!(db.count("passkeys").await?, 1);
    assert_eq!(db.count("verifications").await?, 0);
    B::close(connection).await
}

async fn passkey_verification_freshness_retains_issued_proof<B: Backend>(db: Db) -> TestResult {
    for zero in [false, true] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.session.fresh_age = Some(if zero {
            chrono::Duration::zero()
        } else {
            chrono::Duration::days(1)
        });
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(PasskeyPlugin::new().origins(vec![ORIGIN.into()]))
            .build()
            .await?;
        let owner = signup(&auth, "owner@example.test").await;
        let foreign = signup(&auth, "foreign@example.test").await;
        let jar = cookies(&owner);
        let options = call(
            &auth,
            request("/passkey/generate-register-options", None, &jar),
            200,
        )
        .await;
        let (key, shape) = keyed(108);
        let signed = proof(&key, &shape, &body(&options)["challenge"]);
        let challenge = cookies(&options);
        let token = body(&owner)["token"].as_str().unwrap().to_owned();
        db.set_timestamp(
            "sessions",
            "created_at",
            ("token", &token),
            chrono::Utc::now() - chrono::Duration::days(3),
        )
        .await?;
        let before = db
            .tables(&["users", "accounts", "sessions", "passkeys", "verifications"])
            .await?;
        let old = request(
            "/passkey/verify-registration",
            Some(json!({"response":signed,"name":"Actual Ceremony"})),
            &format!("{jar}; {challenge}"),
        );
        let accepted = if zero {
            call(&auth, old, 200).await
        } else {
            let stale = call(&auth, old, 403).await;
            assert_eq!(body(&stale)["code"], "SESSION_NOT_FRESH");
            assert!(stale.headers.get_all("set-cookie").next().is_none());
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "passkeys", "verifications"])
                    .await?,
                before
            );
            let fresh = call(
                &auth,
                request(
                    "/sign-in/email",
                    Some(json!({"email":"owner@example.test","password":PASSWORD})),
                    "",
                ),
                200,
            )
            .await;
            call(
                &auth,
                request(
                    "/passkey/verify-registration",
                    Some(json!({"response":signed,"name":"Actual Ceremony"})),
                    &format!("{}; {challenge}", cookies(&fresh)),
                ),
                200,
            )
            .await
        };
        assert_eq!(accepted.status, 200);
        let id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
        assert_eq!(
            db.count_where("SELECT COUNT(*) FROM passkeys WHERE user_id=$1", &[&id])
                .await?,
            1
        );
        assert_eq!(db.count("verifications").await?, 0);
        authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}
