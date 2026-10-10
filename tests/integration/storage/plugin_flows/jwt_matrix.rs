//! JWT remote-signer claim defaults and managed session-cache authentication.
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::jwt::{
    DefineJwtPayload, JwtAudience, JwtClaimsConfig, JwtExpiration, JwtPlugin, JwtPluginConfig,
    JwtSession, JwtSignOptions, RemoteJwtClaim, RemoteJwtPayload, SignRemoteJwt,
};
use alibi::utils::json::{JsValue, parse_value};
use alibi::{AuthError, AuthResult, CookieCacheConfig, CookieCacheStrategy, CookieCacheVersion};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Map;

backend_tests!(
    jwt_remote_signer_observes_raw_claims_and_defaults,
    jwt_session_cache_accepts_only_matching_managed_tokens,
    jwt_server_endpoint_overrides_and_reference_nonce,
    jwt_public_keyring_failures_preserve_context_and_owned_storage,
    jwt_session_claim_failures_stop_before_keyring_and_preserve_sessions,
    jwt_server_keyring_preserves_absent_request_and_virtual_endpoint,
    jwt_application_keyring_concurrent_initial_discovery_retains_both_signing_keys,
    jwt_remote_signer_selection_options
);

#[derive(Default)]
struct Signer(Mutex<Vec<(Vec<String>, Value)>>);

fn capture(value: &JsValue) -> Value {
    match value {
        JsValue::Number(number) if !number.is_finite() => {
            json!({"$number": format!("{number}")})
        }
        JsValue::Array(values) => values.iter().map(capture).collect(),
        JsValue::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), capture(value)))
                .collect(),
        ),
        value => value.to_json_value().unwrap(),
    }
}

#[async_trait::async_trait]
impl SignRemoteJwt for Signer {
    async fn sign(&self, payload: &RemoteJwtPayload, _: &JwtSignOptions) -> AuthResult<String> {
        let mut seen = Map::new();
        for key in payload.own_keys() {
            let value = match payload.claim(key) {
                RemoteJwtClaim::Undefined => json!("<undefined>"),
                RemoteJwtClaim::Value(value) => capture(value),
                RemoteJwtClaim::Absent => json!("<absent>"),
            };
            _ = seen.insert(key.clone(), value);
        }
        if payload.raw_claims().get("fail").is_some() {
            return Err(AuthError::internal("signer unavailable"));
        }
        self.0
            .lock()
            .unwrap()
            .push((payload.own_keys().to_vec(), Value::Object(seen)));
        Ok("signed".into())
    }
}

struct Claims;
#[async_trait::async_trait]
impl DefineJwtPayload for Claims {
    async fn define_payload(&self, _: &JwtSession) -> AuthResult<Map<String, Value>> {
        Ok(Map::new())
    }
}

/// Replace values equal to the signing clock plus a known lifetime with a label.
fn stamp(value: &mut Value, start: f64, end: f64) {
    match value {
        Value::Number(number) => {
            let n = number.as_f64().unwrap();
            for lifetime in [0.0, 1.5, 60.0, 900.0] {
                if (start..=end).contains(&(n - lifetime)) {
                    *value = json!(format!("now+{lifetime}"));
                    return;
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(|value| stamp(value, start, end)),
        Value::Object(values) => values
            .values_mut()
            .for_each(|value| stamp(value, start, end)),
        _ => {}
    }
}

async fn jwt_remote_signer_observes_raw_claims_and_defaults<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let signer = Arc::new(Signer::default());
    let jwt = JwtPlugin::with_config(JwtPluginConfig {
        remote_url: Some("https://keys.example.test/jwks".into()),
        remote_signer: Some(signer.clone()),
        define_payload: Some(Arc::new(Claims)),
        ..Default::default()
    });
    let auth = builder::<B>(&connection)
        .plugin(jwt.clone())
        .build()
        .await?;
    let mut trace = Trace::default();
    let literals = [
        r#"{"10":"ten","2":"two","custom":{"nested":[null,false,"literal"]}}"#,
        r#"{"exp":1e400,"iat":-0,"nbf":false,"sub":0,"jti":false}"#,
        r#"{"iat":1e400,"nbf":1e400}"#,
        r#"{"iat":100}"#,
        r#"{"iat":1.5}"#,
        r#"{"iat":true}"#,
        r#"{"iat":false}"#,
        r#"{"iat":null,"exp":null,"iss":null,"aud":null}"#,
        r#"{"iat":"100"}"#,
        r#"{"iat":"1e3","exp":"1 hour","nbf":"-5 seconds","aud":["a","b"]}"#,
        r#"{"iat":["7",null,false],"nbf":[],"sub":[],"jti":{}}"#,
        r#"{"iat":{"custom":true}}"#,
        r#"{"iat":-1e400,"nbf":-1e400}"#,
    ];
    let lifetimes = [
        ("default", JwtClaimsConfig::default()),
        (
            "seconds",
            JwtClaimsConfig {
                expiration: JwtExpiration::After(chrono::Duration::seconds(60)),
                issuer: Some("issuer".into()),
                audience: Some(JwtAudience::Many(vec!["one".into(), "two".into()])),
            },
        ),
        (
            "fractional",
            JwtClaimsConfig {
                expiration: JwtExpiration::AfterSeconds(1.5),
                ..Default::default()
            },
        ),
        (
            "absolute",
            JwtClaimsConfig {
                expiration: JwtExpiration::At(
                    chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap(),
                ),
                ..Default::default()
            },
        ),
        (
            "numeric",
            JwtClaimsConfig {
                expiration: JwtExpiration::Numeric(7.0),
                ..Default::default()
            },
        ),
    ];
    for (name, claims) in &lifetimes {
        for literal in literals {
            let start = chrono::Utc::now().timestamp() as f64;
            let options = JwtSignOptions {
                claims: Some(claims.clone()),
                ..Default::default()
            };
            let token = jwt
                .sign_jwt_json(&parse_value(literal)?, &options, None, auth.context())
                .await?;
            assert_eq!(token, "signed");
            let end = chrono::Utc::now().timestamp() as f64;
            let (keys, mut seen) = signer.0.lock().unwrap().pop().unwrap();
            stamp(&mut seen, start, end);
            trace.value(
                &format!("{name} {literal}"),
                json!({"ownKeys": keys, "payload": seen}),
            );
        }
    }
    let mut nan = parse_value(r#"{"iat":123}"#)?;
    if let JsValue::Object(fields) = &mut nan {
        _ = fields.insert("iat".into(), JsValue::Number(f64::NAN));
    }
    let _ = jwt
        .sign_jwt_json(&nan, &JwtSignOptions::default(), None, auth.context())
        .await?;
    trace.value(
        "nan iat",
        json!(signer.0.lock().unwrap().pop().unwrap().1["exp"]),
    );

    let failed = jwt
        .sign_jwt_json(
            &parse_value(r#"{"fail":true}"#)?,
            &JwtSignOptions::default(),
            None,
            auth.context(),
        )
        .await;
    assert!(
        matches!(failed, Err(AuthError::CallbackFailure(_))),
        "{failed:?}"
    );
    let scalar = jwt
        .sign_jwt_json(
            &json!([1]).into(),
            &JwtSignOptions::default(),
            None,
            auth.context(),
        )
        .await;
    assert!(
        matches!(scalar, Err(AuthError::BadRequest(_))),
        "{scalar:?}"
    );
    trace.assert("jwt/remote-signer-raw-claims");
    B::close(connection).await
}

async fn jwt_session_cache_accepts_only_matching_managed_tokens<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            strategy: CookieCacheStrategy::Jwt,
            max_age: 300.0,
            version: Some(CookieCacheVersion::Literal("1".into())),
        });
    let jwt = JwtPlugin::with_config(JwtPluginConfig {
        session_cookie_cache: true,
        ..Default::default()
    });
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(jwt.clone())
        .build()
        .await?;
    let signup = signup(&auth, "cache@example.test").await;
    let jar = cookies(&signup);
    let cached = jar
        .split("; ")
        .find_map(|cookie| cookie.strip_prefix("better-auth.session_data="))
        .unwrap()
        .to_owned();
    let session = jar
        .split("; ")
        .find(|cookie| cookie.starts_with("better-auth.session_token="))
        .unwrap()
        .to_owned();
    let claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(cached.split('.').nth(1).unwrap())?)?;
    assert_eq!(claims["aud"], "better-auth:session-cache");
    assert_eq!(claims["iss"], ORIGIN);
    assert_eq!(claims["sub"], claims["user"]["id"]);
    assert_eq!(claims["sid"], claims["session"]["token"]);

    let forged = async |mutate: &dyn Fn(&mut Map<String, Value>), typ: &str| {
        let mut payload = claims.as_object().unwrap().clone();
        payload["user"]["name"] = json!("Forged name");
        mutate(&mut payload);
        let options = JwtSignOptions {
            header: Some(json!({"typ":typ}).as_object().unwrap().clone()),
            ..Default::default()
        };
        let token = jwt
            .sign_jwt(payload, &options, None, auth.context())
            .await
            .unwrap();
        let response = call(
            &auth,
            request(
                "/get-session",
                None,
                &format!("{session}; better-auth.session_data={token}"),
            ),
            200,
        )
        .await;
        body(&response)["user"]["name"].clone()
    };
    let good = "better-auth.session-cache+jwt";
    assert_eq!(forged(&|_| {}, good).await, "Forged name");
    assert_eq!(forged(&|_| {}, "JWT").await, "Native owner");
    assert_eq!(
        forged(
            &|payload| _ = payload.insert("sub".into(), json!("someone-else")),
            good
        )
        .await,
        "Native owner"
    );
    assert_eq!(
        forged(
            &|payload| _ = payload.insert("sid".into(), json!("another-token")),
            good
        )
        .await,
        "Native owner"
    );
    assert_eq!(
        forged(
            &|payload| _ = payload.insert("aud".into(), json!("elsewhere")),
            good
        )
        .await,
        "Native owner"
    );
    assert_eq!(
        forged(
            &|payload| _ = payload.insert("iss".into(), json!("https://other.example")),
            good
        )
        .await,
        "Native owner"
    );
    for garbage in ["not-a-token", "e30.e30.sig", "!!!.e30.sig"] {
        let response = call(
            &auth,
            request(
                "/get-session",
                None,
                &format!("{session}; better-auth.session_data={garbage}"),
            ),
            200,
        )
        .await;
        assert_eq!(body(&response)["user"]["name"], "Native owner");
    }
    B::close(connection).await
}

async fn jwt_server_endpoint_overrides_and_reference_nonce<B: Backend>(db: Db) -> TestResult {
    use alibi::endpoint::{EndpointOptions, ServerEndpoint};
    use alibi::plugins::{OpenApiConfig, OpenApiPlugin};
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OpenApiPlugin::with_config(
            OpenApiConfig::default().nonce("page-nonce"),
        ))
        .build()
        .await?;
    let mut trace = crate::snapshot::Trace::default();
    let overrides = [
        ("none", json!(null)),
        (
            "claims",
            json!({"jwt":{"issuer":"i","audience":"a","expirationTime":"1h"}}),
        ),
        (
            "audience list",
            json!({"jwt":{"audience":["a","b"],"expirationTime":90}}),
        ),
        ("issuer type", json!({"jwt":{"issuer":5}})),
        ("expiration type", json!({"jwt":{"expirationTime":true}})),
        ("expiration text", json!({"jwt":{"expirationTime":"soon"}})),
        (
            "expiration ago",
            json!({"jwt":{"expirationTime":"2 days ago"}}),
        ),
        (
            "signed expiration ago",
            json!({"jwt":{"expirationTime":"-2 days ago"}}),
        ),
        (
            "expiration units",
            json!({"jwt":{"expirationTime":"+1.5 weeks"}}),
        ),
        (
            "expiration decimal",
            json!({"jwt":{"expirationTime":"1.s"}}),
        ),
        (
            "expiration unit",
            json!({"jwt":{"expirationTime":"3 fortnights"}}),
        ),
        (
            "expiration from now",
            json!({"jwt":{"expirationTime":"5 minutes from now"}}),
        ),
        (
            "keys",
            json!({"jwks":{"keyPairConfig":{"alg":"ES256"},"keyPairConfigs":[{"alg":"RS256","modulusLength":2048}],"rotationInterval":0,"gracePeriod":10,"disablePrivateKeyEncryption":true}}),
        ),
        (
            "rotation",
            json!({"jwks":{"rotationInterval":3600,"remoteUrl":"https://keys.example.test/jwks"}}),
        ),
        (
            "bad algorithm",
            json!({"jwks":{"keyPairConfig":{"alg":"HS256"}}}),
        ),
        (
            "bad modulus",
            json!({"jwks":{"keyPairConfig":{"alg":"RS256","modulusLength":-1}}}),
        ),
        ("bad grace", json!({"jwks":{"gracePeriod":1e300}})),
        ("adapter", json!({"adapter":{}})),
    ];
    for (label, overrides) in overrides {
        let mut body = serde_json::Map::new();
        _ = body.insert("payload".into(), json!({"sub":"subject"}));
        if !overrides.is_null() {
            _ = body.insert("overrideOptions".into(), overrides);
        }
        let start = chrono::Utc::now().timestamp() as f64;
        let endpoint = ServerEndpoint::<alibi::plugins::jwt::JwtTokenOutput>::new("jwt", "signJWT")
            .with_body_value(JsValue::from(Value::Object(body)));
        let result = auth
            .dispatch_endpoint(endpoint, EndpointOptions::default())
            .await
            .and_then(|response| Ok(response.decode()?.token));
        let shown = match result {
            Ok(token) => {
                let claims: Value = serde_json::from_slice(
                    &URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap())?,
                )?;
                json!({
                    "iss": claims["iss"],
                    "aud": claims["aud"],
                    "lifetime": ((claims["exp"].as_f64().unwrap() - start) / 10.0).round() * 10.0,
                })
            }
            Err(error) => json!(error.to_string()),
        };
        trace.value(label, shown);
    }
    let page = call(&auth, request("/reference", None, ""), 200).await;
    assert!(String::from_utf8_lossy(&page.body).contains("nonce=\"page-nonce\""));
    trace.assert("jwt/server-endpoint-overrides");
    B::close(connection).await
}

async fn jwt_public_keyring_failures_preserve_context_and_owned_storage<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::jwt::{JwtKeyring, JwtKeyringContext};
    use alibi::{CreateJwk, Jwk};
    #[derive(Default)]
    struct Ring {
        rows: Mutex<Vec<Jwk>>,
        events: Mutex<Vec<(String, String, Option<String>, Option<String>)>>,
        failure: Mutex<(&'static str, u16)>,
    }
    impl Ring {
        fn observe(&self, operation: &str, context: &JwtKeyringContext<'_>) -> AuthResult<()> {
            self.events.lock().unwrap().push((
                operation.into(),
                context.path.into(),
                context.request.map(|r| format!("{:?}", r.method)),
                context
                    .request
                    .and_then(|r| r.headers.get("x-keyring-proof").cloned()),
            ));
            let failure = *self.failure.lock().unwrap();
            if failure.0 == operation {
                if failure.1 == 0 {
                    return Err(AuthError::internal("private keyring failure"));
                }
                return Err(AuthError::Api {
                    status: failure.1,
                    code: Some("APPLICATION_KEYRING_DENIED".into()),
                    message: "application denied keys".into(),
                });
            }
            Ok(())
        }
    }
    #[async_trait::async_trait]
    impl JwtKeyring for Ring {
        async fn keys(&self, context: &JwtKeyringContext<'_>) -> AuthResult<Vec<Jwk>> {
            self.observe("read", context)?;
            Ok(self.rows.lock().unwrap().clone())
        }
        async fn create_key(
            &self,
            data: CreateJwk,
            context: &JwtKeyringContext<'_>,
        ) -> AuthResult<Jwk> {
            self.observe("create", context)?;
            let mut rows = self.rows.lock().unwrap();
            let key = Jwk {
                id: format!("application-key-{}", rows.len() + 1),
                public_key: data.public_key,
                private_key: data.private_key,
                created_at: data.created_at,
                expires_at: data.expires_at,
                alg: data.alg,
                crv: data.crv,
            };
            rows.push(key.clone());
            Ok(key)
        }
    }

    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let app = Arc::new(Ring::default());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::with_config(JwtPluginConfig {
            keyring: Some(app.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    for operation in ["read", "create"] {
        for status in [0, 403, 500] {
            *app.failure.lock().unwrap() = (operation, status);
            app.events.lock().unwrap().clear();
            let mut input = request("/jwks", None, "");
            _ = input
                .headers
                .insert("x-keyring-proof".into(), "application-marker".into());
            let rejected = call(&auth, input, if status == 0 { 500 } else { status }).await;
            if status == 0 {
                assert!(rejected.body.is_empty());
            } else {
                assert_eq!(body(&rejected)["code"], "APPLICATION_KEYRING_DENIED");
                assert_eq!(body(&rejected)["message"], "application denied keys");
            }
            let expected = if operation == "read" {
                vec!["read"]
            } else {
                vec!["read", "create"]
            };
            let events = app.events.lock().unwrap().clone();
            assert_eq!(
                events.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(),
                expected
            );
            for e in events.iter() {
                assert_eq!(e.1, "/jwks");
                assert_eq!(e.2.as_deref(), Some("Get"));
                assert_eq!(e.3.as_deref(), Some("application-marker"));
            }
            assert!(app.rows.lock().unwrap().is_empty());
            assert!(auth.store().list_jwks().await?.is_empty());
            assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
        }
    }
    *app.failure.lock().unwrap() = ("", 0);
    let keys = body(&call(&auth, request("/jwks", None, ""), 200).await);
    assert_eq!(keys["keys"].as_array().unwrap().len(), 1);
    assert_eq!(app.rows.lock().unwrap().len(), 1);
    assert!(auth.store().list_jwks().await?.is_empty());
    authenticated(&auth, &cookies(&owner), "owner@example.test").await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn jwt_session_claim_failures_stop_before_keyring_and_preserve_sessions<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::jwt::{JwtKeyring, JwtKeyringContext};
    use alibi::{CreateJwk, Jwk};
    #[derive(Default)]
    struct Ring {
        rows: Mutex<Vec<Jwk>>,
        events: Mutex<Vec<(String, String, Option<String>, Option<String>)>>,
        failure: Mutex<(&'static str, u16)>,
    }
    impl Ring {
        fn observe(&self, operation: &str, context: &JwtKeyringContext<'_>) -> AuthResult<()> {
            self.events.lock().unwrap().push((
                operation.into(),
                context.path.into(),
                context.request.map(|r| format!("{:?}", r.method)),
                context
                    .request
                    .and_then(|r| r.headers.get("x-keyring-proof").cloned()),
            ));
            let failure = *self.failure.lock().unwrap();
            if failure.0 == operation {
                if failure.1 == 0 {
                    return Err(AuthError::internal("private keyring failure"));
                }
                return Err(AuthError::Api {
                    status: failure.1,
                    code: Some("APPLICATION_KEYRING_DENIED".into()),
                    message: "application denied keys".into(),
                });
            }
            Ok(())
        }
    }
    #[async_trait::async_trait]
    impl JwtKeyring for Ring {
        async fn keys(&self, context: &JwtKeyringContext<'_>) -> AuthResult<Vec<Jwk>> {
            self.observe("read", context)?;
            Ok(self.rows.lock().unwrap().clone())
        }
        async fn create_key(
            &self,
            data: CreateJwk,
            context: &JwtKeyringContext<'_>,
        ) -> AuthResult<Jwk> {
            self.observe("create", context)?;
            let mut rows = self.rows.lock().unwrap();
            let key = Jwk {
                id: format!("application-key-{}", rows.len() + 1),
                public_key: data.public_key,
                private_key: data.private_key,
                created_at: data.created_at,
                expires_at: data.expires_at,
                alg: data.alg,
                crv: data.crv,
            };
            rows.push(key.clone());
            Ok(key)
        }
    }

    use alibi::plugins::jwt::DefineJwtSubject;
    #[async_trait::async_trait]
    impl DefineJwtPayload for Ring {
        async fn define_payload(&self, _: &JwtSession) -> AuthResult<Map<String, Value>> {
            self.observe(
                "payload",
                &JwtKeyringContext {
                    path: "claims",
                    request: None,
                    endpoint: None,
                },
            )?;
            Ok(Map::new())
        }
    }
    #[async_trait::async_trait]
    impl DefineJwtSubject for Ring {
        async fn subject(&self, _: &JwtSession) -> AuthResult<Option<String>> {
            self.observe(
                "subject",
                &JwtKeyringContext {
                    path: "claims",
                    request: None,
                    endpoint: None,
                },
            )?;
            Ok(Some("owner-subject".into()))
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let app = Arc::new(Ring::default());
    let jwt = JwtPlugin::with_config(JwtPluginConfig {
        keyring: Some(app.clone()),
        define_payload: Some(app.clone()),
        define_subject: Some(app.clone()),
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(jwt.clone())
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    for operation in ["payload", "subject"] {
        for status in [0, 403, 500] {
            for path in ["/token", "/get-session"] {
                *app.failure.lock().unwrap() = (operation, status);
                app.events.lock().unwrap().clear();
                let response = call(
                    &auth,
                    request(path, None, &cookies(&owner)),
                    if status == 0 { 500 } else { status },
                )
                .await;
                assert!(!response.headers.contains_key("set-auth-jwt"));
                if status == 0 {
                    assert!(response.body.is_empty());
                } else {
                    assert_eq!(body(&response)["code"], "APPLICATION_KEYRING_DENIED");
                }
                let events = app
                    .events
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|e| e.0.clone())
                    .collect::<Vec<_>>();
                assert_eq!(
                    events,
                    if operation == "payload" {
                        vec!["payload"]
                    } else {
                        vec!["payload", "subject"]
                    }
                );
                assert!(app.rows.lock().unwrap().is_empty());
                assert!(auth.store().list_jwks().await?.is_empty());
                assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
            }
        }
    }
    *app.failure.lock().unwrap() = ("", 0);
    let token = body(&call(&auth, request("/token", None, &cookies(&owner)), 200).await)["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let verified = jwt
        .verify_jwt(&token, None, None, auth.context())
        .await?
        .unwrap();
    assert_eq!(verified["sub"], "owner-subject");
    assert_eq!(app.rows.lock().unwrap().len(), 1);
    assert!(auth.store().list_jwks().await?.is_empty());
    authenticated(&auth, &cookies(&owner), "owner@example.test").await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn jwt_server_keyring_preserves_absent_request_and_virtual_endpoint<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::jwt::{JwtKeyring, JwtKeyringContext};
    use alibi::{CreateJwk, Jwk};
    #[derive(Default)]
    struct Ring {
        rows: Mutex<Vec<Jwk>>,
        events: Mutex<Vec<(String, String, Option<String>, Option<String>)>>,
        failure: Mutex<(&'static str, u16)>,
    }
    impl Ring {
        fn observe(&self, operation: &str, context: &JwtKeyringContext<'_>) -> AuthResult<()> {
            self.events.lock().unwrap().push((
                operation.into(),
                context.path.into(),
                context.request.map(|r| format!("{:?}", r.method)),
                context
                    .request
                    .and_then(|r| r.headers.get("x-keyring-proof").cloned()),
            ));
            let failure = *self.failure.lock().unwrap();
            if failure.0 == operation {
                if failure.1 == 0 {
                    return Err(AuthError::internal("private keyring failure"));
                }
                return Err(AuthError::Api {
                    status: failure.1,
                    code: Some("APPLICATION_KEYRING_DENIED".into()),
                    message: "application denied keys".into(),
                });
            }
            Ok(())
        }
    }
    #[async_trait::async_trait]
    impl JwtKeyring for Ring {
        async fn keys(&self, context: &JwtKeyringContext<'_>) -> AuthResult<Vec<Jwk>> {
            self.observe("read", context)?;
            Ok(self.rows.lock().unwrap().clone())
        }
        async fn create_key(
            &self,
            data: CreateJwk,
            context: &JwtKeyringContext<'_>,
        ) -> AuthResult<Jwk> {
            self.observe("create", context)?;
            let mut rows = self.rows.lock().unwrap();
            let key = Jwk {
                id: format!("application-key-{}", rows.len() + 1),
                public_key: data.public_key,
                private_key: data.private_key,
                created_at: data.created_at,
                expires_at: data.expires_at,
                alg: data.alg,
                crv: data.crv,
            };
            rows.push(key.clone());
            Ok(key)
        }
    }

    use alibi::endpoint::EndpointOptions;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let app = Arc::new(Ring::default());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::with_config(JwtPluginConfig {
            keyring: Some(app.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let token = auth
        .dispatch_endpoint(
            JwtPlugin::sign_endpoint(JsValue::from(
                json!({"sub":"server-owner","exp":4102444800_i64}),
            )),
            EndpointOptions::default(),
        )
        .await?
        .decode()?
        .token;
    let events = app.events.lock().unwrap().clone();
    assert!(!events.is_empty());
    for e in events {
        assert_eq!(e.1, "virtual:");
        assert_eq!(e.2, None);
        assert_eq!(e.3, None);
    }
    for supplied in [false, true] {
        app.events.lock().unwrap().clear();
        let mut http = request("/caller-owned-transport", Some(json!({})), "");
        _ = http
            .headers
            .insert("x-keyring-proof".into(), "server-marker".into());
        let result = auth
            .dispatch_endpoint(
                JwtPlugin::verify_endpoint(&token, None),
                EndpointOptions {
                    request: supplied.then_some(http),
                    ..Default::default()
                },
            )
            .await?
            .decode()?;
        assert_eq!(result.payload.unwrap()["sub"], "server-owner");
        let events = app.events.lock().unwrap().clone();
        assert!(!events.is_empty());
        for e in events.iter() {
            assert_eq!(e.1, "virtual:");
            assert_eq!(e.2.as_deref(), supplied.then_some("Post"));
            assert_eq!(e.3.as_deref(), supplied.then_some("server-marker"));
        }
    }
    assert_eq!(app.rows.lock().unwrap().len(), 1);
    assert!(auth.store().list_jwks().await?.is_empty());
    assert_eq!(db.count("sessions").await?, 0);
    B::close(connection).await
}

async fn jwt_application_keyring_concurrent_initial_discovery_retains_both_signing_keys<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    use alibi::plugins::jwt::{JwtKeyring, JwtKeyringContext};
    use alibi::{CreateJwk, Jwk};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Ring {
        rows: Mutex<Vec<Jwk>>,
        initial: tokio::sync::Barrier,
        reads: AtomicUsize,
        release: tokio::sync::Notify,
        created: Mutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl JwtKeyring for Ring {
        async fn keys(&self, _: &JwtKeyringContext<'_>) -> AuthResult<Vec<Jwk>> {
            let rows = self.rows.lock().unwrap().clone();
            if self.reads.fetch_add(1, Ordering::SeqCst) < 2 {
                _ = self.initial.wait().await;
            }
            Ok(rows)
        }
        async fn create_key(
            &self,
            data: CreateJwk,
            context: &JwtKeyringContext<'_>,
        ) -> AuthResult<Jwk> {
            assert_eq!(context.path, "/jwks");
            let request = context.request.unwrap();
            assert_eq!(request.method, HttpMethod::Get);
            let marker = request.headers.get("x-keyring-proof").unwrap().clone();
            if marker == "second" {
                self.release.notified().await;
            }
            let mut rows = self.rows.lock().unwrap();
            let key = Jwk {
                id: format!("racing-key-{}", rows.len() + 1),
                public_key: data.public_key,
                private_key: data.private_key,
                created_at: data.created_at,
                expires_at: data.expires_at,
                alg: data.alg,
                crv: data.crv,
            };
            rows.push(key.clone());
            self.created.lock().unwrap().push(marker);
            Ok(key)
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let app = Arc::new(Ring {
        rows: Mutex::new(Vec::new()),
        initial: tokio::sync::Barrier::new(2),
        reads: AtomicUsize::new(0),
        release: tokio::sync::Notify::new(),
        created: Mutex::new(Vec::new()),
    });
    let jwt = JwtPlugin::with_config(JwtPluginConfig {
        keyring: Some(app.clone()),
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(jwt.clone())
        .build()
        .await?;
    let mut first = request("/jwks", None, "");
    _ = first
        .headers
        .insert("x-keyring-proof".into(), "first".into());
    let mut second = request("/jwks", None, "");
    _ = second
        .headers
        .insert("x-keyring-proof".into(), "second".into());
    let (first, second) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            async {
                let response = call(&auth, first, 200).await;
                app.release.notify_one();
                response
            },
            call(&auth, second, 200)
        )
    })
    .await?;
    let left = body(&first);
    let right = body(&second);
    assert_eq!(left["keys"].as_array().unwrap().len(), 1);
    assert_eq!(right["keys"].as_array().unwrap().len(), 2);
    assert_eq!(left["keys"][0]["kid"], right["keys"][0]["kid"]);
    assert_eq!(*app.created.lock().unwrap(), vec!["first", "second"]);
    let rows = app.rows.lock().unwrap().clone();
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].id, rows[1].id);
    for key in rows {
        assert!(serde_json::from_str::<Value>(&key.private_key)?.is_string());
        let token = jwt
            .sign_jwt(
                json!({"sub":"racing-owner"}).as_object().unwrap().clone(),
                &JwtSignOptions {
                    signing_key_id: Some(key.id.clone()),
                    ..Default::default()
                },
                None,
                auth.context(),
            )
            .await?;
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').next().unwrap())?)?;
        assert_eq!(header["kid"], key.id);
        assert_eq!(
            jwt.verify_jwt(&token, None, None, auth.context())
                .await?
                .unwrap()["sub"],
            "racing-owner"
        );
    }
    assert!(auth.store().list_jwks().await?.is_empty());
    assert_eq!(db.count("sessions").await?, 0);
    B::close(connection).await
}

async fn jwt_remote_signer_selection_options<B: Backend>(db: Db) -> TestResult {
    struct Signer(Mutex<Vec<JwtSignOptions>>);
    #[async_trait::async_trait]
    impl SignRemoteJwt for Signer {
        async fn sign(&self, p: &RemoteJwtPayload, o: &JwtSignOptions) -> AuthResult<String> {
            self.0.lock().unwrap().push(o.clone());
            let header = jsonwebtoken::Header {
                alg: jsonwebtoken::Algorithm::HS256,
                kid: Some("application-key".into()),
                typ: Some("APP".into()),
                ..Default::default()
            };
            jsonwebtoken::encode(
                &header,
                &capture(p.raw_claims()),
                &jsonwebtoken::EncodingKey::from_secret(b"application-hmac-authority"),
            )
            .map_err(|e| AuthError::internal(e.to_string()))
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let signer = Arc::new(Signer(Mutex::new(Vec::new())));
    let jwt = JwtPlugin::with_config(JwtPluginConfig {
        remote_url: Some("https://application.example.test/jwks".into()),
        remote_signer: Some(signer.clone()),
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(jwt.clone())
        .build()
        .await?;
    for header in [
        None,
        Some(Map::new()),
        Some(
            json!({"typ":"application/custom","custom":{"literal":true},"kid":"caller-header"})
                .as_object()
                .unwrap()
                .clone(),
        ),
    ] {
        let options = JwtSignOptions {
            header: header.clone(),
            signing_key_id: Some("application-only-selection".into()),
            signing_algorithm: Some(alibi::plugins::jwt::JwtAlgorithm::Es256),
            ..Default::default()
        };
        let token = jwt
            .sign_jwt_json(
                &parse_value(
                    r#"{"sub":"remote-owner","custom":{"nested":[true,null,"literal"]}}"#,
                )?,
                &options,
                None,
                auth.context(),
            )
            .await?;
        let seen = signer.0.lock().unwrap().last().unwrap().clone();
        assert_eq!(seen.header, header);
        assert_eq!(
            seen.signing_key_id.as_deref(),
            Some("application-only-selection")
        );
        assert_eq!(
            seen.signing_algorithm,
            Some(alibi::plugins::jwt::JwtAlgorithm::Es256)
        );
        let actual = jsonwebtoken::decode_header(&token)?;
        assert_eq!(actual.alg, jsonwebtoken::Algorithm::HS256);
        assert_eq!(actual.kid.as_deref(), Some("application-key"));
        assert_eq!(actual.typ.as_deref(), Some("APP"));
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_aud = false;
        let claims = jsonwebtoken::decode::<Value>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(b"application-hmac-authority"),
            &validation,
        )?
        .claims;
        assert_eq!(claims["sub"], "remote-owner");
        assert_eq!(claims["custom"], json!({"nested":[true,null,"literal"]}));
        assert_eq!(db.count("jwks").await?, 0);
    }
    assert_eq!(signer.0.lock().unwrap().len(), 3);
    B::close(connection).await
}
