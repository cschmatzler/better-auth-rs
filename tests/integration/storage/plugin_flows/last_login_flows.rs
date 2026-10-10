//! Last-login tracking across passwordless and passkey sign-in, application
//! resolvers and cookie attributes.
use super::passkey_attestation::{Shape, client};
use super::passkey_matrix::{ATTESTED, Authenticator, USER_PRESENT, USER_VERIFIED};
use super::passwordless::Mailbox;
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::OAuthPlugin;
use alibi::plugins::anonymous::{AnonymousConfig, AnonymousIdentity};
use alibi::plugins::email_otp::{EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin};
use alibi::plugins::last_login_method::{
    LastLoginMethodConfig, LastLoginMethodContext, LastLoginMethodPlugin, ResolveLastLoginMethod,
};
use alibi::plugins::magic_link::{MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin};
use alibi::plugins::oauth::{
    OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use alibi::plugins::{AnonymousPlugin, PasskeyPlugin};
use alibi::{AuthError, AuthResult};

backend_tests!(
    last_login_tracks_every_sign_in_method,
    last_login_resolver_and_cookie_policy,
    last_login_tracks_social_callbacks,
    last_login_resolver_receives_transformed_numbers_and_original_http_bytes,
    last_login_tracking_update_failure_is_best_effort_for_authentication,
    last_login_configured_tracking_cookie_receipt
);

const COOKIE: &str = "better-auth.last_used_login_method";

struct Identity;

#[async_trait::async_trait]
impl AnonymousIdentity for Identity {
    async fn email(&self) -> AuthResult<Option<String>> {
        Ok(Some("anonymous-last-login@example.test".into()))
    }
}

fn tracked(response: &AuthResponse) -> Option<String> {
    response
        .headers
        .get_all("set-cookie")
        .find(|header| header.starts_with(&format!("{COOKIE}=")))
        .map(|header| header.split(';').next().unwrap().to_owned())
}

async fn last_login_tracks_every_sign_in_method<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let links = Arc::new(Mailbox::<MagicLinkDelivery>::default());
    let codes = Arc::new(Mailbox::<EmailOtpDelivery>::default());
    let auth = builder::<B>(&connection)
        .plugin(AnonymousPlugin::with_config(AnonymousConfig {
            identity: Some(Arc::new(Identity)),
            ..Default::default()
        }))
        .plugin(PasskeyPlugin::new())
        .plugin(MagicLinkPlugin::new(MagicLinkConfig {
            send_magic_link: Some(links.clone()),
            ..Default::default()
        }))
        .plugin(EmailOtpPlugin::new(EmailOtpConfig {
            send_verification_otp: Some(codes.clone()),
            ..Default::default()
        }))
        .plugin(LastLoginMethodPlugin::with_config(LastLoginMethodConfig {
            store_in_database: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let owner = signup(&auth, "last-login-passkey@example.test").await;
    trace.value("email sign-up", json!(tracked(&owner)));
    let session = cookies(&owner);

    let key = Authenticator::new(5, "last-login-key");
    let options = call(
        &auth,
        request("/passkey/generate-register-options", None, &session),
        200,
    )
    .await;
    let client_data = client(&body(&options)["challenge"]);
    let shape = Shape {
        flags: USER_PRESENT | USER_VERIFIED | ATTESTED,
        ..Default::default()
    };
    let bytes = serde_json::to_vec(&client_data)?;
    _ = call(
        &auth,
        request(
            "/passkey/verify-registration",
            Some(json!({"response": key.registration(&client_data, &shape.build(&key, &bytes), false)})),
            &format!("{session}; {}", cookies(&options)),
        ),
        200,
    )
    .await;
    let options = call(
        &auth,
        request("/passkey/generate-authenticate-options", None, ""),
        200,
    )
    .await;
    let assertion_client =
        json!({"type": "webauthn.get", "challenge": body(&options)["challenge"], "origin": ORIGIN});
    let signed_in = call(
        &auth,
        request(
            "/passkey/verify-authentication",
            Some(
                json!({"response": key.assertion(&assertion_client, "localhost", USER_PRESENT, 2)}),
            ),
            &cookies(&options),
        ),
        200,
    )
    .await;
    trace.value("passkey", json!(tracked(&signed_in)));

    _ = call(
        &auth,
        request(
            "/sign-in/magic-link",
            Some(json!({"email": "last-login-magic@example.test"})),
            "",
        ),
        200,
    )
    .await;
    let link = url::Url::parse(&links.take().url)?;
    let mut redeem = AuthRequest::new(HttpMethod::Get, link.path());
    redeem.query.extend(link.query_pairs().into_owned());
    let redeemed = call(&auth, redeem, 302).await;
    trace.value("magic link", json!(tracked(&redeemed)));

    _ = call(
        &auth,
        request(
            "/email-otp/send-verification-otp",
            Some(json!({"email": "last-login-otp@example.test", "type": "sign-in"})),
            "",
        ),
        200,
    )
    .await;
    let delivery = codes.take();
    let otp = call(
        &auth,
        request(
            "/sign-in/email-otp",
            Some(json!({"email": delivery.email, "otp": delivery.otp})),
            "",
        ),
        200,
    )
    .await;
    trace.value("email otp", json!(tracked(&otp)));

    let anonymous = call(
        &auth,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    trace.value("anonymous", json!(tracked(&anonymous)));
    let rejected = Box::pin(auth.handle_request(request(
        "/sign-up/email",
        Some(json!({
            "email": "rejected-last-login@example.test",
            "password": PASSWORD,
            "name": "Rejected",
            "lastLoginMethod": "forged",
        })),
        "",
    )))
    .await?;
    trace.response("forged method on sign-up", &rejected);
    let update = Box::pin(auth.handle_request(request(
        "/update-user",
        Some(json!({"lastLoginMethod": "forged"})),
        &session,
    )))
    .await?;
    trace.response("forged method on update", &update);
    trace.value(
        "stored methods",
        json!(
            db.text(
                "SELECT GROUP_CONCAT(email || '=' || COALESCE(last_login_method, 'none'), ',') FROM (SELECT * FROM users ORDER BY email)",
                &[],
            )
            .await?
        ),
    );
    trace.assert("last-login/every-sign-in-method");
    B::close(connection).await
}

struct Resolver;

impl ResolveLastLoginMethod for Resolver {
    fn resolve(&self, context: &LastLoginMethodContext) -> AuthResult<Option<String>> {
        let header = |name: &str| context.request.headers.get(name).map(String::as_str);
        match header("x-resolve") {
            Some("custom") => Ok(Some("custom method!(*)'".into())),
            Some("empty") => Ok(Some(String::new())),
            Some("internal") => Err(AuthError::internal("resolver unavailable")),
            Some("api") => Err(AuthError::forbidden("resolver denied")),
            _ => Ok(None),
        }
    }
}

async fn last_login_resolver_and_cookie_policy<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    let variants: Vec<(&str, LastLoginMethodConfig, bool)> = vec![
        (
            "resolver",
            LastLoginMethodConfig {
                resolver: Some(Arc::new(Resolver)),
                store_in_database: true,
                ..Default::default()
            },
            false,
        ),
        (
            "resolver cookie only",
            LastLoginMethodConfig {
                resolver: Some(Arc::new(Resolver)),
                ..Default::default()
            },
            false,
        ),
        (
            "lifetime too long",
            LastLoginMethodConfig {
                max_age: 40_000_000.0,
                ..Default::default()
            },
            false,
        ),
        (
            "strict and cross-subdomain",
            LastLoginMethodConfig {
                max_age: -1.0,
                ..Default::default()
            },
            true,
        ),
    ];
    for (index, (label, login, strict)) in variants.into_iter().enumerate() {
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        if strict {
            config.session.cookie_same_site = alibi::config::SameSite::Strict;
            config.advanced.cross_sub_domain_cookies = Some(alibi::config::CrossSubDomainConfig {
                domain: "example.test".into(),
            });
        }
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(alibi::plugins::EmailPasswordPlugin::new())
            .plugin(SessionManagementPlugin::new())
            .plugin(LastLoginMethodPlugin::with_config(login))
            .build()
            .await?;
        for (name, header) in [
            ("none", None),
            ("custom", Some("custom")),
            ("empty", Some("empty")),
            ("internal", Some("internal")),
            ("api", Some("api")),
        ] {
            let mut sign_up = request(
                "/sign-up/email",
                Some(json!({
                    "email": format!("policy-{index}-{name}@example.test"),
                    "password": PASSWORD,
                    "name": "Policy",
                })),
                "",
            );
            if let Some(header) = header {
                _ = sign_up.headers.insert("x-resolve".into(), header.into());
            }
            let response = Box::pin(auth.handle_request(sign_up)).await?;
            trace.response(&format!("{label}: {name}"), &response);
            trace.value(
                &format!("{label}: {name} cookie"),
                json!(tracked(&response)),
            );
        }
    }
    trace.value(
        "stored methods",
        json!(
            db.text(
                "SELECT GROUP_CONCAT(email || '=' || COALESCE(last_login_method, 'none'), ',') FROM (SELECT * FROM users ORDER BY email)",
                &[],
            )
            .await?
        ),
    );
    trace.assert("last-login/resolver-and-cookie-policy");
    B::close(connection).await
}

struct Profile;

#[async_trait::async_trait]
impl OAuthUserInfoHandler for Profile {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let user = OAuthUserInfo {
            additional_fields: Default::default(),
            id: "last-login-sub".into(),
            email: "last-login-social@example.test".into(),
            name: Some("Social".into()),
            image: None,
            email_verified: true,
        };
        Ok(OAuthUserInfoResponse {
            user_output: None,
            data: json!({"sub": user.id, "email": user.email}),
            user,
        })
    }
}

async fn last_login_tracks_social_callbacks<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = Provider::start(
        "application/json",
        json!({"access_token": "provider-access", "token_type": "Bearer", "expires_in": 3600})
            .to_string(),
    )
    .await;
    let mut google = OAuthProvider::google("google-client", "google-secret");
    google.token_url = provider.url.join("token")?.into();
    google.get_user_info = Some(Arc::new(Profile));
    let auth = builder::<B>(&connection)
        .plugin(OAuthPlugin::new().add_provider("google", google))
        .plugin(LastLoginMethodPlugin::with_config(LastLoginMethodConfig {
            store_in_database: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let started = call(
        &auth,
        request(
            "/sign-in/social",
            Some(json!({"provider": "google", "callbackURL": "/done"})),
            "",
        ),
        200,
    )
    .await;
    let state = url::Url::parse(body(&started)["url"].as_str().unwrap())?
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let mut callback = request("/callback/google", None, &cookies(&started));
    callback.set_query_pairs([("code", "grant"), ("state", state.as_str())]);
    let finished = call(&auth, callback, 302).await;
    assert_eq!(
        tracked(&finished).as_deref(),
        Some("better-auth.last_used_login_method=google")
    );
    assert_eq!(
        db.text("SELECT last_login_method FROM users", &[])
            .await?
            .as_deref(),
        Some("google")
    );
    B::close(connection).await
}

async fn last_login_resolver_receives_transformed_numbers_and_original_http_bytes<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::last_login_method::BeforeStoreLastLoginMethodCookie;
    struct Capture(Mutex<Vec<LastLoginMethodContext>>);
    impl ResolveLastLoginMethod for Capture {
        fn resolve(&self, context: &LastLoginMethodContext) -> AuthResult<Option<String>> {
            self.0.lock().unwrap().push(context.clone());
            Ok(Some("body:Infinity:-0".into()))
        }
    }
    #[async_trait::async_trait]
    impl BeforeStoreLastLoginMethodCookie for Capture {
        async fn before_store(
            &self,
            context: &LastLoginMethodContext,
            _: &str,
        ) -> AuthResult<bool> {
            self.0.lock().unwrap().push(context.clone());
            Ok(true)
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let capture = Arc::new(Capture(Mutex::new(Vec::new())));
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .trusted_origin(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password().enable_username(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(LastLoginMethodPlugin::with_config(LastLoginMethodConfig {
            store_in_database: true,
            resolver: Some(capture.clone()),
            before_store_cookie: Some(capture.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let raw = r#"{"email":"numeric@example.test","password":"a-native-password-123","name":"Numeric Owner","username":"numericowner","extra":{"overflow":1e400,"zero":-0,"nested":[null,false,"literal"]}}"#;
    let mut input = request("/sign-up/email", Some(json!({})), "");
    input.body = Some(raw.as_bytes().to_vec());
    _ = input
        .headers
        .insert("x-last-login-body".into(), "true".into());
    let issued = call(&auth, input, 200).await;
    {
        let contexts = capture.0.lock().unwrap();
        assert!(contexts.len() >= 3);
        for context in contexts.iter() {
            assert_eq!(context.request.body.as_deref(), Some(raw.as_bytes()));
            assert_eq!(
                context
                    .request
                    .headers
                    .get("x-last-login-body")
                    .map(String::as_str),
                Some("true")
            );
            assert_eq!(context.route_path, "/sign-up/email");
            let body = context.body.as_ref().unwrap();
            assert_eq!(
                body.get("displayUsername").unwrap().as_str(),
                Some("numericowner")
            );
            let extra = body.get("extra").unwrap();
            assert_eq!(extra.get("overflow").unwrap().as_f64(), Some(f64::INFINITY));
            let zero = extra.get("zero").unwrap().as_f64().unwrap();
            assert_eq!(zero, 0.0);
            assert!(zero.is_sign_negative());
            assert_eq!(
                extra.get("nested"),
                Some(&alibi::utils::json::JsValue::from(json!([
                    null, false, "literal"
                ])))
            );
        }
    }
    assert_eq!(
        tracked(&issued).as_deref(),
        Some("better-auth.last_used_login_method=body%3AInfinity%3A-0")
    );
    assert_eq!(
        db.text("SELECT last_login_method FROM users", &[])
            .await?
            .as_deref(),
        Some("body:Infinity:-0")
    );
    authenticated(&auth, &cookies(&issued), "numeric@example.test").await;
    B::close(connection).await
}

async fn last_login_tracking_update_failure_is_best_effort_for_authentication<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(LastLoginMethodPlugin::with_config(LastLoginMethodConfig {
            store_in_database: true,
            resolver: Some(Arc::new(Resolver)),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let users = db.table("users").await?;
    let accounts = db.table("accounts").await?;
    _ = db.execute("CREATE TRIGGER reject_tracking BEFORE UPDATE OF last_login_method ON users BEGIN SELECT RAISE(ABORT, 'tracking unavailable'); END",&[]).await?;
    let mut input = request(
        "/sign-in/email",
        Some(json!({"email":"owner@example.test","password":PASSWORD})),
        "",
    );
    _ = input.headers.insert("x-resolve".into(), "custom".into());
    let issued = call(&auth, input, 200).await;
    assert_eq!(
        tracked(&issued).as_deref(),
        Some("better-auth.last_used_login_method=custom%20method!(*)'")
    );
    assert_eq!(db.table("users").await?, users);
    assert_eq!(db.table("accounts").await?, accounts);
    assert_eq!(db.count("sessions").await?, 3);
    for cookie in [cookies(&owner), cookies(&issued)] {
        authenticated(&auth, &cookie, "owner@example.test").await;
    }
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    _ = db.execute("DROP TRIGGER reject_tracking", &[]).await?;
    B::close(connection).await
}

async fn last_login_configured_tracking_cookie_receipt<B: Backend>(db: Db) -> TestResult {
    use alibi::config::SameSite;
    for (age, expected, strict) in [
        (123.9, Some("123"), false),
        (0.0, Some("0"), true),
        (f64::NAN, None, false),
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        if strict {
            config.advanced.default_cookie_attributes.same_site = Some(SameSite::Strict);
        }
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(LastLoginMethodPlugin::with_config(LastLoginMethodConfig {
                cookie_name: "application.last_login".into(),
                max_age: age,
                store_in_database: true,
                ..Default::default()
            }))
            .build()
            .await?;
        let owner = signup(&auth, "tracking-age@example.test").await;
        let signed = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"tracking-age@example.test","password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        for response in [&owner, &signed] {
            let headers = response
                .headers
                .get_all("set-cookie")
                .filter(|v| v.starts_with("application.last_login="))
                .collect::<Vec<_>>();
            assert_eq!(headers.len(), 1);
            let raw = headers[0];
            assert!(raw.starts_with("application.last_login=email;"));
            assert!(!raw.contains("HttpOnly"));
            assert!(raw.contains("Path=/"));
            assert!(raw.contains(if strict {
                "SameSite=Strict"
            } else {
                "SameSite=Lax"
            }));
            assert_eq!(
                raw.split("; ").find_map(|v| v.strip_prefix("Max-Age=")),
                expected
            );
            assert!(
                !response
                    .headers
                    .get_all("set-cookie")
                    .any(|v| v.starts_with(COOKIE))
            );
            authenticated(&auth, &cookies(response), "tracking-age@example.test").await;
        }
        assert_eq!(
            db.text(
                "SELECT last_login_method FROM users WHERE id=$1",
                &[body(&owner)["user"]["id"].as_str().unwrap()]
            )
            .await?
            .as_deref(),
            Some("email")
        );
        let before = db.tables(&["users", "accounts", "sessions"]).await?;
        let rejected = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"tracking-age@example.test","password":"wrong-password"})),
                "",
            ),
            401,
        )
        .await;
        assert!(
            !rejected
                .headers
                .get_all("set-cookie")
                .any(|v| v.starts_with("application.last_login="))
        );
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
        B::close(connection).await?;
    }
    Ok(())
}
