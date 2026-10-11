//! One Tap admission and account outcomes with signed Google ID tokens.
use super::*;
use crate::snapshot::Trace;
use alibi::hooks::RequestHookContext;
use alibi::plugins::oauth::{HttpOAuthJwksSource, OAuthProvider};
use alibi::plugins::one_tap::{OneTapClientId, OneTapConfig, OneTapPlugin};
use alibi::plugins::{AdminPlugin, OAuthPlugin};
use alibi::user_validation::{UserInfoValidator, UserValidationData, UserValidationRejection};
use alibi::{AccountConfig, AuthResult};

backend_tests!(
    one_tap_token_admission_matrix,
    one_tap_identity_outcomes,
    one_tap_account_cookie_and_remember_state,
    one_tap_strict_upgrade_admits_only_next_request
);

struct DenyList;

#[async_trait::async_trait]
impl UserInfoValidator for DenyList {
    async fn validate(
        &self,
        data: &mut UserValidationData,
        _: &RequestHookContext,
    ) -> AuthResult<Option<UserValidationRejection>> {
        Ok(data
            .user
            .email
            .as_deref()
            .is_some_and(|email| email.starts_with("deny"))
            .then(|| UserValidationRejection {
                error: "TAP_DENIED".into(),
                error_description: Some("One Tap identity denied".into()),
            }))
    }
}

struct Tap {
    remote: Provider,
}

impl Tap {
    async fn start() -> Self {
        Self {
            remote: Provider::start(
                "application/json",
                include_str!("../../../fixtures/one-tap/jwks.json"),
            )
            .await,
        }
    }

    fn config(&self, client_id: Option<OneTapClientId>, disable_signup: bool) -> OneTapConfig {
        OneTapConfig {
            client_id,
            disable_signup,
            jwks_source: Some(Arc::new(HttpOAuthJwksSource::new(
                self.remote.url.join("keys").unwrap().to_string(),
            ))),
        }
    }

    async fn auth<B: Backend>(
        &self,
        connection: &B::Connection,
        account: AccountConfig,
        one_tap: OneTapConfig,
        google: Option<OAuthProvider>,
    ) -> TestResult<Alibi<B::Schema>> {
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN).account(account);
        config.user_validation = Some(Arc::new(DenyList));
        let mut builder = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new())
            .plugin(SessionManagementPlugin::new())
            .plugin(AdminPlugin::new())
            .plugin(OneTapPlugin::with_config(one_tap));
        if let Some(google) = google {
            builder = builder.plugin(OAuthPlugin::new().add_provider("google", google));
        }
        Ok(builder.build().await?)
    }
}

fn token(claims: Value) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut full = json!({"iss":"https://accounts.google.com","aud":"tap-client","iat":now,"exp":now+300,"sub":"tap-sub","email":"tap@example.test","email_verified":true,"name":"Tap User","picture":"https://images.example/tap"});
    for (key, value) in claims.as_object().unwrap() {
        if value.is_null() {
            drop(full.as_object_mut().unwrap().remove(key));
        } else {
            drop(
                full.as_object_mut()
                    .unwrap()
                    .insert(key.clone(), value.clone()),
            );
        }
    }
    super::oauth_signed::token(&full, false, "one-tap-local-rs256").unwrap()
}

async fn tap<S: AuthSchema>(auth: &Alibi<S>, claims: Value, cookie: &str) -> AuthResponse {
    Box::pin(auth.handle_request(request(
        "/one-tap/callback",
        Some(json!({"idToken": token(claims)})),
        cookie,
    )))
    .await
    .unwrap()
}

async fn one_tap_token_admission_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let tap_remote = Tap::start().await;
    let mut trace = Trace::default();

    let workspace = |domain: &str| {
        let mut provider = OAuthProvider::google("provider-client", "provider-secret");
        provider.additional_client_ids = vec!["provider-extra".into()];
        provider.hosted_domain = Some(domain.into());
        provider
    };
    let multiple = tap_remote
        .auth::<B>(
            &connection,
            AccountConfig::default(),
            tap_remote.config(
                Some(OneTapClientId::Multiple(vec![
                    "tap-client".into(),
                    "second-client".into(),
                ])),
                false,
            ),
            Some(workspace("workspace.test")),
        )
        .await?;
    for (label, claims) in [
        ("missing hosted domain", json!({})),
        ("wrong hosted domain", json!({"hd":"other.test"})),
        ("empty hosted domain", json!({"hd":""})),
        (
            "second audience",
            json!({"hd":"workspace.test","aud":"second-client","sub":"second-sub","email":"second@example.test"}),
        ),
        (
            "provider audience ignored",
            json!({"hd":"workspace.test","aud":"provider-client"}),
        ),
        ("missing email", json!({"hd":"workspace.test","email":null})),
        ("empty email", json!({"hd":"workspace.test","email":""})),
    ] {
        trace.response(label, &tap(&multiple, claims, "").await);
    }

    let wildcard = tap_remote
        .auth::<B>(
            &connection,
            AccountConfig::default(),
            tap_remote.config(Some("tap-client".into()), false),
            Some(workspace("*")),
        )
        .await?;
    trace.response(
        "wildcard without domain",
        &tap(&wildcard, json!({}), "").await,
    );
    trace.response(
        "wildcard with domain",
        &tap(
            &wildcard,
            json!({"hd":"anything.test","sub":"wild-sub","email":"wild@example.test"}),
            "",
        )
        .await,
    );

    for (label, sub) in [
        ("number subject", json!(5)),
        ("boolean subject", json!(true)),
        ("array subject", json!([1])),
        ("object subject", json!({"id": 1})),
        ("zero subject", json!(0)),
        ("empty subject", json!("")),
    ] {
        trace.response(
            label,
            &tap(&wildcard, json!({"hd":"x.test","sub":sub}), "").await,
        );
    }

    let mut malformed = request("/one-tap/callback", Some(json!({"idToken":"garbage"})), "");
    trace.response(
        "garbage token",
        &Box::pin(wildcard.handle_request(malformed.clone())).await?,
    );
    malformed.body = Some(b"{}".to_vec());
    trace.response(
        "missing token",
        &Box::pin(wildcard.handle_request(malformed)).await?,
    );

    let derived = tap_remote
        .auth::<B>(
            &connection,
            AccountConfig::default(),
            tap_remote.config(Some(OneTapClientId::Single(String::new())), false),
            Some({
                let mut provider = OAuthProvider::google("tap-client", "provider-secret");
                provider.additional_client_ids = vec!["extra-client".into()];
                provider
            }),
        )
        .await?;
    trace.response(
        "provider audience",
        &tap(
            &derived,
            json!({"sub":"derived-sub","email":"derived@example.test"}),
            "",
        )
        .await,
    );
    trace.response(
        "provider additional audience",
        &tap(
            &derived,
            json!({"aud":"extra-client","sub":"extra-sub","email":"extra@example.test"}),
            "",
        )
        .await,
    );
    trace.response(
        "foreign audience",
        &tap(&derived, json!({"aud":"foreign-client"}), "").await,
    );
    let now = chrono::Utc::now().timestamp();
    let claims = json!({"iss":"https://accounts.google.com","aud":"tap-client","sub":"alg-sub","email":"alg@example.test","iat":now,"exp":now+300});
    trace.response(
        "unexpected algorithm",
        &Box::pin(derived.handle_request(request(
            "/one-tap/callback",
            Some(json!({"idToken": super::oauth_signed::protected_token(&claims, json!({"alg":"RS384","kid":"one-tap-local-rs256"}))?})),
            "",
        )))
        .await?,
    );

    let bare = tap_remote
        .auth::<B>(
            &connection,
            AccountConfig::default(),
            tap_remote.config(None, false),
            None,
        )
        .await?;
    trace.response("no client configured", &tap(&bare, json!({}), "").await);

    let closed = tap_remote
        .auth::<B>(
            &connection,
            AccountConfig::default(),
            tap_remote.config(Some("tap-client".into()), true),
            None,
        )
        .await?;
    let created = db.count("users").await?;
    trace.response(
        "sign up disabled",
        &tap(
            &closed,
            json!({"sub":"closed-sub","email":"closed@example.test"}),
            "",
        )
        .await,
    );
    assert_eq!(db.count("users").await?, created);

    let strict = tap_remote
        .auth::<B>(
            &connection,
            AccountConfig::default(),
            tap_remote.config(Some("tap-client".into()), false),
            Some({
                let mut provider = OAuthProvider::google("tap-client", "provider-secret");
                provider.require_email_verification = true;
                provider
            }),
        )
        .await?;
    trace.response(
        "unverified email required",
        &tap(
            &strict,
            json!({"sub":"strict-sub","email":"strict@example.test","email_verified":false}),
            "",
        )
        .await,
    );
    trace.response(
        "string-verified email",
        &tap(
            &strict,
            json!({"sub":"string-sub","email":"string@example.test","email_verified":"true"}),
            "",
        )
        .await,
    );
    trace.value(
        "accounts",
        json!(
            db.count_where(
                "SELECT COUNT(*) FROM accounts WHERE provider_id = $1",
                &["google"]
            )
            .await?
        ),
    );
    trace.assert("social/one-tap-admission");
    B::close(connection).await
}

async fn one_tap_identity_outcomes<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let remote = Tap::start().await;
    let mut trace = Trace::default();
    let mut linking = AccountConfig::default();
    linking.account_linking.require_local_email_verified = false;
    linking.account_linking.update_user_info_on_link = true;
    let auth = remote
        .auth::<B>(
            &connection,
            linking,
            remote.config(Some("tap-client".into()), false),
            None,
        )
        .await?;

    trace.response("registered", &tap(&auth, json!({}), "").await);
    trace.response("returning", &tap(&auth, json!({}), "").await);
    trace.response(
        "unverified registration",
        &tap(
            &auth,
            json!({"sub":"late-sub","email":"late@example.test","email_verified":false}),
            "",
        )
        .await,
    );
    let promoted = tap(
        &auth,
        json!({"sub":"late-sub","email":"late@example.test","email_verified":true}),
        "",
    )
    .await;
    trace.response("verified later", &promoted);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE email = $1 AND email_verified = true",
            &["late@example.test"]
        )
        .await?,
        1
    );

    drop(signup(&auth, "local@example.test").await);
    let linked = tap(
        &auth,
        json!({"sub":"local-sub","email":"local@example.test","name":"Provider Name"}),
        "",
    )
    .await;
    trace.response("linked to local user", &linked);
    assert_eq!(
        db.text(
            "SELECT name FROM users WHERE email = $1",
            &["local@example.test"]
        )
        .await?
        .as_deref(),
        Some("Provider Name")
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE email = $1 AND email_verified = true",
            &["local@example.test"]
        )
        .await?,
        1
    );

    trace.response(
        "denied by admission policy",
        &tap(
            &auth,
            json!({"sub":"deny-sub","email":"deny@example.test"}),
            "",
        )
        .await,
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE email = $1",
            &["deny@example.test"]
        )
        .await?,
        0
    );

    _ = db
        .execute(
            "UPDATE users SET banned = true WHERE email = $1",
            &["tap@example.test"],
        )
        .await?;
    trace.response("banned", &tap(&auth, json!({}), "").await);
    B::close(connection).await?;
    trace.assert("social/one-tap-identity");
    Ok(())
}

async fn one_tap_account_cookie_and_remember_state<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let remote = Tap::start().await;
    let mut trace = Trace::default();
    let mut account = AccountConfig {
        store_account_cookie: true,
        ..Default::default()
    };
    account.account_linking.require_local_email_verified = false;
    let auth = remote
        .auth::<B>(
            &connection,
            account,
            remote.config(Some("tap-client".into()), false),
            None,
        )
        .await?;
    let owner = signup(&auth, "remember@example.test").await;
    let owner_session = cookies(&owner);
    let forgetful = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"remember@example.test","password":PASSWORD,"rememberMe":false})),
            "",
        ),
        200,
    )
    .await;
    let cookie = cookies(&forgetful);
    assert!(cookie.contains("dont_remember="), "{cookie}");
    let response = tap(
        &auth,
        json!({"sub":"remember-sub","email":"remember@example.test"}),
        &cookie,
    )
    .await;
    trace.response("not remembered", &response);
    assert!(
        response
            .headers
            .get_all("set-cookie")
            .any(|header| header.starts_with("better-auth.dont_remember="))
    );
    assert!(
        response
            .headers
            .get_all("set-cookie")
            .any(|header| header.starts_with("better-auth.account_data="))
    );
    let remembered = tap(
        &auth,
        json!({"sub":"remember-sub","email":"remember@example.test"}),
        &owner_session,
    )
    .await;
    trace.response("remembered", &remembered);
    assert!(
        !remembered
            .headers
            .get_all("set-cookie")
            .any(|header| header.starts_with("better-auth.dont_remember=")
                && !header.contains("Max-Age=0"))
    );
    trace.assert("social/one-tap-cookies");
    B::close(connection).await
}

async fn one_tap_strict_upgrade_admits_only_next_request<B: Backend>(db: Db) -> TestResult {
    fn runtime<B: Backend>(
        connection: &B::Connection,
        account: AccountConfig,
        one_tap: OneTapConfig,
        google: Option<OAuthProvider>,
    ) -> AuthBuilder<B::Schema> {
        let config = AuthConfig::new(SECRET).base_url(ORIGIN).account(account);
        let mut b = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(OneTapPlugin::with_config(one_tap));
        if let Some(g) = google {
            b = b.plugin(OAuthPlugin::new().add_provider("google", g));
        }
        b
    }

    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let remote = Tap::start().await;
    let mut google = OAuthProvider::google("tap-client", "secret");
    google.require_email_verification = true;
    let auth = runtime::<B>(
        &connection,
        AccountConfig::default(),
        remote.config(None, false),
        Some(google),
    )
    .build()
    .await?;
    let foreign = signup(&auth, "foreign@example.test").await;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let first = tap(&auth, json!({"email_verified":false}), "").await;
    assert_eq!(first.status, 403);
    assert_eq!(body(&first)["code"], "EMAIL_NOT_VERIFIED");
    assert!(first.headers.get_all("set-cookie").next().is_none());
    let id = db
        .text("SELECT id FROM users WHERE email=$1", &["tap@example.test"])
        .await?
        .unwrap();
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE id=$1 AND email_verified=false",
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
    let second = tap(&auth, json!({"email_verified":true}), "").await;
    assert_eq!(second.status, 403);
    assert_eq!(body(&second)["code"], "EMAIL_NOT_VERIFIED");
    assert!(second.headers.get_all("set-cookie").next().is_none());
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE id=$1 AND email_verified=true",
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
    let third = tap(&auth, json!({"email_verified":true}), "").await;
    assert_eq!(third.status, 200);
    assert_eq!(body(&third)["user"]["id"], id);
    assert_eq!(body(&third)["user"]["emailVerified"], true);
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM sessions WHERE user_id=$1", &[&id])
            .await?,
        1
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM accounts WHERE provider_id='google' AND user_id=$1",
            &[&id]
        )
        .await?,
        1
    );
    authenticated(&auth, &cookies(&third), "tap@example.test").await;
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    for (before, now) in before.iter().zip(after.iter()) {
        let before: Vec<Value> = serde_json::from_str(before)?;
        let now: Vec<Value> = serde_json::from_str(now)?;
        assert!(before.iter().all(|r| now.contains(r)));
    }
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}
