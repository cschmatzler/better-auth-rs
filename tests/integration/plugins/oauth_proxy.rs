//! Genuine provider HTTP and public dispatch own proxy state, row and principal transitions.
#![allow(
    clippy::unwrap_used,
    reason = "local fixture setup and contract assertions must succeed"
)]

use crate::storage::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::plugins::oauth::OAuthProvider;
use alibi::plugins::{
    EmailPasswordPlugin, OAuthPlugin, OAuthProxyConfig, OAuthProxyPlugin, SessionManagementPlugin,
};
use alibi::{Alibi, AuthBuilder, AuthConfig, AuthSchema};
use alibi::{AuthRequest, AuthResponse, AuthSession, AuthUser, HttpMethod};
use axum::{
    Json, Router,
    extract::{Form, State},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

const PREVIEW: &str = "http://localhost:42681";

const PRODUCTION: &str = "http://127.0.0.1:42681";

const SECRET: &str = "local-proxy-test-session-secret-32";

const PROXY_SECRET: &str = "local-proxy-test-dedicated-secret-32";

#[derive(Default)]
struct Provider {
    verifier: String,
    code: usize,
    consumed: bool,
    receipts: Vec<Value>,
}

struct Fixture<B: Backend> {
    preview: Alibi<B::Schema>,
    production: Alibi<B::Schema>,
    preview_db: Db,
    production_db: Db,
    _connections: (B::Connection, B::Connection),
    provider: Arc<Mutex<Provider>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Copy, Default)]
struct Options {
    cookie_state: bool,
    shared_secret: bool,
}

impl<B: Backend> Fixture<B> {
    async fn new(preview_db: Db) -> Self {
        Self::with(preview_db, Options::default()).await
    }

    async fn with(preview_db: Db, options: Options) -> Self {
        let provider = Arc::new(Mutex::new(Provider::default()));
        let router = Router::new().route("/oauth/token", post(|State(state): State<Arc<Mutex<Provider>>>, Form(form): Form<HashMap<String, String>>| async move {
            let mut provider_2 = state.lock().unwrap(); provider_2.receipts.push(json!({"stage":"token", "form":form}));
            assert_eq!(form.get("client_id").expect("provider fixture contains this parameter"), "local-client"); assert_eq!(form.get("client_secret").expect("provider fixture contains this parameter"), "local-secret");
            assert_eq!(form.get("redirect_uri").expect("provider fixture contains this parameter"), &format!("{PRODUCTION}/api/auth/callback/gitlab"));
            assert_eq!(form.get("code_verifier").expect("provider fixture contains this parameter"), &provider_2.verifier); assert_eq!(provider_2.verifier.len(), 128);
            if provider_2.consumed || form.get("code").expect("provider fixture contains this parameter") != &format!("real-code-{}", provider_2.code) { return (axum::http::StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))); }
            provider_2.consumed = true; drop(provider_2);
            (axum::http::StatusCode::OK, Json(json!({"access_token":"real-provider-access", "refresh_token":"real-provider-refresh", "token_type":"Bearer", "scope":"read_user issued", "expires_in":3600})))
        })).route("/api/v4/user", get(|State(state): State<Arc<Mutex<Provider>>>, headers: axum::http::HeaderMap| async move {
            state.lock().unwrap().receipts.push(json!({"stage":"userinfo", "authorization":headers.get("authorization").expect("provider fixture contains this parameter").to_str().unwrap()}));
            Json(json!({"id":777,"email":"proxy-owner@fixture.test","email_verified":true,"name":"Actual Provider Owner","state":"active","locked":false,"avatar_url":"https://assets.fixture.test/owner.png"}))
        })).with_state(Arc::clone(&provider));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let production_db = preview_db.fresh().await.unwrap();
        let (preview_connection, _) = preview_db.migrated::<B>(SECRET).await.unwrap();
        let (production_connection, _) = production_db.migrated::<B>(SECRET).await.unwrap();
        let enabled = std::env::var_os("OAUTH_PROXY_BASELINE").is_none();
        let preview = build::<B>(PREVIEW, &issuer, &preview_connection, enabled, options).await;
        let production = build::<B>(
            PRODUCTION,
            &issuer,
            &production_connection,
            enabled,
            options,
        )
        .await;
        Self {
            preview,
            production,
            preview_db,
            production_db,
            _connections: (preview_connection, production_connection),
            provider,
            task,
        }
    }
    async fn issue(&self, endpoint: &str, cookie: Option<&str>) -> (url::Url, Value) {
        let (url, state, _) = self.issue_with(endpoint, cookie, json!({})).await;
        (url, state)
    }

    /// Also returns the cookies the authorization response set.
    async fn issue_with(
        &self,
        endpoint: &str,
        cookie: Option<&str>,
        extra: Value,
    ) -> (url::Url, Value, String) {
        let mut input = json!({"provider":"gitlab", "callbackURL":format!("{PREVIEW}/complete?application=kept"), "newUserCallbackURL":format!("{PREVIEW}/new-owner"), "errorCallbackURL":format!("{PREVIEW}/failure"), "disableRedirect":true, "additionalData":{"serverContext":{"anonymousUserId":"forged-foreign"},"application":{"kept":true}}});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let issued = request(&self.preview, endpoint, Some(input), cookie).await;
        assert_eq!(issued.status, 200);
        let body: Value = serde_json::from_slice(&issued.body).unwrap();
        let url = url::Url::parse(
            body.get("url")
                .expect("provider fixture contains this parameter")
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            query
                .get("redirect_uri")
                .expect("provider fixture contains this parameter"),
            &format!("{PRODUCTION}/api/auth/callback/gitlab"),
            "original Native OAuth redirected to preview instead of production"
        );
        let raw = self
            .preview_db
            .text(
                "SELECT value FROM verifications WHERE identifier LIKE 'auth-state:%'",
                &[],
            )
            .await
            .unwrap();
        let state: Value = match raw {
            Some(raw) => serde_json::from_str(&raw).unwrap(),
            None => {
                let cookie = issued
                    .headers
                    .get_all("set-cookie")
                    .find(|cookie| cookie.starts_with("better-auth.oauth_state="))
                    .unwrap();
                let value = cookie.split(';').next().unwrap().split_once('=').unwrap().1;
                open(value, SECRET, "oauth-state-cookie")
            }
        };
        assert_eq!(
            state
                .get("application")
                .expect("provider fixture contains this parameter"),
            &json!({"kept":true})
        );
        assert!(state.get("serverContext").is_none());
        let mut provider = self.provider.lock().unwrap();
        provider.code += 1;
        provider.consumed = false;
        provider.verifier = state
            .get("codeVerifier")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        drop(provider);
        (url, state, cookies(&issued))
    }
    async fn forward(&self, authorization: &url::Url) -> (AuthResponse, url::Url) {
        let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
        let mut callback = url::Url::parse(
            query
                .get("redirect_uri")
                .expect("provider fixture contains this parameter"),
        )
        .unwrap();
        _ = callback
            .query_pairs_mut()
            .append_pair(
                "state",
                query
                    .get("state")
                    .expect("provider fixture contains this parameter"),
            )
            .append_pair(
                "code",
                &format!("real-code-{}", self.provider.lock().unwrap().code),
            );
        let response = request(&self.production, &target(&callback), None, None).await;
        assert_eq!(response.status, 302);
        let bridge = location(&response);
        assert_eq!(bridge.origin().ascii_serialization(), PREVIEW);
        assert_eq!(bridge.path(), "/api/auth/callback/gitlab/oauth-proxy");
        (response, bridge)
    }
}

impl<B: Backend> Drop for Fixture<B> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn request<S: AuthSchema>(
    auth: &Alibi<S>,
    path: &str,
    body: Option<Value>,
    cookie: Option<&str>,
) -> AuthResponse {
    let mut req = AuthRequest::new(
        if body.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        path.split('?').next().unwrap(),
    );
    if let Some((_, query)) = path.split_once('?') {
        req.query = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
    }
    drop(req.headers.insert("origin".into(), PREVIEW.into()));
    if let Some(body) = body {
        req.body = Some(body.to_string().into_bytes());
        drop(
            req.headers
                .insert("content-type".into(), "application/json".into()),
        );
    }
    if let Some(cookie) = cookie {
        drop(req.headers.insert("cookie".into(), cookie.into()));
    }
    Box::pin(auth.handle_request(req)).await.unwrap()
}

fn cookies(response: &AuthResponse) -> String {
    response
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}

fn location(response: &AuthResponse) -> url::Url {
    url::Url::parse(
        response
            .headers
            .get("location")
            .expect("provider fixture contains this parameter"),
    )
    .unwrap()
}

fn target(url: &url::Url) -> String {
    format!("{}?{}", url.path(), url.query().unwrap_or_default())
}

async fn rows(database: &Db) -> Value {
    let mut value = serde_json::Map::new();
    for table in ["users", "accounts", "sessions", "verifications"] {
        drop(value.insert(
            table.into(),
            serde_json::from_str(&database.table(table).await.unwrap()).unwrap(),
        ));
    }
    Value::Object(value)
}

async fn build<B: Backend>(
    origin: &str,
    issuer: &str,
    database: &B::Connection,
    proxy: bool,
    options: Options,
) -> Alibi<B::Schema> {
    let mut config = AuthConfig::new(SECRET)
        .base_url(origin)
        .trusted_origin(PREVIEW)
        .trusted_origin(PRODUCTION);
    if options.cookie_state {
        config.account.store_state_strategy = alibi::config::OAuthStateStrategy::Cookie;
    }
    let builder = AuthBuilder::<B::Schema>::new(config.clone())
        .store(B::store(Arc::new(config), database))
        .plugin(EmailPasswordPlugin::new().enable_username(false))
        .plugin(SessionManagementPlugin::new())
        .plugin(OAuthPlugin::new().add_provider(
            "gitlab",
            OAuthProvider::gitlab_with_issuer("local-client", "local-secret", issuer),
        ));
    if proxy {
        builder
            .plugin(OAuthProxyPlugin::with_config(OAuthProxyConfig {
                current_url: Some(origin.into()),
                production_url: Some(PRODUCTION.into()),
                secret: (!options.shared_secret).then(|| PROXY_SECRET.into()),
                ..Default::default()
            }))
            .build()
            .await
            .unwrap()
    } else {
        builder.build().await.unwrap()
    }
}

fn cipher(secret: &str, purpose: &str) -> chacha20poly1305::XChaCha20Poly1305 {
    use chacha20poly1305::KeyInit;
    use sha2::{Digest, Sha256};
    let mut key = [0_u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(b"better-auth:oauth-encryption:v1"), secret.as_bytes())
        .expand(format!("better-auth:{purpose}:v1").as_bytes(), &mut key)
        .unwrap();
    let hex = key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    chacha20poly1305::XChaCha20Poly1305::new(&Sha256::digest(hex.as_bytes()))
}

/// The pinned symmetric encryption under a purpose-derived key.
fn seal(plain: &str, secret: &str, purpose: &str) -> String {
    use chacha20poly1305::aead::Aead;
    let nonce = [7_u8; 24];
    let sealed = cipher(secret, purpose)
        .encrypt(&chacha20poly1305::XNonce::from(nonce), plain.as_bytes())
        .unwrap();
    [nonce.as_slice(), &sealed]
        .concat()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn open(sealed: &str, secret: &str, purpose: &str) -> Value {
    use chacha20poly1305::aead::Aead;
    let bytes = (0..sealed.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&sealed[index..index + 2], 16).unwrap())
        .collect::<Vec<_>>();
    let (nonce, ciphertext) = bytes.split_at(24);
    let plain = cipher(secret, purpose)
        .decrypt(
            &chacha20poly1305::XNonce::try_from(nonce).unwrap(),
            ciphertext,
        )
        .unwrap();
    serde_json::from_slice(&plain).unwrap()
}

async fn restored_cookie_state_replays_create_sessions_without_rebinding_owner<B: Backend>(
    db: Db,
) -> TestResult {
    let fixture = Fixture::<B>::with(
        db,
        Options {
            cookie_state: true,
            shared_secret: false,
        },
    )
    .await;
    let (authorization, _, browser) = fixture
        .issue_with("/api/auth/sign-in/social", None, json!({}))
        .await;
    let (_, bridge) = fixture.forward(&authorization).await;
    let production = rows(&fixture.production_db).await;
    let first = request(&fixture.preview, &target(&bridge), None, Some(&browser)).await;
    assert_eq!(first.status, 302);
    assert!(
        first
            .headers
            .get_all("set-cookie")
            .any(|x| x.starts_with("better-auth.oauth_state=") && x.contains("Max-Age=0"))
    );
    let owner = fixture
        .preview
        .store()
        .get_user_by_email("proxy-owner@fixture.test")
        .await?
        .unwrap();
    let owner_id = owner.id().into_owned();
    let stable = rows(&fixture.preview_db).await;
    let ordinary = request(
        &fixture.preview,
        &target(&bridge),
        None,
        Some(&cookies(&first)),
    )
    .await;
    assert!(
        location(&ordinary)
            .as_str()
            .contains("error=state_mismatch")
    );
    assert_eq!(rows(&fixture.preview_db).await, stable);
    let second = request(&fixture.preview, &target(&bridge), None, Some(&browser)).await;
    assert_eq!(second.status, 302);
    assert_eq!(
        location(&second).as_str(),
        format!("{PREVIEW}/complete?application=kept")
    );
    let path = target(&bridge);
    let (a, b) = tokio::join!(
        request(&fixture.preview, &path, None, Some(&browser)),
        request(&fixture.preview, &path, None, Some(&browser))
    );
    assert_eq!((a.status, b.status), (302, 302));
    assert_eq!(fixture.preview_db.count("users").await?, 1);
    assert_eq!(fixture.preview_db.count("accounts").await?, 1);
    assert_eq!(fixture.preview_db.count("sessions").await?, 4);
    assert_eq!(fixture.preview_db.count("verifications").await?, 0);
    for response in [&first, &second, &a, &b] {
        let read = request(
            &fixture.preview,
            "/api/auth/get-session",
            None,
            Some(&cookies(response)),
        )
        .await;
        let view: Value = serde_json::from_slice(&read.body)?;
        assert_eq!(
            view.get("user").unwrap().get("id").unwrap().as_str(),
            Some(owner_id.as_str())
        );
    }
    assert_eq!(rows(&fixture.production_db).await, production);
    Ok(())
}

async fn cookie_state_link_restores_initiating_owner_across_session_change<B: Backend>(
    db: Db,
) -> TestResult {
    let fixture = Fixture::<B>::with(
        db,
        Options {
            cookie_state: true,
            shared_secret: false,
        },
    )
    .await;
    let owner = request(
        &fixture.preview,
        "/api/auth/sign-up/email",
        Some(json!({"email":"proxy-owner@fixture.test","name":"Owner","password":"password123"})),
        None,
    )
    .await;
    let foreign = request(
        &fixture.preview,
        "/api/auth/sign-up/email",
        Some(json!({"email":"foreign@fixture.test","name":"Foreign","password":"password123"})),
        None,
    )
    .await;
    assert_eq!((owner.status, foreign.status), (200, 200));
    let owner_view: Value = serde_json::from_slice(&owner.body)?;
    let foreign_view: Value = serde_json::from_slice(&foreign.body)?;
    let (authorization, _, browser) = fixture
        .issue_with("/api/auth/link-social", Some(&cookies(&owner)), json!({}))
        .await;
    let (_, bridge) = fixture.forward(&authorization).await;
    let before = rows(&fixture.preview_db).await;
    let production = rows(&fixture.production_db).await;
    let denied = request(
        &fixture.preview,
        &target(&bridge),
        None,
        Some(&cookies(&foreign)),
    )
    .await;
    assert!(location(&denied).as_str().contains("error=state_mismatch"));
    assert_eq!(rows(&fixture.preview_db).await, before);
    let restored = browser
        .split("; ")
        .filter(|x| x.starts_with("better-auth.oauth_state="))
        .collect::<Vec<_>>()
        .join("; ");
    let jar = format!("{}; {restored}", cookies(&foreign));
    let linked = request(&fixture.preview, &target(&bridge), None, Some(&jar)).await;
    assert_eq!(linked.status, 302);
    assert_eq!(
        location(&linked).as_str(),
        format!("{PREVIEW}/complete?application=kept")
    );
    assert!(
        !linked
            .headers
            .get_all("set-cookie")
            .any(|x| x.starts_with("better-auth.session_token="))
    );
    assert_eq!(
        serde_json::from_str::<Value>(&fixture.preview_db.table("users").await?)?,
        before.get("users").unwrap().clone()
    );
    assert_eq!(
        serde_json::from_str::<Value>(&fixture.preview_db.table("sessions").await?)?,
        before.get("sessions").unwrap().clone()
    );
    assert_eq!(
        fixture
            .preview_db
            .text(
                "SELECT user_id FROM accounts WHERE provider_id='gitlab'",
                &[]
            )
            .await?
            .as_deref(),
        owner_view.get("user").unwrap().get("id").unwrap().as_str()
    );
    let read = request(
        &fixture.preview,
        "/api/auth/get-session",
        None,
        Some(&cookies(&foreign)),
    )
    .await;
    let view: Value = serde_json::from_slice(&read.body)?;
    assert_eq!(
        view.get("user").unwrap().get("id").unwrap(),
        foreign_view.get("user").unwrap().get("id").unwrap()
    );
    assert_eq!(
        view.get("session").unwrap().get("token").unwrap(),
        foreign_view.get("token").unwrap()
    );
    let after = rows(&fixture.preview_db).await;
    let replay = request(
        &fixture.preview,
        &target(&bridge),
        None,
        Some(&cookies(&foreign)),
    )
    .await;
    assert!(location(&replay).as_str().contains("error=state_mismatch"));
    assert_eq!(rows(&fixture.preview_db).await, after);
    assert_eq!(rows(&fixture.production_db).await, production);
    Ok(())
}

async fn cookie_state_expiry_clears_only_authenticated_matching_proof<B: Backend>(
    db: Db,
) -> TestResult {
    let fixture = Fixture::<B>::with(
        db,
        Options {
            cookie_state: true,
            shared_secret: false,
        },
    )
    .await;
    let (authorization, state, browser) = fixture
        .issue_with("/api/auth/sign-in/social", None, json!({}))
        .await;
    let (_, bridge) = fixture.forward(&authorization).await;
    let before = rows(&fixture.preview_db).await;
    let production = rows(&fixture.production_db).await;
    let mut mismatch = state.clone();
    _ = mismatch
        .as_object_mut()
        .unwrap()
        .insert("oauthState".into(), json!("another-nonce"));
    let mut absent = state.clone();
    _ = absent.as_object_mut().unwrap().remove("oauthState");
    let mut expired = state.clone();
    _ = expired.as_object_mut().unwrap().insert(
        "expiresAt".into(),
        json!(chrono::Utc::now().timestamp_millis() - 60_000),
    );
    for (cookie, clear) in [
        ("".to_owned(), false),
        ("better-auth.oauth_state=00".into(), false),
        (
            format!(
                "better-auth.oauth_state={}",
                seal(&mismatch.to_string(), SECRET, "oauth-state-cookie")
            ),
            false,
        ),
        (
            format!(
                "better-auth.oauth_state={}",
                seal(&absent.to_string(), SECRET, "oauth-state-cookie")
            ),
            false,
        ),
        (
            format!(
                "better-auth.oauth_state={}",
                seal(&expired.to_string(), SECRET, "oauth-state-cookie")
            ),
            true,
        ),
    ] {
        let denied = request(&fixture.preview, &target(&bridge), None, Some(&cookie)).await;
        assert!(location(&denied).as_str().contains("error=state_mismatch"));
        assert_eq!(
            denied
                .headers
                .get_all("set-cookie")
                .any(|x| x.starts_with("better-auth.oauth_state=") && x.contains("Max-Age=0")),
            clear
        );
        assert_eq!(rows(&fixture.preview_db).await, before);
        assert_eq!(rows(&fixture.production_db).await, production);
    }
    let recovered = request(&fixture.preview, &target(&bridge), None, Some(&browser)).await;
    assert_eq!(recovered.status, 302);
    assert_eq!(
        location(&recovered).as_str(),
        format!("{PREVIEW}/new-owner")
    );
    assert_eq!(fixture.preview_db.count("sessions").await?, 1);
    Ok(())
}

async fn raw_profile_max_age_controls_admission_before_state_consumption<B: Backend>(
    db: Db,
) -> TestResult {
    for (max_age, age, accepts) in [
        (0.125, 200, false),
        (f64::NEG_INFINITY, 0, false),
        (f64::NAN, 65_000, true),
        (f64::INFINITY, 65_000, true),
    ] {
        let db = db.fresh().await?;
        let mut fixture = Fixture::<B>::new(db).await;
        let (authorization, _) = fixture.issue("/api/auth/sign-in/social", None).await;
        let (_, mut bridge) = fixture.forward(&authorization).await;
        let config = (*fixture.preview.context().config).clone();
        let issuer = authorization.origin().ascii_serialization();
        fixture.preview = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &fixture._connections.0))
            .plugin(SessionManagementPlugin::new())
            .plugin(OAuthPlugin::new().add_provider(
                "gitlab",
                OAuthProvider::gitlab_with_issuer("local-client", "local-secret", &issuer),
            ))
            .plugin(OAuthProxyPlugin::with_config(OAuthProxyConfig {
                current_url: Some(PREVIEW.into()),
                production_url: Some(PRODUCTION.into()),
                max_age_seconds: max_age,
                secret: Some(PROXY_SECRET.into()),
            }))
            .build()
            .await?;
        let profile = bridge
            .query_pairs()
            .find(|(k, _)| k == "profile")
            .unwrap()
            .1
            .into_owned();
        let mut payload = open(&profile, PROXY_SECRET, "oauth-proxy-profile");
        _ = payload.as_object_mut().unwrap().insert(
            "timestamp".into(),
            json!(chrono::Utc::now().timestamp_millis() - age),
        );
        let sealed = seal(&payload.to_string(), PROXY_SECRET, "oauth-proxy-profile");
        let pairs = bridge
            .query_pairs()
            .map(|(k, v)| {
                let value = if k == "profile" {
                    sealed.clone()
                } else {
                    v.into_owned()
                };
                (k.into_owned(), value)
            })
            .collect::<Vec<_>>();
        _ = bridge.query_pairs_mut().clear().extend_pairs(pairs);
        let before = rows(&fixture.preview_db).await;
        let production = rows(&fixture.production_db).await;
        let result = request(&fixture.preview, &target(&bridge), None, None).await;
        if accepts {
            assert_eq!(location(&result).as_str(), format!("{PREVIEW}/new-owner"));
            assert_eq!(fixture.preview_db.count("sessions").await?, 1);
            assert_eq!(fixture.preview_db.count("verifications").await?, 0);
        } else {
            assert!(location(&result).as_str().contains("error=payload_expired"));
            assert_eq!(result.headers.get_all("set-cookie").count(), 0);
            assert_eq!(rows(&fixture.preview_db).await, before);
        }
        assert_eq!(rows(&fixture.production_db).await, production);
    }
    Ok(())
}

async fn proxy_cache_publication_failure_retains_commit_and_discards_all_cookies<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::{
        AuthResult, CacheVersionContext, CacheVersionSource, CookieCacheConfig, CookieCacheVersion,
        CookieCacheVersionResolver,
    };
    struct Version;
    #[async_trait::async_trait]
    impl CookieCacheVersionResolver for Version {
        async fn resolve(&self, c: &CacheVersionContext) -> AuthResult<String> {
            if c.source() == CacheVersionSource::Created {
                Err(alibi::AuthError::internal("application publication outage"))
            } else {
                Ok("v1".into())
            }
        }
    }
    let mut fixture = Fixture::<B>::with(
        db,
        Options {
            cookie_state: true,
            shared_secret: false,
        },
    )
    .await;
    let (authorization, _, browser) = fixture
        .issue_with("/api/auth/sign-in/social", None, json!({}))
        .await;
    let (_, bridge) = fixture.forward(&authorization).await;
    let first = request(&fixture.preview, &target(&bridge), None, Some(&browser)).await;
    assert_eq!(first.status, 302);
    let (authorization, _, browser) = fixture
        .issue_with("/api/auth/sign-in/social", None, json!({}))
        .await;
    let (_, bridge) = fixture.forward(&authorization).await;
    let mut config = (*fixture.preview.context().config).clone();
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: true,
        version: Some(CookieCacheVersion::Resolver(Arc::new(Version))),
        ..Default::default()
    });
    let issuer = authorization.origin().ascii_serialization();
    fixture.preview = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &fixture._connections.0))
        .plugin(SessionManagementPlugin::new())
        .plugin(OAuthPlugin::new().add_provider(
            "gitlab",
            OAuthProvider::gitlab_with_issuer("local-client", "local-secret", &issuer),
        ))
        .plugin(OAuthProxyPlugin::with_config(OAuthProxyConfig {
            current_url: Some(PREVIEW.into()),
            production_url: Some(PRODUCTION.into()),
            secret: Some(PROXY_SECRET.into()),
            ..Default::default()
        }))
        .build()
        .await?;
    let users = fixture.preview_db.table("users").await?;
    let production = rows(&fixture.production_db).await;
    let count = fixture.preview_db.count("sessions").await?;
    let failed = request(&fixture.preview, &target(&bridge), None, Some(&browser)).await;
    assert_eq!(failed.status, 500);
    assert!(failed.body.is_empty());
    assert!(failed.headers.get("location").is_none());
    assert_eq!(failed.headers.get_all("set-cookie").count(), 0);
    assert_eq!(fixture.preview_db.table("users").await?, users);
    assert_eq!(fixture.preview_db.count("sessions").await?, count + 1);
    assert_eq!(fixture.preview_db.count("verifications").await?, 0);
    let id = fixture
        .preview_db
        .text(
            "SELECT id FROM users WHERE email='proxy-owner@fixture.test'",
            &[],
        )
        .await?
        .unwrap();
    assert_eq!(
        fixture
            .preview_db
            .count_where("SELECT COUNT(*) FROM sessions WHERE user_id=$1", &[&id])
            .await?,
        2
    );
    assert_eq!(rows(&fixture.production_db).await, production);
    Ok(())
}

async fn proxy_loose_profile_retains_resolved_account_key_authority<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::oauth::{OAuthAccountKey, OAuthAccountKeyContext, OAuthAccountKeyResolver};
    struct Key;
    #[async_trait::async_trait]
    impl OAuthAccountKeyResolver for Key {
        async fn resolve(&self, c: OAuthAccountKeyContext) -> Result<Value, String> {
            assert_eq!(c.profile.get("id").unwrap(), 777);
            assert_eq!(
                c.tokens.access_token.as_deref(),
                Some("real-provider-access")
            );
            Ok(json!("stable-custom-account"))
        }
    }
    let mut fixture = Fixture::<B>::new(db).await;
    let (authorization, _) = fixture.issue("/api/auth/sign-in/social", None).await;
    let issuer = authorization.origin().ascii_serialization();
    let config = (*fixture.production.context().config).clone();
    let mut provider = OAuthProvider::gitlab_with_issuer("local-client", "local-secret", &issuer);
    provider
        .authorization
        .get_or_insert_with(Default::default)
        .account_key = Some(OAuthAccountKey(Arc::new(Key)));
    fixture.production = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &fixture._connections.1))
        .plugin(OAuthPlugin::new().add_provider("gitlab", provider))
        .plugin(OAuthProxyPlugin::with_config(OAuthProxyConfig {
            current_url: Some(PRODUCTION.into()),
            production_url: Some(PRODUCTION.into()),
            secret: Some(PROXY_SECRET.into()),
            ..Default::default()
        }))
        .build()
        .await?;
    let (_, mut bridge) = fixture.forward(&authorization).await;
    let profile = bridge
        .query_pairs()
        .find(|(k, _)| k == "profile")
        .unwrap()
        .1
        .into_owned();
    let mut payload = open(&profile, PROXY_SECRET, "oauth-proxy-profile");
    assert_eq!(
        payload.get("account").unwrap().get("accountId").unwrap(),
        "stable-custom-account"
    );
    _ = payload
        .get_mut("userInfo")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("id".into(), json!("display-only-id"));
    _ = payload
        .get_mut("userInfo")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("unrelated".into(), json!({"nested":true}));
    _ = payload
        .get_mut("account")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), json!({"kept":"input"}));
    _ = payload
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), json!([1, true]));
    let sealed = seal(&payload.to_string(), PROXY_SECRET, "oauth-proxy-profile");
    let pairs = bridge
        .query_pairs()
        .map(|(k, v)| {
            let value = if k == "profile" {
                sealed.clone()
            } else {
                v.into_owned()
            };
            (k.into_owned(), value)
        })
        .collect::<Vec<_>>();
    _ = bridge.query_pairs_mut().clear().extend_pairs(pairs);
    let production = rows(&fixture.production_db).await;
    let done = request(&fixture.preview, &target(&bridge), None, None).await;
    assert_eq!(done.status, 302);
    assert_eq!(location(&done).as_str(), format!("{PREVIEW}/new-owner"));
    assert_eq!(
        fixture
            .preview_db
            .text(
                "SELECT account_id FROM accounts WHERE provider_id='gitlab'",
                &[]
            )
            .await?
            .as_deref(),
        Some("stable-custom-account")
    );
    assert_eq!(
        fixture
            .preview_db
            .count_where(
                "SELECT COUNT(*) FROM accounts WHERE account_id='display-only-id'",
                &[]
            )
            .await?,
        0
    );
    let read = request(
        &fixture.preview,
        "/api/auth/get-session",
        None,
        Some(&cookies(&done)),
    )
    .await;
    let view: Value = serde_json::from_slice(&read.body)?;
    assert_eq!(
        view.get("user").unwrap().get("email").unwrap(),
        "proxy-owner@fixture.test"
    );
    assert_eq!(
        fixture
            .preview_db
            .text(
                "SELECT user_id FROM accounts WHERE provider_id='gitlab'",
                &[]
            )
            .await?
            .as_deref(),
        view.get("user").unwrap().get("id").unwrap().as_str()
    );
    assert_eq!(rows(&fixture.production_db).await, production);
    Ok(())
}

async fn empty_query_code_prevents_body_grant_fallback_and_preserves_pending_state<B: Backend>(
    db: Db,
) -> TestResult {
    let fixture = Fixture::<B>::new(db).await;
    let (authorization, _) = fixture.issue("/api/auth/sign-in/social", None).await;
    let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
    let original = rows(&fixture.preview_db).await;
    let production = rows(&fixture.production_db).await;
    let code = format!("real-code-{}", fixture.provider.lock().unwrap().code);
    let mut callback = AuthRequest::new(HttpMethod::Post, "/api/auth/callback/gitlab");
    _ = callback.headers.insert("origin".into(), PREVIEW.into());
    _ = callback.headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    _ = callback
        .query
        .insert("state".into(), query.get("state").unwrap().clone());
    _ = callback.query.insert("code".into(), String::new());
    callback.body = Some(
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("code", &code)
            .finish()
            .into_bytes(),
    );
    let denied = fixture.production.handle_request(callback.clone()).await?;
    assert_eq!(denied.status, 302);
    assert!(location(&denied).as_str().contains("error=no_code"));
    assert!(fixture.provider.lock().unwrap().receipts.is_empty());
    assert_eq!(rows(&fixture.preview_db).await, original);
    assert_eq!(rows(&fixture.production_db).await, production);
    _ = callback.query.insert("code".into(), code.clone());
    callback.body = Some(b"code=invalid-body-code".to_vec());
    let forwarded = fixture.production.handle_request(callback).await?;
    assert_eq!(forwarded.status, 302);
    let bridge = location(&forwarded);
    let done = request(&fixture.preview, &target(&bridge), None, None).await;
    assert_eq!(location(&done).as_str(), format!("{PREVIEW}/new-owner"));
    assert_eq!(
        fixture
            .provider
            .lock()
            .unwrap()
            .receipts
            .first()
            .unwrap()
            .get("form")
            .unwrap()
            .get("code")
            .unwrap()
            .as_str(),
        Some(code.as_str())
    );
    assert_eq!(fixture.preview_db.count("sessions").await?, 1);
    assert_eq!(rows(&fixture.production_db).await, production);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    backend_tests!(
    production_exchange_preserves_rows_then_preview_consumes_state_and_issues_only_the_actual_owner,completion_rejects_foreign_origin_provider_tampering_and_expired_state_before_any_principal_write,crafted_profiles_and_forward_errors_redirect_without_principal_writes,proxied_link_social_links_the_signed_in_owner,cookie_state_completion_requires_the_originating_browser,proxied_link_with_a_different_email_redirects_with_the_link_error,
    restored_cookie_state_replays_create_sessions_without_rebinding_owner,
    cookie_state_link_restores_initiating_owner_across_session_change,
    cookie_state_expiry_clears_only_authenticated_matching_proof,
    raw_profile_max_age_controls_admission_before_state_consumption,
    proxy_cache_publication_failure_retains_commit_and_discards_all_cookies,
    proxy_loose_profile_retains_resolved_account_key_authority,
    empty_query_code_prevents_body_grant_fallback_and_preserves_pending_state
);
    postgres_tests!(production_exchange_preserves_rows_then_preview_consumes_state_and_issues_only_the_actual_owner,completion_rejects_foreign_origin_provider_tampering_and_expired_state_before_any_principal_write);

    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn production_exchange_preserves_rows_then_preview_consumes_state_and_issues_only_the_actual_owner<
        B: Backend,
    >(
        db: Db,
    ) -> TestResult {
        for legacy in [false, true] {
            let db = db.fresh().await?;
            let fixture = Fixture::<B>::new(db).await;
            let foreign = request(
        &fixture.preview,
        "/api/auth/sign-up/email",
        Some(
            json!({"email":"foreign-proxy@fixture.test","name":"Foreign","password":"password123"}),
        ),
        None,
    )
    .await;
            assert_eq!(foreign.status, 200);
            let foreign_body: Value = serde_json::from_slice(&foreign.body).unwrap();
            let foreign_id = foreign_body
                .get("user")
                .unwrap()
                .get("id")
                .unwrap()
                .as_str()
                .unwrap();
            let before = rows(&fixture.preview_db).await;
            let prod_before = rows(&fixture.production_db).await;
            let (authorization, state) = fixture.issue("/api/auth/sign-in/social", None).await;
            let original_state = state
                .get("oauthState")
                .expect("provider fixture contains this parameter")
                .as_str()
                .unwrap();
            let issued = rows(&fixture.preview_db).await;
            let (_, mut bridge) = fixture.forward(&authorization).await;
            if legacy {
                bridge.set_path("/api/auth/oauth-proxy-callback");
            }
            assert_eq!(rows(&fixture.production_db).await, prod_before);
            assert_eq!(rows(&fixture.preview_db).await, issued);
            let completed = request(&fixture.preview, &target(&bridge), None, None).await;
            assert_eq!(completed.status, 302);
            assert_eq!(
                location(&completed).as_str(),
                &format!("{PREVIEW}/new-owner")
            );
            assert!(
                fixture
                    .preview
                    .store()
                    .get_verification_by_identifier(&format!("auth-state:{original_state}"))
                    .await
                    .unwrap()
                    .is_none()
            );
            let owner = fixture
                .preview
                .store()
                .get_user_by_email("proxy-owner@fixture.test")
                .await
                .unwrap()
                .unwrap();
            let sessions = fixture
                .preview
                .store()
                .get_user_sessions(&owner.id())
                .await
                .unwrap();
            assert_eq!(sessions.len(), 1);
            let current = request(
                &fixture.preview,
                "/api/auth/get-session",
                None,
                Some(&cookies(&completed)),
            )
            .await;
            let current: Value = serde_json::from_slice(&current.body).unwrap();
            assert_eq!(
                current
                    .get("user")
                    .expect("provider fixture contains this parameter")
                    .get("id")
                    .expect("provider fixture contains this parameter"),
                owner.id().as_ref()
            );
            assert_eq!(
                current
                    .get("session")
                    .expect("provider fixture contains this parameter")
                    .get("token")
                    .expect("provider fixture contains this parameter"),
                sessions.first().unwrap().token()
            );
            assert_eq!(
                fixture
                    .preview
                    .store()
                    .get_user_sessions(foreign_id)
                    .await
                    .unwrap()
                    .len(),
                1
            );
            let accounts = fixture
                .preview
                .store()
                .get_user_accounts(&owner.id())
                .await
                .unwrap();
            assert_eq!(accounts.len(), 1);
            let after = rows(&fixture.preview_db).await;
            let replay = request(&fixture.preview, &target(&bridge), None, None).await;
            assert!(location(&replay).as_str().contains("error=state_mismatch"));
            assert_eq!(rows(&fixture.preview_db).await, after);
            let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
            let mut callback = url::Url::parse(
                query
                    .get("redirect_uri")
                    .expect("provider fixture contains this parameter"),
            )
            .unwrap();
            _ = callback
                .query_pairs_mut()
                .append_pair(
                    "state",
                    query
                        .get("state")
                        .expect("provider fixture contains this parameter"),
                )
                .append_pair("code", "real-code-1");
            let retry = request(&fixture.production, &target(&callback), None, None).await;
            assert!(location(&retry).as_str().contains("error=invalid_code"));
            assert_eq!(rows(&fixture.preview_db).await, after);
            assert_eq!(rows(&fixture.production_db).await, prod_before);
            writeln!(std::io::stderr(),
        "PROXY_NATIVE_LIFECYCLE {}",
        json!({"before":before,"issued":issued,"authorization":authorization.as_str(),"bridge":bridge.as_str(),"completed":{"status":completed.status,"headers":completed.headers.iter().collect::<Vec<_>>()},"current":current,"after":after,"production":prod_before,"receipts":fixture.provider.lock().unwrap().receipts})
    ).expect("write native lifecycle observation");
        }
        Ok(())
    }

    async fn completion_rejects_foreign_origin_provider_tampering_and_expired_state_before_any_principal_write<
        B: Backend,
    >(
        db: Db,
    ) -> TestResult {
        let fixture = Fixture::<B>::new(db).await;
        let (authorization, state) = fixture.issue("/api/auth/sign-in/social", None).await;
        let (_, bridge) = fixture.forward(&authorization).await;
        let issued = rows(&fixture.preview_db).await;
        let mut foreign = bridge.clone();
        let profile = foreign
            .query_pairs()
            .find(|(key, _)| key == "profile")
            .unwrap()
            .1
            .into_owned();
        foreign.set_query(None);
        _ = foreign
            .query_pairs_mut()
            .append_pair("callbackURL", "https://foreign.fixture.test/leak")
            .append_pair("profile", &profile);
        let denied = request(&fixture.preview, &target(&foreign), None, None).await;
        assert_eq!(denied.status, 403);
        assert_eq!(rows(&fixture.preview_db).await, issued);
        let mut provider = bridge.clone();
        provider.set_path("/api/auth/callback/google/oauth-proxy");
        let denied_2 = request(&fixture.preview, &target(&provider), None, None).await;
        assert!(
            location(&denied_2)
                .as_str()
                .contains("error=provider_mismatch")
        );
        assert_eq!(rows(&fixture.preview_db).await, issued);
        let mut invalid = bridge.clone();
        invalid.set_query(None);
        _ = invalid
            .query_pairs_mut()
            .append_pair("callbackURL", PREVIEW)
            .append_pair("profile", &format!("{profile}00"));
        let denied_3 = request(&fixture.preview, &target(&invalid), None, None).await;
        assert!(
            location(&denied_3)
                .as_str()
                .contains("error=invalid_profile")
        );
        assert_eq!(rows(&fixture.preview_db).await, issued);
        let mut expired = state.clone();
        *expired.get_mut("expiresAt").unwrap() = json!(chrono::Utc::now().timestamp_millis() - 1);
        _ = fixture
            .preview_db
            .execute("UPDATE verifications SET value=$1", &[&expired.to_string()])
            .await?;
        let denied_4 = request(&fixture.preview, &target(&bridge), None, None).await;
        assert!(
            location(&denied_4)
                .as_str()
                .contains("error=state_mismatch")
        );
        let after = rows(&fixture.preview_db).await;
        assert_eq!(
            after
                .get("users")
                .expect("provider fixture contains this parameter"),
            issued
                .get("users")
                .expect("provider fixture contains this parameter")
        );
        assert_eq!(
            after
                .get("accounts")
                .expect("provider fixture contains this parameter"),
            issued
                .get("accounts")
                .expect("provider fixture contains this parameter")
        );
        assert_eq!(
            after
                .get("sessions")
                .expect("provider fixture contains this parameter"),
            issued
                .get("sessions")
                .expect("provider fixture contains this parameter")
        );
        assert_eq!(
            after
                .get("verifications")
                .expect("provider fixture contains this parameter"),
            &json!([])
        );
        Ok(())
    }

    fn with_profile(bridge: &url::Url, profile: Option<&str>) -> String {
        let mut url = bridge.clone();
        let callback = bridge
            .query_pairs()
            .find(|(key, _)| key == "callbackURL")
            .unwrap()
            .1
            .into_owned();
        url.set_query(None);
        _ = url.query_pairs_mut().append_pair("callbackURL", &callback);
        if let Some(profile) = profile {
            _ = url.query_pairs_mut().append_pair("profile", profile);
        }
        target(&url)
    }

    async fn crafted_profiles_and_forward_errors_redirect_without_principal_writes<B: Backend>(
        db: Db,
    ) -> TestResult {
        let fixture = Fixture::<B>::new(db).await;
        let (authorization, _) = fixture.issue("/api/auth/sign-in/social", None).await;
        let (_, bridge) = fixture.forward(&authorization).await;
        let issued = rows(&fixture.preview_db).await;
        let profile = bridge
            .query_pairs()
            .find(|(key, _)| key == "profile")
            .unwrap()
            .1
            .into_owned();
        let payload = open(&profile, PROXY_SECRET, "oauth-proxy-profile");
        let mutate = |change: &dyn Fn(&mut Value)| {
            let mut payload = payload.clone();
            change(&mut payload);
            seal(&payload.to_string(), PROXY_SECRET, "oauth-proxy-profile")
        };
        let cases: Vec<(&str, Option<String>)> = vec![
            ("missing_profile", None),
            (
                "invalid_payload",
                Some(seal("not json", PROXY_SECRET, "oauth-proxy-profile")),
            ),
            (
                "invalid_payload",
                Some(mutate(&|payload| payload["profile"] = json!("text"))),
            ),
            (
                "invalid_payload",
                Some(mutate(&|payload| payload["scopes"] = json!([1]))),
            ),
            (
                "invalid_payload",
                Some(mutate(&|payload| payload["errorURL"] = json!(5))),
            ),
            (
                "invalid_payload",
                Some(mutate(&|payload| payload["disableSignUp"] = json!("yes"))),
            ),
            (
                "invalid_payload",
                Some(mutate(&|payload| payload["state"] = json!(""))),
            ),
            (
                "invalid_payload",
                Some(mutate(&|payload| payload["userInfo"] = json!(null))),
            ),
            (
                "payload_expired",
                Some(mutate(&|payload| payload["timestamp"] = json!(1_000))),
            ),
            (
                "payload_expired",
                Some(mutate(&|payload| {
                    payload["timestamp"] = json!(chrono::Utc::now().timestamp_millis() + 60_000);
                })),
            ),
            (
                "state_mismatch",
                Some(mutate(&|payload| payload["state"] = json!("unknown"))),
            ),
        ];
        for (error, profile) in cases {
            let response = request(
                &fixture.preview,
                &with_profile(&bridge, profile.as_deref()),
                None,
                None,
            )
            .await;
            assert_eq!(response.status, 302, "{error}");
            assert!(
                location(&response)
                    .as_str()
                    .contains(&format!("error={error}")),
                "{error}: {}",
                location(&response)
            );
        }
        assert_eq!(rows(&fixture.preview_db).await, issued);

        let (authorization, _) = fixture.issue("/api/auth/sign-in/social", None).await;
        let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
        let callback = |extra: &[(&str, &str)]| {
            let mut url = url::Url::parse(query.get("redirect_uri").unwrap()).unwrap();
            _ = url
                .query_pairs_mut()
                .append_pair("state", query.get("state").unwrap());
            for (key, value) in extra {
                _ = url.query_pairs_mut().append_pair(key, value);
            }
            target(&url)
        };
        for (extra, error) in [
            (vec![("error", "access_denied")], "access_denied"),
            (vec![], "no_code"),
            (vec![("code", "wrong-code")], "invalid_code"),
        ] {
            let response = request(&fixture.production, &callback(&extra), None, None).await;
            assert_eq!(response.status, 302);
            assert!(
                location(&response)
                    .as_str()
                    .contains(&format!("error={error}")),
                "{error}: {}",
                location(&response)
            );
        }
        Ok(())
    }

    async fn proxied_link_social_links_the_signed_in_owner<B: Backend>(db: Db) -> TestResult {
        let fixture = Fixture::<B>::new(db).await;
        let signup = request(
            &fixture.preview,
            "/api/auth/sign-up/email",
            Some(
                json!({"email":"proxy-owner@fixture.test","name":"Owner","password":"password123"}),
            ),
            None,
        )
        .await;
        assert_eq!(signup.status, 200);
        let session = cookies(&signup);
        let (authorization, _) = fixture.issue("/api/auth/link-social", Some(&session)).await;
        let (_, bridge) = fixture.forward(&authorization).await;
        let linked = request(&fixture.preview, &target(&bridge), None, Some(&session)).await;
        assert_eq!(linked.status, 302);
        assert_eq!(
            location(&linked).as_str(),
            &format!("{PREVIEW}/complete?application=kept")
        );
        let accounts: Value = serde_json::from_str(&fixture.preview_db.table("accounts").await?)?;
        let providers = accounts
            .as_array()
            .unwrap()
            .iter()
            .map(|account| account["provider_id"].as_str().unwrap().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            providers,
            ["credential".to_owned(), "gitlab".to_owned()].into()
        );
        Ok(())
    }

    async fn cookie_state_completion_requires_the_originating_browser<B: Backend>(
        db: Db,
    ) -> TestResult {
        let fixture = Fixture::<B>::with(
            db,
            Options {
                cookie_state: true,
                shared_secret: true,
            },
        )
        .await;
        let (authorization, _, browser) = fixture
            .issue_with("/api/auth/sign-in/social", None, json!({}))
            .await;
        let (_, bridge) = fixture.forward(&authorization).await;
        let (_, _, other_browser) = fixture
            .issue_with("/api/auth/sign-in/social", None, json!({}))
            .await;
        for (cookie, label) in [
            (None, "missing cookie"),
            (Some("better-auth.oauth_state=00"), "unreadable cookie"),
            (Some(other_browser.as_str()), "another authorization"),
        ] {
            let denied = request(&fixture.preview, &target(&bridge), None, cookie).await;
            assert!(
                location(&denied).as_str().contains("error=state_mismatch"),
                "{label}: {}",
                location(&denied)
            );
        }
        let dont_remember = format!(
            "{browser}; better-auth.dont_remember={}",
            alibi::utils::cookie_utils::sign_cookie_value("true", SECRET)
        );
        let completed = request(
            &fixture.preview,
            &target(&bridge),
            None,
            Some(&dont_remember),
        )
        .await;
        assert_eq!(completed.status, 302);
        assert_eq!(
            location(&completed).as_str(),
            &format!("{PREVIEW}/new-owner")
        );
        let set_cookies = completed.headers.get_all("set-cookie").collect::<Vec<_>>();
        assert!(
            set_cookies
                .iter()
                .any(|cookie| cookie.starts_with("better-auth.dont_remember="))
        );
        assert!(
            set_cookies
                .iter()
                .any(|cookie| cookie.starts_with("better-auth.session_token=")
                    && !cookie.contains("Max-Age"))
        );
        Ok(())
    }

    async fn proxied_link_with_a_different_email_redirects_with_the_link_error<B: Backend>(
        db: Db,
    ) -> TestResult {
        let fixture = Fixture::<B>::new(db).await;
        let signup = request(
            &fixture.preview,
            "/api/auth/sign-up/email",
            Some(json!({"email":"someone-else@fixture.test","name":"Other","password":"password123"})),
            None,
        )
        .await;
        let session = cookies(&signup);
        let (authorization, _) = fixture.issue("/api/auth/link-social", Some(&session)).await;
        let (_, bridge) = fixture.forward(&authorization).await;
        let denied = request(&fixture.preview, &target(&bridge), None, Some(&session)).await;
        assert_eq!(denied.status, 302);
        assert_eq!(
            location(&denied).as_str(),
            &format!("{PREVIEW}/failure?error=email_does_not_match")
        );
        Ok(())
    }
}
