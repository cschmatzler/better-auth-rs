//! Request-scoped refresh configuration must not replace grant authority or leak
//! into another request; application refresh handlers own their own transport.
use super::*;
use alibi::plugins::OAuthPlugin;
use alibi::plugins::oauth::*;
use async_trait::async_trait;
use std::collections::BTreeMap;

backend_tests!(
    dynamic_refresh_preserves_grant_authority_and_callback_precedence,
    account_info_dynamic_refresh_preserves_request_and_grant_authority,
    concurrent_accepted_refreshes_preserve_account_and_browser_authority
);
postgres_tests!(dynamic_refresh_preserves_grant_authority_and_callback_precedence);

struct Params(Arc<Mutex<Vec<String>>>);
#[async_trait]
impl OAuthRefreshTokenParamsResolver for Params {
    async fn resolve(
        &self,
        context: Option<OAuthRefreshContext<'_>>,
    ) -> Result<Option<BTreeMap<String, String>>, String> {
        let request = context.ok_or("missing refresh context")?.request;
        let mode = request
            .headers
            .get("x-refresh-mode")
            .ok_or("missing mode")?;
        self.0.lock().unwrap().push(mode.clone());
        match mode.as_str() {
            "none" => Ok(None),
            "error" => Err("private resolver failure".into()),
            "approved-a" | "approved-b" => Ok(Some(
                [
                    ("audience", mode.as_str()),
                    ("scope", "approved-scope"),
                    ("grant_type", "authorization_code"),
                    ("refresh_token", "wrong-token"),
                    ("client_id", "wrong-client"),
                    ("__proto__", "blocked"),
                    ("constructor", "blocked"),
                    ("prototype", "blocked"),
                ]
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
            )),
            _ => Err("unapproved application input".into()),
        }
    }
}
struct CustomRefresh;
#[async_trait]
impl OAuthRefreshTokenHandler for CustomRefresh {
    async fn refresh_access_token(&self, token: &str) -> Result<OAuthTokenSet, String> {
        assert_eq!(token, "refresh-none");
        Ok(OAuthTokenSet {
            access_token: Some("custom-access".into()),
            refresh_token: Some("custom-refresh".into()),
            ..Default::default()
        })
    }
}

async fn dynamic_refresh_preserves_grant_authority_and_callback_precedence<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let remote = Provider::start("application/json", "{}").await;
    remote.respond_at("/token",200,json!({"access_token":"initial-access","refresh_token":"initial-refresh","expires_in":3600,"token_type":"Bearer"}));
    remote.respond_at("/profile",200,json!({"id":"refresh-subject","email":"refresh@example.test","name":"Refresh User","email_verified":true}));
    let mut config = GenericOAuthConfig::new("native-client", "native-secret");
    config.authorization_url = Some(remote.url.join("authorize")?.into());
    config.token_url = Some(remote.url.join("token")?.into());
    config.user_info_url = Some(remote.url.join("profile")?.into());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let policy = config.provider.authorization.as_mut().unwrap();
    policy.token_endpoint_auth = Some(OAuthTokenEndpointAuth::ClientSecretPost);
    policy.pkce = true;
    policy.authorization_code_params = [
        ("code", "wrong-code"),
        ("grant_type", "refresh_token"),
        ("redirect_uri", "https://wrong.example"),
        ("code_verifier", "wrong-verifier"),
        ("client_id", "wrong-client"),
        ("client_secret", "wrong-secret"),
        ("audience", "approved-code-audience"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    policy.authorization_code_headers = vec![("x-code-policy".into(), "operator-value".into())];
    policy.refresh_scope = Some("base-scope".into());
    policy.refresh_token_params = [
        ("audience".into(), "static-only".into()),
        ("staticOnly".into(), "must-disappear".into()),
    ]
    .into_iter()
    .collect();
    policy.refresh_token_params_resolver =
        Some(OAuthRefreshTokenParams(Arc::new(Params(calls.clone()))));
    let provider = config.resolve().await?.unwrap().provider;
    let auth = builder::<B>(&connection)
        .plugin(OAuthPlugin::new().add_provider("generic", provider.clone()))
        .build()
        .await?;
    let (authorization, cookie) = super::oauth_profiles::begin(&auth, "generic").await;
    let signed_in =
        super::oauth_profiles::complete(&auth, "generic", &authorization, &cookie).await;
    authenticated(&auth, &cookies(&signed_in), "refresh@example.test").await;
    assert!(calls.lock().unwrap().is_empty());
    let exchanges = remote.take();
    let grant = exchanges
        .iter()
        .find(|exchange| exchange.path == "/token")
        .unwrap();
    let pairs = url::form_urlencoded::parse(&grant.body)
        .into_owned()
        .collect::<Vec<_>>();
    for (key, expected) in [
        ("code", "one-use-grant"),
        ("grant_type", "authorization_code"),
        (
            "redirect_uri",
            "http://localhost:43219/api/auth/callback/generic",
        ),
        ("client_id", "native-client"),
        ("client_secret", "native-secret"),
        ("audience", "approved-code-audience"),
    ] {
        assert_eq!(
            pairs
                .iter()
                .filter(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            vec![expected]
        );
    }
    let verifier = pairs
        .iter()
        .find(|(key, _)| key == "code_verifier")
        .unwrap()
        .1
        .as_bytes();
    use base64::Engine as _;
    use sha2::Digest as _;
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier)),
        authorization["code_challenge"]
    );
    assert_eq!(grant.headers["x-code-policy"], "operator-value");
    let account = db.text("SELECT id FROM accounts", &[]).await?.unwrap();
    let make_request = |path: &str, mode: &str| {
        let mut req = request(
            path,
            Some(json!({"accountId":account})),
            &cookies(&signed_in),
        );
        drop(req.headers.insert("x-refresh-mode".into(), mode.into()));
        req
    };
    let mut prior_refresh = "initial-refresh".to_owned();
    for mode in ["approved-a", "approved-b", "none"] {
        let access = format!("access-{mode}");
        let refresh = format!("refresh-{mode}");
        remote.respond_at("/token",200,json!({"access_token":access,"refresh_token":refresh,"expires_in":3600,"token_type":"Bearer"}));
        let response = call(&auth, make_request("/refresh-token", mode), 200).await;
        assert_eq!(body(&response)["accessToken"], access);
        let delivered = remote.take();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].path, "/token");
        assert_eq!(delivered[0].method, "POST");
        assert!(!delivered[0].headers.contains_key("x-code-policy"));
        let pairs = url::form_urlencoded::parse(&delivered[0].body)
            .into_owned()
            .collect::<Vec<_>>();
        for (key, value) in [
            ("grant_type", "refresh_token"),
            ("refresh_token", prior_refresh.as_str()),
            ("client_id", "native-client"),
            ("client_secret", "native-secret"),
        ] {
            assert_eq!(
                pairs
                    .iter()
                    .filter(|(name, _)| name == key)
                    .map(|(_, value)| value.as_str())
                    .collect::<Vec<_>>(),
                vec![value]
            );
        }
        let fields: BTreeMap<_, _> = pairs.into_iter().collect();
        for key in ["staticOnly", "__proto__", "constructor", "prototype"] {
            assert!(!fields.contains_key(key));
        }
        assert_eq!(
            fields["scope"],
            if mode == "none" {
                "base-scope"
            } else {
                "approved-scope"
            }
        );
        assert_eq!(
            fields.get("audience").map(String::as_str),
            if mode == "none" { None } else { Some(mode) }
        );
        assert_eq!(
            db.text("SELECT access_token FROM accounts", &[])
                .await?
                .as_deref(),
            Some(access.as_str())
        );
        assert_eq!(
            db.text("SELECT refresh_token FROM accounts", &[])
                .await?
                .as_deref(),
            Some(refresh.as_str())
        );
        prior_refresh = refresh;
    }
    let unchanged = db.table("accounts").await?;
    let rejected = call(&auth, make_request("/refresh-token", "error"), 400).await;
    assert_eq!(body(&rejected)["code"], "FAILED_TO_REFRESH_ACCESS_TOKEN");
    assert!(remote.take().is_empty());
    assert_eq!(db.table("accounts").await?, unchanged);
    db.set_timestamp(
        "accounts",
        "access_token_expires_at",
        ("id", &account),
        chrono::Utc::now() - chrono::Duration::hours(1),
    )
    .await?;
    let unchanged = db.table("accounts").await?;
    let rejected = call(&auth, make_request("/get-access-token", "error"), 400).await;
    assert_eq!(body(&rejected)["code"], "FAILED_TO_GET_ACCESS_TOKEN");
    assert!(remote.take().is_empty());
    assert_eq!(db.table("accounts").await?, unchanged);
    let observed = calls.lock().unwrap().clone();
    assert_eq!(
        observed,
        vec!["approved-a", "approved-b", "none", "error", "error"]
    );
    let mut custom = provider;
    custom.refresh_access_token = Some(Arc::new(CustomRefresh));
    let custom_auth = builder::<B>(&connection)
        .plugin(OAuthPlugin::new().add_provider("generic", custom))
        .build()
        .await?;
    let response = call(&custom_auth, make_request("/refresh-token", "error"), 200).await;
    assert_eq!(body(&response)["accessToken"], "custom-access");
    assert_eq!(
        db.text("SELECT refresh_token FROM accounts", &[])
            .await?
            .as_deref(),
        Some("custom-refresh")
    );
    assert_eq!(*calls.lock().unwrap(), observed);
    assert!(remote.take().is_empty());
    B::close(connection).await
}

async fn account_info_dynamic_refresh_preserves_request_and_grant_authority<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::{AuthAccount as _, CreateAccount};
    async fn seed<S: AuthSchema>(auth: &Alibi<S>, user: &str) -> alibi::AuthResult<String> {
        let account = auth
            .context()
            .database
            .create_account(CreateAccount {
                additional_fields: Default::default(),
                user_id: user.into(),
                account_id: "account-subject".into(),
                provider_id: "generic".into(),
                access_token: Some("old-access".into()),
                refresh_token: Some("old-refresh".into()),
                id_token: Some("old-id".into()),
                access_token_expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
                refresh_token_expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
                scope: Some("calendar,drive".into()),
                password: None,
            })
            .await?;
        Ok(account.id().to_string())
    }

    struct Policy(Mutex<Vec<AuthRequest>>);
    #[async_trait]
    impl OAuthRefreshTokenParamsResolver for Policy {
        async fn resolve(
            &self,
            c: Option<OAuthRefreshContext<'_>>,
        ) -> Result<Option<BTreeMap<String, String>>, String> {
            let request = c.ok_or("Actual request required")?.request;
            self.0.lock().unwrap().push(request.clone());
            Ok(Some(
                [
                    ("audience".into(), request.headers["x-refresh-mode"].clone()),
                    ("refresh_token".into(), "forged-refresh".into()),
                    ("client_id".into(), "forged-client".into()),
                    ("grant_type".into(), "authorization_code".into()),
                ]
                .into_iter()
                .collect(),
            ))
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let remote = Provider::start("application/json", "{}").await;
    remote.respond_at(
        "/profile",
        200,
        json!({"id":"account-subject","email":"profile@example.test","email_verified":true}),
    );
    let policy = Arc::new(Policy(Mutex::new(Vec::new())));
    let mut config = GenericOAuthConfig::new("native-client", "native-secret");
    config.authorization_url = Some(remote.url.join("authorize")?.into());
    config.token_url = Some(remote.url.join("token")?.into());
    config.user_info_url = Some(remote.url.join("profile")?.into());
    config
        .provider
        .authorization
        .as_mut()
        .unwrap()
        .refresh_token_params_resolver = Some(OAuthRefreshTokenParams(policy.clone()));
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(
            OAuthPlugin::new().add_provider("generic", config.resolve().await?.unwrap().provider),
        )
        .build()
        .await?;
    let owner = signup(&auth, "dynamic-info-owner@example.test").await;
    let foreign = signup(&auth, "dynamic-info-foreign@example.test").await;
    let id = seed(&auth, body(&owner)["user"]["id"].as_str().unwrap()).await?;
    let protected = db.tables(&["users", "sessions"]).await?;
    for mode in ["approved-a", "approved-b"] {
        _=db.execute("UPDATE accounts SET access_token='old-access',refresh_token='old-refresh' WHERE id=$1",&[&id]).await?;
        db.set_timestamp(
            "accounts",
            "access_token_expires_at",
            ("id", &id),
            chrono::Utc::now() - chrono::Duration::hours(1),
        )
        .await?;
        remote.respond_at("/token",200,json!({"access_token":format!("access-{mode}"),"refresh_token":format!("refresh-{mode}"),"expires_in":3600,"scope":"replacement-scope"}));
        let mut input = request("/account-info", None, &cookies(&owner));
        input.set_query_pairs([("accountId", id.as_str())]);
        _ = input.headers.insert("x-refresh-mode".into(), mode.into());
        assert_eq!(
            body(&call(&auth, input, 200).await)["user"]["email"],
            "profile@example.test"
        );
        let received = policy.0.lock().unwrap().last().unwrap().clone();
        assert_eq!(received.method, HttpMethod::Get);
        assert_eq!(received.headers["x-refresh-mode"], mode);
        assert_eq!(received.headers["cookie"], cookies(&owner));
        assert_eq!(received.query["accountId"], id);
        let exchanges = remote.take();
        assert_eq!(exchanges.len(), 2);
        let grant = exchanges
            .iter()
            .find(|exchange| exchange.path == "/token")
            .unwrap();
        let fields = url::form_urlencoded::parse(&grant.body)
            .into_owned()
            .collect::<BTreeMap<_, _>>();
        assert_eq!(fields["audience"], mode);
        assert_eq!(fields["refresh_token"], "old-refresh");
        assert_eq!(fields["client_id"], "native-client");
        assert_eq!(fields["grant_type"], "refresh_token");
        assert_eq!(
            exchanges
                .iter()
                .find(|exchange| exchange.path == "/profile")
                .unwrap()
                .headers["authorization"],
            format!("Bearer access-{mode}")
        );
        assert_eq!(
            db.text("SELECT scope FROM accounts WHERE id=$1", &[&id])
                .await?
                .as_deref(),
            Some("calendar,drive")
        );
        assert_eq!(db.tables(&["users", "sessions"]).await?, protected);
    }
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let called = policy.0.lock().unwrap().len();
    let mut input = request("/account-info", None, &cookies(&foreign));
    input.set_query_pairs([("accountId", id.as_str())]);
    _ = input
        .headers
        .insert("x-refresh-mode".into(), "approved-a".into());
    _ = call(&auth, input, 400).await;
    assert_eq!(policy.0.lock().unwrap().len(), called);
    assert!(remote.take().is_empty());
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    B::close(connection).await
}

async fn concurrent_accepted_refreshes_preserve_account_and_browser_authority<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::{AuthAccount as _, CreateAccount};
    async fn seed<S: AuthSchema>(auth: &Alibi<S>, user: &str) -> alibi::AuthResult<String> {
        let account = auth
            .context()
            .database
            .create_account(CreateAccount {
                additional_fields: Default::default(),
                user_id: user.into(),
                account_id: "account-subject".into(),
                provider_id: "generic".into(),
                access_token: Some("old-access".into()),
                refresh_token: Some("old-refresh".into()),
                id_token: Some("old-id".into()),
                access_token_expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
                refresh_token_expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
                scope: Some("calendar,drive".into()),
                password: None,
            })
            .await?;
        Ok(account.id().to_string())
    }

    struct Refresh {
        barrier: tokio::sync::Barrier,
        entered: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl OAuthRefreshTokenHandler for Refresh {
        async fn refresh_access_token(&self, token: &str) -> Result<OAuthTokenSet, String> {
            assert_eq!(token, "old-refresh");
            _ = self
                .entered
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            _ = self.barrier.wait().await;
            Ok(OAuthTokenSet {
                access_token: Some("concurrent-access".into()),
                refresh_token: Some("concurrent-refresh".into()),
                id_token: Some("concurrent-id".into()),
                scopes: vec!["ignored-scope".into()],
                ..Default::default()
            })
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let remote = Provider::start("application/json", "{}").await;
    let mut config = GenericOAuthConfig::new("native-client", "native-secret");
    config.authorization_url = Some(remote.url.join("authorize")?.into());
    config.token_url = Some(remote.url.join("token")?.into());
    config.user_info_url = Some(remote.url.join("profile")?.into());
    let handler = Arc::new(Refresh {
        barrier: tokio::sync::Barrier::new(2),
        entered: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut provider = config.resolve().await?.unwrap().provider;
    provider.refresh_access_token = Some(handler.clone());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OAuthPlugin::new().add_provider("generic", provider))
        .build()
        .await?;
    let owner = signup(&auth, "concurrent-refresh@example.test").await;
    let foreign = signup(&auth, "concurrent-foreign@example.test").await;
    let id = seed(&auth, body(&owner)["user"]["id"].as_str().unwrap()).await?;
    let protected = db.tables(&["users", "sessions"]).await?;
    let input = request(
        "/refresh-token",
        Some(json!({"accountId":id})),
        &cookies(&owner),
    );
    let (left, right) = tokio::join!(call(&auth, input.clone(), 200), call(&auth, input, 200));
    for response in [left, right] {
        assert_eq!(body(&response)["accessToken"], "concurrent-access");
        assert_eq!(body(&response)["refreshToken"], "concurrent-refresh");
    }
    assert_eq!(handler.entered.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(remote.take().is_empty());
    assert_eq!(
        db.text("SELECT user_id FROM accounts WHERE id=$1", &[&id])
            .await?,
        body(&owner)["user"]["id"].as_str().map(str::to_owned)
    );
    assert_eq!(
        db.text("SELECT account_id FROM accounts WHERE id=$1", &[&id])
            .await?
            .as_deref(),
        Some("account-subject")
    );
    assert_eq!(
        db.text("SELECT provider_id FROM accounts WHERE id=$1", &[&id])
            .await?
            .as_deref(),
        Some("generic")
    );
    assert_eq!(
        db.text("SELECT scope FROM accounts WHERE id=$1", &[&id])
            .await?
            .as_deref(),
        Some("calendar,drive")
    );
    for (column, expected) in [
        ("access_token", "concurrent-access"),
        ("refresh_token", "concurrent-refresh"),
        ("id_token", "concurrent-id"),
    ] {
        assert_eq!(
            db.text(
                &format!("SELECT {column} FROM accounts WHERE id=$1"),
                &[&id]
            )
            .await?
            .as_deref(),
            Some(expected)
        );
    }
    assert_eq!(db.count("accounts").await?, 3);
    assert_eq!(db.tables(&["users", "sessions"]).await?, protected);
    authenticated(&auth, &cookies(&foreign), "concurrent-foreign@example.test").await;
    B::close(connection).await
}
