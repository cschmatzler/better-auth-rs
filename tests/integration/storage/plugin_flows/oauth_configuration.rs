//! Operator configuration is checked at resolution; account authority at callback.
use super::*;
use alibi::plugins::OAuthPlugin;
use alibi::plugins::oauth::{
    GenericOAuthConfig, GenericOAuthError, OAuthAccountKey, OAuthAccountKeyContext,
    OAuthAccountKeyResolver, OAuthProfileMapper, OAuthTokenEndpointAuth,
};
use async_trait::async_trait;

backend_tests!(
    generic_oauth_fallback_mapping_and_account_authority,
    configured_oauth_expiry_preserves_zero_negative_and_grant_precedence
);
postgres_tests!(generic_oauth_fallback_mapping_and_account_authority);

struct Mapper;
struct RawProfile(Arc<std::sync::atomic::AtomicU8>);
#[async_trait]
impl alibi::plugins::oauth::OAuthUserInfoHandler for RawProfile {
    async fn get_user_info(
        &self,
        _: alibi::plugins::oauth::OAuthUserInfoRequest,
    ) -> Result<alibi::plugins::oauth::OAuthUserInfoResponse, String> {
        Ok(alibi::plugins::oauth::OAuthUserInfoResponse {
            user: alibi::plugins::oauth::OAuthUserInfo {
                id: "raw-oauth-id".into(),
                email: "mapping@example.test".into(),
                name: Some("Initial".into()),
                image: None,
                email_verified: false,
                additional_fields: Default::default(),
            },
            data: json!({"id":"raw-oauth-id"}),
            user_output: Some(
                [
                    ("id".into(), json!("raw-oauth-id")),
                    ("email".into(), json!("mapping@example.test")),
                    (
                        "name".into(),
                        if self.0.load(std::sync::atomic::Ordering::SeqCst) == 2 {
                            json!({"invalid":"scalar"})
                        } else {
                            json!(37 + self.0.load(std::sync::atomic::Ordering::SeqCst))
                        },
                    ),
                    (
                        "image".into(),
                        json!(self.0.load(std::sync::atomic::Ordering::SeqCst) == 1),
                    ),
                    (
                        "emailVerified".into(),
                        json!(u8::from(
                            self.0.load(std::sync::atomic::Ordering::SeqCst) == 1
                        )),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
        })
    }
}

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(
        &self,
        profile: Value,
    ) -> Result<alibi::field_policy::FieldOutput, String> {
        assert_eq!(profile["id"], "raw-oauth-id");
        Ok([
            ("id".into(), json!("foreign-presentation-id")),
            ("name".into(), json!("Application Name")),
        ]
        .into_iter()
        .collect())
    }
}
struct AccountKey(&'static str);
#[async_trait]
impl OAuthAccountKeyResolver for AccountKey {
    async fn resolve(&self, context: OAuthAccountKeyContext) -> Result<Value, String> {
        assert_eq!(context.profile["id"], "raw-oauth-id");
        assert_eq!(
            context.tokens.access_token.as_deref(),
            Some("access-from-grant")
        );
        match self.0 {
            "custom" => Ok(json!("tenant:raw-oauth-id")),
            "invalid" => Ok(Value::Null),
            _ => Err("private account resolver failure".into()),
        }
    }
}

#[tokio::test]
async fn generic_resolution_rejects_conflicting_credentials_and_missing_required_metadata()
-> TestResult {
    for (method, secret) in [
        (OAuthTokenEndpointAuth::None, "secret"),
        (OAuthTokenEndpointAuth::PrivateKeyJwt, "secret"),
        (OAuthTokenEndpointAuth::ClientSecretBasic, ""),
        (OAuthTokenEndpointAuth::ClientSecretPost, ""),
    ] {
        let mut config = GenericOAuthConfig::new("client", secret);
        config
            .provider
            .authorization
            .as_mut()
            .unwrap()
            .token_endpoint_auth = Some(method);
        assert!(matches!(
            config.resolve().await,
            Err(GenericOAuthError::InvalidTokenAuthentication)
        ));
    }
    let mut config = GenericOAuthConfig::new("client", "");
    config.require_id_token_verification = true;
    assert!(matches!(
        config.resolve().await,
        Err(GenericOAuthError::RequiredVerificationUnavailable)
    ));
    let peer = Provider::start("application/json", "{\"error\":\"unavailable\"}").await;
    peer.respond(503, "application/json", "{}");
    for verification_required in [false, true] {
        let mut config = GenericOAuthConfig::new("client", "");
        config.discovery_url = Some(peer.url.join("discovery")?.into());
        config.require_id_token_verification = verification_required;
        assert!(config.resolve().await?.is_none());
    }
    // These endpoints are usable; verification itself must distinguish the two
    // outcomes, rather than an earlier missing-endpoint guard.
    peer.respond(200,"application/json",json!({"authorization_endpoint":peer.url.join("authorize")?,"token_endpoint":peer.url.join("token")?,"userinfo_endpoint":peer.url.join("profile")?}).to_string());
    for required in [false, true] {
        let mut config = GenericOAuthConfig::new("client", "");
        config.discovery_url = Some(peer.url.join("discovery")?.into());
        config.require_id_token_verification = required;
        assert_eq!(config.resolve().await?.is_some(), !required);
    }
    Ok(())
}

async fn generic_oauth_fallback_mapping_and_account_authority<B: Backend>(db: Db) -> TestResult {
    for mode in [
        "fallback",
        "scalars",
        "override",
        "oidc-subject",
        "custom",
        "invalid",
        "error",
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let peer = Provider::start("application/json", "{}").await;
        peer.respond_at("/discovery",if mode=="fallback" {503} else {200},json!({"authorization_endpoint":peer.url.join("unused-authorize")?,"token_endpoint":peer.url.join("unused-token")?,"userinfo_endpoint":peer.url.join("unused-profile")?,"id_token_signing_alg_values_supported":if mode=="oidc-subject" {vec!["RS256"]}else{vec![]},"end_session_endpoint":peer.url.join("logout")?}));
        peer.respond_at("/token",200,json!({"access_token":"access-from-grant","refresh_token":"refresh-from-grant","token_type":"Bearer","expires_in":3600}));
        peer.respond_at("/profile",200,json!({"id":"raw-oauth-id","sub":"raw-oidc-subject","email":"mapping@example.test","name":"Remote Name","email_verified":true}));
        let mut config = GenericOAuthConfig::new("public-client", "");
        config.discovery_url = Some(peer.url.join("discovery")?.into());
        config.authorization_url = Some(peer.url.join("authorize")?.into());
        config.token_url = Some(peer.url.join("token")?.into());
        config.user_info_url = Some(peer.url.join("profile")?.into());
        config.map_profile = Some(Arc::new(Mapper));
        config.disable_provider_logout = true;
        config
            .provider
            .authorization
            .as_mut()
            .unwrap()
            .token_endpoint_auth = Some(OAuthTokenEndpointAuth::None);
        if matches!(mode, "custom" | "invalid" | "error") {
            config.account_key = Some(OAuthAccountKey(Arc::new(AccountKey(mode))));
        }
        let reject_raw = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let mut provider = config.resolve().await?.unwrap().provider;
        if mode == "scalars" {
            provider.get_user_info = Some(Arc::new(RawProfile(reject_raw.clone())));
            provider.override_user_info_on_sign_in = true;
            provider
                .authorization
                .as_mut()
                .unwrap()
                .honor_factory_options = true;
            provider
                .authorization
                .as_mut()
                .unwrap()
                .preserve_raw_profile_scalars = true;
        }
        let auth = builder::<B>(&connection)
            .plugin(OAuthPlugin::new().add_provider("generic", provider))
            .build()
            .await?;
        let (authorization, cookie) = super::oauth_profiles::begin(&auth, "generic").await;
        let response =
            super::oauth_profiles::complete(&auth, "generic", &authorization, &cookie).await;
        let destination = url::Url::parse(response.headers.get("location").unwrap())?;
        if matches!(mode, "invalid" | "error") {
            assert_eq!(destination.path(), "/failed", "{mode}");
            for table in ["users", "accounts", "sessions"] {
                assert_eq!(db.count(table).await?, 0);
            }
        } else {
            assert_eq!(destination.path(), "/done", "{mode}");
            authenticated(&auth, &cookies(&response), "mapping@example.test").await;
            if mode == "scalars" {
                assert_eq!(
                    db.text("SELECT name FROM users", &[]).await?.as_deref(),
                    Some("Initial")
                );
                reject_raw.store(1, std::sync::atomic::Ordering::SeqCst);
                let (authorization, cookie) = super::oauth_profiles::begin(&auth, "generic").await;
                let returning =
                    super::oauth_profiles::complete(&auth, "generic", &authorization, &cookie)
                        .await;
                authenticated(&auth, &cookies(&returning), "mapping@example.test").await;
                assert_eq!(db.count("users").await?, 1);
                assert_eq!(db.count("accounts").await?, 1);
            }
            let expected = match mode {
                "oidc-subject" => "raw-oidc-subject",
                "custom" => "tenant:raw-oauth-id",
                _ => "raw-oauth-id",
            };
            assert_eq!(
                db.text("SELECT account_id FROM accounts", &[])
                    .await?
                    .as_deref(),
                Some(expected)
            );
            assert_eq!(
                db.text("SELECT name FROM users", &[]).await?.as_deref(),
                Some(if mode == "scalars" {
                    "38"
                } else {
                    "Application Name"
                })
            );
            if mode == "scalars" {
                assert_eq!(
                    db.text("SELECT image FROM users", &[]).await?.as_deref(),
                    Some(if db.is_postgres() { "true" } else { "1" })
                );
                let session = call(
                    &auth,
                    request("/get-session", None, &cookies(&response)),
                    200,
                )
                .await;
                assert_eq!(body(&session)["user"]["emailVerified"], true);
            }
            if mode == "scalars" {
                let before = db.tables(&["users", "sessions"]).await?;
                reject_raw.store(2, std::sync::atomic::Ordering::SeqCst);
                let (authorization, cookie) = super::oauth_profiles::begin(&auth, "generic").await;
                let denied =
                    super::oauth_profiles::complete(&auth, "generic", &authorization, &cookie)
                        .await;
                assert_eq!(
                    url::Url::parse(denied.headers.get("location").unwrap())?.path(),
                    "/failed"
                );
                assert_eq!(db.tables(&["users", "sessions"]).await?, before);
            }
            let signed_out = call(
                &auth,
                request("/sign-out", Some(json!({})), &cookies(&response)),
                200,
            )
            .await;
            assert!(body(&signed_out).get("url").is_none());
            assert_eq!(
                db.count("sessions").await?,
                if mode == "scalars" { 1 } else { 0 }
            );
        }
        let requests = peer.take();
        assert!(requests.iter().all(|r| !r.path.starts_with("/unused")));
        let token = requests.iter().find(|r| r.path == "/token").unwrap();
        let form: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(&token.body)
                .into_owned()
                .collect();
        assert_eq!(form["client_id"], "public-client");
        assert!(!form.contains_key("client_secret"));
        assert!(!token.headers.contains_key("authorization"));
        if mode != "scalars" {
            let profile = requests.iter().find(|r| r.path == "/profile").unwrap();
            assert_eq!(profile.headers["authorization"], "Bearer access-from-grant");
        }
        B::close(connection).await?;
    }
    Ok(())
}

async fn configured_oauth_expiry_preserves_zero_negative_and_grant_precedence<B: Backend>(
    db: Db,
) -> TestResult {
    use chrono::{DateTime, Duration, Utc};
    for seconds in [17, 0, -60] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let peer = Provider::start("application/json", "{}").await;
        peer.respond_at("/token", 200, json!({"access_token":"initial-access","refresh_token":"initial-refresh","scope":"calendar"}));
        peer.respond_at("/profile", 200, json!({"id":"expiry-sub","email":"expiry@example.test","name":"Expiry owner","email_verified":true}));
        let mut config = GenericOAuthConfig::new("native-client", "native-secret");
        config.authorization_url = Some(peer.url.join("authorize")?.into());
        config.token_url = Some(peer.url.join("token")?.into());
        config.user_info_url = Some(peer.url.join("profile")?.into());
        config.access_token_expires_in = Some(f64::from(seconds));
        let provider = config.resolve().await?.unwrap().provider;
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(OAuthPlugin::new().add_provider("generic", provider))
            .build()
            .await?;
        let (authorization, cookie) = super::oauth_profiles::begin(&auth, "generic").await;
        let before = Utc::now();
        let response =
            super::oauth_profiles::complete(&auth, "generic", &authorization, &cookie).await;
        let after = Utc::now();
        assert_eq!(
            url::Url::parse(response.headers.get("location").unwrap())?.path(),
            "/done"
        );
        let id = db.text("SELECT id FROM accounts", &[]).await?.unwrap();
        let expiry = db
            .text(
                "SELECT access_token_expires_at FROM accounts WHERE id=$1",
                &[&id],
            )
            .await?;
        if seconds == 0 {
            assert!(expiry.is_none());
        } else {
            let expiry =
                DateTime::parse_from_rfc3339(expiry.as_deref().unwrap())?.with_timezone(&Utc);
            assert!(
                expiry >= before + Duration::seconds(i64::from(seconds)) - Duration::seconds(1)
            );
            assert!(expiry <= after + Duration::seconds(i64::from(seconds)) + Duration::seconds(1));
        }
        authenticated(&auth, &cookies(&response), "expiry@example.test").await;
        let stable = db.tables(&["users", "sessions"]).await?;
        let receipts = peer.take();
        assert_eq!(
            receipts
                .iter()
                .filter(|receipt| receipt.path == "/token")
                .count(),
            1
        );
        peer.respond_at("/token", 200, json!({"access_token":"rotated-access","refresh_token":"rotated-refresh","expires_in":3600}));
        let before = Utc::now();
        let refreshed = call(
            &auth,
            request(
                "/refresh-token",
                Some(json!({"accountId":id})),
                &cookies(&response),
            ),
            200,
        )
        .await;
        let after = Utc::now();
        assert_eq!(body(&refreshed)["accessToken"], "rotated-access");
        let expiry = db
            .text(
                "SELECT access_token_expires_at FROM accounts WHERE id=$1",
                &[&id],
            )
            .await?
            .unwrap();
        let expiry = DateTime::parse_from_rfc3339(&expiry)?.with_timezone(&Utc);
        assert!(expiry >= before + Duration::seconds(3599));
        assert!(expiry <= after + Duration::seconds(3601));
        assert_eq!(db.tables(&["users", "sessions"]).await?, stable);
        let receipts = peer.take();
        assert_eq!(receipts.len(), 1);
        let fields: std::collections::BTreeMap<_, _> =
            url::form_urlencoded::parse(&receipts[0].body).collect();
        assert_eq!(
            fields.get("grant_type").map(|value| value.as_ref()),
            Some("refresh_token")
        );
        assert_eq!(
            fields.get("refresh_token").map(|value| value.as_ref()),
            Some("initial-refresh")
        );
        B::close(connection).await?;
    }
    Ok(())
}
