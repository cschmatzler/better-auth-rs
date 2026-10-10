//! Social sign-in, linking and callback outcomes through a controllable
//! provider: a local token endpoint plus application profile and ID-token
//! callbacks, as the compatibility fixture's Google provider uses.
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::OAuthPlugin;
use alibi::plugins::oauth::{
    OAuthIdTokenVerifier, OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest,
    OAuthUserInfoResponse,
};
use alibi::plugins::{AccountManagementPlugin, EmailVerificationPlugin, SendVerificationEmail};
use alibi::prelude::UserView;
use alibi::{AccountConfig, AccountLinkingConfig};

backend_tests!(
    redirect_linking_outcomes,
    id_token_linking_outcomes,
    id_token_sign_in_outcomes,
    callback_protocol_outcomes,
    sign_in_policies,
    different_email_opt_in_links_unlinks_and_relinks_original_owner
);

#[derive(Clone)]
pub(super) struct Profile {
    pub(super) user: Arc<Mutex<OAuthUserInfo>>,
    pub(super) fail: Arc<Mutex<bool>>,
    pub(super) valid_id_token: Arc<Mutex<bool>>,
}

impl Profile {
    fn new() -> Self {
        Self {
            user: Arc::new(Mutex::new(user("social-sub", "social@example.com", true))),
            fail: Arc::default(),
            valid_id_token: Arc::new(Mutex::new(true)),
        }
    }

    pub(super) fn set(&self, sub: &str, email: &str, verified: bool) {
        *self.user.lock().unwrap() = user(sub, email, verified);
    }
}

fn user(sub: &str, email: &str, verified: bool) -> OAuthUserInfo {
    OAuthUserInfo {
        additional_fields: Default::default(),
        id: sub.into(),
        email: email.into(),
        name: Some(format!("Provider {sub}")),
        image: Some(format!("https://images.example/{sub}")),
        email_verified: verified,
    }
}

#[async_trait::async_trait]
impl OAuthUserInfoHandler for Profile {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        if *self.fail.lock().unwrap() {
            return Err("profile unavailable".into());
        }
        let user = self.user.lock().unwrap().clone();
        Ok(OAuthUserInfoResponse {
            user_output: None,
            data: json!({"sub": user.id, "email": user.email, "name": user.name}),
            user,
        })
    }
}

#[async_trait::async_trait]
impl OAuthIdTokenVerifier for Profile {
    async fn verify_id_token(&self, _: &str, _: Option<&str>) -> Result<bool, String> {
        Ok(*self.valid_id_token.lock().unwrap())
    }
}

#[derive(Default)]
struct Outbox(Mutex<Vec<String>>);

#[async_trait::async_trait]
impl SendVerificationEmail for Outbox {
    async fn send(&self, user: &UserView, _: &str, _: &str) -> alibi::AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push(user.email.clone().unwrap_or_default());
        Ok(())
    }
}

pub(super) struct Social {
    pub(super) provider: Provider,
    pub(super) profile: Profile,
}

impl Social {
    pub(super) async fn start() -> Self {
        Self {
            provider: Provider::start(
                "application/json",
                json!({
                    "access_token": "provider-access",
                    "refresh_token": "provider-refresh",
                    "id_token": "provider-id-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "openid email profile",
                })
                .to_string(),
            )
            .await,
            profile: Profile::new(),
        }
    }

    fn google(&self, configure: impl FnOnce(&mut OAuthProvider)) -> OAuthProvider {
        let mut provider = OAuthProvider::google("google-client", "google-secret");
        provider.token_url = self.provider.url.join("token").unwrap().into();
        provider.get_user_info = Some(Arc::new(self.profile.clone()));
        provider.verify_id_token = Some(Arc::new(self.profile.clone()));
        configure(&mut provider);
        provider
    }

    pub(super) async fn auth<B: Backend>(
        &self,
        connection: &B::Connection,
        account: AccountConfig,
        configure: impl FnOnce(&mut OAuthProvider),
    ) -> TestResult<Alibi<B::Schema>> {
        self.auth_with::<B>(connection, account, configure, |builder| builder)
            .await
    }

    pub(super) async fn auth_with<B: Backend>(
        &self,
        connection: &B::Connection,
        account: AccountConfig,
        configure: impl FnOnce(&mut OAuthProvider),
        extend: impl FnOnce(AuthBuilder<B::Schema>) -> AuthBuilder<B::Schema>,
    ) -> TestResult<Alibi<B::Schema>> {
        let config = AuthConfig::new(SECRET).base_url(ORIGIN).account(account);
        self.auth_configured::<B>(connection, config, configure, extend, |store| store)
            .await
    }

    pub(super) async fn auth_configured<B: Backend>(
        &self,
        connection: &B::Connection,
        config: AuthConfig,
        configure: impl FnOnce(&mut OAuthProvider),
        extend: impl FnOnce(AuthBuilder<B::Schema>) -> AuthBuilder<B::Schema>,
        store: impl FnOnce(B::Store) -> B::Store,
    ) -> TestResult<Alibi<B::Schema>> {
        let builder = AuthBuilder::new(config.clone())
            .store(store(B::store(Arc::new(config), connection)))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new())
            .plugin(SessionManagementPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .plugin(OAuthPlugin::new().add_provider("google", self.google(configure)));
        Ok(extend(builder).build().await?)
    }
}

/// Start an authorization and return the provider `state` with the cookies to
/// replay on the callback.
pub(super) async fn authorize<S: AuthSchema>(
    auth: &Alibi<S>,
    path: &str,
    input: Value,
    cookie: &str,
) -> (String, String) {
    let response = call(auth, request(path, Some(input), cookie), 200).await;
    let url = url::Url::parse(body(&response)["url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let cookies = [cookie.to_owned(), super::cookies(&response)]
        .into_iter()
        .filter(|cookie| !cookie.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    (state, cookies)
}

pub(super) async fn callback<S: AuthSchema>(
    auth: &Alibi<S>,
    query: &[(&str, &str)],
    cookie: &str,
) -> AuthResponse {
    let mut request = request("/callback/google", None, cookie);
    request.set_query_pairs(query.iter().copied());
    Box::pin(auth.handle_request(request)).await.unwrap()
}

pub(super) async fn accounts<S: AuthSchema>(auth: &Alibi<S>, cookie: &str) -> Value {
    let accounts = body(&call(auth, request("/list-accounts", None, cookie), 200).await);
    let mut providers = accounts
        .as_array()
        .unwrap()
        .iter()
        .map(|account| account["providerId"].clone())
        .collect::<Vec<_>>();
    providers.sort_by_key(ToString::to_string);
    Value::Array(providers)
}

pub(super) fn linking(configure: impl FnOnce(&mut AccountLinkingConfig)) -> AccountConfig {
    let mut account = AccountConfig::default();
    configure(&mut account.account_linking);
    account
}

async fn redirect_linking_outcomes<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let auth = social
        .auth::<B>(&connection, AccountConfig::default(), |_| {})
        .await?;
    let mut trace = Trace::default();
    let owner = cookies(&signup(&auth, "social@example.com").await);
    let link = async |cookie: &str| {
        let (state, cookies) = authorize(
            &auth,
            "/link-social",
            json!({"provider": "google", "callbackURL": "/settings", "errorCallbackURL": "/link-error"}),
            cookie,
        )
        .await;
        callback(&auth, &[("code", "grant"), ("state", &state)], &cookies).await
    };

    social.profile.set("link-sub", "social@example.com", false);
    trace.response("unverified", &link(&owner).await);
    social.profile.set("link-sub", "other@example.com", true);
    trace.response("different email", &link(&owner).await);
    social.profile.set("link-sub", "social@example.com", true);
    trace.response("linked", &link(&owner).await);
    trace.response("relinked", &link(&owner).await);
    trace.value("accounts", accounts(&auth, &owner).await);

    let intruder = cookies(&signup(&auth, "intruder@example.com").await);
    social.profile.set("link-sub", "intruder@example.com", true);
    trace.response("linked elsewhere", &link(&intruder).await);
    *social.profile.fail.lock().unwrap() = true;
    trace.response("profile failure", &link(&owner).await);
    *social.profile.fail.lock().unwrap() = false;

    let disabled = social
        .auth::<B>(
            &connection,
            linking(|linking| linking.enabled = false),
            |_| {},
        )
        .await?;
    let (state, cookies) = authorize(
        &disabled,
        "/link-social",
        json!({"provider": "google", "callbackURL": "/settings"}),
        &owner,
    )
    .await;
    trace.response(
        "linking disabled",
        &callback(&disabled, &[("code", "grant"), ("state", &state)], &cookies).await,
    );
    trace.assert("social/redirect-linking");
    B::close(connection).await
}

async fn id_token_linking_outcomes<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let auth = social
        .auth::<B>(&connection, AccountConfig::default(), |_| {})
        .await?;
    let mut trace = Trace::default();
    let owner = cookies(&signup(&auth, "token-owner@example.com").await);
    let link = async |cookie: &str| {
        Box::pin(auth.handle_request(request(
            "/link-social",
            Some(json!({
                "provider": "google",
                "idToken": {
                    "token": "id-token",
                    "accessToken": "access",
                    "refreshToken": "refresh",
                    "expiresAt": 4_102_444_800_i64,
                    "scopes": ["openid", "email"],
                },
            })),
            cookie,
        )))
        .await
        .unwrap()
    };

    *social.profile.valid_id_token.lock().unwrap() = false;
    trace.response("invalid token", &link(&owner).await);
    *social.profile.valid_id_token.lock().unwrap() = true;
    social.profile.set("token-sub", "", true);
    trace.response("missing email", &link(&owner).await);
    social
        .profile
        .set("token-sub", "token-owner@example.com", false);
    trace.response("unverified", &link(&owner).await);
    social
        .profile
        .set("token-sub", "elsewhere@example.com", true);
    trace.response("different email", &link(&owner).await);
    social
        .profile
        .set("token-sub", "token-owner@example.com", true);
    trace.response("linked", &link(&owner).await);
    trace.response("already linked", &link(&owner).await);
    trace.value("accounts", accounts(&auth, &owner).await);
    let other = cookies(&signup(&auth, "token-other@example.com").await);
    trace.response("linked elsewhere", &link(&other).await);
    trace.response("unauthenticated", &link("").await);

    let updating = social
        .auth::<B>(
            &connection,
            linking(|linking| {
                linking.update_user_info_on_link = true;
                linking.trusted_providers = vec!["google".into()];
            }),
            |_| {},
        )
        .await?;
    social
        .profile
        .set("trusted-sub", "token-other@example.com", false);
    trace.response(
        "trusted and updated",
        &Box::pin(updating.handle_request(request(
            "/link-social",
            Some(json!({"provider": "google", "idToken": {"token": "id-token"}})),
            &other,
        )))
        .await?,
    );
    trace.value(
        "updated user",
        body(&call(&updating, request("/get-session", None, &other), 200).await)["user"].clone(),
    );

    let disabled = social
        .auth::<B>(&connection, AccountConfig::default(), |provider| {
            provider.disable_id_token_sign_in = true;
        })
        .await?;
    trace.response(
        "id token disabled",
        &Box::pin(disabled.handle_request(request(
            "/link-social",
            Some(json!({"provider": "google", "idToken": {"token": "id-token"}})),
            &owner,
        )))
        .await?,
    );
    trace.assert("social/id-token-linking");
    B::close(connection).await
}

async fn id_token_sign_in_outcomes<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let auth = social
        .auth::<B>(&connection, AccountConfig::default(), |_| {})
        .await?;
    let mut trace = Trace::default();
    let sign_in = async |auth: &Alibi<B::Schema>| {
        Box::pin(auth.handle_request(request(
            "/sign-in/social",
            Some(json!({
                "provider": "google",
                "callbackURL": "/home",
                "idToken": {"token": "id-token", "nonce": "nonce"},
            })),
            "",
        )))
        .await
        .unwrap()
    };
    social.profile.set("new-sub", "new@example.com", true);
    trace.response("new user", &sign_in(&auth).await);
    trace.response("returning user", &sign_in(&auth).await);
    social.profile.set("other-sub", "new@example.com", false);
    trace.response("unverified implicit link", &sign_in(&auth).await);
    social.profile.set("other-sub", "new@example.com", true);
    trace.response("verified implicit link", &sign_in(&auth).await);

    let closed = social
        .auth::<B>(&connection, AccountConfig::default(), |provider| {
            provider.disable_sign_up = true;
        })
        .await?;
    social.profile.set("closed-sub", "closed@example.com", true);
    trace.response("sign up disabled", &sign_in(&closed).await);
    let updating = social
        .auth::<B>(&connection, AccountConfig::default(), |provider| {
            provider.override_user_info_on_sign_in = true;
        })
        .await?;
    social.profile.set("new-sub", "new@example.com", true);
    social.profile.user.lock().unwrap().name = Some("Renamed".into());
    trace.response("override user info", &sign_in(&updating).await);
    trace.assert("social/id-token-sign-in");
    B::close(connection).await
}

async fn callback_protocol_outcomes<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let auth = social
        .auth::<B>(&connection, AccountConfig::default(), |_| {})
        .await?;
    let mut trace = Trace::default();
    let start = async |auth: &Alibi<B::Schema>| {
        authorize(
            auth,
            "/sign-in/social",
            json!({
                "provider": "google",
                "callbackURL": "/home",
                "newUserCallbackURL": "/welcome",
                "errorCallbackURL": "/oops",
            }),
            "",
        )
        .await
    };

    trace.response(
        "missing state",
        &callback(&auth, &[("code", "grant")], "").await,
    );
    trace.response(
        "unknown state",
        &callback(&auth, &[("code", "grant"), ("state", "unknown")], "").await,
    );
    let (state, cookies) = start(&auth).await;
    trace.response(
        "foreign cookie",
        &callback(&auth, &[("code", "grant"), ("state", &state)], "").await,
    );
    let (state, cookies_2) = start(&auth).await;
    trace.response(
        "provider error",
        &callback(
            &auth,
            &[
                ("state", &state),
                ("error", "access_denied"),
                ("error_description", "User cancelled"),
            ],
            &cookies_2,
        )
        .await,
    );
    let (state, cookies_3) = start(&auth).await;
    trace.response(
        "no code",
        &callback(&auth, &[("state", &state)], &cookies_3).await,
    );
    social.provider.respond(
        400,
        "application/json",
        json!({"error": "invalid_grant"}).to_string(),
    );
    let (state, cookies_4) = start(&auth).await;
    trace.response(
        "token failure",
        &callback(&auth, &[("code", "grant"), ("state", &state)], &cookies_4).await,
    );
    social.provider.respond(
        200,
        "application/json",
        json!({"access_token": "provider-access", "token_type": "Bearer"}).to_string(),
    );
    social
        .profile
        .set("callback-sub", "callback@example.com", true);
    let (state, cookies_5) = start(&auth).await;
    trace.response(
        "registered",
        &callback(&auth, &[("code", "grant"), ("state", &state)], &cookies_5).await,
    );
    let (state, cookies_6) = start(&auth).await;
    trace.response(
        "returning",
        &callback(&auth, &[("code", "grant"), ("state", &state)], &cookies_6).await,
    );
    trace.response(
        "replayed state",
        &callback(&auth, &[("code", "grant"), ("state", &state)], &cookies_6).await,
    );
    drop(cookies);

    let mut form = request("/callback/google", None, "");
    form.method = alibi::HttpMethod::Post;
    form.body = Some(b"code=posted&state=form-state&user=%7B%7D".to_vec());
    _ = form.headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    trace.response("form post", &Box::pin(auth.handle_request(form)).await?);

    let idp = social
        .auth::<B>(&connection, AccountConfig::default(), |provider| {
            provider.allow_idp_initiated = true;
        })
        .await?;
    trace.response(
        "idp initiated",
        &callback(&idp, &[("code", "unsolicited")], "").await,
    );
    let mut unknown = request("/callback/unknown", None, "");
    unknown.set_query_pairs([("code", "grant"), ("state", "x")]);
    trace.response(
        "unknown provider",
        &Box::pin(auth.handle_request(unknown)).await?,
    );
    trace.assert("social/callback-protocol");
    B::close(connection).await
}

async fn sign_in_policies<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let mut trace = Trace::default();
    let outbox = Arc::new(Outbox::default());
    let verification = EmailVerificationPlugin::new()
        .send_on_sign_in(true)
        .custom_send_verification_email(Arc::clone(&outbox) as _);
    let auth = social
        .auth_with::<B>(
            &connection,
            AccountConfig::default(),
            |provider| provider.require_email_verification = true,
            |builder| builder.plugin(verification),
        )
        .await?;
    social
        .profile
        .set("unverified-sub", "unverified@example.com", false);
    let sign_in = async |auth: &Alibi<B::Schema>| {
        let (state, cookies) = authorize(
            auth,
            "/sign-in/social",
            json!({"provider": "google", "callbackURL": "/home"}),
            "",
        )
        .await;
        callback(auth, &[("code", "grant"), ("state", &state)], &cookies).await
    };
    trace.response("unverified new user", &sign_in(&auth).await);
    trace.response("unverified returning user", &sign_in(&auth).await);
    trace.value("verification mail", json!(outbox.0.lock().unwrap().len()));

    let implicit = social
        .auth::<B>(&connection, AccountConfig::default(), |provider| {
            provider.disable_implicit_sign_up = true;
        })
        .await?;
    social
        .profile
        .set("implicit-sub", "implicit@example.com", true);
    trace.response("implicit sign up disabled", &sign_in(&implicit).await);
    let (state, cookies) = authorize(
        &implicit,
        "/sign-in/social",
        json!({"provider": "google", "callbackURL": "/home", "requestSignUp": true}),
        "",
    )
    .await;
    trace.response(
        "requested sign up",
        &callback(&implicit, &[("code", "grant"), ("state", &state)], &cookies).await,
    );
    trace.assert("social/sign-in-policies");
    B::close(connection).await
}

async fn different_email_opt_in_links_unlinks_and_relinks_original_owner<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let mut provider = OAuthProvider::google("google-client", "google-secret");
    provider.token_url = social.provider.url.join("token").unwrap().into();
    provider.get_user_info = Some(Arc::new(social.profile.clone()));
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .account(linking(|policy| policy.allow_different_emails = true));
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .plugin(OAuthPlugin::new().add_provider("google", provider))
        .build()
        .await?;
    let owner = signup(&auth, "local-link-owner@example.test").await;
    let foreign = signup(&auth, "local-link-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    _ = db.execute("INSERT INTO accounts (id,user_id,account_id,provider_id,created_at,updated_at) SELECT 'github-backup',user_id,'local-github','github',created_at,updated_at FROM accounts WHERE user_id=$1", &[&owner_id]).await?;
    let before = db.tables(&["users", "sessions"]).await?;
    let before_accounts: Vec<Value> = serde_json::from_str(&db.table("accounts").await?)?;
    social
        .profile
        .set("different-email-sub", "provider-link@example.test", true);
    for destination in ["/linked", "/relinked"] {
        let (state, cookie) = authorize(
            &auth,
            "/link-social",
            json!({"provider":"google","callbackURL":destination}),
            &cookies(&owner),
        )
        .await;
        let completed = callback(&auth, &[("code", "grant"), ("state", &state)], &cookie).await;
        assert_eq!(completed.status, 302);
        assert_eq!(
            completed.headers.get("location").map(String::as_str),
            Some(destination)
        );
        let current =
            body(&call(&auth, request("/get-session", None, &cookies(&owner)), 200).await);
        assert_eq!(current["user"]["id"], owner_id);
        assert_eq!(current["user"]["email"], "local-link-owner@example.test");
        assert_eq!(
            accounts(&auth, &cookies(&owner)).await,
            json!(["credential", "github", "google"])
        );
        let all: Vec<Value> = serde_json::from_str(&db.table("accounts").await?)?;
        assert_eq!(all.len(), before_accounts.len() + 1);
        assert!(before_accounts.iter().all(|row| all.contains(row)));
        let google = all
            .iter()
            .find(|row| row["provider_id"] == "google")
            .unwrap();
        assert_eq!(google["user_id"], owner_id);
        assert_eq!(google["account_id"], "different-email-sub");
        if destination == "/linked" {
            assert_eq!(
                body(
                    &call(
                        &auth,
                        request(
                            "/unlink-account",
                            Some(json!({"accountId":google["id"]})),
                            &cookies(&owner)
                        ),
                        200
                    )
                    .await
                )["status"],
                true
            );
            assert_eq!(
                accounts(&auth, &cookies(&owner)).await,
                json!(["credential", "github"])
            );
            assert_eq!(
                serde_json::from_str::<Vec<Value>>(&db.table("accounts").await?)?,
                before_accounts
            );
        }
        assert_eq!(db.tables(&["users", "sessions"]).await?, before);
    }
    authenticated(&auth, &cookies(&foreign), "local-link-foreign@example.test").await;
    B::close(connection).await
}
