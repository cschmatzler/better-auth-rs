//! Account and user effects of social sign-in: cookies, token retention,
//! implicit linking, verification promotion and provider-supplied fields.
use super::social_flows::{Social, authorize, callback, linking};
use super::*;
use crate::snapshot::Trace;
use alibi::AuthResult;
use alibi::field_policy::FieldConfig;
use alibi::hooks::RequestHookContext;
use alibi::plugins::email_otp::{EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, SendEmailOtp};
use alibi::plugins::oauth::{
    OAuthCallbackUserPayload, OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use alibi::plugins::{EmailVerificationConfig, EmailVerificationPlugin};
use alibi::user_validation::{UserInfoValidator, UserValidationData, UserValidationRejection};
use alibi::{AccountConfig, CallbackContext};

backend_tests!(
    account_cookie_and_token_retention_on_sign_in,
    implicit_linking_and_verification_promotion,
    provider_supplied_fields_and_identity_denials,
    id_token_sign_in_failure_modes,
    callback_user_payload_reaches_the_profile_handler,
    unverified_social_sign_in_delegates_to_the_otp_override,
    ambiguous_provider_accounts_fail_closed,
    returning_social_signin_preserves_previously_granted_scopes,
    orphan_oauth_binding_never_adopts_same_email_owner
);

struct Deny;

#[async_trait::async_trait]
impl UserInfoValidator for Deny {
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
                error: "SOCIAL_DENIED".into(),
                error_description: Some("Social identity denied".into()),
            }))
    }
}

async fn sign_in<S: AuthSchema>(auth: &Alibi<S>, cookie: &str) -> AuthResponse {
    let (state, cookies) = authorize(
        auth,
        "/sign-in/social",
        json!({"provider": "google", "callbackURL": "/home", "newUserCallbackURL": "/welcome", "errorCallbackURL": "/oops"}),
        cookie,
    )
    .await;
    callback(auth, &[("code", "grant"), ("state", &state)], &cookies).await
}

fn account_cookie(response: &AuthResponse) -> bool {
    response.headers.get_all("set-cookie").any(|header| {
        header.starts_with("better-auth.account_data=") && !header.contains("Max-Age=0")
    })
}

async fn account_cookie_and_token_retention_on_sign_in<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    let social = Social::start().await;
    let account = AccountConfig {
        store_account_cookie: true,
        ..Default::default()
    };
    let auth = social
        .auth::<B>(&connection, account.clone(), |_| {})
        .await?;
    let registered = sign_in(&auth, "").await;
    assert!(account_cookie(&registered));
    trace.response("registered", &registered);
    let stored = |column: &'static str| {
        let db = &db;
        async move {
            db.text(
                &format!("SELECT {column} FROM accounts WHERE account_id = $1"),
                &["social-sub"],
            )
            .await
        }
    };
    assert_eq!(
        stored("refresh_token").await?.as_deref(),
        Some("provider-refresh")
    );

    social.provider.respond(
        200,
        "application/json",
        json!({"access_token":"rotated-access","token_type":"Bearer"}).to_string(),
    );
    let returning = sign_in(&auth, "").await;
    assert!(account_cookie(&returning));
    trace.response("returning without refresh token", &returning);
    assert_eq!(
        stored("access_token").await?.as_deref(),
        Some("rotated-access")
    );
    assert_eq!(
        stored("refresh_token").await?.as_deref(),
        Some("provider-refresh")
    );

    let frozen = {
        let mut frozen = account.clone();
        frozen.update_account_on_sign_in = false;
        social.auth::<B>(&connection, frozen, |_| {}).await?
    };
    social.provider.respond(
        200,
        "application/json",
        json!({"access_token":"ignored-access","token_type":"Bearer"}).to_string(),
    );
    let unchanged = sign_in(&frozen, "").await;
    assert!(account_cookie(&unchanged));
    trace.response("returning without token update", &unchanged);
    assert_eq!(
        stored("access_token").await?.as_deref(),
        Some("rotated-access")
    );

    let mut lifetime = account.clone();
    lifetime.cookie_max_age = Some(60.0);
    let bounded = social.auth::<B>(&connection, lifetime, |_| {}).await?;
    social
        .profile
        .set("bounded-sub", "bounded@example.com", true);
    let response = sign_in(&bounded, "").await;
    assert!(
        response
            .headers
            .get_all("set-cookie")
            .any(|header| header.starts_with("better-auth.account_data=")
                && header.contains("Max-Age=60"))
    );

    let mut invalid = account;
    invalid.cookie_max_age = Some(f64::NAN);
    let broken = social.auth::<B>(&connection, invalid, |_| {}).await?;
    social.profile.set("broken-sub", "broken@example.com", true);
    let failed = sign_in(&broken, "").await;
    trace.response("unusable account cookie lifetime", &failed);
    assert!(!cookies(&failed).contains("session_token"));
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE email = $1",
            &["broken@example.com"]
        )
        .await?,
        1
    );
    assert_eq!(db.count("sessions").await?, 4);
    trace.assert("social/account-cookie");
    B::close(connection).await
}

async fn implicit_linking_and_verification_promotion<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    let social = Social::start().await;

    let mut account = linking(|linking| {
        linking.require_local_email_verified = false;
        linking.update_user_info_on_link = true;
    });
    account.update_account_on_sign_in = true;
    let auth = social.auth::<B>(&connection, account, |_| {}).await?;
    drop(signup(&auth, "local@example.com").await);
    social.profile.set("local-sub", "local@example.com", true);
    trace.response("linked and updated", &sign_in(&auth, "").await);
    trace.value(
        "local user",
        json!(
            db.count_where(
                "SELECT COUNT(*) FROM users WHERE email = $1 AND name = 'Provider local-sub' AND image = 'https://images.example/local-sub' AND email_verified = true",
                &["local@example.com"]
            )
            .await?
        ),
    );

    social.profile.set("late-sub", "late@example.com", false);
    trace.response("unverified registration", &sign_in(&auth, "").await);
    social.profile.set("late-sub", "late@example.com", true);
    trace.response("verified later", &sign_in(&auth, "").await);
    trace.value(
        "late user",
        json!(
            db.count_where(
                "SELECT COUNT(*) FROM users WHERE email = $1 AND email_verified = true",
                &["late@example.com"]
            )
            .await?
        ),
    );

    let overriding = social
        .auth::<B>(&connection, AccountConfig::default(), |provider| {
            provider.override_user_info_on_sign_in = true;
        })
        .await?;
    social
        .profile
        .set("moving-sub", "moving@example.com", false);
    trace.response("moving registration", &sign_in(&overriding, "").await);
    social.profile.set("moving-sub", "moved@example.com", true);
    trace.response("moved and verified", &sign_in(&overriding, "").await);
    trace.value(
        "moved user",
        json!(
            db.count_where(
                "SELECT COUNT(*) FROM users WHERE email = $1 AND email_verified = true",
                &["moved@example.com"]
            )
            .await?
        ),
    );

    let promoting = social
        .auth::<B>(
            &connection,
            linking(|linking| linking.require_local_email_verified = false),
            |provider| provider.override_user_info_on_sign_in = true,
        )
        .await?;
    drop(signup(&promoting, "promote@example.com").await);
    social
        .profile
        .set("promote-sub", "promote@example.com", true);
    trace.response("override while linking", &sign_in(&promoting, "").await);
    trace.assert("social/linking-promotion");
    B::close(connection).await
}

async fn provider_supplied_fields_and_identity_denials<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    let social = Social::start().await;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    drop(
        config
            .user
            .additional_fields
            .insert("role".into(), FieldConfig::new(json!({"type":"string"}))),
    );
    config.user_validation = Some(Arc::new(Deny));
    let auth = social
        .auth_configured::<B>(
            &connection,
            config,
            |provider| {
                provider.override_user_info_on_sign_in = true;
            },
            |builder| builder,
            |store| store,
        )
        .await?;

    social.profile.set("fields-sub", "fields@example.com", true);
    {
        let mut user = social.profile.user.lock().unwrap();
        drop(
            user.additional_fields
                .insert("role".into(), json!("member")),
        );
        drop(
            user.additional_fields
                .insert("email".into(), json!("ignored@example.com")),
        );
        drop(
            user.additional_fields
                .insert("unregistered".into(), json!("ignored")),
        );
    }
    trace.response("registered with fields", &sign_in(&auth, "").await);
    assert_eq!(
        db.text(
            "SELECT role FROM users WHERE email = $1",
            &["fields@example.com"]
        )
        .await?
        .as_deref(),
        Some("member")
    );
    _ = social
        .profile
        .user
        .lock()
        .unwrap()
        .additional_fields
        .insert("role".into(), json!("owner"));
    trace.response("returning with fields", &sign_in(&auth, "").await);
    assert_eq!(
        db.text(
            "SELECT role FROM users WHERE email = $1",
            &["fields@example.com"]
        )
        .await?
        .as_deref(),
        Some("owner")
    );

    social.profile.set("deny-sub", "deny@example.com", true);
    trace.response("denied registration", &sign_in(&auth, "").await);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE email = $1",
            &["deny@example.com"]
        )
        .await?,
        0
    );
    social.profile.set("empty-sub", "", true);
    trace.response("profile without email", &sign_in(&auth, "").await);
    trace.assert("social/provider-fields");
    B::close(connection).await
}

async fn id_token_sign_in_failure_modes<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    let social = Social::start().await;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.user_validation = Some(Arc::new(Deny));
    let sign_in = async |auth: &Alibi<B::Schema>| {
        Box::pin(auth.handle_request(request(
            "/sign-in/social",
            Some(json!({"provider":"google","idToken":{"token":"id-token"}})),
            "",
        )))
        .await
        .unwrap()
    };
    let ordinary = social
        .auth_configured::<B>(
            &connection,
            config.clone(),
            |_| {},
            |builder| builder,
            |store| store,
        )
        .await?;
    social.profile.set("denied-sub", "deny@example.com", true);
    trace.response("denied", &sign_in(&ordinary).await);
    social.profile.set("empty-sub", "", true);
    trace.response("profile without email", &sign_in(&ordinary).await);
    social.profile.set("valid-sub", "valid@example.com", true);
    let unusable = social
        .auth_configured::<B>(
            &connection,
            config.clone(),
            |provider| provider.account_subject = Some(|_| Err("unusable subject".into())),
            |builder| builder,
            |store| store,
        )
        .await?;
    trace.response("unusable account key", &sign_in(&unusable).await);
    let unsupported = social
        .auth_configured::<B>(
            &connection,
            config,
            |provider| {
                provider.verify_id_token = None;
                provider.id_token = None;
            },
            |builder| builder,
            |store| store,
        )
        .await?;
    trace.response("verification unavailable", &sign_in(&unsupported).await);
    for table in ["users", "accounts", "sessions"] {
        assert_eq!(db.count(table).await?, 0, "{table}");
    }
    trace.assert("social/id-token-failures");
    B::close(connection).await
}

struct Recorder(
    super::social_flows::Profile,
    Arc<Mutex<Vec<Option<OAuthCallbackUserPayload>>>>,
);

#[async_trait::async_trait]
impl OAuthUserInfoHandler for Recorder {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        self.1.lock().unwrap().push(request.user.clone());
        self.0.get_user_info(request).await
    }
}

async fn callback_user_payload_reaches_the_profile_handler<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::new(Recorder(social.profile.clone(), Arc::clone(&seen)));
    let auth = social
        .auth::<B>(&connection, AccountConfig::default(), |provider| {
            provider.get_user_info = Some(recorder);
        })
        .await?;
    for (index, user) in [
        Some(r#"{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"ada@example.com"}"#),
        Some(r#"{"name":{"firstName":"Only"},"email":5}"#),
        Some(r#"{"name":"flat"}"#),
        Some("not json"),
        None,
    ]
    .into_iter()
    .enumerate()
    {
        social.profile.set(
            &format!("payload-sub-{index}"),
            &format!("payload-{index}@example.com"),
            true,
        );
        let (state, cookie) = authorize(
            &auth,
            "/sign-in/social",
            json!({"provider":"google","callbackURL":"/home"}),
            "",
        )
        .await;
        let mut query = vec![("code", "grant"), ("state", state.as_str())];
        if let Some(user) = user {
            query.push(("user", user));
        }
        assert_eq!(callback(&auth, &query, &cookie).await.status, 302);
    }
    let summary: Vec<_> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|user| {
            user.as_ref().map(|user| {
                json!([
                    user.name.as_ref().and_then(|name| name.first_name.clone()),
                    user.name.as_ref().and_then(|name| name.last_name.clone()),
                    user.email,
                ])
            })
        })
        .collect();
    assert_eq!(
        summary,
        [
            Some(json!(["Ada", "Lovelace", "ada@example.com"])),
            Some(json!(["Only", null, null])),
            Some(json!([null, null, null])),
            None,
            None,
        ]
    );
    B::close(connection).await
}

#[derive(Default)]
struct Otp(Mutex<Vec<String>>);

#[async_trait::async_trait]
impl SendEmailOtp for Otp {
    async fn send(&self, delivery: &EmailOtpDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.0.lock().unwrap().push(delivery.email.clone());
        Ok(())
    }
}

async fn unverified_social_sign_in_delegates_to_the_otp_override<B: Backend>(db: Db) -> TestResult {
    let mut trace = Trace::default();
    for (label, verification_plugin) in [("configured plugin", true), ("no plugin", false)] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let social = Social::start().await;
        let otp = Arc::new(Otp::default());
        let sender = Arc::clone(&otp);
        let auth = social
            .auth_with::<B>(
                &connection,
                AccountConfig::default(),
                |provider| provider.require_email_verification = true,
                move |builder| {
                    let builder = builder.plugin(EmailOtpPlugin::new(EmailOtpConfig {
                        override_default_email_verification: true,
                        send_verification_otp: Some(sender),
                        ..Default::default()
                    }));
                    if verification_plugin {
                        builder.plugin(EmailVerificationPlugin::with_config(
                            EmailVerificationConfig {
                                send_on_sign_up: Some(true),
                                send_on_sign_in: true,
                                ..Default::default()
                            },
                        ))
                    } else {
                        builder
                    }
                },
            )
            .await?;
        social.profile.set("otp-sub", "otp@example.com", false);
        trace.response(&format!("{label}: registration"), &sign_in(&auth, "").await);
        trace.response(&format!("{label}: returning"), &sign_in(&auth, "").await);
        trace.value(
            &format!("{label}: codes sent"),
            json!(otp.0.lock().unwrap().clone()),
        );
        B::close(connection).await?;
    }
    trace.assert("social/otp-override");
    Ok(())
}

async fn ambiguous_provider_accounts_fail_closed<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    let social = Social::start().await;
    let auth = social
        .auth::<B>(&connection, AccountConfig::default(), |_| {})
        .await?;
    assert_eq!(sign_in(&auth, "").await.status, 302);
    let owner = cookies(&signup(&auth, "owner@example.com").await);
    _ = db
        .execute(
            "INSERT INTO accounts (id, user_id, account_id, provider_id, created_at, updated_at) SELECT 'duplicate-account', user_id, account_id, provider_id, created_at, updated_at FROM accounts WHERE provider_id = 'google'",
            &[],
        )
        .await?;
    let sessions = db.count("sessions").await?;
    trace.response("callback sign-in", &sign_in(&auth, "").await);
    let by_token = |path: &'static str, cookie: &str| {
        let req = request(
            path,
            Some(json!({"provider":"google","idToken":{"token":"id-token"}})),
            cookie,
        );
        let auth = &auth;
        async move { Box::pin(auth.handle_request(req)).await.unwrap() }
    };
    trace.response("id token sign-in", &by_token("/sign-in/social", "").await);
    trace.response("id token link", &by_token("/link-social", &owner).await);
    let (state, cookie) = authorize(
        &auth,
        "/link-social",
        json!({"provider":"google","callbackURL":"/settings"}),
        &owner,
    )
    .await;
    social.profile.set("social-sub", "owner@example.com", true);
    trace.response(
        "callback link",
        &callback(&auth, &[("code", "grant"), ("state", &state)], &cookie).await,
    );
    assert_eq!(db.count("sessions").await?, sessions);
    trace.assert("social/ambiguous-accounts");
    B::close(connection).await
}

async fn returning_social_signin_preserves_previously_granted_scopes<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let auth = social
        .auth::<B>(&connection, AccountConfig::default(), |_| {})
        .await?;
    social
        .profile
        .set("foreign-sub", "foreign@example.test", true);
    let foreign = sign_in(&auth, "").await;
    assert_eq!(foreign.status, 302);
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    social.profile.set("social-sub", "social@example.com", true);
    let initial = sign_in(&auth, "").await;
    assert_eq!(initial.status, 302);
    let current = body(
        &call(
            &auth,
            request("/get-session", None, &cookies(&initial)),
            200,
        )
        .await,
    );
    let owner_id = current["user"]["id"].clone();
    _=db.execute("UPDATE accounts SET scope='calendar,drive' WHERE account_id=$1 AND provider_id='google'",&["social-sub"]).await?;
    let before: Vec<Value> = serde_json::from_str(&db.table("accounts").await?)?;
    let original = before
        .iter()
        .find(|row| row["account_id"] == "social-sub")
        .unwrap();
    let users = db.table("users").await?;
    let sessions: Vec<Value> = serde_json::from_str(&db.table("sessions").await?)?;
    social.provider.respond(200,"application/json",json!({"access_token":"rotated-access","refresh_token":"rotated-refresh","id_token":"rotated-id","token_type":"Bearer","expires_in":3600,"scope":"openid email profile"}).to_string());
    _ = social.provider.take();
    let returning = sign_in(&auth, "").await;
    assert_eq!(returning.status, 302);
    assert_eq!(
        returning.headers.get("location").map(String::as_str),
        Some("/home")
    );
    let current = body(
        &call(
            &auth,
            request("/get-session", None, &cookies(&returning)),
            200,
        )
        .await,
    );
    assert_eq!(current["user"]["id"], owner_id);
    let after: Vec<Value> = serde_json::from_str(&db.table("accounts").await?)?;
    assert_eq!(after.len(), before.len());
    let updated = after
        .iter()
        .find(|row| row["id"] == original["id"])
        .unwrap();
    for field in [
        "id",
        "user_id",
        "account_id",
        "provider_id",
        "created_at",
        "scope",
    ] {
        assert_eq!(updated[field], original[field], "{field}");
    }
    assert_eq!(updated["scope"], "calendar,drive");
    assert_eq!(updated["access_token"], "rotated-access");
    assert_eq!(updated["refresh_token"], "rotated-refresh");
    assert_eq!(updated["id_token"], "rotated-id");
    for row in before.iter().filter(|row| row["id"] != original["id"]) {
        assert!(after.contains(row));
    }
    let listed = body(
        &call(
            &auth,
            request("/list-accounts", None, &cookies(&returning)),
            200,
        )
        .await,
    );
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["id"], original["id"]);
    assert_eq!(listed[0]["accountId"], "social-sub");
    assert_eq!(listed[0]["scopes"], json!(["calendar", "drive"]));
    assert_eq!(db.table("users").await?, users);
    let new_sessions: Vec<Value> = serde_json::from_str(&db.table("sessions").await?)?;
    assert_eq!(new_sessions.len(), sessions.len() + 1);
    assert!(sessions.iter().all(|row| new_sessions.contains(row)));
    let receipts = social.provider.take();
    assert_eq!(receipts.len(), 1);
    let fields = url::form_urlencoded::parse(&receipts[0].body)
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        fields.get("grant_type").map(|value| value.as_ref()),
        Some("authorization_code")
    );
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn orphan_oauth_binding_never_adopts_same_email_owner<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let mut provider =
        alibi::plugins::oauth::OAuthProvider::google("google-client", "google-secret");
    provider.token_url = social.provider.url.join("token").unwrap().into();
    provider.get_user_info = Some(Arc::new(social.profile.clone()));
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(alibi::plugins::OAuthPlugin::new().add_provider("google", provider))
        .build()
        .await?;
    let owner = signup(&auth, "orphan-owner@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    _ = db.execute("INSERT INTO accounts (id,user_id,account_id,provider_id,access_token,refresh_token,created_at,updated_at) SELECT 'orphan-account',user_id,'orphan-sub','google','old-access','old-refresh',created_at,updated_at FROM accounts WHERE user_id=$1", &[&owner_id]).await?;
    _ = db.execute("PRAGMA foreign_keys=OFF", &[]).await?;
    _ = db
        .execute(
            "UPDATE accounts SET user_id='missing-owner' WHERE id='orphan-account'",
            &[],
        )
        .await?;
    _ = db.execute("PRAGMA foreign_keys=ON", &[]).await?;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    social
        .profile
        .set("orphan-sub", "orphan-owner@example.test", true);
    let (state, cookie) = authorize(
        &auth,
        "/sign-in/social",
        json!({"provider":"google","callbackURL":"/home","errorCallbackURL":"/oops"}),
        &cookies(&owner),
    )
    .await;
    let rejected = callback(&auth, &[("code", "grant"), ("state", &state)], &cookie).await;
    assert_eq!(rejected.status, 302);
    let location = url::Url::parse(&format!(
        "{ORIGIN}{}",
        rejected.headers.get("location").unwrap()
    ))
    .or_else(|_| url::Url::parse(rejected.headers.get("location").unwrap()))?;
    assert_eq!(
        location
            .query_pairs()
            .find(|(key, _)| key == "error")
            .unwrap()
            .1,
        "unable_to_link_account"
    );
    assert!(cookies(&rejected).is_empty());
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    assert_eq!(db.count("verifications").await?, 0);
    authenticated(&auth, &cookies(&owner), "orphan-owner@example.test").await;
    B::close(connection).await
}
