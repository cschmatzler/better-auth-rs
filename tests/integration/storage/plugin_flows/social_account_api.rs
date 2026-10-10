//! Linked-account token and profile endpoints: input validation, authentication
//! and refresh outcomes.
use super::social_flows::{Social, authorize, callback};
use super::*;
use crate::snapshot::Trace;
use alibi::AccountConfig;
use alibi::plugins::oauth::{OAuthAccountApi, OAuthAccountSelection};

backend_tests!(
    account_endpoints_validate_selection_authentication_and_refresh,
    automatic_refresh_uses_access_expiry_without_refresh_lifetime_veto,
    automatic_refresh_distinguishes_null_empty_response_and_persisted_tokens,
    corrupt_imported_oauth_ciphertexts_reject_before_transport_or_writes
);

async fn account_endpoints_validate_selection_authentication_and_refresh<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let mut trace = Trace::default();
    let account = AccountConfig {
        store_account_cookie: true,
        ..Default::default()
    };
    let auth = social.auth::<B>(&connection, account, |_| {}).await?;
    let (state, cookie) = authorize(
        &auth,
        "/sign-in/social",
        json!({"provider":"google","callbackURL":"/home"}),
        "",
    )
    .await;
    let signed_in = callback(&auth, &[("code", "grant"), ("state", &state)], &cookie).await;
    assert_eq!(signed_in.status, 302);
    let session = cookies(&signed_in);
    let id = db.text("SELECT id FROM accounts", &[]).await?.unwrap();

    let post = |path: &'static str, input: Value, cookie: String| {
        let auth = &auth;
        async move {
            Box::pin(auth.handle_request(request(path, Some(input), &cookie)))
                .await
                .unwrap()
        }
    };
    for path in ["/get-access-token", "/refresh-token"] {
        for (label, input) in [
            ("empty object", json!({})),
            ("array", json!([])),
            ("unknown key", json!({"accountId": id, "extra": 1})),
            (
                "unknown keys",
                json!({"accountId": id, "extra": 1, "more": 2}),
            ),
            (
                "both selectors",
                json!({"accountId": id, "useAccountCookie": true}),
            ),
            ("foreign user", json!({"accountId": id, "userId": 5})),
            ("account cookie selector", json!({"useAccountCookie": true})),
            ("unknown account", json!({"accountId": "missing"})),
        ] {
            trace.response(
                &format!("{path} {label}"),
                &post(path, input, session.clone()).await,
            );
        }
        trace.response(
            &format!("{path} unauthenticated"),
            &post(path, json!({"accountId": id}), String::new()).await,
        );
    }
    for (label, query, cookie) in [
        (
            "account-info selected",
            vec![("accountId", id.as_str())],
            session.as_str(),
        ),
        (
            "account-info unknown key",
            vec![("accountId", id.as_str()), ("extra", "1")],
            session.as_str(),
        ),
        ("account-info no selector", vec![], session.as_str()),
        (
            "account-info unauthenticated",
            vec![("accountId", id.as_str())],
            "",
        ),
    ] {
        let mut req = request("/account-info", None, cookie);
        req.set_query_pairs(query);
        trace.response(label, &Box::pin(auth.handle_request(req)).await?);
    }

    social.provider.respond(
        200,
        "application/json",
        json!({"access_token":"rotated-access","token_type":"Bearer","expires_in":3600})
            .to_string(),
    );
    let refreshed = post("/refresh-token", json!({"accountId": id}), session.clone()).await;
    trace.response("refresh without a new refresh token", &refreshed);
    assert_eq!(body(&refreshed)["refreshToken"], "provider-refresh");
    assert_eq!(
        db.text("SELECT refresh_token FROM accounts", &[])
            .await?
            .as_deref(),
        Some("provider-refresh")
    );

    for selection in [
        OAuthAccountSelection::Id(id.clone()),
        OAuthAccountSelection::Cookie,
    ] {
        let error = OAuthAccountApi::get_access_token("", selection, auth.context())
            .await
            .unwrap_err();
        trace.value("server call without user", json!(error.to_string()));
    }
    trace.assert("social/account-api");
    B::close(connection).await
}

async fn automatic_refresh_uses_access_expiry_without_refresh_lifetime_veto<B: Backend>(
    db: Db,
) -> TestResult {
    use chrono::{DateTime, Utc};
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let auth = social
        .auth::<B>(&connection, AccountConfig::default(), |_| {})
        .await?;
    let issue = async || {
        let (state, cookie) = authorize(
            &auth,
            "/sign-in/social",
            json!({"provider":"google","callbackURL":"/home"}),
            "",
        )
        .await;
        callback(&auth, &[("code", "grant"), ("state", &state)], &cookie).await
    };
    social
        .profile
        .set("foreign-sub", "foreign@example.test", true);
    let foreign = issue().await;
    assert_eq!(foreign.status, 302);
    social.profile.set("social-sub", "social@example.com", true);
    let owner = issue().await;
    assert_eq!(owner.status, 302);
    let cookie = cookies(&owner);
    let current = body(&call(&auth, request("/get-session", None, &cookie), 200).await);
    let owner_id = current["user"]["id"].clone();
    let id = db
        .text(
            "SELECT id FROM accounts WHERE account_id=$1 AND provider_id='google'",
            &["social-sub"],
        )
        .await?
        .unwrap();
    let past = DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")?.with_timezone(&Utc);
    let future = DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")?.with_timezone(&Utc);
    db.set_timestamp("accounts", "refresh_token_expires_at", ("id", &id), past)
        .await?;
    social.provider.respond(200,"application/json",json!({"access_token":"rotated-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":3600,"scope":"openid"}).to_string());
    _ = social.provider.take();
    for expiry in [None, Some(future), Some(past)] {
        _=db.execute("UPDATE accounts SET access_token='old-access',refresh_token='old-refresh',scope='calendar,drive',access_token_expires_at=NULL WHERE id=$1",&[&id]).await?;
        if let Some(expiry) = expiry {
            db.set_timestamp("accounts", "access_token_expires_at", ("id", &id), expiry)
                .await?;
        }
        let before = db.tables(&["users", "accounts", "sessions"]).await?;
        let started = Utc::now();
        let result = body(
            &call(
                &auth,
                request("/get-access-token", Some(json!({"accountId":id})), &cookie),
                200,
            )
            .await,
        );
        let finished = Utc::now();
        let receipts = social.provider.take();
        let after = db.tables(&["users", "accounts", "sessions"]).await?;
        if expiry != Some(past) {
            assert_eq!(result["accessToken"], "old-access");
            assert!(receipts.is_empty());
            assert_eq!(after, before);
        } else {
            assert_eq!(result["accessToken"], "rotated-access");
            assert_eq!(result["scopes"], json!(["calendar", "drive"]));
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].method, axum::http::Method::POST);
            assert_eq!(receipts[0].path, "/token");
            let fields = url::form_urlencoded::parse(&receipts[0].body)
                .collect::<std::collections::BTreeMap<_, _>>();
            assert_eq!(
                fields.get("grant_type").map(|value| value.as_ref()),
                Some("refresh_token")
            );
            assert_eq!(
                fields.get("refresh_token").map(|value| value.as_ref()),
                Some("old-refresh")
            );
            assert_eq!(after[0], before[0]);
            assert_eq!(after[2], before[2]);
            let original: Vec<Value> = serde_json::from_str(&before[1])?;
            let updated: Vec<Value> = serde_json::from_str(&after[1])?;
            assert_eq!(updated.len(), original.len());
            let original_row = original.iter().find(|row| row["id"] == id).unwrap();
            let updated_row = updated.iter().find(|row| row["id"] == id).unwrap();
            for field in [
                "id",
                "account_id",
                "provider_id",
                "user_id",
                "scope",
                "created_at",
                "refresh_token_expires_at",
            ] {
                assert_eq!(updated_row[field], original_row[field], "{field}");
            }
            assert_eq!(updated_row["user_id"], owner_id);
            assert_eq!(updated_row["access_token"], "rotated-access");
            assert_eq!(updated_row["refresh_token"], "rotated-refresh");
            let expires = DateTime::parse_from_rfc3339(
                updated_row["access_token_expires_at"].as_str().unwrap(),
            )?
            .with_timezone(&Utc);
            assert!(expires >= started + chrono::Duration::seconds(3600));
            assert!(expires <= finished + chrono::Duration::seconds(3600));
            for row in original.iter().filter(|row| row["id"] != id) {
                assert!(updated.contains(row));
            }
        }
    }
    authenticated(&auth, &cookie, "social@example.com").await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn automatic_refresh_distinguishes_null_empty_response_and_persisted_tokens<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::{OAuthPlugin, oauth::GenericOAuthConfig};
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

    for endpoint in ["/get-access-token", "/account-info"] {
        for token in [Value::Null, json!("")] {
            let db = db.fresh().await?;
            let (connection, _) = db.migrated::<B>(SECRET).await?;
            let remote = Provider::start("application/json", "{}").await;
            remote.respond_at("/token",200,json!({"access_token":token,"refresh_token":"","id_token":"","expires_in":0,"refresh_token_expires_in":0}));
            remote.respond_at("/profile",200,json!({"id":"account-subject","email":"profile@example.test","name":"Profile","email_verified":true}));
            let mut config = GenericOAuthConfig::new("native-client", "native-secret");
            config.authorization_url = Some(remote.url.join("authorize")?.into());
            config.token_url = Some(remote.url.join("token")?.into());
            config.user_info_url = Some(remote.url.join("profile")?.into());
            let auth = super::auth_probe::fast_builder::<B>(&connection)
                .plugin(
                    OAuthPlugin::new()
                        .add_provider("generic", config.resolve().await?.unwrap().provider),
                )
                .build()
                .await?;
            let owner = signup(&auth, "refresh-boundary@example.test").await;
            let id = seed(&auth, body(&owner)["user"]["id"].as_str().unwrap()).await?;
            let protected = db.tables(&["users", "sessions"]).await?;
            let old_refresh_expiry = db
                .text(
                    "SELECT refresh_token_expires_at FROM accounts WHERE id=$1",
                    &[&id],
                )
                .await?;
            let input = if endpoint == "/get-access-token" {
                request(endpoint, Some(json!({"accountId":id})), &cookies(&owner))
            } else {
                let mut input = request(endpoint, None, &cookies(&owner));
                input.set_query_pairs([("accountId", id.as_str())]);
                input
            };
            let response = call(
                &auth,
                input,
                if endpoint == "/account-info" && token == json!("") {
                    400
                } else {
                    200
                },
            )
            .await;
            if endpoint == "/get-access-token" {
                assert_eq!(
                    body(&response)["accessToken"],
                    if token.is_null() {
                        json!("old-access")
                    } else {
                        token.clone()
                    }
                );
                assert_eq!(body(&response)["idToken"], "");
            } else if token.is_null() {
                assert_eq!(body(&response)["user"]["email"], "profile@example.test");
            } else {
                assert_eq!(body(&response)["code"], "ACCESS_TOKEN_NOT_FOUND");
            }
            assert_eq!(
                db.text("SELECT access_token FROM accounts WHERE id=$1", &[&id])
                    .await?,
                token.as_str().map(str::to_owned)
            );
            assert_eq!(
                db.text("SELECT refresh_token FROM accounts WHERE id=$1", &[&id])
                    .await?
                    .as_deref(),
                Some("old-refresh")
            );
            assert_eq!(
                db.text("SELECT id_token FROM accounts WHERE id=$1", &[&id])
                    .await?
                    .as_deref(),
                Some("old-id")
            );
            assert_eq!(
                db.text(
                    "SELECT refresh_token_expires_at FROM accounts WHERE id=$1",
                    &[&id]
                )
                .await?,
                old_refresh_expiry
            );
            assert_eq!(
                db.text("SELECT scope FROM accounts WHERE id=$1", &[&id])
                    .await?
                    .as_deref(),
                Some("calendar,drive")
            );
            assert_eq!(db.tables(&["users", "sessions"]).await?, protected);
            let exchanges = remote.take();
            assert_eq!(
                exchanges
                    .iter()
                    .filter(|exchange| exchange.path == "/token")
                    .count(),
                1
            );
            assert_eq!(
                exchanges
                    .iter()
                    .filter(|exchange| exchange.path == "/profile")
                    .count(),
                usize::from(endpoint == "/account-info" && token.is_null())
            );
            B::close(connection).await?;
        }
    }
    Ok(())
}

async fn corrupt_imported_oauth_ciphertexts_reject_before_transport_or_writes<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::{
        OAuthPlugin,
        oauth::{GenericOAuthConfig, encryption::encrypt_token},
    };
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

    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let remote = Provider::start("application/json", "{}").await;
    let mut config = GenericOAuthConfig::new("native-client", "native-secret");
    config.authorization_url = Some(remote.url.join("authorize")?.into());
    config.token_url = Some(remote.url.join("token")?.into());
    config.user_info_url = Some(remote.url.join("profile")?.into());
    let cfg = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .account(AccountConfig {
            encrypt_oauth_tokens: true,
            ..Default::default()
        });
    let auth = AuthBuilder::new(cfg.clone())
        .store(B::store(Arc::new(cfg), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(
            OAuthPlugin::new().add_provider("generic", config.resolve().await?.unwrap().provider),
        )
        .build()
        .await?;
    let owner = signup(&auth, "cipher-owner@example.test").await;
    let foreign = signup(&auth, "cipher-foreign@example.test").await;
    let id = seed(&auth, body(&owner)["user"]["id"].as_str().unwrap()).await?;
    db.set_timestamp(
        "accounts",
        "access_token_expires_at",
        ("id", &id),
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
    .await?;
    let valid = encrypt_token("imported-access", SECRET)?;
    let wrong = encrypt_token("imported-access", "wrong-key-material-at-least-32")?;
    let mut tampered = valid.clone();
    let replacement = if tampered.ends_with('0') { '1' } else { '0' };
    _ = tampered.pop();
    tampered.push(replacement);
    for (stored, expected) in [
        (valid.clone(), Some("imported-access")),
        (valid.to_uppercase(), Some("imported-access")),
        (wrong.clone(), None),
        (tampered.clone(), None),
        ("00".into(), None),
        ("legacy-plaintext".into(), Some("legacy-plaintext")),
        ("abc".into(), Some("abc")),
    ] {
        _ = db
            .execute(
                "UPDATE accounts SET access_token=$1 WHERE id=$2",
                &[&stored, &id],
            )
            .await?;
        let before = db.tables(&["users", "accounts", "sessions"]).await?;
        let response = call(
            &auth,
            request(
                "/get-access-token",
                Some(json!({"accountId":id})),
                &cookies(&owner),
            ),
            if expected.is_some() { 200 } else { 400 },
        )
        .await;
        if let Some(expected) = expected {
            assert_eq!(body(&response)["accessToken"], expected);
        } else {
            assert_eq!(body(&response)["code"], "FAILED_TO_GET_ACCESS_TOKEN");
        }
        assert!(remote.take().is_empty());
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    }
    for stored in [wrong, tampered, "00".into()] {
        _ = db
            .execute(
                "UPDATE accounts SET access_token=$1,refresh_token=$2 WHERE id=$3",
                &[&valid, &stored, &id],
            )
            .await?;
        let before = db.tables(&["users", "accounts", "sessions"]).await?;
        let rejected = call(
            &auth,
            request(
                "/refresh-token",
                Some(json!({"accountId":id})),
                &cookies(&owner),
            ),
            400,
        )
        .await;
        assert_eq!(body(&rejected)["code"], "FAILED_TO_REFRESH_ACCESS_TOKEN");
        assert!(remote.take().is_empty());
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    }
    authenticated(&auth, &cookies(&foreign), "cipher-foreign@example.test").await;
    B::close(connection).await
}
