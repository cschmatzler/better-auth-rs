//! Session cookie cache strategies, chunking, cleanup and managed JWT signing on both adapters.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "tests assert independently specified wire fields and fixtures"
)]
use super::*;
use alibi::config::{CookieAttributes, CookieOverride, OAuthStateStrategy};
use alibi::plugins::jwt::{JwtPlugin, JwtPluginConfig};
use alibi::plugins::user_management::{ChangeEmailConfig, UserManagementConfig};
use alibi::plugins::{TwoFactorPlugin, UserManagementPlugin};
use alibi::session::cookie_cache::runtime::published_session_snapshot;
use alibi::{
    AuthContext, AuthPlugin, AuthResult, AuthRoute, CookieCacheConfig, CookieCacheStrategy,
};
use async_trait::async_trait;

backend_tests!(
    every_strategy_serves_reads_from_the_cookie_and_rejects_tampering,
    oversized_cache_is_chunked_and_cleared_on_sign_out,
    sign_out_expires_account_and_oauth_state_cookies,
    browser_session_preference_and_zero_cache_age,
    managed_jwt_signer_issues_and_verifies_cache_tokens,
    update_user_refreshes_the_cache_and_invalid_sessions_clear_every_cookie_family,
    pending_factor_challenge_clears_cache_cookies_including_incoming_chunks,
    published_snapshot_exposes_public_views_to_response_hooks,
    verification_renews_original_cached_snapshot_and_publishes_it_to_later_hooks
);
postgres_tests!(
    every_strategy_serves_reads_from_the_cookie_and_rejects_tampering,
    oversized_cache_is_chunked_and_cleared_on_sign_out,
    sign_out_expires_account_and_oauth_state_cookies,
    browser_session_preference_and_zero_cache_age,
    managed_jwt_signer_issues_and_verifies_cache_tokens,
    update_user_refreshes_the_cache_and_invalid_sessions_clear_every_cookie_family,
    pending_factor_challenge_clears_cache_cookies_including_incoming_chunks,
    published_snapshot_exposes_public_views_to_response_hooks
);

fn cached<B: Backend>(
    connection: &B::Connection,
    strategy: CookieCacheStrategy,
    tweak: impl FnOnce(&mut AuthConfig),
) -> AuthBuilder<B::Schema> {
    let mut config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            strategy,
            ..Default::default()
        });
    tweak(&mut config);
    AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
}

fn names(response: &AuthResponse) -> Vec<String> {
    response
        .headers
        .get_all("set-cookie")
        .map(|cookie| cookie.split('=').next().unwrap().to_owned())
        .collect()
}

async fn every_strategy_serves_reads_from_the_cookie_and_rejects_tampering<B: Backend>(
    db: Db,
) -> TestResult {
    for (index, strategy) in [
        CookieCacheStrategy::Compact,
        CookieCacheStrategy::Jwt,
        CookieCacheStrategy::Jwe,
    ]
    .into_iter()
    .enumerate()
    {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = cached::<B>(&connection, strategy.clone(), |_| {})
            .build()
            .await?;
        let email = format!("cache-{index}@example.test");
        let issued = signup(&auth, &email).await;
        assert!(names(&issued).contains(&"better-auth.session_data".to_owned()));
        let jar = cookies(&issued);
        assert_eq!(db.execute("DELETE FROM sessions", &[]).await?, 1);
        let cached_read = call(&auth, request("/get-session", None, &jar), 200).await;
        assert_eq!(body(&cached_read)["user"]["email"], email, "{strategy:?}");

        let forged = jar
            .split("; ")
            .map(|pair| {
                if pair.starts_with("better-auth.session_data=") {
                    format!("{pair}x")
                } else {
                    pair.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        let rejected = call(&auth, request("/get-session", None, &forged), 200).await;
        assert_eq!(body(&rejected), Value::Null, "{strategy:?}");
    }
    Ok(())
}

async fn oversized_cache_is_chunked_and_cleared_on_sign_out<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = cached::<B>(&connection, CookieCacheStrategy::Compact, |_| {})
        .build()
        .await?;
    let name = "N".repeat(9000);
    let issued = call(
        &auth,
        request(
            "/sign-up/email",
            Some(json!({"email":"chunks@example.test","password":PASSWORD,"name":name})),
            "",
        ),
        200,
    )
    .await;
    let chunk_names: Vec<_> = names(&issued)
        .into_iter()
        .filter(|name| name.starts_with("better-auth.session_data."))
        .collect();
    assert!(chunk_names.len() >= 2, "{chunk_names:?}");
    assert!(!names(&issued).contains(&"better-auth.session_data".to_owned()));
    let jar = cookies(&issued);
    assert_eq!(db.execute("DELETE FROM sessions", &[]).await?, 1);
    let read = call(&auth, request("/get-session", None, &jar), 200).await;
    assert_eq!(body(&read)["user"]["name"], name);

    let signed_out = call(&auth, request("/sign-out", Some(json!({})), &jar), 200).await;
    let cleared = signed_out
        .headers
        .get_all("set-cookie")
        .filter(|cookie| cookie.contains("Max-Age=0"))
        .map(|cookie| cookie.split('=').next().unwrap().to_owned())
        .collect::<Vec<_>>();
    for chunk in &chunk_names {
        assert!(
            cleared.contains(chunk),
            "{chunk} not cleared in {cleared:?}"
        );
    }
    Ok(())
}

async fn sign_out_expires_account_and_oauth_state_cookies<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = cached::<B>(&connection, CookieCacheStrategy::Compact, |config| {
        config.account.store_account_cookie = true;
        config.account.store_state_strategy = OAuthStateStrategy::Cookie;
    })
    .build()
    .await?;
    let issued = signup(&auth, "signout@example.test").await;
    let jar = format!(
        "{}; better-auth.account_data.0=stale; better-auth.account_data.1=stale",
        cookies(&issued)
    );
    let signed_out = call(&auth, request("/sign-out", Some(json!({})), &jar), 200).await;
    let cleared: Vec<_> = signed_out
        .headers
        .get_all("set-cookie")
        .filter(|cookie| cookie.contains("Max-Age=0"))
        .map(|cookie| cookie.split('=').next().unwrap().to_owned())
        .collect();
    for expected in [
        "better-auth.session_token",
        "better-auth.session_data",
        "better-auth.account_data",
        "better-auth.account_data.0",
        "better-auth.account_data.1",
        "better-auth.oauth_state",
        "better-auth.dont_remember",
    ] {
        assert!(
            cleared.contains(&expected.to_owned()),
            "{expected} not cleared in {cleared:?}"
        );
    }
    Ok(())
}

async fn browser_session_preference_and_zero_cache_age<B: Backend>(db: Db) -> TestResult {
    for strategy in [CookieCacheStrategy::Compact, CookieCacheStrategy::Jwt] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = cached::<B>(&connection, strategy, |config| {
            drop(config.advanced.cookies.insert(
                "session_data".into(),
                CookieOverride {
                    name: None,
                    attributes: CookieAttributes {
                        max_age: Some(0.0),
                        ..Default::default()
                    },
                },
            ));
        })
        .build()
        .await?;
        let issued = signup(&auth, "browser@example.test").await;
        let cache_cookie = issued
            .headers
            .get_all("set-cookie")
            .find(|cookie| cookie.starts_with("better-auth.session_data="))
            .unwrap();
        assert!(cache_cookie.contains("Max-Age=0"), "{cache_cookie}");

        let signed_in = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({
                    "email":"browser@example.test",
                    "password":PASSWORD,
                    "rememberMe":false,
                })),
                "",
            ),
            200,
        )
        .await;
        let headers: Vec<_> = signed_in.headers.get_all("set-cookie").collect();
        assert!(
            headers
                .iter()
                .any(|cookie| cookie.starts_with("better-auth.dont_remember="))
        );
        assert!(
            headers
                .iter()
                .filter(|cookie| cookie.starts_with("better-auth.session_data="))
                .all(|cookie| !cookie.contains("Max-Age")),
            "{headers:?}"
        );
        authenticated(&auth, &cookies(&signed_in), "browser@example.test").await;
    }
    Ok(())
}

async fn managed_jwt_signer_issues_and_verifies_cache_tokens<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = cached::<B>(&connection, CookieCacheStrategy::Jwt, |_| {})
        .plugin(JwtPlugin::with_config(JwtPluginConfig {
            session_cookie_cache: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let issued = signup(&auth, "managed@example.test").await;
    let jar = cookies(&issued);
    let token = jar
        .split("; ")
        .find_map(|pair| pair.strip_prefix("better-auth.session_data="))
        .unwrap();
    let header = token.split('.').next().unwrap();
    let header: Value = serde_json::from_slice(&base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        header,
    )?)?;
    assert_eq!(header["typ"], "better-auth.session-cache+jwt");
    assert_eq!(db.count("jwks").await?, 1);
    assert_eq!(db.execute("DELETE FROM sessions", &[]).await?, 1);
    let read = call(&auth, request("/get-session", None, &jar), 200).await;
    assert_eq!(body(&read)["user"]["email"], "managed@example.test");

    let forged = jar.replace("better-auth.session_data=", "better-auth.session_data=AAAA");
    let rejected = call(&auth, request("/get-session", None, &forged), 200).await;
    assert_eq!(body(&rejected), Value::Null);
    Ok(())
}

fn cleared(response: &AuthResponse) -> Vec<String> {
    response
        .headers
        .get_all("set-cookie")
        .filter(|cookie| cookie.contains("Max-Age=0"))
        .map(|cookie| cookie.split('=').next().unwrap().to_owned())
        .collect()
}

fn merged(jar: &str, update: &str) -> String {
    let mut cookies = std::collections::BTreeMap::new();
    for pair in jar.split("; ").chain(update.split("; ")) {
        let (name, value) = pair.split_once('=').unwrap();
        let _ = cookies.insert(name, value);
    }
    cookies
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn without(jar: &str, name: &str) -> String {
    jar.split("; ")
        .filter(|pair| !pair.starts_with(&format!("{name}=")))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn update_user_refreshes_the_cache_and_invalid_sessions_clear_every_cookie_family<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = cached::<B>(&connection, CookieCacheStrategy::Compact, |config| {
        config.account.store_account_cookie = true;
        config.account.store_state_strategy = OAuthStateStrategy::Cookie;
    })
    .plugin(UserManagementPlugin::with_config(UserManagementConfig {
        change_email: ChangeEmailConfig {
            enabled: true,
            update_without_verification: true,
            ..Default::default()
        },
        ..Default::default()
    }))
    .build()
    .await?;
    let issued = signup(&auth, "update@example.test").await;
    let jar = cookies(&issued);
    let updated = call(
        &auth,
        request("/update-user", Some(json!({"name":"Renamed"})), &jar),
        200,
    )
    .await;
    assert!(names(&updated).contains(&"better-auth.session_data".to_owned()));
    let changed = call(
        &auth,
        request(
            "/change-email",
            Some(json!({"newEmail":"moved@example.test"})),
            &jar,
        ),
        200,
    )
    .await;
    assert!(names(&changed).contains(&"better-auth.session_data".to_owned()));
    let refreshed = merged(&jar, &cookies(&updated));
    let read = call(&auth, request("/get-session", None, &refreshed), 200).await;
    assert_eq!(body(&read)["user"]["name"], "Renamed");

    assert_eq!(db.execute("DELETE FROM sessions", &[]).await?, 1);
    let orphan = without(&jar, "better-auth.session_data");
    let rejected = call(&auth, request("/get-session", None, &orphan), 200).await;
    assert_eq!(body(&rejected), Value::Null);
    let cleared = cleared(&rejected);
    for expected in [
        "better-auth.session_token",
        "better-auth.session_data",
        "better-auth.account_data",
        "better-auth.oauth_state",
    ] {
        assert!(
            cleared.contains(&expected.to_owned()),
            "{expected} in {cleared:?}"
        );
    }
    Ok(())
}

async fn pending_factor_challenge_clears_cache_cookies_including_incoming_chunks<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = cached::<B>(&connection, CookieCacheStrategy::Compact, |config| {
        config.account.store_account_cookie = true;
        config.account.store_state_strategy = OAuthStateStrategy::Cookie;
    })
    .plugin(TwoFactorPlugin::new())
    .build()
    .await?;
    let owner = signup(&auth, "challenge@example.test").await;
    let enrollment = call(
        &auth,
        request(
            "/two-factor/enable",
            Some(json!({"password":PASSWORD})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let authenticator = totp_rs::Totp::from_url(body(&enrollment)["totpURI"].as_str().unwrap())?;
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":authenticator.generate_current().to_string()})),
            &cookies(&owner),
        ),
        200,
    )
    .await;

    let incoming =
        "better-auth.account_data.0=a; better-auth.account_data.1=b; better-auth.session_data.0=c";
    let challenge = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"challenge@example.test","password":PASSWORD})),
            incoming,
        ),
        200,
    )
    .await;
    assert_eq!(body(&challenge)["twoFactorRedirect"], true);
    let cleared = cleared(&challenge);
    for expected in [
        "better-auth.session_token",
        "better-auth.session_data",
        "better-auth.session_data.0",
        "better-auth.account_data",
        "better-auth.account_data.0",
        "better-auth.account_data.1",
        "better-auth.oauth_state",
    ] {
        assert!(
            cleared.contains(&expected.to_owned()),
            "{expected} in {cleared:?}"
        );
    }
    assert!(names(&challenge).contains(&"better-auth.two_factor".to_owned()));
    Ok(())
}

struct Observer(Arc<Mutex<Vec<Value>>>);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Observer {
    fn name(&self) -> &'static str {
        "snapshot-observer"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        _: &AuthContext<S>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        if let Some(snapshot) = published_session_snapshot(req) {
            self.0.lock().unwrap().push(json!({
                "email": snapshot.user().email,
                "token": snapshot.session().token,
                "userOutput": snapshot.user_output().is_some(),
                "sessionOutput": snapshot.session_output().is_some(),
            }));
        }
        Ok(response)
    }
}

async fn published_snapshot_exposes_public_views_to_response_hooks<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let auth = cached::<B>(&connection, CookieCacheStrategy::Compact, |_| {})
        .plugin(Observer(Arc::clone(&seen)))
        .build()
        .await?;
    let issued = signup(&auth, "observer@example.test").await;
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["email"], "observer@example.test");
    assert_eq!(seen[0]["token"], body(&issued)["token"]);
    Ok(())
}

async fn verification_renews_original_cached_snapshot_and_publishes_it_to_later_hooks<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    fn fast_cached<B: Backend>(
        connection: &B::Connection,
        strategy: CookieCacheStrategy,
        tweak: impl FnOnce(&mut AuthConfig),
    ) -> AuthBuilder<B::Schema> {
        let mut config = AuthConfig::new(SECRET)
            .base_url(ORIGIN)
            .session_cookie_cache(CookieCacheConfig {
                enabled: true,
                strategy,
                ..Default::default()
            });
        tweak(&mut config);
        AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
    }

    use alibi::plugins::{
        EmailVerificationConfig, EmailVerificationPlugin, MultiSessionPlugin, SendVerificationEmail,
    };
    use alibi::wire::UserView;
    struct Inbox(Mutex<Option<String>>);
    #[async_trait]
    impl SendVerificationEmail for Inbox {
        async fn send(&self, _: &UserView, _: &str, token: &str) -> AuthResult<()> {
            *self.0.lock().unwrap() = Some(token.into());
            Ok(())
        }
    }
    struct Publication(Arc<Mutex<Vec<Value>>>);
    #[async_trait]
    impl<S: AuthSchema> AuthPlugin<S> for Publication {
        fn name(&self) -> &'static str {
            "verified-cache-publication"
        }
        fn routes(&self) -> Vec<AuthRoute> {
            Vec::new()
        }
        async fn on_request(
            &self,
            _: &AuthRequest,
            _: &AuthContext<S>,
        ) -> AuthResult<Option<AuthResponse>> {
            Ok(None)
        }
        async fn after_request(
            &self,
            r: &AuthRequest,
            _: &AuthContext<S>,
            response: AuthResponse,
        ) -> AuthResult<AuthResponse> {
            if let Some(s) = published_session_snapshot(r) {
                self.0
                    .lock()
                    .unwrap()
                    .push(json!({"user":s.user(),"session":s.session()}));
            }
            Ok(response)
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let inbox = Arc::new(Inbox(Mutex::new(None)));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let auth = fast_cached::<B>(&connection, CookieCacheStrategy::Compact, |_| {})
        .plugin(EmailVerificationPlugin::with_config(
            EmailVerificationConfig {
                send_verification_email: Some(inbox.clone()),
                send_on_sign_up: Some(false),
                auto_sign_in_after_verification: true,
                ..Default::default()
            },
        ))
        .plugin(alibi::plugins::UserManagementPlugin::new())
        .plugin(MultiSessionPlugin::new())
        .plugin(Publication(seen.clone()))
        .build()
        .await?;
    let foreign = signup(&auth, "foreign@example.test").await;
    let baseline = db.tables(&["users", "accounts", "sessions"]).await?;
    let owner=call(&auth,request("/sign-up/email",Some(json!({"email":"owner@example.test","name":"Original Cached Name","password":PASSWORD})),""),200).await;
    let id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let jar = cookies(&owner)
        .split("; ")
        .filter(|x| !x.contains("_multi-"))
        .map(str::to_owned)
        .collect::<Vec<_>>()
        .join("; ");
    let original = body(&call(&auth, request("/get-session", None, &jar), 200).await);
    seen.lock().unwrap().clear();
    _ = call(
        &auth,
        request(
            "/send-verification-email",
            Some(json!({"email":"owner@example.test"})),
            &jar,
        ),
        200,
    )
    .await;
    let token = inbox.0.lock().unwrap().clone().unwrap();
    assert_eq!(
        db.execute(
            "UPDATE users SET name='Physical Later Name' WHERE id=$1",
            &[&id]
        )
        .await?,
        1
    );
    let before = db.tables(&["accounts", "sessions"]).await?;
    let mut proof = request("/verify-email", None, &jar);
    proof.set_query_pairs([("token", token.as_str())]);
    let verified = call(&auth, proof, 200).await;
    let value = cookies(&verified)
        .split("; ")
        .find_map(|p| {
            p.strip_prefix("better-auth.session_data=")
                .map(str::to_owned)
        })
        .unwrap();
    let decoded = alibi::session::cookie_cache::decode_compact(&value, SECRET).unwrap();
    let mut expected = original["user"].clone();
    expected["emailVerified"] = json!(true);
    assert_eq!(serde_json::to_value(&decoded.user)?, expected);
    assert_eq!(serde_json::to_value(&decoded.session)?, original["session"]);
    assert!(
        verified
            .headers
            .get_all("set-cookie")
            .any(|x| x.contains("_multi-") && !x.contains("Max-Age=0"))
    );
    let receipts = seen.lock().unwrap().clone();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["user"], expected);
    assert_eq!(receipts[0]["session"], original["session"]);
    assert_eq!(
        db.text("SELECT name FROM users WHERE id=$1", &[&id])
            .await?
            .as_deref(),
        Some("Physical Later Name")
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE id=$1 AND email_verified=true",
            &[&id]
        )
        .await?,
        1
    );
    assert_eq!(db.tables(&["accounts", "sessions"]).await?, before);
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    for (before, now) in baseline.iter().zip(after.iter()) {
        let before: Vec<Value> = serde_json::from_str(before)?;
        let now: Vec<Value> = serde_json::from_str(now)?;
        assert!(before.iter().all(|x| now.contains(x)));
    }
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}
