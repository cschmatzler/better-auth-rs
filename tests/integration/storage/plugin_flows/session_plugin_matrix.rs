//! Bearer headers, device-session limits, session management failures and
//! device-session projections.
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::custom_session::{CustomSessionPlugin, SessionTransform};
use alibi::plugins::multi_session::MultiSessionConfig;
use alibi::plugins::{BearerPlugin, MultiSessionPlugin};
use alibi::{AuthContext, AuthError, AuthResult, CookieCacheConfig, CookieCacheStrategy};
use std::collections::BTreeMap;

backend_tests!(
    bearer_authorization_matrix,
    multi_session_limits_and_revocation,
    session_management_failures,
    device_session_projection,
    multi_session_raw_capacity_controls_proofs_without_evicting_durable_sessions,
    multi_session_repeated_genuine_proofs_retire_before_fractional_capacity,
    multi_session_without_database_preserves_order_fallback_and_cache_replay_limits,
    parallel_sibling_revocation_retains_owned_deletes_after_rejection,
    bearer_browser_header_precedence,
    bearer_completed_issuance_header_receipt,
    bearer_configured_cookie_authority,
    bearer_real_hmac_padding_alias
);

fn merge(first: &str, second: &str) -> String {
    let mut jar = BTreeMap::new();
    for pair in first.split("; ").chain(second.split("; ")) {
        if let Some((name, value)) = pair.split_once('=') {
            if value.is_empty() {
                _ = jar.remove(name);
            } else {
                _ = jar.insert(name.to_owned(), value.to_owned());
            }
        }
    }
    jar.into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn builder_with<B: Backend>(
    connection: &B::Connection,
    config: AuthConfig,
) -> AuthBuilder<B::Schema> {
    AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(alibi::plugins::EmailPasswordPlugin::new())
}

fn raw(path: &str, text: &str, cookie: &str, content_type: &str) -> AuthRequest {
    let mut request = request(path, None, cookie);
    request.method = HttpMethod::Post;
    request.body = Some(text.as_bytes().to_vec());
    _ = request
        .headers
        .insert("content-type".into(), content_type.into());
    request
}

async fn bearer_authorization_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    for (label, require_signature) in [("signed only", true), ("signature optional", false)] {
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let auth = builder_with::<B>(&connection, config)
            .plugin(SessionManagementPlugin::new())
            .plugin(BearerPlugin::with_config(
                alibi::plugins::bearer::BearerConfig { require_signature },
            ))
            .build()
            .await?;
        let issued = signup(
            &auth,
            &format!("bearer-{}@example.com", label.replace(' ', "-")),
        )
        .await;
        let token = body(&issued)["token"].as_str().unwrap().to_owned();
        let signed = cookies(&issued)
            .split("; ")
            .find_map(|pair| {
                pair.strip_prefix("better-auth.session_token=")
                    .map(str::to_owned)
            })
            .unwrap();
        let decoded = signed
            .replace("%3D", "=")
            .replace("%2B", "+")
            .replace("%2F", "/");
        for (name, header) in [
            ("signed cookie value", format!("Bearer {signed}")),
            ("decoded signed value", format!("Bearer {decoded}")),
            ("lowercase scheme", format!("bearer {signed}")),
            ("padded token", format!("Bearer   {signed}  ")),
            ("unsigned token", format!("Bearer {token}")),
            ("empty token", "Bearer ".to_owned()),
            ("blank token", "Bearer    ".to_owned()),
            ("wrong scheme", format!("Basic {signed}")),
            ("no scheme", signed.clone()),
            ("malformed escape", format!("Bearer {token}.%zz")),
            ("tampered signature", format!("Bearer {token}.AAAA")),
            ("url-safe signature", format!("Bearer {token}.-_-_")),
            ("padded signature", format!("Bearer {token}.AAAA==")),
        ] {
            let mut read = request("/get-session", None, "");
            _ = read.headers.insert("authorization".into(), header);
            let response = Box::pin(auth.handle_request(read)).await?;
            trace.value(
                &format!("{label}: {name}"),
                json!({
                    "status": response.status,
                    "user": body(&response)["user"]["email"].is_string(),
                }),
            );
        }
    }
    trace.assert("session-plugins/bearer-matrix");
    B::close(connection).await
}

async fn multi_session_limits_and_revocation<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder_with::<B>(&connection, AuthConfig::new(SECRET).base_url(ORIGIN))
        .plugin(SessionManagementPlugin::new())
        .plugin(MultiSessionPlugin::with_config(MultiSessionConfig {
            maximum_sessions: 2.0,
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let mut jar = String::new();
    let mut tokens = Vec::new();
    for name in ["first", "second", "third"] {
        let response = call(
            &auth,
            request(
                "/sign-up/email",
                Some(json!({
                    "email": format!("device-{name}@example.com"),
                    "password": PASSWORD,
                    "name": name,
                })),
                &jar,
            ),
            200,
        )
        .await;
        tokens.push(body(&response)["token"].as_str().unwrap().to_owned());
        jar = merge(&jar, &cookies(&response));
        trace.value(
            &format!("device cookies after {name}"),
            json!(jar.matches("_multi-").count()),
        );
    }
    let listed = call(
        &auth,
        request("/multi-session/list-device-sessions", None, &jar),
        200,
    )
    .await;
    assert_eq!(body(&listed).as_array().unwrap().len(), 2);

    for (label, input) in [
        ("array body", json!([])),
        ("missing token", json!({})),
        ("numeric token", json!({"sessionToken": 5})),
        ("unknown device", json!({"sessionToken": "missing"})),
    ] {
        for path in ["/multi-session/set-active", "/multi-session/revoke"] {
            trace.response(
                &format!("{path} {label}"),
                &Box::pin(auth.handle_request(request(path, Some(input.clone()), &jar))).await?,
            );
        }
    }

    _ = signup(&auth, "device-fourth@example.com").await;
    let remembered = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email": "device-fourth@example.com", "password": PASSWORD, "rememberMe": false})),
            "",
        ),
        200,
    )
    .await;
    let dont_remember = cookies(&remembered)
        .split("; ")
        .find(|pair| pair.contains("dont_remember"))
        .unwrap()
        .to_owned();
    let remembering = merge(&jar, &dont_remember);
    let selected = call(
        &auth,
        request(
            "/multi-session/set-active",
            Some(json!({"sessionToken": tokens[0]})),
            &remembering,
        ),
        200,
    )
    .await;
    assert!(cookies(&selected).contains("dont_remember"));
    trace.response("select with remember-me proof", &selected);

    let active = merge(&jar, &cookies(&selected));
    let revoked = call(
        &auth,
        request(
            "/multi-session/revoke",
            Some(json!({"sessionToken": tokens[0]})),
            &active,
        ),
        200,
    )
    .await;
    trace.response("revoke the active device", &revoked);
    let rest = merge(&active, &cookies(&revoked));
    let revoked_second = call(
        &auth,
        request(
            "/multi-session/revoke",
            Some(json!({"sessionToken": tokens[1]})),
            &rest,
        ),
        200,
    )
    .await;
    trace.response("revoke the last active device", &revoked_second);
    let none_left = merge(&rest, &cookies(&revoked_second));
    trace.response(
        "list after revocation",
        &Box::pin(auth.handle_request(request(
            "/multi-session/list-device-sessions",
            None,
            &none_left,
        )))
        .await?,
    );
    trace.assert("session-plugins/multi-session-limits");
    B::close(connection).await
}

async fn session_management_failures<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            strategy: CookieCacheStrategy::Compact,
            ..Default::default()
        });
    let auth = builder_with::<B>(&connection, config)
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let mut trace = Trace::default();
    let owner = signup(&auth, "management@example.com").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let cookie = cookies(&owner);
    for (label, text, content_type) in [
        ("array", "[]", "application/json"),
        ("string", "\"text\"", "application/json"),
        ("number", "5", "application/json"),
        ("null", "null", "application/json"),
        ("invalid JSON", "{", "application/json"),
        ("wrong media type", "{}", "text/plain"),
    ] {
        trace.response(
            &format!("update-session {label}"),
            &Box::pin(auth.handle_request(raw("/update-session", text, &cookie, content_type)))
                .await?,
        );
    }
    for (path, text) in [
        ("/sign-out", "5"),
        ("/revoke-session", "[]"),
        ("/revoke-session", r#"{"token": 5}"#),
    ] {
        trace.response(
            &format!("{path} {text}"),
            &Box::pin(auth.handle_request(raw(path, text, &cookie, "application/json"))).await?,
        );
    }

    let other = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email": "management@example.com", "password": PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let other_token = body(&other)["token"].as_str().unwrap().to_owned();
    _ = db
        .execute(
            "CREATE TRIGGER fail_session_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, 'forced'); END",
            &[],
        )
        .await?;
    for (path, input) in [
        ("/revoke-other-sessions", json!({})),
        ("/revoke-sessions", json!({})),
        ("/revoke-session", json!({"token": other_token})),
    ] {
        trace.response(
            &format!("{path} storage failure"),
            &Box::pin(auth.handle_request(request(path, Some(input), &cookie))).await?,
        );
    }
    _ = db.execute("DROP TRIGGER fail_session_delete", &[]).await?;

    _ = db
        .execute("ALTER TABLE sessions RENAME TO sessions_unavailable", &[])
        .await?;
    trace.response(
        "list-sessions storage failure",
        &Box::pin(auth.handle_request(request("/list-sessions", None, &cookie))).await?,
    );
    _ = db
        .execute("ALTER TABLE sessions_unavailable RENAME TO sessions", &[])
        .await?;

    db.set_timestamp(
        "sessions",
        "created_at",
        ("user_id", &owner_id),
        chrono::Utc::now() - chrono::Duration::days(3),
    )
    .await?;
    let uncached = cookie
        .split("; ")
        .filter(|pair| pair.starts_with("better-auth.session_token="))
        .collect::<Vec<_>>()
        .join("; ");
    let fresh = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email": "management@example.com", "password": PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    trace.response(
        "list-sessions stale",
        &Box::pin(auth.handle_request(request("/list-sessions", None, &uncached))).await?,
    );
    trace.response(
        "list-sessions fresh",
        &Box::pin(auth.handle_request(request("/list-sessions", None, &cookies(&fresh)))).await?,
    );

    _ = db
        .execute(
            "DELETE FROM sessions WHERE token = $1",
            &[body(&owner)["token"].as_str().unwrap()],
        )
        .await?;
    trace.response(
        "sign-out of a vanished session",
        &Box::pin(auth.handle_request(request("/sign-out", Some(json!({})), &cookie))).await?,
    );
    trace.assert("session-plugins/management-failures");
    B::close(connection).await
}

struct Projection(Arc<Mutex<&'static str>>);

#[async_trait::async_trait]
impl<S: AuthSchema> SessionTransform<S> for Projection {
    async fn transform(
        &self,
        session: Value,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Value> {
        let mode = *self.0.lock().unwrap();
        match mode {
            "api" => Err(AuthError::Api {
                status: 418,
                code: Some("PROJECTION_DENIED".into()),
                message: "projection denied".into(),
            }),
            "internal" => Err(AuthError::internal("projection unavailable")),
            _ => Ok(json!({"email": session["user"]["email"], "projected": true})),
        }
    }
}

async fn device_session_projection<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mode = Arc::new(Mutex::new("ok"));
    let auth = builder_with::<B>(&connection, AuthConfig::new(SECRET).base_url(ORIGIN))
        .plugin(MultiSessionPlugin::new())
        .plugin(CustomSessionPlugin::new(Projection(mode.clone())).mutate_device_sessions(true))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let mut trace = Trace::default();
    let mut jar = String::new();
    for name in ["one", "two"] {
        let response = call(
            &auth,
            request(
                "/sign-up/email",
                Some(json!({"email": format!("projection-{name}@example.com"), "password": PASSWORD, "name": name})),
                &jar,
            ),
            200,
        )
        .await;
        jar = merge(&jar, &cookies(&response));
    }
    for name in ["ok", "api", "internal"] {
        *mode.lock().unwrap() = name;
        // Both sessions can share a creation instant, so their order is unspecified.
        let listed = Box::pin(auth.handle_request(request(
            "/multi-session/list-device-sessions",
            None,
            &jar,
        )))
        .await?;
        let mut sessions: Value = serde_json::from_slice(&listed.body).unwrap_or(Value::Null);
        if let Some(sessions) = sessions.as_array_mut() {
            sessions.sort_by_key(|session| session["email"].to_string());
        }
        trace.value(
            &format!("device sessions {name}"),
            json!({"status": listed.status, "body": sessions}),
        );
        trace.response(
            &format!("session {name}"),
            &Box::pin(auth.handle_request(request("/get-session", None, &jar))).await?,
        );
    }
    trace.response(
        "device sessions without a browser",
        &Box::pin(auth.handle_request(request("/multi-session/list-device-sessions", None, "")))
            .await?,
    );
    trace.assert("session-plugins/device-projection");
    B::close(connection).await
}

async fn multi_session_raw_capacity_controls_proofs_without_evicting_durable_sessions<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    for (capacity, expected) in [
        (0.0, 0),
        (1.5, 1),
        (-1.0, 0),
        (f64::NAN, 3),
        (f64::INFINITY, 3),
        (f64::NEG_INFINITY, 0),
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(MultiSessionPlugin::with_config(MultiSessionConfig {
                maximum_sessions: capacity,
            }))
            .build()
            .await?;
        let mut jar = String::new();
        let mut tokens = Vec::new();
        for index in 0..3 {
            let issued=call(&auth,request("/sign-up/email",Some(json!({"email":format!("owner-{index}@example.test"),"password":PASSWORD,"name":"Owner"})),&jar),200).await;
            tokens.push(body(&issued)["token"].as_str().unwrap().to_owned());
            jar = merge(&jar, &cookies(&issued));
        }
        assert_eq!(jar.matches("_multi-").count(), expected);
        let listed = body(
            &call(
                &auth,
                request("/multi-session/list-device-sessions", None, &jar),
                200,
            )
            .await,
        );
        assert_eq!(listed.as_array().unwrap().len(), expected);
        authenticated(&auth, &jar, "owner-2@example.test").await;
        assert_eq!(db.count("sessions").await?, 3);
        for token in &tokens {
            assert!(auth.store().get_session(token).await?.is_some());
        }
        let foreign = signup(&auth, "foreign@example.test").await;
        let before = db.table("sessions").await?;
        let denied = call(
            &auth,
            request(
                "/multi-session/set-active",
                Some(json!({"sessionToken":body(&foreign)["token"]})),
                &jar,
            ),
            401,
        )
        .await;
        assert_eq!(body(&denied)["code"], "INVALID_SESSION_TOKEN");
        let selected = call(
            &auth,
            request(
                "/multi-session/set-active",
                Some(json!({"sessionToken":tokens[0]})),
                &jar,
            ),
            if expected == 0 { 401 } else { 200 },
        )
        .await;
        if expected > 0 {
            assert_eq!(body(&selected)["session"]["token"], tokens[0]);
        }
        assert_eq!(db.table("sessions").await?, before);
        authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn multi_session_repeated_genuine_proofs_retire_before_fractional_capacity<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(MultiSessionPlugin::with_config(MultiSessionConfig {
            maximum_sessions: 1.5,
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let original = body(&owner)["token"].as_str().unwrap().to_owned();
    let proof = owner
        .headers
        .get_all("set-cookie")
        .find(|raw| raw.contains("_multi-"))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let (name, signed) = proof.split_once('=').unwrap();
    let alias = format!("another_multi-{original}={signed}");
    let issued = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"owner@example.test","password":PASSWORD})),
            &format!("{proof}; {alias}"),
        ),
        200,
    )
    .await;
    let current = body(&issued)["token"].as_str().unwrap().to_owned();
    assert_ne!(current, original);
    let retired: Vec<_> = issued
        .headers
        .get_all("set-cookie")
        .filter(|raw| raw.contains("_multi-") && raw.contains("Max-Age=0"))
        .collect();
    assert_eq!(retired.len(), 2);
    assert!(
        retired
            .iter()
            .any(|raw| raw.starts_with(&format!("{name}=")))
    );
    assert!(
        retired
            .iter()
            .any(|raw| raw.starts_with(&format!("another_multi-{original}=")))
    );
    let fresh: Vec<_> = issued
        .headers
        .get_all("set-cookie")
        .filter(|raw| raw.contains("_multi-") && !raw.contains("Max-Age=0"))
        .collect();
    assert_eq!(fresh.len(), 1);
    assert!(fresh[0].contains(&current));
    assert!(auth.store().get_session(&original).await?.is_none());
    assert_eq!(db.count("sessions").await?, 1);
    let selector = call(
        &auth,
        request(
            "/multi-session/set-active",
            Some(json!({"sessionToken":current})),
            fresh[0].split(';').next().unwrap(),
        ),
        200,
    )
    .await;
    assert_eq!(body(&selector)["session"]["token"], current);
    authenticated(&auth, &cookies(&selector), "owner@example.test").await;
    B::close(connection).await
}

async fn multi_session_without_database_preserves_order_fallback_and_cache_replay_limits<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    fn apply(jar: &str, response: &AuthResponse) -> String {
        let wire = response
            .headers
            .get_all("set-cookie")
            .map(|raw| raw.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        merge(jar, &wire)
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = AuthBuilder::without_database(
        AuthConfig::new(SECRET)
            .base_url(ORIGIN)
            .trusted_origin(ORIGIN),
    )
    .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
    .plugin(super::auth_probe::fast_password())
    .plugin(SessionManagementPlugin::new())
    .plugin(MultiSessionPlugin::new())
    .build()
    .await?;
    let mut jar = String::new();
    let mut tokens = Vec::new();
    for index in 0..3 {
        let issued=call(&auth,request("/sign-up/email",Some(json!({"email":format!("no-db-{index}@example.test"),"password":PASSWORD,"name":"Owner"})),&jar),200).await;
        tokens.push(body(&issued)["token"].as_str().unwrap().to_owned());
        assert!(cookies(&issued).contains("session_data="));
        jar = apply(&jar, &issued);
    }
    let foreign = signup(&auth, "foreign@example.test").await;
    let listed = body(
        &call(
            &auth,
            request("/multi-session/list-device-sessions", None, &jar),
            200,
        )
        .await,
    );
    let ordered: Vec<_> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["session"]["token"].as_str().unwrap())
        .collect();
    assert_eq!(
        ordered,
        tokens.iter().map(String::as_str).collect::<Vec<_>>()
    );
    _ = call(
        &auth,
        request(
            "/multi-session/set-active",
            Some(json!({"sessionToken":tokens[0]})),
            &cookies(&foreign),
        ),
        401,
    )
    .await;
    let selected = call(
        &auth,
        request(
            "/multi-session/set-active",
            Some(json!({"sessionToken":tokens[0]})),
            &jar,
        ),
        200,
    )
    .await;
    jar = apply(&jar, &selected);
    authenticated(&auth, &jar, "no-db-0@example.test").await;
    let revoked = call(
        &auth,
        request(
            "/multi-session/revoke",
            Some(json!({"sessionToken":tokens[0]})),
            &jar,
        ),
        200,
    )
    .await;
    jar = apply(&jar, &revoked);
    authenticated(&auth, &jar, "no-db-1@example.test").await;
    let captured = cookies(&revoked);
    let listed = body(
        &call(
            &auth,
            request("/multi-session/list-device-sessions", None, &jar),
            200,
        )
        .await,
    );
    assert_eq!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["session"]["token"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![tokens[1].as_str(), tokens[2].as_str()]
    );
    let logout = call(&auth, request("/sign-out", Some(json!({})), &jar), 200).await;
    jar = apply(&jar, &logout);
    let after_logout = body(&call(&auth, request("/get-session", None, &jar), 200).await);
    assert!(after_logout.is_null());
    assert_eq!(
        body(
            &call(
                &auth,
                request("/multi-session/list-device-sessions", None, &jar),
                200
            )
            .await
        ),
        json!([])
    );
    let replay = call(&auth, request("/get-session", None, &captured), 200).await;
    assert_eq!(body(&replay)["session"]["token"], tokens[1]);
    let mut physical = request("/get-session", None, &captured);
    _ = physical
        .query
        .insert("disableCookieCache".into(), "true".into());
    assert!(body(&call(&auth, physical, 200).await).is_null());
    _ = call(
        &auth,
        request(
            "/multi-session/set-active",
            Some(json!({"sessionToken":tokens[1]})),
            &captured,
        ),
        401,
    )
    .await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    for table in ["users", "accounts", "sessions"] {
        assert_eq!(db.count(table).await?, 0);
    }
    B::close(connection).await
}

async fn parallel_sibling_revocation_retains_owned_deletes_after_rejection<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::AuthSession;
    use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
    struct Gates {
        modes: Mutex<BTreeMap<String, usize>>,
        started: [tokio::sync::Notify; 3],
        held_release: tokio::sync::Notify,
        failure_release: tokio::sync::Notify,
        success_committed: tokio::sync::Notify,
        held_committed: tokio::sync::Notify,
    }
    struct Hooks(Arc<Gates>);
    #[async_trait::async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for Hooks {
        async fn before_delete_session(
            &self,
            session: &S::Session,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            let mode = self.0.modes.lock().unwrap().get(session.token()).copied();
            if let Some(mode) = mode {
                self.0.started[mode].notify_one();
                match mode {
                    0 => self.0.held_release.notified().await,
                    1 => {
                        self.0.failure_release.notified().await;
                        return Err(AuthError::internal("sibling application rejection"));
                    }
                    _ => {}
                }
            }
            Ok(HookControl::Continue)
        }
        async fn after_delete_session(
            &self,
            session: &S::Session,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<()> {
            match self.0.modes.lock().unwrap().get(session.token()).copied() {
                Some(0) => self.0.held_committed.notify_one(),
                Some(2) => self.0.success_committed.notify_one(),
                _ => {}
            }
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let gates = Arc::new(Gates {
        modes: Mutex::new(BTreeMap::new()),
        started: std::array::from_fn(|_| tokio::sync::Notify::new()),
        held_release: tokio::sync::Notify::new(),
        failure_release: tokio::sync::Notify::new(),
        success_committed: tokio::sync::Notify::new(),
        held_committed: tokio::sync::Notify::new(),
    });
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let store = B::hook(
        B::store(Arc::new(config.clone()), &connection),
        Hooks(gates.clone()),
    );
    let auth = Arc::new(
        AuthBuilder::new(config)
            .store(store)
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?,
    );
    let owner = signup(&auth, "parallel-owner@example.test").await;
    let foreign = signup(&auth, "parallel-foreign@example.test").await;
    let mut siblings = Vec::new();
    for mode in 0..3 {
        let response = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"parallel-owner@example.test","password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        let token = body(&response)["token"].as_str().unwrap().to_owned();
        let _ = gates.modes.lock().unwrap().insert(token.clone(), mode);
        siblings.push((token, cookies(&response)));
    }
    let input = request("/revoke-other-sessions", Some(json!({})), &cookies(&owner));
    let worker = auth.clone();
    let response = tokio::spawn(async move { call(&worker, input, 500).await });
    for started in &gates.started {
        tokio::time::timeout(std::time::Duration::from_secs(2), started.notified()).await?;
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        gates.success_committed.notified(),
    )
    .await?;
    gates.failure_release.notify_one();
    let rejected = tokio::time::timeout(std::time::Duration::from_secs(2), response).await??;
    assert!(!rejected.headers.contains_key("set-cookie"));
    assert_eq!(db.count("sessions").await?, 4);
    for (index, (token, _)) in siblings.iter().enumerate() {
        assert_eq!(
            db.count_where("SELECT COUNT(*) FROM sessions WHERE token = $1", &[token])
                .await?,
            i64::from(index != 2)
        );
    }
    gates.held_release.notify_one();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        gates.held_committed.notified(),
    )
    .await?;
    assert_eq!(db.count("sessions").await?, 3);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM sessions WHERE token = $1",
            &[&siblings[0].0]
        )
        .await?,
        0
    );
    authenticated(&auth, &siblings[1].1, "parallel-owner@example.test").await;
    authenticated(&auth, &cookies(&owner), "parallel-owner@example.test").await;
    authenticated(&auth, &cookies(&foreign), "parallel-foreign@example.test").await;
    Ok(())
}

async fn bearer_browser_header_precedence<B: Backend>(db: Db) -> TestResult {
    use alibi::plugins::bearer::BearerConfig;
    for signature_required in [false, true] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(BearerPlugin::with_config(BearerConfig {
                require_signature: signature_required,
            }))
            .build()
            .await?;
        let owner = signup(&auth, "header-owner@example.test").await;
        let foreign = signup(&auth, "header-foreign@example.test").await;
        let jar = cookies(&foreign);
        let own = cookies(&owner);
        let encoded = own
            .split("; ")
            .find_map(|v| v.strip_prefix("better-auth.session_token="))
            .unwrap();
        let query = format!("v={encoded}");
        let signed = url::form_urlencoded::parse(query.as_bytes())
            .next()
            .unwrap()
            .1
            .into_owned();
        let before = db.tables(&["users", "accounts", "sessions"]).await?;
        for route in ["/get-session", "/list-sessions"] {
            let mut input = request(route, None, &jar);
            _ = input
                .headers
                .insert("authorization".into(), format!("Bearer {signed}"));
            let response = call(&auth, input, 200).await;
            if route == "/get-session" {
                assert_eq!(body(&response)["user"]["id"], body(&owner)["user"]["id"]);
                assert_eq!(body(&response)["session"]["token"], body(&owner)["token"]);
            } else {
                let records = body(&response);
                let sessions = records.as_array().unwrap();
                assert_eq!(sessions.len(), 1);
                assert_eq!(sessions[0]["userId"], body(&owner)["user"]["id"]);
                assert_eq!(sessions[0]["token"], body(&owner)["token"]);
            }
        }
        let mut rejected = request("/get-session", None, &jar);
        _ = rejected.headers.insert(
            "authorization".into(),
            format!("Bearer {}.invalid", body(&owner)["token"].as_str().unwrap()),
        );
        let fallback = call(&auth, rejected, 200).await;
        assert_eq!(body(&fallback)["user"]["id"], body(&foreign)["user"]["id"]);
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
        let mut logout = request("/sign-out", Some(json!({})), &jar);
        _ = logout
            .headers
            .insert("authorization".into(), format!("Bearer {signed}"));
        _ = call(&auth, logout, 200).await;
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM sessions WHERE token=$1",
                &[body(&owner)["token"].as_str().unwrap()]
            )
            .await?,
            0
        );
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM sessions WHERE token=$1",
                &[body(&foreign)["token"].as_str().unwrap()]
            )
            .await?,
            1
        );
        assert_eq!(db.tables(&["users", "accounts"]).await?, before[..2]);
        authenticated(&auth, &jar, "header-foreign@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn bearer_completed_issuance_header_receipt<B: Backend>(db: Db) -> TestResult {
    struct Exposure;
    #[async_trait::async_trait]
    impl<S: AuthSchema> alibi::AuthPlugin<S> for Exposure {
        async fn on_request(
            &self,
            _: &AuthRequest,
            _: &alibi::AuthContext<S>,
        ) -> AuthResult<Option<AuthResponse>> {
            Ok(None)
        }
        fn name(&self) -> &'static str {
            "application-exposure"
        }
        fn routes(&self) -> Vec<alibi::AuthRoute> {
            Vec::new()
        }
        async fn after_request(
            &self,
            _: &AuthRequest,
            _: &AuthContext<S>,
            mut response: AuthResponse,
        ) -> AuthResult<AuthResponse> {
            _ = response.headers.insert(
                "access-control-expose-headers",
                "X-First, X-First, X-Second",
            );
            Ok(response)
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(Exposure)
        .plugin(BearerPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "receipt-owner@example.test").await;
    let signed = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"receipt-owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    for response in [&owner, &signed] {
        let raw = response
            .headers
            .get_all("set-cookie")
            .filter(|v| v.starts_with("better-auth.session_token=") && !v.contains("Max-Age=0"))
            .last()
            .unwrap();
        let encoded = raw.split(';').next().unwrap().split_once('=').unwrap().1;
        let query = format!("v={encoded}");
        let value = url::form_urlencoded::parse(query.as_bytes())
            .next()
            .unwrap()
            .1
            .into_owned();
        assert_eq!(response.headers.get("set-auth-token"), Some(&value));
        assert_ne!(value, body(response)["token"].as_str().unwrap());
        assert!(value.starts_with(&format!("{}.", body(response)["token"].as_str().unwrap())));
        assert_eq!(
            response
                .headers
                .get("access-control-expose-headers")
                .map(String::as_str),
            Some("X-First, X-Second, set-auth-token")
        );
        let mut read = request("/get-session", None, "");
        _ = read
            .headers
            .insert("authorization".into(), format!("Bearer {value}"));
        let actual = call(&auth, read, 200).await;
        assert_eq!(body(&actual)["session"]["token"], body(response)["token"]);
        assert_eq!(body(&actual)["user"]["id"], body(response)["user"]["id"]);
    }
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let failed = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"receipt-owner@example.test","password":"incorrect-password"})),
            "",
        ),
        401,
    )
    .await;
    assert!(!failed.headers.contains_key("set-auth-token"));
    assert_eq!(
        failed
            .headers
            .get("access-control-expose-headers")
            .map(String::as_str),
        Some("X-First, X-First, X-Second")
    );
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let logout = call(
        &auth,
        request("/sign-out", Some(json!({})), &cookies(&signed)),
        200,
    )
    .await;
    assert!(!logout.headers.contains_key("set-auth-token"));
    assert_eq!(
        logout
            .headers
            .get("access-control-expose-headers")
            .map(String::as_str),
        Some("X-First, X-First, X-Second")
    );
    authenticated(&auth, &cookies(&owner), "receipt-owner@example.test").await;
    B::close(connection).await
}

async fn bearer_configured_cookie_authority<B: Backend>(db: Db) -> TestResult {
    use alibi::config::CookieOverride;
    for secure in [false, true] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let name = if secure {
            config.advanced.use_secure_cookies = Some(true);
            config.advanced.cookie_prefix = Some("bearer-app".into());
            "__Secure-bearer-app.session_token"
        } else {
            _ = config.advanced.cookies.insert(
                "session_token".into(),
                CookieOverride {
                    name: Some("configured-bearer-token".into()),
                    attributes: Default::default(),
                },
            );
            "configured-bearer-token"
        };
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(BearerPlugin::new())
            .build()
            .await?;
        let owner = signup(&auth, "named-header-owner@example.test").await;
        let foreign = signup(&auth, "named-header-foreign@example.test").await;
        let jar = cookies(&owner);
        assert_eq!(
            owner
                .headers
                .get_all("set-cookie")
                .filter(|v| v.starts_with(&format!("{name}=")))
                .count(),
            1
        );
        assert!(
            !owner
                .headers
                .get_all("set-cookie")
                .any(|v| v.starts_with("better-auth.session_token="))
        );
        let encoded = jar
            .split("; ")
            .find_map(|v| v.strip_prefix(&format!("{name}=")))
            .unwrap();
        let query = format!("v={encoded}");
        let signed = url::form_urlencoded::parse(query.as_bytes())
            .next()
            .unwrap()
            .1
            .into_owned();
        assert_eq!(owner.headers.get("set-auth-token"), Some(&signed));
        authenticated(&auth, &jar, "named-header-owner@example.test").await;
        let before = db.tables(&["users", "accounts", "sessions"]).await?;
        for token in [body(&owner)["token"].as_str().unwrap(), signed.as_str()] {
            let mut input = request("/get-session", None, &cookies(&foreign));
            _ = input
                .headers
                .insert("authorization".into(), format!("Bearer {token}"));
            let read = call(&auth, input, 200).await;
            assert_eq!(body(&read)["session"]["token"], body(&owner)["token"]);
            assert_eq!(body(&read)["user"]["id"], body(&owner)["user"]["id"]);
        }
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
        let mut input = request("/sign-out", Some(json!({})), &cookies(&foreign));
        _ = input
            .headers
            .insert("authorization".into(), format!("Bearer {signed}"));
        let logout = call(&auth, input, 200).await;
        assert!(
            logout
                .headers
                .get_all("set-cookie")
                .any(|v| v.starts_with(&format!("{name}=")) && v.contains("Max-Age=0"))
        );
        assert!(!logout.headers.contains_key("set-auth-token"));
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM sessions WHERE token=$1",
                &[body(&owner)["token"].as_str().unwrap()]
            )
            .await?,
            0
        );
        authenticated(
            &auth,
            &cookies(&foreign),
            "named-header-foreign@example.test",
        )
        .await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn bearer_real_hmac_padding_alias<B: Backend>(db: Db) -> TestResult {
    use alibi::plugins::bearer::BearerConfig;
    use base64::{
        Engine, alphabet,
        engine::{GeneralPurpose, GeneralPurposeConfig},
    };
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(BearerPlugin::with_config(BearerConfig {
            require_signature: true,
        }))
        .build()
        .await?;
    let owner = signup(&auth, "padding-owner@example.test").await;
    let foreign = signup(&auth, "padding-foreign@example.test").await;
    let jar = cookies(&owner);
    let encoded = jar
        .split("; ")
        .find_map(|v| v.strip_prefix("better-auth.session_token="))
        .unwrap();
    let query = format!("v={encoded}");
    let signed = url::form_urlencoded::parse(query.as_bytes())
        .next()
        .unwrap()
        .1
        .into_owned();
    let (payload, signature) = signed.rsplit_once('.').unwrap();
    assert!(signature.ends_with('='));
    let alphabet_bytes = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut chars = signature.as_bytes().to_vec();
    let position = chars.len() - 2;
    let index = alphabet_bytes
        .iter()
        .position(|c| *c == chars[position])
        .unwrap();
    chars[position] = alphabet_bytes[index ^ 1];
    let alias = String::from_utf8(chars.clone())?;
    let engine = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    assert_eq!(engine.decode(&alias)?, engine.decode(signature)?);
    chars[position] = alphabet_bytes[index ^ 4];
    let corrupt = String::from_utf8(chars)?;
    assert_ne!(engine.decode(&corrupt)?, engine.decode(signature)?);
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    for (value, cookie, expected) in [
        (alias.as_str(), String::new(), Some(&owner)),
        (alias.as_str(), cookies(&foreign), Some(&owner)),
        (corrupt.as_str(), cookies(&foreign), Some(&foreign)),
        (corrupt.as_str(), String::new(), None),
    ] {
        let mut input = request("/get-session", None, &cookie);
        _ = input
            .headers
            .insert("authorization".into(), format!("Bearer {payload}.{value}"));
        let response = call(&auth, input, 200).await;
        if let Some(expected) = expected {
            assert_eq!(body(&response)["session"]["token"], body(expected)["token"]);
            assert_eq!(body(&response)["user"]["id"], body(expected)["user"]["id"]);
        } else {
            assert_eq!(body(&response), Value::Null);
        }
    }
    let mut list = request("/list-sessions", None, &cookies(&foreign));
    _ = list
        .headers
        .insert("authorization".into(), format!("Bearer {payload}.{alias}"));
    let response = call(&auth, list, 200).await;
    assert_eq!(
        body(&response)
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["userId"].clone())
            .collect::<Vec<_>>(),
        [body(&owner)["user"]["id"].clone()]
    );
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    B::close(connection).await
}
