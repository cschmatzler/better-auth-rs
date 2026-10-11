//! Anonymous identity generation, remember-me sessions, account linking and
//! storage failures.
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::AnonymousPlugin;
use alibi::plugins::anonymous::{
    AnonymousConfig, AnonymousIdentity, AnonymousLink, LinkAnonymousAccount,
};
use alibi::store::{DatabaseHookContext, DatabaseHooks, HookControl};
use alibi::{AuthResult, CreateSession, CreateUser};
use std::collections::BTreeMap;

backend_tests!(
    anonymous_identity_and_lifecycle,
    anonymous_creation_failures,
    anonymous_deletion_and_linking,
    anonymous_transfer_uses_original_completed_snapshot,
    anonymous_transfer_failure_preserves_committed_login,
    anonymous_database_hook_errors_preserve_stage_commit,
    anonymous_issuance_ignores_tampered_browser_preference,
    anonymous_transfer_retains_cached_old_projection_and_new_completed_owner,
    anonymous_passwordless_completion_paths_transfer_actual_owner
);

#[derive(Default)]
struct Identity(Mutex<Option<String>>);

#[async_trait::async_trait]
impl AnonymousIdentity for Identity {
    async fn email(&self) -> AuthResult<Option<String>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[derive(Default)]
struct Linker(Mutex<Vec<(String, String)>>);

#[async_trait::async_trait]
impl LinkAnonymousAccount for Linker {
    async fn link(&self, accounts: &AnonymousLink, _: &AuthRequest) -> AuthResult<()> {
        self.0.lock().unwrap().push((
            accounts.anonymous_user.id.clone(),
            accounts.new_user.id.clone(),
        ));
        assert_eq!(accounts.new_session.user_id, accounts.new_user.id);
        Ok(())
    }
}

#[derive(Default)]
struct Cancel {
    users: Mutex<bool>,
    sessions: Mutex<bool>,
}

#[async_trait::async_trait]
impl<S: AuthSchema, B: alibi::store::HookBackend> DatabaseHooks<S, B> for Cancel {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        _: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(
            if *self.users.lock().unwrap() && user.is_anonymous == Some(true) {
                HookControl::Cancel
            } else {
                HookControl::Continue
            },
        )
    }
    async fn before_create_session(
        &self,
        _: &mut CreateSession,
        _: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(if *self.sessions.lock().unwrap() {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }
}

fn merge(first: &str, second: &str) -> String {
    let mut jar = BTreeMap::new();
    for pair in first.split("; ").chain(second.split("; ")) {
        if let Some((name, value)) = pair.split_once('=') {
            _ = jar.insert(name.to_owned(), value.to_owned());
        }
    }
    jar.into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn trigger(db: &Db, name: &str, event: &str, table: &str) -> TestResult {
    _ = db
        .execute(
            &format!("CREATE TRIGGER {name} BEFORE {event} ON {table} BEGIN SELECT RAISE(ABORT, 'forced'); END"),
            &[],
        )
        .await?;
    Ok(())
}

async fn anonymous_identity_and_lifecycle<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let identity = Arc::new(Identity::default());
    let auth = builder::<B>(&connection)
        .plugin(AnonymousPlugin::with_config(AnonymousConfig {
            identity: Some(identity.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    for (label, email) in [
        ("malformed generated email", Some("not-an-email")),
        ("generated email", Some("generated-anonymous@example.test")),
        ("default email", None),
    ] {
        *identity.0.lock().unwrap() = email.map(str::to_owned);
        let response =
            Box::pin(auth.handle_request(request("/sign-in/anonymous", Some(json!({})), "")))
                .await?;
        trace.response(label, &response);
        trace.value(
            &format!("{label} user"),
            json!(
                body(&response)["user"]["email"].as_str().map(|email| email
                    .rsplit('@')
                    .next()
                    .unwrap()
                    .to_owned())
            ),
        );
        if response.status == 200 {
            let current = cookies(&response);
            trace.response(
                &format!("{label}: second anonymous sign-in"),
                &Box::pin(auth.handle_request(request(
                    "/sign-in/anonymous",
                    Some(json!({})),
                    &current,
                )))
                .await?,
            );
        }
    }

    let remembered = call(
        &auth,
        request(
            "/sign-up/email",
            Some(json!({"email": "remembered@example.test", "password": PASSWORD, "name": "R"})),
            "",
        ),
        200,
    )
    .await;
    _ = remembered;
    let device = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email": "remembered@example.test", "password": PASSWORD, "rememberMe": false})),
            "",
        ),
        200,
    )
    .await;
    let from_remembered = Box::pin(auth.handle_request(request(
        "/sign-in/anonymous",
        Some(json!({})),
        &cookies(&device),
    )))
    .await?;
    trace.response("anonymous from a remember-me browser", &from_remembered);
    assert!(cookies(&from_remembered).contains("dont_remember"));
    trace.assert("anonymous/identity-and-lifecycle");
    B::close(connection).await
}

async fn anonymous_creation_failures<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let cancel = Arc::new(Cancel::default());
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let store = B::hook(
        B::store(Arc::new(config.clone()), &connection),
        SharedCancel(cancel.clone()),
    );
    let auth = AuthBuilder::new(config)
        .store(store)
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(alibi::plugins::EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(AnonymousPlugin::new())
        .build()
        .await?;
    let mut trace = Trace::default();
    let anonymous = || request("/sign-in/anonymous", Some(json!({})), "");
    *cancel.users.lock().unwrap() = true;
    trace.response(
        "user creation cancelled",
        &Box::pin(auth.handle_request(anonymous())).await?,
    );
    *cancel.users.lock().unwrap() = false;
    *cancel.sessions.lock().unwrap() = true;
    trace.response(
        "session creation cancelled",
        &Box::pin(auth.handle_request(anonymous())).await?,
    );
    *cancel.sessions.lock().unwrap() = false;
    trigger(&db, "fail_user_insert", "INSERT", "users").await?;
    trace.response(
        "user storage failure",
        &Box::pin(auth.handle_request(anonymous())).await?,
    );
    _ = db.execute("DROP TRIGGER fail_user_insert", &[]).await?;
    trigger(&db, "fail_session_insert", "INSERT", "sessions").await?;
    trace.response(
        "session storage failure",
        &Box::pin(auth.handle_request(anonymous())).await?,
    );
    _ = db.execute("DROP TRIGGER fail_session_insert", &[]).await?;
    trace.value("users left", json!(db.count("users").await?));
    trace.assert("anonymous/creation-failures");
    B::close(connection).await
}

struct SharedCancel(Arc<Cancel>);

#[async_trait::async_trait]
impl<S: AuthSchema, B: alibi::store::HookBackend> DatabaseHooks<S, B> for SharedCancel {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        DatabaseHooks::<S, B>::before_create_user(&*self.0, user, context).await
    }
    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        DatabaseHooks::<S, B>::before_create_session(&*self.0, session, context).await
    }
}

async fn anonymous_deletion_and_linking<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let linker = Arc::new(Linker::default());
    let enabled = builder::<B>(&connection)
        .plugin(AnonymousPlugin::with_config(AnonymousConfig {
            on_link_account: Some(linker.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let anonymous = call(
        &enabled,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    let anonymous_id = body(&anonymous)["user"]["id"].as_str().unwrap().to_owned();
    trace.mask(&anonymous_id);
    let linked = Box::pin(enabled.handle_request(request(
        "/sign-up/email",
        Some(json!({"email": "linked@example.test", "password": PASSWORD, "name": "Linked"})),
        &cookies(&anonymous),
    )))
    .await?;
    trace.response("upgrade by sign-up", &linked);
    assert_eq!(linker.0.lock().unwrap().len(), 1);
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM users WHERE is_anonymous = 1", &[])
            .await?,
        0
    );
    let regular = cookies(&linked);
    trace.response(
        "delete as a regular user",
        &Box::pin(enabled.handle_request(request(
            "/delete-anonymous-user",
            Some(json!({})),
            &regular,
        )))
        .await?,
    );
    trace.response(
        "delete without a session",
        &Box::pin(enabled.handle_request(request("/delete-anonymous-user", Some(json!({})), "")))
            .await?,
    );

    let second = call(
        &enabled,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    trigger(&db, "fail_session_delete", "DELETE", "sessions").await?;
    trace.response(
        "session cleanup failure",
        &Box::pin(enabled.handle_request(request(
            "/delete-anonymous-user",
            Some(json!({})),
            &cookies(&second),
        )))
        .await?,
    );
    _ = db.execute("DROP TRIGGER fail_session_delete", &[]).await?;
    let third = call(
        &enabled,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    trigger(&db, "fail_user_delete", "DELETE", "users").await?;
    trace.response(
        "user cleanup failure",
        &Box::pin(enabled.handle_request(request(
            "/delete-anonymous-user",
            Some(json!({})),
            &cookies(&third),
        )))
        .await?,
    );
    let upgraded = Box::pin(enabled.handle_request(request(
        "/sign-up/email",
        Some(json!({"email": "undeletable@example.test", "password": PASSWORD, "name": "U"})),
        &cookies(&third),
    )))
    .await?;
    trace.response("upgrade with cleanup failure", &upgraded);
    _ = db.execute("DROP TRIGGER fail_user_delete", &[]).await?;
    let fourth = call(
        &enabled,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    trace.response(
        "delete anonymous",
        &Box::pin(enabled.handle_request(request(
            "/delete-anonymous-user",
            Some(json!({})),
            &cookies(&fourth),
        )))
        .await?,
    );

    let fresh = db.fresh().await?;
    let (disabled_connection, _) = fresh.migrated::<B>(SECRET).await?;
    let disabled = builder::<B>(&disabled_connection)
        .plugin(AnonymousPlugin::with_config(AnonymousConfig {
            disable_delete_anonymous_user: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let kept = call(
        &disabled,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    trace.response(
        "deletion disabled",
        &Box::pin(disabled.handle_request(request(
            "/delete-anonymous-user",
            Some(json!({})),
            &cookies(&kept),
        )))
        .await?,
    );
    let merged = Box::pin(disabled.handle_request(request(
        "/sign-up/email",
        Some(json!({"email": "kept@example.test", "password": PASSWORD, "name": "K"})),
        &merge("", &cookies(&kept)),
    )))
    .await?;
    trace.response("upgrade keeps the anonymous user", &merged);
    B::close(disabled_connection).await?;
    trace.assert("anonymous/deletion-and-linking");
    B::close(connection).await
}

async fn anonymous_transfer_uses_original_completed_snapshot<B: Backend>(db: Db) -> TestResult {
    use alibi::AuthSession;
    struct Hook(crate::storage::Raw);
    #[async_trait::async_trait]
    impl<S: AuthSchema, H: alibi::store::HookBackend> DatabaseHooks<S, H> for Hook {
        async fn after_create_session(
            &self,
            session: &S::Session,
            context: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<()> {
            if context
                .request
                .as_ref()
                .is_some_and(|request| request.path.ends_with("/sign-up/email"))
            {
                _ = self
                    .0
                    .execute(
                        "UPDATE users SET name='Stored Hook Name' WHERE id=$1",
                        &[session.user_id().as_ref()],
                    )
                    .await
                    .map_err(|error| alibi::AuthError::internal(error.to_string()))?;
            }
            Ok(())
        }
    }
    struct Capture(Mutex<Vec<Value>>);
    #[async_trait::async_trait]
    impl LinkAnonymousAccount for Capture {
        async fn link(&self, link: &AnonymousLink, request: &AuthRequest) -> AuthResult<()> {
            self.0.lock().unwrap().push(json!({"anonymousUser":link.anonymous_user,"anonymousSession":link.anonymous_session,"newUser":link.new_user,"newSession":link.new_session,"path":request.path}));
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let linker = Arc::new(Capture(Mutex::new(Vec::new())));
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .store(B::hook(
            B::store(
                Arc::new(AuthConfig::new(SECRET).base_url(ORIGIN)),
                &connection,
            ),
            Hook(db.raw.clone()),
        ))
        .plugin(AnonymousPlugin::with_config(AnonymousConfig {
            on_link_account: Some(linker.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let foreign = signup(&auth, "foreign@example.test").await;
    let baseline = db.tables(&["users", "accounts", "sessions"]).await?;
    let anonymous = call(
        &auth,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    let original = body(
        &call(
            &auth,
            request("/get-session", None, &cookies(&anonymous)),
            200,
        )
        .await,
    );
    let upgrade=call(&auth,request("/sign-up/email",Some(json!({"email":"upgrade@example.test","password":PASSWORD,"name":"Original New Owner"})),&cookies(&anonymous)),200).await;
    assert_eq!(body(&upgrade)["user"]["name"], "Original New Owner");
    let receipts = linker.0.lock().unwrap().clone();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["anonymousUser"], original["user"]);
    assert_eq!(receipts[0]["anonymousSession"], original["session"]);
    assert_eq!(receipts[0]["newUser"], body(&upgrade)["user"]);
    assert_eq!(receipts[0]["newSession"]["token"], body(&upgrade)["token"]);
    assert_eq!(
        receipts[0]["newSession"]["userId"],
        body(&upgrade)["user"]["id"]
    );
    assert!(
        receipts[0]["path"]
            .as_str()
            .unwrap()
            .ends_with("/sign-up/email")
    );
    let old_id = body(&anonymous)["user"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM users WHERE id=$1", &[&old_id])
            .await?,
        0
    );
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM sessions WHERE user_id=$1", &[&old_id])
            .await?,
        0
    );
    let current = body(
        &call(
            &auth,
            request("/get-session", None, &cookies(&upgrade)),
            200,
        )
        .await,
    );
    assert_eq!(current["user"]["id"], body(&upgrade)["user"]["id"]);
    assert_eq!(current["user"]["name"], "Stored Hook Name");
    assert_eq!(current["session"]["token"], body(&upgrade)["token"]);
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    for (before, after) in baseline.iter().zip(after.iter()) {
        let before: Vec<Value> = serde_json::from_str(before)?;
        let after: Vec<Value> = serde_json::from_str(after)?;
        assert!(before.iter().all(|row| after.contains(row)));
    }
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn anonymous_transfer_failure_preserves_committed_login<B: Backend>(db: Db) -> TestResult {
    struct Reject {
        mode: usize,
        seen: Mutex<Vec<Value>>,
    }
    #[async_trait::async_trait]
    impl LinkAnonymousAccount for Reject {
        async fn link(&self, link: &AnonymousLink, _: &AuthRequest) -> AuthResult<()> {
            self.seen.lock().unwrap().push(json!({"oldUser":link.anonymous_user,"oldSession":link.anonymous_session,"newUser":link.new_user,"newSession":link.new_session}));
            Err(if self.mode == 0 {
                alibi::AuthError::internal("Configured anonymous transfer denied")
            } else {
                alibi::AuthError::Api {
                    status: 403,
                    code: (self.mode == 2).then(|| "APPLICATION_LINK_DENIED".into()),
                    message: "Configured anonymous transfer denied".into(),
                }
            })
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for mode in 0..3 {
        let linker = Arc::new(Reject {
            mode,
            seen: Mutex::new(Vec::new()),
        });
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(AnonymousPlugin::with_config(AnonymousConfig {
                on_link_account: Some(linker.clone()),
                ..Default::default()
            }))
            .build()
            .await?;
        let email = format!("owner-{mode}@example.test");
        let regular = signup(&auth, &email).await;
        let foreign_email = format!("foreign-{mode}@example.test");
        let foreign = signup(&auth, &foreign_email).await;
        let anonymous = call(
            &auth,
            request("/sign-in/anonymous", Some(json!({})), ""),
            200,
        )
        .await;
        let original = body(
            &call(
                &auth,
                request("/get-session", None, &cookies(&anonymous)),
                200,
            )
            .await,
        );
        let before = db.tables(&["users", "accounts", "sessions"]).await?;
        _ = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":email,"password":"wrong-password"})),
                &cookies(&anonymous),
            ),
            401,
        )
        .await;
        assert!(linker.seen.lock().unwrap().is_empty());
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
        let error = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":email,"password":PASSWORD})),
                &cookies(&anonymous),
            ),
            if mode == 0 { 500 } else { 403 },
        )
        .await;
        if mode == 0 {
            assert!(error.body.is_empty());
        } else {
            let expected = if mode == 1 {
                json!({"message":"Configured anonymous transfer denied"})
            } else {
                json!({"code":"APPLICATION_LINK_DENIED","message":"Configured anonymous transfer denied"})
            };
            assert_eq!(body(&error), expected);
        }
        let seen = linker.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0]["oldUser"], original["user"]);
        assert_eq!(seen[0]["oldSession"], original["session"]);
        assert_eq!(seen[0]["newUser"]["id"], body(&regular)["user"]["id"]);
        assert_eq!(db.tables(&["users", "accounts"]).await?, before[..2]);
        let old: Vec<Value> = serde_json::from_str(&before[2])?;
        let new: Vec<Value> = serde_json::from_str(&db.table("sessions").await?)?;
        assert_eq!(new.len(), old.len() + 1);
        assert!(old.iter().all(|row| new.contains(row)));
        let committed = new
            .iter()
            .find(|row| row["token"] == seen[0]["newSession"]["token"])
            .unwrap();
        assert_eq!(committed["user_id"], body(&regular)["user"]["id"]);
        assert_eq!(
            body(
                &call(
                    &auth,
                    request("/get-session", None, &cookies(&anonymous)),
                    200
                )
                .await
            ),
            original
        );
        authenticated(&auth, &cookies(&regular), &email).await;
        authenticated(&auth, &cookies(&foreign), &foreign_email).await;
    }
    B::close(connection).await
}

async fn anonymous_database_hook_errors_preserve_stage_commit<B: Backend>(db: Db) -> TestResult {
    struct Hook(Arc<Mutex<usize>>);
    fn rejected(stage: &str) -> alibi::AuthError {
        alibi::AuthError::Api {
            status: 403,
            code: None,
            message: format!("{stage} creation cancelled by database hook"),
        }
    }
    #[async_trait::async_trait]
    impl<S: AuthSchema, H: alibi::store::HookBackend> DatabaseHooks<S, H> for Hook {
        async fn before_create_user(
            &self,
            user: &mut CreateUser,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            if user.is_anonymous == Some(true) && *self.0.lock().unwrap() == 1 {
                return Err(rejected("user"));
            }
            Ok(HookControl::Continue)
        }
        async fn before_create_session(
            &self,
            _: &mut CreateSession,
            context: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            if *self.0.lock().unwrap() == 2
                && context
                    .request
                    .as_ref()
                    .is_some_and(|request| request.path.ends_with("/sign-in/anonymous"))
            {
                return Err(rejected("session"));
            }
            Ok(HookControl::Continue)
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mode = Arc::new(Mutex::new(0));
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .store(B::hook(
            B::store(
                Arc::new(AuthConfig::new(SECRET).base_url(ORIGIN)),
                &connection,
            ),
            Hook(mode.clone()),
        ))
        .plugin(AnonymousPlugin::new())
        .build()
        .await?;
    let foreign = signup(&auth, "foreign@example.test").await;
    for (stage, label, delta) in [(1, "user", 0), (2, "session", 1)] {
        *mode.lock().unwrap() = stage;
        let before = db.tables(&["users", "accounts", "sessions"]).await?;
        let before_users = db.count("users").await?;
        let denied = call(
            &auth,
            request("/sign-in/anonymous", Some(json!({})), ""),
            403,
        )
        .await;
        assert_eq!(
            body(&denied),
            json!({"message":format!("{label} creation cancelled by database hook")})
        );
        assert_eq!(denied.headers.get_all("set-cookie").count(), 0);
        assert_eq!(db.count("users").await?, before_users + delta);
        assert_eq!(db.tables(&["accounts", "sessions"]).await?, before[1..]);
        if delta == 0 {
            assert_eq!(db.table("users").await?, before[0]);
        } else {
            let old: Vec<Value> = serde_json::from_str(&before[0])?;
            let new: Vec<Value> = serde_json::from_str(&db.table("users").await?)?;
            assert!(old.iter().all(|row| new.contains(row)));
            assert_eq!(
                new.iter().find(|row| !old.contains(row)).unwrap()["is_anonymous"],
                1
            );
        }
        assert_eq!(
            body(&call(&auth, request("/get-session", None, ""), 200).await),
            Value::Null
        );
        authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    }
    B::close(connection).await
}

async fn anonymous_issuance_ignores_tampered_browser_preference<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(AnonymousPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let browser = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"owner@example.test","password":PASSWORD,"rememberMe":false})),
            "",
        ),
        200,
    )
    .await;
    let preference = cookies(&browser)
        .split("; ")
        .find(|pair| pair.starts_with("better-auth.dont_remember="))
        .unwrap()
        .to_owned();
    let baseline = db.tables(&["users", "accounts", "sessions"]).await?;
    let valid = call(
        &auth,
        request("/sign-in/anonymous", Some(json!({})), &preference),
        200,
    )
    .await;
    let valid_headers = valid.headers.get_all("set-cookie").collect::<Vec<_>>();
    assert_eq!(valid_headers.len(), 2);
    assert!(
        valid_headers
            .iter()
            .all(|header| !header.to_ascii_lowercase().contains("max-age"))
    );
    assert!(cookies(&valid).contains("dont_remember="));
    let mut tampered = preference.into_bytes();
    let index = tampered
        .iter()
        .rposition(|byte| byte.is_ascii_alphanumeric())
        .unwrap();
    tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
    let invalid = call(
        &auth,
        request(
            "/sign-in/anonymous",
            Some(json!({})),
            &String::from_utf8(tampered)?,
        ),
        200,
    )
    .await;
    let invalid_headers = invalid.headers.get_all("set-cookie").collect::<Vec<_>>();
    assert_eq!(invalid_headers.len(), 1);
    assert!(invalid_headers[0].starts_with("better-auth.session_token="));
    assert!(
        invalid_headers[0]
            .to_ascii_lowercase()
            .contains("max-age=604800")
    );
    assert!(!cookies(&invalid).contains("dont_remember="));
    for issued in [&valid, &invalid] {
        let current =
            body(&call(&auth, request("/get-session", None, &cookies(issued)), 200).await);
        assert_eq!(current["user"]["id"], body(issued)["user"]["id"]);
        assert_eq!(current["session"]["token"], body(issued)["token"]);
    }
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    for (before, after) in baseline.iter().zip(after.iter()) {
        let before: Vec<Value> = serde_json::from_str(before)?;
        let after: Vec<Value> = serde_json::from_str(after)?;
        assert!(before.iter().all(|row| after.contains(row)));
    }
    assert_eq!(db.table("accounts").await?, baseline[1]);
    authenticated(&auth, &cookies(&owner), "owner@example.test").await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn anonymous_transfer_retains_cached_old_projection_and_new_completed_owner<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::MultiSessionPlugin;
    use alibi::{CookieCacheConfig, CookieCacheStrategy};
    struct Capture(Mutex<Vec<Value>>);
    #[async_trait::async_trait]
    impl LinkAnonymousAccount for Capture {
        async fn link(&self, l: &AnonymousLink, _: &AuthRequest) -> AuthResult<()> {
            self.0.lock().unwrap().push(json!({"oldUser":l.anonymous_user,"oldSession":l.anonymous_session,"newUser":l.new_user,"newSession":l.new_session}));
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            strategy: CookieCacheStrategy::Compact,
            ..Default::default()
        });
    let linker = Arc::new(Capture(Mutex::new(Vec::new())));
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(AnonymousPlugin::with_config(AnonymousConfig {
            on_link_account: Some(linker.clone()),
            ..Default::default()
        }))
        .plugin(MultiSessionPlugin::new())
        .build()
        .await?;
    let foreign = signup(&auth, "foreign@example.test").await;
    let baseline = db.tables(&["users", "accounts", "sessions"]).await?;
    let anon = call(
        &auth,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    let jar = cookies(&anon);
    let original = body(&call(&auth, request("/get-session", None, &jar), 200).await);
    let old_id = original["user"]["id"].as_str().unwrap();
    assert_eq!(
        db.execute(
            "UPDATE users SET name='Physical Changed Anonymous' WHERE id=$1",
            &[old_id]
        )
        .await?,
        1
    );
    let completed=call(&auth,request("/sign-up/email",Some(json!({"email":"upgrade@example.test","name":"Completed Real Owner","password":PASSWORD})),&jar),200).await;
    let new = body(&completed);
    let receipts = linker.0.lock().unwrap().clone();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["oldUser"], original["user"]);
    assert_eq!(receipts[0]["oldSession"], original["session"]);
    assert_eq!(receipts[0]["newUser"], new["user"]);
    assert_eq!(receipts[0]["newSession"]["token"], new["token"]);
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM users WHERE id=$1", &[old_id])
            .await?,
        0
    );
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM sessions WHERE user_id=$1", &[old_id])
            .await?,
        0
    );
    let id = new["user"]["id"].as_str().unwrap();
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM sessions WHERE user_id=$1", &[id])
            .await?,
        1
    );
    assert!(
        completed
            .headers
            .get_all("set-cookie")
            .any(|x| x.contains("_multi-") && !x.contains("Max-Age=0"))
    );
    let read = body(
        &call(
            &auth,
            request("/get-session", None, &cookies(&completed)),
            200,
        )
        .await,
    );
    assert_eq!(read["user"], new["user"]);
    assert_eq!(read["session"]["token"], new["token"]);
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    for (before, now) in baseline.iter().zip(after.iter()) {
        let before: Vec<Value> = serde_json::from_str(before)?;
        let now: Vec<Value> = serde_json::from_str(now)?;
        assert!(before.iter().all(|x| now.contains(x)));
    }
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn anonymous_passwordless_completion_paths_transfer_actual_owner<B: Backend>(
    db: Db,
) -> TestResult {
    use super::passwordless::Mailbox;
    use alibi::plugins::{
        email_otp::{EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin},
        magic_link::{MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin},
        phone_number::{PhoneNumberConfig, PhoneNumberPlugin, PhoneOtpDelivery},
    };
    struct Capture(Mutex<Vec<Value>>);
    #[async_trait::async_trait]
    impl LinkAnonymousAccount for Capture {
        async fn link(&self, a: &AnonymousLink, r: &AuthRequest) -> AuthResult<()> {
            self.0.lock().unwrap().push(json!({"oldUser":a.anonymous_user,"oldSession":a.anonymous_session,"newUser":a.new_user,"newSession":a.new_session,"path":r.path}));
            Ok(())
        }
    }
    for method in ["magic", "email-otp-verification", "phone"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let magic = Arc::new(Mailbox::<MagicLinkDelivery>::default());
        let email = Arc::new(Mailbox::<EmailOtpDelivery>::default());
        let phone = Arc::new(Mailbox::<PhoneOtpDelivery>::default());
        let capture = Arc::new(Capture(Mutex::new(Vec::new())));
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(alibi::plugins::SessionManagementPlugin::new())
            .plugin(MagicLinkPlugin::new(MagicLinkConfig {
                send_magic_link: Some(magic.clone()),
                ..Default::default()
            }))
            .plugin(EmailOtpPlugin::new(EmailOtpConfig {
                send_verification_otp: Some(email.clone()),
                auto_sign_in_after_verification: true,
                ..Default::default()
            }))
            .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
                send_otp: Some(phone.clone()),
                ..Default::default()
            }))
            .plugin(AnonymousPlugin::with_config(AnonymousConfig {
                on_link_account: Some(capture.clone()),
                ..Default::default()
            }))
            .build()
            .await?;
        let number = "+15552224444";
        let target = call(&auth,request("/sign-up/email",Some(json!({"email":"passwordless-target@example.test","password":PASSWORD,"name":"Target","phoneNumber":number})),""),200).await;
        let target_id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
        let foreign = signup(&auth, "passwordless-foreign@example.test").await;
        let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
        let foreign_token = db
            .text(
                "SELECT token FROM sessions WHERE user_id=$1",
                &[&foreign_id],
            )
            .await?;
        let anonymous = call(
            &auth,
            request("/sign-in/anonymous", Some(json!({})), ""),
            200,
        )
        .await;
        let old_id = body(&anonymous)["user"]["id"].as_str().unwrap().to_owned();
        let original = body(
            &call(
                &auth,
                request("/get-session", None, &cookies(&anonymous)),
                200,
            )
            .await,
        );
        let mut redeem = match method {
            "magic" => {
                let _ = call(
                    &auth,
                    request(
                        "/sign-in/magic-link",
                        Some(json!({"email":"passwordless-target@example.test"})),
                        "",
                    ),
                    200,
                )
                .await;
                let url = url::Url::parse(&magic.take().url)?;
                let mut r = request("/magic-link/verify", None, &cookies(&anonymous));
                r.query.extend(url.query_pairs().into_owned());
                r
            }
            "email-otp-verification" => {
                let _=call(&auth,request("/email-otp/send-verification-otp",Some(json!({"email":"passwordless-target@example.test","type":"email-verification"})),""),200).await;
                request(
                    "/email-otp/verify-email",
                    Some(
                        json!({"email":"passwordless-target@example.test","otp":email.take().otp}),
                    ),
                    &cookies(&anonymous),
                )
            }
            _ => {
                let _ = call(
                    &auth,
                    request(
                        "/phone-number/send-otp",
                        Some(json!({"phoneNumber":number})),
                        "",
                    ),
                    200,
                )
                .await;
                request(
                    "/phone-number/verify",
                    Some(json!({"phoneNumber":number,"code":phone.take().code})),
                    &cookies(&anonymous),
                )
            }
        };
        _ = redeem
            .headers
            .insert("x-anonymous-marker".into(), method.into());
        let before = db.tables(&["users", "accounts", "sessions"]).await?;
        let mut invalid = redeem.clone();
        if method == "magic" {
            _ = invalid
                .query
                .insert("token".into(), "unissued-token".into());
        } else {
            let mut b: Value = serde_json::from_slice(invalid.body.as_ref().unwrap())?;
            b[if method == "phone" { "code" } else { "otp" }] = json!("unissued-code");
            invalid.body = Some(serde_json::to_vec(&b)?);
        }
        let denied = call(&auth, invalid, if method == "magic" { 302 } else { 400 }).await;
        assert!(denied.headers.get_all("set-cookie").next().is_none());
        assert!(capture.0.lock().unwrap().is_empty());
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
        let done = call(
            &auth,
            redeem.clone(),
            if method == "magic" { 302 } else { 200 },
        )
        .await;
        let current = body(&call(&auth, request("/get-session", None, &cookies(&done)), 200).await);
        assert_eq!(current["user"]["id"], target_id);
        let receipts = capture.0.lock().unwrap().clone();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0]["oldUser"], original["user"]);
        assert_eq!(receipts[0]["oldSession"], original["session"]);
        assert_eq!(receipts[0]["newUser"]["id"], target_id);
        assert_eq!(
            receipts[0]["newSession"]["token"],
            current["session"]["token"]
        );
        assert!(
            receipts[0]["path"]
                .as_str()
                .unwrap()
                .ends_with(match method {
                    "magic" => "/magic-link/verify",
                    "phone" => "/phone-number/verify",
                    _ => "/email-otp/verify-email",
                })
        );
        assert_eq!(
            db.count_where("SELECT COUNT(*) FROM users WHERE id=$1", &[&old_id])
                .await?,
            0
        );
        assert_eq!(
            db.count_where("SELECT COUNT(*) FROM sessions WHERE user_id=$1", &[&old_id])
                .await?,
            0
        );
        let count = db.count("sessions").await?;
        let _ = call(&auth, redeem, if method == "magic" { 302 } else { 400 }).await;
        assert_eq!(capture.0.lock().unwrap().len(), 1);
        assert_eq!(db.count("sessions").await?, count);
        assert_eq!(
            db.text(
                "SELECT token FROM sessions WHERE user_id=$1",
                &[&foreign_id]
            )
            .await?,
            foreign_token
        );
        authenticated(
            &auth,
            &cookies(&foreign),
            "passwordless-foreign@example.test",
        )
        .await;
        B::close(connection).await?;
    }
    Ok(())
}

#[tokio::test]
#[cfg(feature = "seaorm")]
async fn anonymous_new_owner_callback_retains_hidden_application_fields() -> TestResult {
    use alibi::AuthSession;
    #[expect(
        unreachable_pub,
        reason = "SeaORM derives require public model and relation types within the application schema"
    )]
    mod application_user {
        use alibi::seaorm::sea_orm::{self, entity::prelude::*};
        use chrono::{DateTime, Utc};
        #[derive(
            Clone, Debug, PartialEq, serde::Serialize, alibi::seaorm::AuthEntity, DeriveEntityModel,
        )]
        #[sea_orm(table_name = "users")]
        #[auth(role = "user", secondary_storage)]
        #[serde(rename_all = "camelCase")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: String,
            pub name: Option<String>,
            pub email: Option<String>,
            pub email_verified: bool,
            pub image: Option<String>,
            pub username: Option<String>,
            pub display_username: Option<String>,
            pub two_factor_enabled: Option<bool>,
            pub role: Option<String>,
            pub banned: Option<bool>,
            pub ban_reason: Option<String>,
            pub ban_expires: Option<DateTime<Utc>>,
            #[sea_orm(column_type = "JsonBinary")]
            pub metadata: alibi::seaorm::JsonMetadata,
            pub is_anonymous: Option<bool>,
            pub phone_number: Option<String>,
            pub phone_number_verified: Option<bool>,
            pub last_login_method: Option<String>,
            pub created_at: DateTime<Utc>,
            pub updated_at: DateTime<Utc>,
            #[sea_orm(column_name = "cargo_label")]
            pub cargo_label: Option<String>,
            #[sea_orm(column_name = "cargo_hidden")]
            pub cargo_hidden: Option<String>,
        }
        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}
        impl ActiveModelBehavior for ActiveModel {}
    }
    type Bundled = <crate::storage::SeaOrm as Backend>::Schema;
    struct ApplicationSchema;
    impl AuthSchema for ApplicationSchema {
        type User = application_user::Model;
        type Session = <Bundled as AuthSchema>::Session;
        type Account = <Bundled as AuthSchema>::Account;
        type Verification = <Bundled as AuthSchema>::Verification;
    }
    struct Hook(crate::storage::Raw);
    #[async_trait::async_trait]
    impl<H: alibi::store::HookBackend> DatabaseHooks<ApplicationSchema, H> for Hook {
        async fn after_create_session(
            &self,
            s: &<ApplicationSchema as AuthSchema>::Session,
            c: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<()> {
            if c.request
                .as_ref()
                .is_some_and(|r| r.path.ends_with("/sign-up/email"))
            {
                _=self.0.execute("UPDATE users SET name='Stored Hook Name',cargo_label='Application Stored',cargo_hidden='Stored Secret' WHERE id=$1",&[s.user_id().as_ref()]).await.map_err(|e|alibi::AuthError::internal(e.to_string()))?;
            }
            Ok(())
        }
    }
    struct Capture(Mutex<Vec<Value>>);
    #[async_trait::async_trait]
    impl LinkAnonymousAccount for Capture {
        async fn link(&self, a: &AnonymousLink, _: &AuthRequest) -> AuthResult<()> {
            self.0.lock().unwrap().push(
                json!({"oldUser":a.anonymous_user,"newUser":a.new_user,"newSession":a.new_session}),
            );
            Ok(())
        }
    }
    let db = Db::sqlite().await?;
    let (connection, _) = db.migrated::<crate::storage::SeaOrm>(SECRET).await?;
    _ = db
        .execute("ALTER TABLE users ADD COLUMN cargo_label TEXT", &[])
        .await?;
    _ = db
        .execute("ALTER TABLE users ADD COLUMN cargo_hidden TEXT", &[])
        .await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    use alibi::field_policy::FieldConfig;
    _ = config.user.additional_fields.insert(
        "cargoLabel".into(),
        FieldConfig::new(json!({"type":"string"}))
            .field_name("cargo_label")
            .default_value(json!("Application Original")),
    );
    _ = config.user.additional_fields.insert(
        "cargoHidden".into(),
        FieldConfig::new(json!({"type":"string"}))
            .field_name("cargo_hidden")
            .default_value(json!("Application Secret"))
            .hidden(),
    );
    let capture = Arc::new(Capture(Mutex::new(Vec::new())));
    let store = alibi::seaorm::SeaOrmStore::<ApplicationSchema>::new(
        Arc::new(config.clone()),
        connection.clone(),
    )
    .hook(Hook(db.raw.clone()));
    let auth = AuthBuilder::new(config)
        .store(store)
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(alibi::plugins::SessionManagementPlugin::new())
        .plugin(AnonymousPlugin::with_config(AnonymousConfig {
            on_link_account: Some(capture.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let foreign = signup(&auth, "hidden-foreign@example.test").await;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let anonymous = call(
        &auth,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    let old_id = body(&anonymous)["user"]["id"].as_str().unwrap().to_owned();
    let done=call(&auth,request("/sign-up/email",Some(json!({"email":"hidden-owner@example.test","name":"Original New Owner","password":PASSWORD})),&cookies(&anonymous)),200).await;
    let public = body(&done);
    assert_eq!(public["user"]["name"], "Original New Owner");
    assert_eq!(public["user"]["cargoLabel"], "Application Original");
    assert!(public["user"].get("cargoHidden").is_none());
    let receipts = capture.0.lock().unwrap().clone();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["oldUser"]["id"], old_id);
    assert_eq!(receipts[0]["newUser"]["id"], public["user"]["id"]);
    assert_eq!(receipts[0]["newUser"]["name"], "Original New Owner");
    assert_eq!(receipts[0]["newUser"]["cargoLabel"], "Application Original");
    assert_eq!(receipts[0]["newUser"]["cargoHidden"], "Application Secret");
    assert_eq!(receipts[0]["newSession"]["token"], public["token"]);
    let id = public["user"]["id"].as_str().unwrap();
    assert_eq!(
        db.text("SELECT name FROM users WHERE id=$1", &[id])
            .await?
            .as_deref(),
        Some("Stored Hook Name")
    );
    assert_eq!(
        db.text("SELECT cargo_hidden FROM users WHERE id=$1", &[id])
            .await?
            .as_deref(),
        Some("Stored Secret")
    );
    let current = body(&call(&auth, request("/get-session", None, &cookies(&done)), 200).await);
    assert_eq!(current["user"]["name"], "Stored Hook Name");
    assert_eq!(current["user"]["cargoLabel"], "Application Stored");
    assert!(current["user"].get("cargoHidden").is_none());
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM users WHERE id=$1", &[&old_id])
            .await?,
        0
    );
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    for (prior, current) in before.into_iter().zip(after) {
        let prior: Vec<Value> = serde_json::from_str(&prior)?;
        let current: Vec<Value> = serde_json::from_str(&current)?;
        for row in prior {
            assert!(current.contains(&row));
        }
    }
    authenticated(&auth, &cookies(&foreign), "hidden-foreign@example.test").await;
    <crate::storage::SeaOrm as Backend>::close(connection).await
}
