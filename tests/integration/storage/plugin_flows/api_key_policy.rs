//! API key configuration limits, server input shapes, stored permission
//! documents, session callbacks, organization ownership and storage edge cases.
use super::*;
use crate::snapshot::Trace;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::api_key::*;
use alibi::plugins::organization::{OrganizationConfig, OrganizationPlugin};
use alibi::plugins::{ApiKeyConfig, ApiKeyPlugin};
use alibi::store::MemoryCacheAdapter;
use alibi::utils::json::parse_value;
use alibi::{AuthError, AuthResult, BackgroundTaskCompletion, BackgroundTaskHandler};

backend_tests!(
    api_key_configuration_limits,
    api_key_server_input_shapes,
    api_key_permission_documents,
    api_key_session_callbacks,
    api_key_organization_ownership,
    api_key_storage_edges,
    static_org_create_grants_admit_nonowner_and_reject_reader,
    static_org_reader_lists_only_tenant_keys_without_plaintext,
    static_org_update_requires_update_action_and_preserves_key_identity,
    static_org_delete_requires_delete_action_and_revokes_only_selected_key,
    disabled_custom_key_expiration_retains_default_lifetime_through_rename,
    banned_api_key_owner_can_verify_but_cannot_use_synthetic_deletion_authority,
    api_key_builtin_fractional_generation,
    api_key_raw_default_expiration
);

fn raw(path: &str, text: &str, cookie: &str) -> AuthRequest {
    let mut request = request(path, None, cookie);
    request.method = HttpMethod::Post;
    request.body = Some(text.as_bytes().to_vec());
    request
}

fn failure(error: &alibi::endpoint::EndpointError) -> Value {
    json!({"status": error.error.status_code(), "message": error.to_string()})
}

async fn api_key_configuration_limits<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    let variants: Vec<(&str, ApiKeyConfig)> = vec![
        (
            "limits",
            ApiKeyConfig {
                min_name_length: 2.0,
                max_name_length: 4.0,
                enable_metadata: false,
                key_expiration: KeyExpirationConfig {
                    min_expires_in: 1.0,
                    max_expires_in: 2.0,
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            "custom expiry disabled",
            ApiKeyConfig {
                key_expiration: KeyExpirationConfig {
                    disable_custom_expires_time: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            "default key length",
            ApiKeyConfig {
                key_length: 0.0,
                prefix: Some("pre_".into()),
                ..Default::default()
            },
        ),
        (
            "invalid key length",
            ApiKeyConfig {
                key_length: -1.0,
                ..Default::default()
            },
        ),
        (
            "required name",
            ApiKeyConfig {
                require_name: true,
                ..Default::default()
            },
        ),
        (
            "unbounded expiry",
            ApiKeyConfig {
                enable_metadata: true,
                key_expiration: KeyExpirationConfig {
                    max_expires_in: f64::INFINITY,
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            "unhashed generated keys",
            ApiKeyConfig {
                custom_key_generator: Some(Arc::new(Surrogate::default())),
                disable_key_hashing: true,
                starting_characters_length: -1.0,
                store_starting_characters: true,
                ..Default::default()
            },
        ),
    ];
    for (index, (label, config)) in variants.into_iter().enumerate() {
        let auth = builder::<B>(&connection)
            .plugin(ApiKeyPlugin::with_config(config))
            .build()
            .await?;
        let owner = cookies(&signup(&auth, &format!("limits-{index}@example.com")).await);
        let mut key_id = None;
        for text in [
            r#"{"name":"x"}"#,
            r#"{"name":"toolong"}"#,
            r#"{"name":"ok","expiresIn":3600}"#,
            r#"{"name":"ok","expiresIn":259200}"#,
            r#"{"name":"ok","metadata":{"a":1}}"#,
            r#"{"expiresIn":129600}"#,
            r#"{"name":"ok","expiresIn":129600}"#,
            r#"{"name":1e999}"#,
            r#"{"name":-1e999}"#,
            r#"{"metadata":null}"#,
            r#"{"expiresIn":1e300}"#,
        ] {
            let response =
                Box::pin(auth.handle_request(raw("/api-key/create", text, &owner))).await?;
            if response.status == 200 {
                let created = body(&response);
                key_id = created["id"].as_str().map(str::to_owned);
                trace.value(
                    &format!("{label} {text} key"),
                    json!({
                        "length": created["key"].as_str().map(|key| key.chars().count()),
                        "prefix": created["key"].as_str().map(|key| key.starts_with("pre_")),
                    }),
                );
            }
            trace.response(&format!("{label} create {text}"), &response);
        }
        if let Some(key_id) = key_id {
            trace.mask(&key_id);
            for fields in [
                r#""expiresIn":3600"#,
                r#""expiresIn":null"#,
                r#""expiresIn":129600"#,
                r#""name":"toolong""#,
                r#""remaining":1e999"#,
                r#""refillAmount":-1e999"#,
                r#""enabled":false,"metadata":{"b":2},"permissions":null"#,
            ] {
                let text = format!(r#"{{"keyId":"{key_id}",{fields}}}"#);
                trace.response(
                    &format!("{label} update {fields}"),
                    &Box::pin(auth.handle_request(raw("/api-key/update", &text, &owner))).await?,
                );
            }
        }
    }
    trace.assert("api-key/configuration-limits");
    B::close(connection).await
}

async fn api_key_server_input_shapes<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
            enable_metadata: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let user_id = body(&signup(&auth, "server-shapes@example.com").await)["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    trace.mask(&user_id);
    let created = Box::pin(auth.dispatch_endpoint(
        ApiKeyPlugin::create_endpoint(&serde_json::from_value(json!({"userId": user_id}))?)?,
        EndpointOptions::default(),
    ))
    .await?
    .decode()?;
    let key_id = created.api_key.id.clone();
    trace.mask(&key_id);
    let bodies: Vec<(&str, String)> = vec![
        ("array", "[]".into()),
        ("null", "null".into()),
        (
            "wrong types",
            r#"{"name":5,"prefix":5,"expiresIn":"x","remaining":-1,"metadata":5,"refillAmount":0,"refillInterval":"x","rateLimitEnabled":"y","rateLimitMax":true,"permissions":5,"organizationId":[{"toString":1}]}"#.into(),
        ),
        (
            "nested permissions",
            r#"{"permissions":{"a":"b","c":[1,"d"]},"prefix":"bad prefix"}"#.into(),
        ),
        (
            "infinite numbers",
            r#"{"expiresIn":1e999,"rateLimitMax":-1e999,"remaining":1e999}"#.into(),
        ),
        ("null owner", r#"{"userId":null}"#.into()),
        ("coerced owner", format!(r#"{{"userId":["{user_id}"]}}"#)),
        ("empty prefix", r#"{"userId":"x","prefix":""}"#.into()),
        (
            "wrong update types",
            r#"{"keyId":5,"userId":{"toString":1},"name":5,"enabled":"y","remaining":0,"metadata":5,"expiresIn":0,"permissions":[]}"#.into(),
        ),
        ("update without key", r#"{"name":"x"}"#.into()),
        (
            "update ok",
            format!(r#"{{"keyId":"{key_id}","userId":"{user_id}","name":"renamed","metadata":null,"permissions":null}}"#),
        ),
        (
            "verify wrong types",
            r#"{"key":5,"configId":5,"permissions":[]}"#.into(),
        ),
        (
            "verify nested permissions",
            r#"{"key":"x","permissions":{"a":[1]}}"#.into(),
        ),
    ];
    for (name, text) in &bodies {
        for (operation, endpoint) in [
            ("createApiKey", "create"),
            ("updateApiKey", "update"),
            ("verifyApiKey", "verify"),
        ] {
            if operation == "verifyApiKey" && !name.starts_with("verify") && name != &"array" {
                continue;
            }
            if endpoint != "verify" && name.starts_with("verify") {
                continue;
            }
            let input = parse_value(text)?;
            let result = Box::pin(auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("api-key", operation).with_body_value(input),
                EndpointOptions::default(),
            ))
            .await;
            trace.value(
                &format!("{endpoint} {name}"),
                match result {
                    Ok(response) => json!({"ok": response.decode().ok().map(|value| value.get("valid").cloned())}),
                    Err(error) => failure(&error),
                },
            );
        }
    }
    trace.assert("api-key/server-input-shapes");
    B::close(connection).await
}

async fn api_key_permission_documents<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = ApiKeyConfig::default();
    let auth = builder::<B>(&connection)
        .plugin(ApiKeyPlugin::with_config(config.clone()))
        .build()
        .await?;
    let plugin = ApiKeyPlugin::with_config(config);
    let mut trace = Trace::default();
    let user_id = body(&signup(&auth, "documents@example.com").await)["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let created = Box::pin(auth.dispatch_endpoint(
        ApiKeyPlugin::create_endpoint(&serde_json::from_value(
            json!({"userId": user_id, "permissions": {"files": ["read"]}}),
        )?)?,
        EndpointOptions::default(),
    ))
    .await?
    .decode()?;
    let key = created.key.clone();
    let stored = [
        r#"{"files":["read","write"]}"#,
        r#"{"files":"read,write"}"#,
        r#"{"files":5}"#,
        r#"[["read"]]"#,
        "not json",
        "null",
        "0",
        r#""""#,
        r#"{"files":["2020-01-01T00:00:00.000Z"]}"#,
        r#"{"files":"2020-01-01T00:00:00.000Z"}"#,
        "true",
    ];
    let required = [
        json!({"files": ["read"]}),
        json!({"files": ["read", "write"]}),
        json!({"files": {"actions": ["read", "write"], "connector": "OR"}}),
        json!({"files": {"actions": ["read", "delete"], "connector": "AND"}}),
        json!({"files": {"actions": ["read"]}}),
        json!({"files": {"connector": "OR"}}),
        json!({"files": []}),
        json!({"files": "read"}),
        json!({"files": [5]}),
        json!({"0": ["read"]}),
        json!({"missing": ["read"]}),
        json!({}),
        json!({"files": ["2020-01-01T00:00:00.000Z"]}),
    ];
    for document in stored {
        _ = db
            .execute("UPDATE api_keys SET permissions = $1", &[document])
            .await?;
        for needed in &required {
            let result = plugin
                .verify_api_key(
                    &VerifyApiKey {
                        key: &key,
                        config_id: None,
                        permissions: Some(needed),
                    },
                    auth.context(),
                )
                .await;
            trace.value(
                &format!("{document} requires {needed}"),
                match result {
                    Ok(_) => json!("valid"),
                    Err(ApiKeyVerificationError::Validation(error)) => {
                        json!(format!("{:?}", error.code))
                    }
                    Err(_) => json!("internal"),
                },
            );
        }
    }
    trace.assert("api-key/permission-documents");
    B::close(connection).await
}

#[derive(Default)]
struct Callbacks {
    mode: Mutex<&'static str>,
    lookups: std::sync::atomic::AtomicUsize,
}

impl ApiKeyGetter for Callbacks {
    fn get_key(&self, context: &ApiKeyCallbackContext<'_>) -> AuthResult<Option<String>> {
        let Some(request) = context.request else {
            return Ok(None);
        };
        let Some(key) = request.headers.get("x-application-key") else {
            return Ok(None);
        };
        let lookup = self
            .lookups
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mode = *self.mode.lock().unwrap();
        if (mode == "getter-fails" && request.headers.contains_key("x-fail"))
            || (mode == "getter-fails-late" && lookup == 1)
        {
            return Err(AuthError::internal("getter unavailable"));
        }
        Ok(Some(key.clone()))
    }
}

#[async_trait::async_trait]
impl ApiKeyValidator for Callbacks {
    async fn validate(&self, _: &ApiKeyCallbackContext<'_>, _: &str) -> AuthResult<bool> {
        let mode = *self.mode.lock().unwrap();
        match mode {
            "reject" => Ok(false),
            "validator-fails" => Err(AuthError::internal("validator unavailable")),
            "validator-denies" => Err(AuthError::forbidden("validator denied")),
            _ => Ok(true),
        }
    }
}

impl BackgroundTaskHandler for Callbacks {
    fn handle(&self, completion: BackgroundTaskCompletion) -> AuthResult<()> {
        drop(completion);
        match *self.mode.lock().unwrap() {
            "background-fails" => Err(AuthError::internal("background unavailable")),
            "background-denies" => Err(AuthError::forbidden("background denied")),
            _ => Ok(()),
        }
    }
}

async fn api_key_session_callbacks<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let callbacks = Arc::new(Callbacks::default());
    let config = ApiKeyConfig {
        enable_session_for_api_keys: true,
        custom_api_key_getter: Some(callbacks.clone()),
        custom_api_key_validator: Some(callbacks.clone()),
        defer_updates: true,
        rate_limit: RateLimitDefaults {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    };
    let auth_config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .background_tasks(callbacks.clone());
    let auth = AuthBuilder::new(auth_config.clone())
        .store(B::store(Arc::new(auth_config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(alibi::plugins::EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(ApiKeyPlugin::with_config(config.clone()))
        .build()
        .await?;
    let plugin = ApiKeyPlugin::with_config(config);
    let mut trace = Trace::default();
    let user_id = body(&signup(&auth, "callbacks@example.com").await)["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    trace.mask(&user_id);
    let created = Box::pin(auth.dispatch_endpoint(
        ApiKeyPlugin::create_endpoint(&serde_json::from_value(json!({"userId": user_id}))?)?,
        EndpointOptions::default(),
    ))
    .await?
    .decode()?;
    let key = created.key.clone();
    trace.mask(&created.api_key.id);
    let session = async |headers: &[(&str, &str)]| {
        let mut request = request("/get-session", None, "");
        for (name, value) in headers {
            _ = request.headers.insert((*name).into(), (*value).into());
        }
        Box::pin(auth.handle_request(request)).await.unwrap()
    };
    for mode in [
        "accept",
        "reject",
        "validator-fails",
        "validator-denies",
        "getter-fails",
        "getter-fails-late",
        "background-fails",
        "background-denies",
    ] {
        *callbacks.mode.lock().unwrap() = mode;
        callbacks
            .lookups
            .store(0, std::sync::atomic::Ordering::SeqCst);
        trace.response(
            &format!("session {mode}"),
            &session(&[("x-application-key", &key), ("x-fail", "1")]).await,
        );
        let verified = plugin
            .verify_api_key_with_request(
                &VerifyApiKey {
                    key: &key,
                    config_id: Some("default"),
                    permissions: None,
                },
                &request("/verify", None, ""),
                auth.context(),
            )
            .await;
        let unscoped = plugin
            .verify_api_key_with_request(
                &VerifyApiKey {
                    key: &key,
                    config_id: None,
                    permissions: None,
                },
                &request("/verify", None, ""),
                auth.context(),
            )
            .await;
        trace.value(
            &format!("unscoped verification {mode}"),
            match unscoped {
                Ok(view) => json!({"valid": view.enabled}),
                Err(ApiKeyVerificationError::Validation(error)) => {
                    json!(format!("{:?}", error.code))
                }
                Err(ApiKeyVerificationError::ExplicitValidator(error)) => {
                    json!({"validator": error.status_code()})
                }
                Err(ApiKeyVerificationError::Internal(error)) => {
                    json!({"internal": error.status_code()})
                }
            },
        );
        trace.value(
            &format!("server verification {mode}"),
            match verified {
                Ok(view) => json!({"valid": view.enabled}),
                Err(ApiKeyVerificationError::Validation(error)) => {
                    json!(format!("{:?}", error.code))
                }
                Err(ApiKeyVerificationError::ExplicitValidator(error)) => {
                    json!({"validator": error.status_code()})
                }
                Err(ApiKeyVerificationError::Internal(error)) => {
                    json!({"internal": error.status_code()})
                }
            },
        );
    }
    *callbacks.mode.lock().unwrap() = "accept";
    let without_permissions = plugin
        .verify_api_key(
            &VerifyApiKey {
                key: &key,
                config_id: None,
                permissions: Some(&json!({"files": ["read"]})),
            },
            auth.context(),
        )
        .await;
    trace.value(
        "permissions required of a key without any",
        json!(without_permissions.is_err()),
    );
    let expiring = Box::pin(auth.dispatch_endpoint(
        ApiKeyPlugin::create_endpoint(&serde_json::from_value(
            json!({"userId": user_id, "expiresIn": 172_800}),
        )?)?,
        EndpointOptions::default(),
    ))
    .await?
    .decode()?;
    trace.mask(&expiring.api_key.id);
    trace.response(
        "session from an expiring key",
        &session(&[("x-application-key", &expiring.key)]).await,
    );
    _ = db
        .execute(
            "UPDATE api_keys SET expires_at = $1 WHERE id = $2",
            &[
                &(chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339(),
                &expiring.api_key.id,
            ],
        )
        .await?;
    _ = db
        .execute(
            "CREATE TRIGGER fail_key_delete BEFORE DELETE ON api_keys BEGIN SELECT RAISE(ABORT, 'forced'); END",
            &[],
        )
        .await?;
    trace.response(
        "expired key with a failing deferred deletion",
        &session(&[("x-application-key", &expiring.key)]).await,
    );
    tokio::task::yield_now().await;
    _ = db.execute("DROP TRIGGER fail_key_delete", &[]).await?;
    _ = db
        .execute("ALTER TABLE api_keys RENAME TO api_keys_unavailable", &[])
        .await?;
    trace.response(
        "session with unavailable storage",
        &session(&[("x-application-key", &key)]).await,
    );
    _ = db
        .execute("ALTER TABLE api_keys_unavailable RENAME TO api_keys", &[])
        .await?;
    _ = db
        .execute("UPDATE api_keys SET expires_at = $1", &["not a date"])
        .await?;
    trace.response(
        "session with corrupt expiry",
        &session(&[("x-application-key", &key)]).await,
    );
    trace.assert("api-key/session-callbacks");
    B::close(connection).await
}

async fn api_key_organization_ownership<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let organization_config = ApiKeyConfig {
        config_id: "organization".into(),
        references: ApiKeyReferences::Organization,
        enable_session_for_api_keys: true,
        ..Default::default()
    };
    let auth = builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(
            OrganizationConfig::default(),
        ))
        .plugin(
            ApiKeyPlugin::with_config(ApiKeyConfig::default()).configuration(organization_config),
        )
        .build()
        .await?;
    let mut trace = Trace::default();
    let owner = signup(&auth, "key-owner@example.com").await;
    let outsider = signup(&auth, "key-outsider@example.com").await;
    let created = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name": "Keys", "slug": "keys"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let organization_id = body(&created)["id"].as_str().unwrap().to_owned();
    trace.mask(&organization_id);
    let owner_cookie = cookies(&owner);
    let outsider_cookie = cookies(&outsider);
    let post = async |trace: &mut Trace, label: &str, path: &str, input: Value, cookie: &str| {
        let response = Box::pin(auth.handle_request(request(path, Some(input), cookie)))
            .await
            .unwrap();
        trace.response(label, &response);
        response
    };
    let get =
        async |trace: &mut Trace, label: &str, path: &str, query: &[(&str, &str)], cookie: &str| {
            let mut input = request(path, None, cookie);
            input.set_query_pairs(query.iter().copied());
            let response = Box::pin(auth.handle_request(input)).await.unwrap();
            trace.response(label, &response);
            response
        };
    _ = post(
        &mut trace,
        "organization key without organization",
        "/api-key/create",
        json!({"configId": "organization", "name": "k"}),
        &owner_cookie,
    )
    .await;
    _ = post(
        &mut trace,
        "outsider creates organization key",
        "/api-key/create",
        json!({"configId": "organization", "organizationId": organization_id}),
        &outsider_cookie,
    )
    .await;
    let key = post(
        &mut trace,
        "owner creates organization key",
        "/api-key/create",
        json!({"configId": "organization", "organizationId": organization_id, "name": "org"}),
        &owner_cookie,
    )
    .await;
    let key_id = body(&key)["id"].as_str().unwrap().to_owned();
    trace.mask(&key_id);
    let secret = body(&key)["key"].as_str().unwrap().to_owned();
    _ = get(
        &mut trace,
        "outsider lists organization keys",
        "/api-key/list",
        &[("organizationId", &organization_id)],
        &outsider_cookie,
    )
    .await;
    _ = get(
        &mut trace,
        "owner lists organization keys",
        "/api-key/list",
        &[("organizationId", &organization_id)],
        &owner_cookie,
    )
    .await;
    _ = get(
        &mut trace,
        "outsider reads organization key",
        "/api-key/get",
        &[("id", &key_id), ("configId", "organization")],
        &outsider_cookie,
    )
    .await;
    _ = get(
        &mut trace,
        "owner reads organization key",
        "/api-key/get",
        &[("id", &key_id), ("configId", "organization")],
        &owner_cookie,
    )
    .await;
    _ = post(
        &mut trace,
        "owner updates organization key",
        "/api-key/update",
        json!({"keyId": key_id, "configId": "organization", "name": "renamed"}),
        &owner_cookie,
    )
    .await;
    let mut as_session = request("/get-session", None, "");
    _ = as_session.headers.insert("x-api-key".into(), secret);
    trace.response(
        "organization key as a session",
        &Box::pin(auth.handle_request(as_session)).await?,
    );
    _ = post(
        &mut trace,
        "outsider deletes organization key",
        "/api-key/delete",
        json!({"keyId": key_id, "configId": "organization"}),
        &outsider_cookie,
    )
    .await;
    _ = db
        .execute(
            "UPDATE users SET banned = 1 WHERE email = $1",
            &["key-owner@example.com"],
        )
        .await?;
    _ = post(
        &mut trace,
        "banned owner deletes organization key",
        "/api-key/delete",
        json!({"keyId": key_id, "configId": "organization"}),
        &owner_cookie,
    )
    .await;
    _ = db
        .execute("ALTER TABLE api_keys RENAME TO api_keys_unavailable", &[])
        .await?;
    _ = get(
        &mut trace,
        "list with unavailable storage",
        "/api-key/list",
        &[],
        &outsider_cookie,
    )
    .await;
    _ = get(
        &mut trace,
        "read with unavailable storage",
        "/api-key/get",
        &[("id", "x")],
        &outsider_cookie,
    )
    .await;
    _ = post(
        &mut trace,
        "create with unavailable storage",
        "/api-key/create",
        json!({}),
        &outsider_cookie,
    )
    .await;
    _ = db
        .execute("ALTER TABLE api_keys_unavailable RENAME TO api_keys", &[])
        .await?;
    trace.assert("api-key/organization-ownership");
    B::close(connection).await
}

#[derive(Default)]
struct Surrogate(std::sync::atomic::AtomicUsize);

#[async_trait::async_trait]
impl ApiKeyGenerator for Surrogate {
    async fn generate_key(&self, _: &ApiKeyGenerationOptions<'_>) -> AuthResult<String> {
        Ok(format!(
            "\u{1F600}surrogate-key-material-{}",
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ))
    }
}

async fn api_key_storage_edges<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let secondary = Arc::new(MemoryCacheAdapter::new());
    let auth = builder::<B>(&connection)
        .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
            storage: ApiKeyStorageMode::SecondaryStorage,
            secondary_storage: Some(secondary.clone()),
            enable_metadata: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let user_id = body(&signup(&auth, "storage-edges@example.com").await)["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    trace.mask(&user_id);
    let create = async |input: Value| {
        let mut input = input;
        input["userId"] = json!(user_id);
        Box::pin(
            auth.dispatch_endpoint(
                ApiKeyPlugin::create_endpoint(
                    &serde_json::from_value::<CreateKeyRequest>(input).unwrap(),
                )
                .unwrap(),
                EndpointOptions::default(),
            ),
        )
        .await
        .unwrap()
        .decode()
        .unwrap()
    };
    let once = create(json!({"name": "once", "remaining": 1})).await;
    trace.mask(&once.api_key.id);
    let verify = async |key: &str| {
        Box::pin(
            auth.dispatch_endpoint(
                ApiKeyPlugin::verify_endpoint(&ApiKeyVerificationInput {
                    key: key.into(),
                    config_id: None,
                    permissions: None,
                })
                .unwrap(),
                EndpointOptions::default(),
            ),
        )
        .await
        .unwrap()
        .decode()
        .unwrap()
    };
    for attempt in ["first", "second", "third"] {
        let output = verify(&once.key).await;
        trace.value(
            &format!("single use {attempt}"),
            json!({"valid": output.valid, "error": output.error.map(|error| alibi::utils::json::to_value(&error).unwrap())}),
        );
    }
    let empty_owner = signup(&auth, "empty-secondary@example.com").await;
    trace.response(
        "list without any key",
        &Box::pin(auth.handle_request(request("/api-key/list", None, &cookies(&empty_owner))))
            .await?,
    );
    let refilling = create(json!({
        "name": "refilling",
        "remaining": 0,
        "refillInterval": 1_000_000_000,
        "refillAmount": 5,
    }))
    .await;
    trace.mask(&refilling.api_key.id);
    let exhausted = verify(&refilling.key).await;
    trace.value(
        "refill not yet due",
        json!({"valid": exhausted.valid, "error": exhausted.error.map(|error| alibi::utils::json::to_value(&error).unwrap())}),
    );
    let unknown = verify("not-a-key").await;
    trace.value("unknown", json!({"valid": unknown.valid}));
    trace.value(
        "stored after exhaustion",
        json!(db.count("api_keys").await?),
    );

    B::close(connection).await?;

    let database = db.fresh().await?;
    let (connection, _) = database.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
            custom_key_generator: Some(Arc::new(Surrogate::default())),
            starting_characters_length: 1.0,
            store_starting_characters: true,
            enable_metadata: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "surrogate-owner@example.com").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let created = Box::pin(auth.dispatch_endpoint(
        ApiKeyPlugin::create_endpoint(&serde_json::from_value(json!({
            "userId": owner_id,
            "name": "surrogate",
            "rateLimitEnabled": true,
            "rateLimitTimeWindow": 1000,
            "rateLimitMax": 1,
        }))?)?,
        EndpointOptions::default(),
    ))
    .await?
    .decode()?;
    let key_id = created.api_key.id.clone();
    trace.mask(&key_id);
    trace.value(
        "stored start",
        json!(
            database
                .text("SELECT HEX(start) FROM api_keys", &[])
                .await?
        ),
    );
    let key = created.key.clone();
    let verify_database = async |key: &str| {
        Box::pin(
            auth.dispatch_endpoint(
                ApiKeyPlugin::verify_endpoint(&ApiKeyVerificationInput {
                    key: key.into(),
                    config_id: None,
                    permissions: None,
                })
                .unwrap(),
                EndpointOptions::default(),
            ),
        )
        .await
        .unwrap()
        .decode()
        .unwrap()
    };
    let single = Box::pin(auth.dispatch_endpoint(
        ApiKeyPlugin::create_endpoint(&serde_json::from_value(
            json!({"userId": owner_id, "name": "single", "remaining": 1}),
        )?)?,
        EndpointOptions::default(),
    ))
    .await?
    .decode()?;
    let racers = tokio::join!(
        verify_database(&single.key),
        verify_database(&single.key),
        verify_database(&single.key),
        verify_database(&single.key),
        verify_database(&single.key),
        verify_database(&single.key),
    );
    let valid = [
        &racers.0, &racers.1, &racers.2, &racers.3, &racers.4, &racers.5,
    ]
    .into_iter()
    .filter(|output| output.valid)
    .count();
    // Never more than one use. SQLx can lose the single use when a concurrent
    // exhausted request deletes the key mid-consumption; SeaORM keeps exactly one.
    assert!(valid <= 1);
    for label in ["first request", "rate limited"] {
        let output = verify_database(&key).await;
        trace.value(
            label,
            json!({"valid": output.valid, "error": output.error.map(|error| alibi::utils::json::to_value(&error).unwrap())}),
        );
    }
    database
        .set_timestamp(
            "api_keys",
            "last_request",
            ("id", &key_id),
            chrono::Utc::now() - chrono::Duration::seconds(5),
        )
        .await?;
    let reset = verify_database(&key).await;
    trace.value(
        "window elapsed",
        json!({"valid": reset.valid, "count": reset.key.map(|key| key.request_count)}),
    );
    for (label, input) in [
        (
            "disable",
            json!({"keyId": key_id, "userId": owner_id, "enabled": false}),
        ),
        (
            "permissions and metadata",
            json!({"keyId": key_id, "userId": owner_id, "enabled": true, "permissions": {"files": ["read"]}, "metadata": {"a": 1}}),
        ),
    ] {
        let updated = Box::pin(auth.dispatch_endpoint(
            ApiKeyPlugin::update_endpoint(&serde_json::from_value(input)?)?,
            EndpointOptions::default(),
        ))
        .await?
        .decode()?;
        trace.value(
            label,
            json!({"enabled": updated.enabled, "permissions": updated.permissions, "metadata": updated.metadata}),
        );
    }
    trace.assert("api-key/storage-edges");
    B::close(connection).await
}

async fn static_org_create_grants_admit_nonowner_and_reject_reader<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::organization::RolePermissions;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let keys = ApiKeyPlugin::with_config(ApiKeyConfig::default()).configuration(ApiKeyConfig {
        config_id: "organization".into(),
        references: ApiKeyReferences::Organization,
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            roles: Some(std::collections::HashMap::from([
                (
                    "owner".into(),
                    RolePermissions {
                        api_key: vec![
                            "create".into(),
                            "read".into(),
                            "update".into(),
                            "delete".into(),
                        ],
                        ..Default::default()
                    },
                ),
                (
                    "member".into(),
                    RolePermissions {
                        api_key: vec!["read".into()],
                        ..Default::default()
                    },
                ),
                (
                    "admin".into(),
                    RolePermissions {
                        api_key: vec!["create".into()],
                        ..Default::default()
                    },
                ),
                (
                    "updater".into(),
                    RolePermissions {
                        api_key: vec!["read".into(), "update".into()],
                        ..Default::default()
                    },
                ),
                (
                    "deleter".into(),
                    RolePermissions {
                        api_key: vec!["read".into(), "delete".into()],
                        ..Default::default()
                    },
                ),
            ])),
            ..Default::default()
        }))
        .plugin(keys.clone())
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let reader = signup(&auth, "reader@example.test").await;
    let owner_cookie = cookies(&owner);
    let reader_cookie = cookies(&reader);
    let created = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Tenant","slug":"tenant"})),
            &owner_cookie,
        ),
        200,
    )
    .await;
    let org = body(&created)["id"].as_str().unwrap().to_owned();
    _ = auth
        .store()
        .create_member(alibi::CreateMember::new(
            &org,
            body(&reader)["user"]["id"].as_str().unwrap(),
            "member",
        ))
        .await?;

    let admin = signup(&auth, "admin@example.test").await;
    _ = auth
        .store()
        .create_member(alibi::CreateMember::new(
            &org,
            body(&admin)["user"]["id"].as_str().unwrap(),
            "admin",
        ))
        .await?;
    let before = db
        .tables(&["api_keys", "users", "accounts", "sessions", "member"])
        .await?;
    let input = json!({"configId":"organization","organizationId":org,"name":"Issued"});
    let denied = call(
        &auth,
        request("/api-key/create", Some(input.clone()), &reader_cookie),
        403,
    )
    .await;
    assert_eq!(body(&denied)["code"], "INSUFFICIENT_API_KEY_PERMISSIONS");
    assert_eq!(
        db.tables(&["api_keys", "users", "accounts", "sessions", "member"])
            .await?,
        before
    );
    let issued = body(
        &call(
            &auth,
            request("/api-key/create", Some(input), &cookies(&admin)),
            200,
        )
        .await,
    );
    assert_eq!(issued["referenceId"], org);
    assert_eq!(issued["configId"], "organization");
    let verified = keys
        .verify_api_key(
            &VerifyApiKey {
                key: issued["key"].as_str().unwrap(),
                config_id: Some("organization"),
                permissions: None,
            },
            auth.context(),
        )
        .await;
    let verified = verified.unwrap();
    assert_eq!(verified.reference_id, org);
    assert_eq!(verified.id, issued["id"]);

    authenticated(&auth, &reader_cookie, "reader@example.test").await;
    B::close(connection).await
}

async fn static_org_reader_lists_only_tenant_keys_without_plaintext<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::organization::RolePermissions;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let keys = ApiKeyPlugin::with_config(ApiKeyConfig::default()).configuration(ApiKeyConfig {
        config_id: "organization".into(),
        references: ApiKeyReferences::Organization,
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            roles: Some(std::collections::HashMap::from([
                (
                    "owner".into(),
                    RolePermissions {
                        api_key: vec![
                            "create".into(),
                            "read".into(),
                            "update".into(),
                            "delete".into(),
                        ],
                        ..Default::default()
                    },
                ),
                (
                    "member".into(),
                    RolePermissions {
                        api_key: vec!["read".into()],
                        ..Default::default()
                    },
                ),
                (
                    "admin".into(),
                    RolePermissions {
                        api_key: vec!["create".into()],
                        ..Default::default()
                    },
                ),
                (
                    "updater".into(),
                    RolePermissions {
                        api_key: vec!["read".into(), "update".into()],
                        ..Default::default()
                    },
                ),
                (
                    "deleter".into(),
                    RolePermissions {
                        api_key: vec!["read".into(), "delete".into()],
                        ..Default::default()
                    },
                ),
            ])),
            ..Default::default()
        }))
        .plugin(keys.clone())
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let reader = signup(&auth, "reader@example.test").await;
    let owner_cookie = cookies(&owner);
    let reader_cookie = cookies(&reader);
    let created = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Tenant","slug":"tenant"})),
            &owner_cookie,
        ),
        200,
    )
    .await;
    let org = body(&created)["id"].as_str().unwrap().to_owned();
    _ = auth
        .store()
        .create_member(alibi::CreateMember::new(
            &org,
            body(&reader)["user"]["id"].as_str().unwrap(),
            "member",
        ))
        .await?;
    let first = call(
        &auth,
        request(
            "/api-key/create",
            Some(json!({"configId":"organization","organizationId":org,"name":"First"})),
            &owner_cookie,
        ),
        200,
    )
    .await;
    let first = body(&first);
    let second = call(
        &auth,
        request(
            "/api-key/create",
            Some(json!({"configId":"organization","organizationId":org,"name":"Second"})),
            &owner_cookie,
        ),
        200,
    )
    .await;
    let second = body(&second);

    _ = call(
        &auth,
        request(
            "/api-key/create",
            Some(json!({"name":"Personal"})),
            &owner_cookie,
        ),
        200,
    )
    .await;
    let foreign = body(
        &call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"Other","slug":"other"})),
                &owner_cookie,
            ),
            200,
        )
        .await,
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    _ = call(
        &auth,
        request(
            "/api-key/create",
            Some(json!({"configId":"organization","organizationId":foreign,"name":"Foreign"})),
            &owner_cookie,
        ),
        200,
    )
    .await;
    let before = db.tables(&["api_keys", "sessions", "member"]).await?;
    for explicit in [false, true] {
        let mut query = request("/api-key/list", None, &reader_cookie);
        _ = query.query.insert("organizationId".into(), org.clone());
        if explicit {
            _ = query.query.insert("configId".into(), "organization".into());
        }
        let listed = body(&call(&auth, query, 200).await);
        assert_eq!(listed["total"], 2);
        let rows = listed["apiKeys"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        for key in [&first, &second] {
            assert!(rows.iter().any(|row| row["id"] == key["id"]));
        }
        for row in rows {
            assert_eq!(row["referenceId"], org);
            assert!(row.get("key").is_none());
        }
    }
    let mut query = request("/api-key/list", None, &reader_cookie);
    query.set_query_pairs([
        ("organizationId", org.as_str()),
        ("configId", "organization"),
        ("sortBy", "name"),
        ("sortDirection", "asc"),
        ("limit", "1"),
        ("offset", "1"),
    ]);
    let page = body(&call(&auth, query.clone(), 200).await);
    assert_eq!(page["total"], 2);
    assert_eq!(page["apiKeys"].as_array().unwrap().len(), 1);
    assert_eq!(page["apiKeys"][0]["id"], second["id"]);
    assert!(page["apiKeys"][0].get("key").is_none());
    _ = query.query.insert("organizationId".into(), foreign);
    let denied = call(&auth, query, 403).await;
    assert_eq!(body(&denied)["code"], "USER_NOT_MEMBER_OF_ORGANIZATION");
    assert_eq!(
        db.tables(&["api_keys", "sessions", "member"]).await?,
        before
    );
    B::close(connection).await
}

async fn static_org_update_requires_update_action_and_preserves_key_identity<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::organization::RolePermissions;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let keys = ApiKeyPlugin::with_config(ApiKeyConfig::default()).configuration(ApiKeyConfig {
        config_id: "organization".into(),
        references: ApiKeyReferences::Organization,
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            roles: Some(std::collections::HashMap::from([
                (
                    "owner".into(),
                    RolePermissions {
                        api_key: vec![
                            "create".into(),
                            "read".into(),
                            "update".into(),
                            "delete".into(),
                        ],
                        ..Default::default()
                    },
                ),
                (
                    "member".into(),
                    RolePermissions {
                        api_key: vec!["read".into()],
                        ..Default::default()
                    },
                ),
                (
                    "admin".into(),
                    RolePermissions {
                        api_key: vec!["create".into()],
                        ..Default::default()
                    },
                ),
                (
                    "updater".into(),
                    RolePermissions {
                        api_key: vec!["read".into(), "update".into()],
                        ..Default::default()
                    },
                ),
                (
                    "deleter".into(),
                    RolePermissions {
                        api_key: vec!["read".into(), "delete".into()],
                        ..Default::default()
                    },
                ),
            ])),
            ..Default::default()
        }))
        .plugin(keys.clone())
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let reader = signup(&auth, "reader@example.test").await;
    let owner_cookie = cookies(&owner);
    let reader_cookie = cookies(&reader);
    let created = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Tenant","slug":"tenant"})),
            &owner_cookie,
        ),
        200,
    )
    .await;
    let org = body(&created)["id"].as_str().unwrap().to_owned();
    _ = auth
        .store()
        .create_member(alibi::CreateMember::new(
            &org,
            body(&reader)["user"]["id"].as_str().unwrap(),
            "member",
        ))
        .await?;
    let selected = call(
        &auth,
        request(
            "/api-key/create",
            Some(json!({"configId":"organization","organizationId":org,"name":"selected"})),
            &owner_cookie,
        ),
        200,
    )
    .await;
    let selected = body(&selected);

    let updater = signup(&auth, "updater@example.test").await;
    _ = auth
        .store()
        .create_member(alibi::CreateMember::new(
            &org,
            body(&updater)["user"]["id"].as_str().unwrap(),
            "updater",
        ))
        .await?;
    let before = db
        .tables(&["api_keys", "users", "sessions", "member"])
        .await?;
    let input = json!({"configId":"organization","keyId":selected["id"],"name":"Granted update"});
    let denied = call(
        &auth,
        request("/api-key/update", Some(input.clone()), &reader_cookie),
        403,
    )
    .await;
    assert_eq!(body(&denied)["code"], "INSUFFICIENT_API_KEY_PERMISSIONS");
    assert_eq!(
        db.tables(&["api_keys", "users", "sessions", "member"])
            .await?,
        before
    );
    let verified = keys
        .verify_api_key(
            &VerifyApiKey {
                key: selected["key"].as_str().unwrap(),
                config_id: Some("organization"),
                permissions: None,
            },
            auth.context(),
        )
        .await;
    let verified = verified.unwrap();
    assert_eq!(verified.reference_id, org);
    assert_eq!(verified.id, selected["id"]);

    _ = call(
        &auth,
        request("/api-key/update", Some(input), &cookies(&updater)),
        200,
    )
    .await;
    let mut query = request("/api-key/get", None, &reader_cookie);
    query.set_query_pairs([
        ("id", selected["id"].as_str().unwrap()),
        ("configId", "organization"),
    ]);
    let view = body(&call(&auth, query, 200).await);
    assert_eq!(view["id"], selected["id"]);
    assert_eq!(view["referenceId"], org);
    assert_eq!(view["configId"], "organization");
    assert_eq!(view["name"], "Granted update");
    let verified = keys
        .verify_api_key(
            &VerifyApiKey {
                key: selected["key"].as_str().unwrap(),
                config_id: Some("organization"),
                permissions: None,
            },
            auth.context(),
        )
        .await;
    let verified = verified.unwrap();
    assert_eq!(verified.reference_id, org);
    assert_eq!(verified.id, selected["id"]);

    B::close(connection).await
}

async fn static_org_delete_requires_delete_action_and_revokes_only_selected_key<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::organization::RolePermissions;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let keys = ApiKeyPlugin::with_config(ApiKeyConfig::default()).configuration(ApiKeyConfig {
        config_id: "organization".into(),
        references: ApiKeyReferences::Organization,
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            roles: Some(std::collections::HashMap::from([
                (
                    "owner".into(),
                    RolePermissions {
                        api_key: vec![
                            "create".into(),
                            "read".into(),
                            "update".into(),
                            "delete".into(),
                        ],
                        ..Default::default()
                    },
                ),
                (
                    "member".into(),
                    RolePermissions {
                        api_key: vec!["read".into()],
                        ..Default::default()
                    },
                ),
                (
                    "admin".into(),
                    RolePermissions {
                        api_key: vec!["create".into()],
                        ..Default::default()
                    },
                ),
                (
                    "updater".into(),
                    RolePermissions {
                        api_key: vec!["read".into(), "update".into()],
                        ..Default::default()
                    },
                ),
                (
                    "deleter".into(),
                    RolePermissions {
                        api_key: vec!["read".into(), "delete".into()],
                        ..Default::default()
                    },
                ),
            ])),
            ..Default::default()
        }))
        .plugin(keys.clone())
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let reader = signup(&auth, "reader@example.test").await;
    let owner_cookie = cookies(&owner);
    let reader_cookie = cookies(&reader);
    let created = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Tenant","slug":"tenant"})),
            &owner_cookie,
        ),
        200,
    )
    .await;
    let org = body(&created)["id"].as_str().unwrap().to_owned();
    _ = auth
        .store()
        .create_member(alibi::CreateMember::new(
            &org,
            body(&reader)["user"]["id"].as_str().unwrap(),
            "member",
        ))
        .await?;
    let selected = call(
        &auth,
        request(
            "/api-key/create",
            Some(json!({"configId":"organization","organizationId":org,"name":"selected"})),
            &owner_cookie,
        ),
        200,
    )
    .await;
    let selected = body(&selected);
    let sibling = call(
        &auth,
        request(
            "/api-key/create",
            Some(json!({"configId":"organization","organizationId":org,"name":"sibling"})),
            &owner_cookie,
        ),
        200,
    )
    .await;
    let sibling = body(&sibling);

    let deleter = signup(&auth, "deleter@example.test").await;
    _ = auth
        .store()
        .create_member(alibi::CreateMember::new(
            &org,
            body(&deleter)["user"]["id"].as_str().unwrap(),
            "deleter",
        ))
        .await?;
    let before = db.tables(&["api_keys", "sessions", "member"]).await?;
    let input = json!({"configId":"organization","keyId":selected["id"]});
    let denied = call(
        &auth,
        request("/api-key/delete", Some(input.clone()), &reader_cookie),
        403,
    )
    .await;
    assert_eq!(body(&denied)["code"], "INSUFFICIENT_API_KEY_PERMISSIONS");
    assert_eq!(
        db.tables(&["api_keys", "sessions", "member"]).await?,
        before
    );
    let verified = keys
        .verify_api_key(
            &VerifyApiKey {
                key: selected["key"].as_str().unwrap(),
                config_id: Some("organization"),
                permissions: None,
            },
            auth.context(),
        )
        .await;
    let verified = verified.unwrap();
    assert_eq!(verified.reference_id, org);
    assert_eq!(verified.id, selected["id"]);

    let mut query = request("/api-key/get", None, &reader_cookie);
    query.set_query_pairs([
        ("id", sibling["id"].as_str().unwrap()),
        ("configId", "organization"),
    ]);
    let sibling_before = body(&call(&auth, query.clone(), 200).await);
    _ = call(
        &auth,
        request("/api-key/delete", Some(input), &cookies(&deleter)),
        200,
    )
    .await;
    assert_eq!(body(&call(&auth, query.clone(), 200).await), sibling_before);
    _ = query
        .query
        .insert("id".into(), selected["id"].as_str().unwrap().into());
    let missing = call(&auth, query, 404).await;
    assert_eq!(body(&missing)["code"], "KEY_NOT_FOUND");
    let verified = keys
        .verify_api_key(
            &VerifyApiKey {
                key: selected["key"].as_str().unwrap(),
                config_id: Some("organization"),
                permissions: None,
            },
            auth.context(),
        )
        .await;
    assert!(verified.is_err());
    let verified = keys
        .verify_api_key(
            &VerifyApiKey {
                key: sibling["key"].as_str().unwrap(),
                config_id: Some("organization"),
                permissions: None,
            },
            auth.context(),
        )
        .await;
    let verified = verified.unwrap();
    assert_eq!(verified.reference_id, org);
    assert_eq!(verified.id, sibling["id"]);

    authenticated(&auth, &owner_cookie, "owner@example.test").await;
    B::close(connection).await
}

async fn disabled_custom_key_expiration_retains_default_lifetime_through_rename<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
            key_expiration: KeyExpirationConfig {
                disable_custom_expires_time: true,
                default_expires_in: Some(120.0),
                ..Default::default()
            },
            rate_limit: RateLimitDefaults {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let cookie = cookies(&owner);
    let rejected = call(
        &auth,
        request(
            "/api-key/create",
            Some(json!({"name":"Rejected","expiresIn":60})),
            &cookie,
        ),
        400,
    )
    .await;
    assert_eq!(body(&rejected)["code"], "KEY_DISABLED_EXPIRATION");
    assert_eq!(db.count("api_keys").await?, 0);
    let start = chrono::Utc::now();
    let created = body(
        &call(
            &auth,
            request(
                "/api-key/create",
                Some(json!({"name":"Default expiry"})),
                &cookie,
            ),
            200,
        )
        .await,
    );
    let end = chrono::Utc::now();
    let expires = chrono::DateTime::parse_from_rfc3339(created["expiresAt"].as_str().unwrap())?
        .with_timezone(&chrono::Utc);
    assert!(expires >= start + chrono::Duration::seconds(120) - chrono::Duration::milliseconds(1));
    assert!(expires <= end + chrono::Duration::seconds(120));
    let before = db.table("api_keys").await?;
    let rejected = call(
        &auth,
        request(
            "/api-key/update",
            Some(json!({"keyId":created["id"],"expiresIn":60})),
            &cookie,
        ),
        400,
    )
    .await;
    assert_eq!(body(&rejected)["code"], "KEY_DISABLED_EXPIRATION");
    assert_eq!(db.table("api_keys").await?, before);
    let id = created["id"].as_str().unwrap();
    let hash = db
        .text("SELECT key FROM api_keys WHERE id=$1", &[id])
        .await?;
    let physical_expiry = db
        .text("SELECT expires_at FROM api_keys WHERE id=$1", &[id])
        .await?;
    let renamed = body(
        &call(
            &auth,
            request(
                "/api-key/update",
                Some(json!({"keyId":id,"name":"Renamed"})),
                &cookie,
            ),
            200,
        )
        .await,
    );
    assert_eq!(renamed["id"], created["id"]);
    assert_eq!(renamed["expiresAt"], created["expiresAt"]);
    assert_eq!(renamed["name"], "Renamed");
    assert_eq!(
        db.text("SELECT key FROM api_keys WHERE id=$1", &[id])
            .await?,
        hash
    );
    assert_eq!(
        db.text("SELECT expires_at FROM api_keys WHERE id=$1", &[id])
            .await?,
        physical_expiry
    );
    assert_eq!(db.count("api_keys").await?, 1);
    authenticated(&auth, &cookie, "owner@example.test").await;
    B::close(connection).await
}

async fn banned_api_key_owner_can_verify_but_cannot_use_synthetic_deletion_authority<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let keys = ApiKeyPlugin::with_config(ApiKeyConfig {
        enable_session_for_api_keys: true,
        rate_limit: RateLimitDefaults {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(alibi::plugins::AdminPlugin::new())
        .plugin(keys.clone())
        .build()
        .await?;
    let admin = signup(&auth, "admin@example.test").await;
    let admin_id = body(&admin)["user"]["id"].as_str().unwrap().to_owned();
    _ = auth
        .store()
        .update_user(
            &admin_id,
            alibi::UpdateUser {
                role: Some("admin".into()),
                ..Default::default()
            },
        )
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let created = body(
        &call(
            &auth,
            request(
                "/api-key/create",
                Some(json!({"name":"Owned key"})),
                &cookies(&owner),
            ),
            200,
        )
        .await,
    );
    let id = created["id"].as_str().unwrap();
    let secret = created["key"].as_str().unwrap();
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let hash = db
        .text("SELECT key FROM api_keys WHERE id=$1", &[id])
        .await?;
    assert!(
        keys.verify_api_key(
            &VerifyApiKey {
                key: secret,
                config_id: None,
                permissions: None
            },
            auth.context()
        )
        .await
        .is_ok()
    );
    _ = call(
        &auth,
        request(
            "/admin/ban-user",
            Some(json!({"userId":owner_id,"banReason":"Key test ban"})),
            &cookies(&admin),
        ),
        200,
    )
    .await;
    assert!(
        keys.verify_api_key(
            &VerifyApiKey {
                key: secret,
                config_id: None,
                permissions: None
            },
            auth.context()
        )
        .await
        .is_ok()
    );
    let mut input = request("/api-key/delete", Some(json!({"keyId":id})), "");
    _ = input.headers.insert("x-api-key".into(), secret.into());
    let denied = call(&auth, input, 401).await;
    assert_eq!(body(&denied)["code"], "USER_BANNED");
    assert!(!denied.headers.contains_key("set-cookie"));
    assert_eq!(
        db.text("SELECT key FROM api_keys WHERE id=$1", &[id])
            .await?,
        hash
    );
    assert_eq!(
        db.text("SELECT reference_id FROM api_keys WHERE id=$1", &[id])
            .await?
            .as_deref(),
        Some(owner_id.as_str())
    );
    assert_eq!(db.count("sessions").await?, 2);
    _ = call(
        &auth,
        request(
            "/admin/unban-user",
            Some(json!({"userId":owner_id})),
            &cookies(&admin),
        ),
        200,
    )
    .await;
    assert!(
        keys.verify_api_key(
            &VerifyApiKey {
                key: secret,
                config_id: None,
                permissions: None
            },
            auth.context()
        )
        .await
        .is_ok()
    );
    _ = call(
        &auth,
        request(
            "/admin/remove-user",
            Some(json!({"userId":owner_id})),
            &cookies(&admin),
        ),
        200,
    )
    .await;
    let mut input = request("/get-session", None, "");
    _ = input.headers.insert("x-api-key".into(), secret.into());
    let orphan = call(&auth, input, 401).await;
    assert_eq!(body(&orphan)["code"], "INVALID_REFERENCE_ID_FROM_API_KEY");
    assert!(!orphan.headers.contains_key("set-cookie"));
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    authenticated(&auth, &cookies(&admin), "admin@example.test").await;
    B::close(connection).await
}

async fn api_key_builtin_fractional_generation<B: Backend>(db: Db) -> TestResult {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest as _, Sha256};
    for (length, expected) in [
        (0.5, Some(1)),
        (2.5, Some(3)),
        (0.0, Some(64)),
        (f64::NAN, Some(64)),
        (-1.0, None),
        (f64::NEG_INFINITY, None),
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
                key_length: length,
                prefix: Some("gen_".into()),
                ..Default::default()
            }))
            .build()
            .await?;
        let owner = signup(&auth, "builtin@example.test").await;
        let before = db
            .tables(&["users", "accounts", "sessions", "api_keys"])
            .await?;
        let response = call(
            &auth,
            request(
                "/api-key/create",
                Some(json!({"name":"Builtin"})),
                &cookies(&owner),
            ),
            if expected.is_some() { 200 } else { 500 },
        )
        .await;
        if let Some(expected) = expected {
            let key = body(&response)["key"].as_str().unwrap().to_owned();
            let suffix = key.strip_prefix("gen_").unwrap();
            assert_eq!(suffix.len(), expected);
            assert!(suffix.bytes().all(|byte| byte.is_ascii_alphabetic()));
            assert_eq!(
                db.text("SELECT key FROM api_keys", &[]).await?.as_deref(),
                Some(
                    URL_SAFE_NO_PAD
                        .encode(Sha256::digest(key.as_bytes()))
                        .as_str()
                )
            );
            assert_eq!(body(&response)["referenceId"], body(&owner)["user"]["id"]);
            assert_eq!(db.count("api_keys").await?, 1);
        } else {
            assert!(response.body.is_empty());
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "api_keys"])
                    .await?,
                before
            );
        }
        B::close(connection).await?;
    }
    struct Generator(Mutex<Vec<(String, Option<String>)>>);
    #[async_trait::async_trait]
    impl ApiKeyGenerator for Generator {
        async fn generate_key(&self, o: &ApiKeyGenerationOptions<'_>) -> AuthResult<String> {
            self.0
                .lock()
                .unwrap()
                .push((o.length.to_string(), o.prefix.map(str::to_owned)));
            Ok("application-owned-secret-material".into())
        }
    }
    for (length, expected) in [
        (0.25, "0.25"),
        (f64::INFINITY, "inf"),
        (f64::NEG_INFINITY, "-inf"),
        (f64::NAN, "64"),
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let generator = Arc::new(Generator(Mutex::new(Vec::new())));
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
                key_length: length,
                prefix: Some("gen_".into()),
                custom_key_generator: Some(generator.clone()),
                ..Default::default()
            }))
            .build()
            .await?;
        let owner = signup(&auth, "custom-length@example.test").await;
        let created = call(
            &auth,
            request("/api-key/create", Some(json!({})), &cookies(&owner)),
            200,
        )
        .await;
        assert_eq!(body(&created)["key"], "application-owned-secret-material");
        assert_eq!(
            *generator.0.lock().unwrap(),
            [(expected.into(), Some("gen_".into()))]
        );
        assert_eq!(
            db.text("SELECT key FROM api_keys", &[]).await?.as_deref(),
            Some(
                URL_SAFE_NO_PAD
                    .encode(Sha256::digest(b"application-owned-secret-material"))
                    .as_str()
            )
        );
        B::close(connection).await?;
    }
    Ok(())
}

async fn api_key_raw_default_expiration<B: Backend>(db: Db) -> TestResult {
    struct Generator(std::sync::atomic::AtomicUsize);
    #[async_trait::async_trait]
    impl ApiKeyGenerator for Generator {
        async fn generate_key(&self, _: &ApiKeyGenerationOptions<'_>) -> AuthResult<String> {
            _ = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok("default-expiry-secret-material".into())
        }
    }
    for expiry in [
        60.125,
        0.0,
        f64::NAN,
        -3600.125,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let generator = Arc::new(Generator(std::sync::atomic::AtomicUsize::new(0)));
        let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
            custom_key_generator: Some(generator.clone()),
            defer_updates: false,
            key_expiration: KeyExpirationConfig {
                default_expires_in: Some(expiry),
                ..Default::default()
            },
            ..Default::default()
        });
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(plugin.clone())
            .build()
            .await?;
        let owner = signup(&auth, "default-expiry@example.test").await;
        let before = db
            .tables(&["users", "accounts", "sessions", "api_keys"])
            .await?;
        let response = call(
            &auth,
            request("/api-key/create", Some(json!({})), &cookies(&owner)),
            if expiry.is_infinite() { 500 } else { 200 },
        )
        .await;
        assert_eq!(generator.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        if expiry.is_infinite() {
            assert!(response.body.is_empty());
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "api_keys"])
                    .await?,
                before
            );
        } else if expiry == 0.0 || expiry.is_nan() {
            assert!(body(&response)["expiresAt"].is_null());
            assert!(
                db.text("SELECT expires_at FROM api_keys", &[])
                    .await?
                    .is_none()
            );
        } else {
            let issued = body(&response);
            let created =
                chrono::DateTime::parse_from_rfc3339(issued["createdAt"].as_str().unwrap())?;
            let expires =
                chrono::DateTime::parse_from_rfc3339(issued["expiresAt"].as_str().unwrap())?;
            let millis = (expires - created).num_milliseconds();
            if expiry.is_sign_positive() {
                assert!((60_100..=60_175).contains(&millis), "{millis}");
            } else {
                assert!((-3_600_150..=-3_600_100).contains(&millis), "{millis}");
                let rejected = plugin
                    .verify_api_key(
                        &VerifyApiKey {
                            key: issued["key"].as_str().unwrap(),
                            config_id: Some("default"),
                            permissions: None,
                        },
                        auth.context(),
                    )
                    .await
                    .unwrap_err();
                match rejected {
                    ApiKeyVerificationError::Validation(error) => {
                        assert_eq!(serde_json::to_value(error)?["code"], "KEY_EXPIRED")
                    }
                    _ => panic!("expiry must reject as KEY_EXPIRED"),
                }
                assert_eq!(db.count("api_keys").await?, 0);
            }
        }
        B::close(connection).await?;
    }
    Ok(())
}
