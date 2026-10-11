//! An application grant layered over the device-code lifecycle: request
//! validation, OpenAPI extension, review context and atomic redemption.
use super::*;
use alibi::plugins::device_authorization::{
    DeviceAuthorizationGrant, DeviceGrantAuthorization, DeviceGrantFailure, DeviceGrantRecord,
    DeviceRedemptionAuthorization, DeviceRedemptionPolicy, redeem_device_code,
};
use alibi::plugins::{DeviceAuthorizationPlugin, OpenApiPlugin};
use alibi::{AuthContext, AuthPlugin, AuthRoute, AuthUser};
use alibi::{AuthError, AuthResult};
use serde_json::Map;

backend_tests!(
    application_grant_lifecycle,
    device_decision_and_issuance_edges,
    device_missing_owner_preserves_approved_grant_for_recovery,
    device_empty_application_codes_complete_real_grant,
    device_fractional_durations_preserve_persisted_milliseconds,
    revoked_compact_browser_claims_and_completes_only_its_device_grant,
    device_poller_session_metadata,
    device_overlapping_reviews_retain_first_claim_authority,
    device_custom_user_codes_prefer_exact_lookup,
    device_user_code_collision_retries_without_replacing_grant,
    device_issuance_retains_prebound_owner_authority,
    device_application_result_owns_consumed_receipt_identity
);

type Events = Arc<Mutex<Vec<Value>>>;

fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap()
}

struct Grant(Events);

#[async_trait::async_trait]
impl DeviceAuthorizationGrant for Grant {
    fn request_schema_fields(&self) -> Map<String, Value> {
        object(json!({
            "audience": {"type": "string", "minLength": 1},
            "nonce": {"type": "string", "minLength": 1},
        }))
    }

    fn on_request_validation_error(&self, issues: &[String]) -> DeviceGrantFailure {
        self.0
            .lock()
            .unwrap()
            .push(json!({"phase": "validation", "issueCount": issues.len()}));
        DeviceGrantFailure::oauth(
            400,
            "application_invalid_request",
            "Application audience and nonce are required",
        )
    }

    async fn authorize_request(
        &self,
        request: &Map<String, Value>,
        _: &AuthRequest,
    ) -> Result<DeviceGrantAuthorization, DeviceGrantFailure> {
        self.0.lock().unwrap().push(json!({"phase": "authorize"}));
        if request["audience"] != "application-api" {
            return Err(DeviceGrantFailure::oauth(
                422,
                "invalid_audience",
                "Audience is not allowed",
            ));
        }
        Ok(DeviceGrantAuthorization {
            client_id: "application-client".into(),
            user_id: None,
            fields: object(
                json!({"grantAudience": request["audience"], "grantNonce": request["nonce"]}),
            ),
        })
    }

    async fn assert_session_redemption(
        &self,
        _: &DeviceGrantRecord,
    ) -> Result<(), DeviceGrantFailure> {
        self.0
            .lock()
            .unwrap()
            .push(json!({"phase": "session-redemption"}));
        Err(DeviceGrantFailure::oauth(
            400,
            "invalid_grant",
            "Application grant cannot issue a standalone session",
        ))
    }

    async fn verification_context(
        &self,
        record: &DeviceGrantRecord,
    ) -> AuthResult<Map<String, Value>> {
        self.0
            .lock()
            .unwrap()
            .push(json!({"phase": "verification"}));
        Ok(object(json!({
            "audience": record.fields["grantAudience"],
            "nonce": record.fields["grantNonce"],
        })))
    }

    fn device_code_schema_fields(&self) -> Vec<alibi::OpenApiField> {
        vec![alibi::OpenApiField::new(
            "grantAudience",
            json!({"type": "string"}),
            false,
        )]
    }

    fn request_error_codes(&self) -> Vec<String> {
        vec!["invalid_audience".into()]
    }

    fn request_openapi_responses(&self) -> Map<String, Value> {
        object(json!({"422": {"description": "Application audience rejected"}}))
    }

    fn verification_openapi_properties(&self) -> Map<String, Value> {
        object(json!({"audience": {"type": "string"}, "nonce": {"type": "string"}}))
    }
}

struct Policy {
    nonce: Value,
    reject_preparation: bool,
}

#[async_trait::async_trait]
impl DeviceRedemptionPolicy for Policy {
    async fn authorize(
        &self,
        record: &DeviceGrantRecord,
    ) -> AuthResult<DeviceRedemptionAuthorization> {
        Ok(DeviceRedemptionAuthorization {
            ownership: object(json!({"grantNonce": self.nonce})),
            context: json!({"nonce": record.fields["grantNonce"]}),
        })
    }

    async fn prepare(&self, record: &DeviceGrantRecord, _: &Value) -> AuthResult<Value> {
        if self.reject_preparation {
            return Err(AuthError::Api {
                status: 403,
                code: Some("APPLICATION_PREPARE_REJECTED".into()),
                message: "Application preparation rejected".into(),
            });
        }
        Ok(json!({"audience": record.fields["grantAudience"]}))
    }
}

/// Redeems an approved grant on behalf of the application.
struct ApplicationToken;

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for ApplicationToken {
    fn name(&self) -> &'static str {
        "application-token"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::post(
            "/device/application-token",
            "application_token",
        )]
    }

    async fn on_request(
        &self,
        request: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let input: Value = request.body_as_json()?;
        let policy = Policy {
            nonce: input["claimNonce"].clone(),
            reject_preparation: input["prepareFailure"] == true,
        };
        let code = input["device_code"].as_str().unwrap_or_default();
        match redeem_device_code(ctx, code, &policy).await {
            Ok(result) => Ok(Some(AuthResponse::json(
                200,
                &json!({
                    "userId": result.user.id(),
                    "audience": result.redemption_context["audience"],
                    "nonce": result.authorization_context["nonce"],
                }),
            )?)),
            Err(failure) => failure.into_response().map(Some),
        }
    }
}

fn get(path: &str, query: &[(&str, &str)], cookie: &str) -> AuthRequest {
    let mut request = request(path, None, cookie);
    request.set_query_pairs(query.iter().copied());
    request
}

async fn rows(db: &Db, code: &str) -> TestResult<i64> {
    db.count_where(
        "SELECT COUNT(*) FROM device_code WHERE device_code = $1",
        &[code],
    )
    .await
}

async fn application_grant_lifecycle<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let events = Events::default();
    let auth = builder::<B>(&connection)
        .plugin(
            DeviceAuthorizationPlugin::new()
                .interval(chrono::Duration::zero())
                .grant(Grant(Arc::clone(&events))),
        )
        .plugin(ApplicationToken)
        .plugin(OpenApiPlugin::new())
        .build()
        .await?;

    let missing = call(
        &auth,
        request("/device/code", Some(json!({"nonce": "n"})), ""),
        400,
    )
    .await;
    assert_eq!(body(&missing)["error"], "application_invalid_request");
    let wrong_type = call(
        &auth,
        request(
            "/device/code",
            Some(json!({"audience": "application-api", "nonce": "n", "scope": 1})),
            "",
        ),
        400,
    )
    .await;
    assert_eq!(body(&wrong_type)["error"], "application_invalid_request");
    let denied = call(
        &auth,
        request(
            "/device/code",
            Some(json!({"audience": "foreign-api", "nonce": "n"})),
            "",
        ),
        422,
    )
    .await;
    assert_eq!(body(&denied)["error"], "invalid_audience");
    assert_eq!(
        denied.headers.get("cache-control").map(String::as_str),
        Some("no-store")
    );
    assert_eq!(db.count("device_code").await?, 0);
    assert_eq!(
        *events.lock().unwrap(),
        [
            json!({"phase": "validation", "issueCount": 1}),
            json!({"phase": "validation", "issueCount": 1}),
            json!({"phase": "authorize"}),
        ]
    );

    let schema = body(&call(&auth, get("/open-api/generate-schema", &[], ""), 200).await);
    let issuance = &schema["paths"]["/device/code"]["post"];
    assert_eq!(
        issuance["responses"]["422"]["description"],
        "Application audience rejected"
    );
    let properties = &issuance["requestBody"]["content"]["application/json"]["schema"];
    for field in ["audience", "nonce", "scope", "client_id", "user_id"] {
        assert!(properties["properties"].get(field).is_some(), "{field}");
    }
    assert_eq!(properties["required"], json!(["audience", "nonce"]));
    let review_properties = &schema["paths"]["/device"]["get"]["responses"]["200"]["content"]["application/json"]
        ["schema"]["properties"];
    assert!(review_properties.get("audience").is_some());
    assert!(review_properties.get("nonce").is_some());

    let owner = cookies(&signup(&auth, "grant-owner@example.com").await);
    let user_id =
        body(&call(&auth, request("/get-session", None, &owner), 200).await)["user"]["id"].clone();
    let issue = async |nonce: &str| {
        let issued = call(
            &auth,
            request(
                "/device/code",
                Some(json!({"audience": "application-api", "nonce": nonce, "scope": "read"})),
                &owner,
            ),
            200,
        )
        .await;
        assert_eq!(
            issued.headers.get("pragma").map(String::as_str),
            Some("no-cache")
        );
        let issued = body(&issued);
        (
            issued["device_code"].as_str().unwrap().to_owned(),
            issued["user_code"].as_str().unwrap().to_owned(),
        )
    };
    let decide = async |decision: &str, user_code: &str| {
        _ = call(
            &auth,
            get("/device", &[("user_code", user_code)], &owner),
            200,
        )
        .await;
        call(
            &auth,
            request(
                &format!("/device/{decision}"),
                Some(json!({"userCode": user_code})),
                &owner,
            ),
            200,
        )
        .await
    };
    let redeem = async |code: &str, nonce: &str, prepare_failure: bool, status: u16| {
        body(
            &call(
                &auth,
                request(
                    "/device/application-token",
                    Some(json!({
                        "device_code": code,
                        "claimNonce": nonce,
                        "prepareFailure": prepare_failure,
                    })),
                    "",
                ),
                status,
            )
            .await,
        )
    };

    events.lock().unwrap().clear();
    let issued = call(
        &auth,
        request(
            "/device/code",
            Some(json!({"audience": "application-api", "nonce": "owned", "scope": "read"})),
            &owner,
        ),
        200,
    )
    .await;
    let issued = body(&issued);
    let code = issued["device_code"].as_str().unwrap();
    let user_code = issued["user_code"].as_str().unwrap();
    assert_eq!(
        db.text(
            "SELECT client_id FROM device_code WHERE device_code = $1",
            &[code]
        )
        .await?
        .as_deref(),
        Some("application-client")
    );
    let guest_view = body(&call(&auth, get("/device", &[("user_code", user_code)], ""), 200).await);
    assert!(guest_view.get("audience").is_none());
    let review = body(
        &call(
            &auth,
            get("/device", &[("user_code", user_code)], &owner),
            200,
        )
        .await,
    );
    assert_eq!(review["audience"], "application-api");
    assert_eq!(review["nonce"], "owned");
    _ = decide("approve", user_code).await;
    let standalone = call(
        &auth,
        request(
            "/device/token",
            Some(json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": code,
                "client_id": "application-client",
            })),
            "",
        ),
        400,
    )
    .await;
    assert_eq!(body(&standalone)["error"], "invalid_grant");
    assert_eq!(rows(&db, code).await?, 1);
    assert_eq!(
        redeem(code, "owned", false, 200).await,
        json!({"userId": user_id, "audience": "application-api", "nonce": "owned"})
    );
    assert_eq!(rows(&db, code).await?, 0);
    assert_eq!(
        redeem(code, "owned", false, 400).await["error"],
        "invalid_grant"
    );
    assert_eq!(
        events
            .lock()
            .unwrap()
            .iter()
            .map(|event| event["phase"].clone())
            .collect::<Vec<_>>(),
        [
            "authorize",
            "verification",
            "verification",
            "session-redemption"
        ]
    );

    let (code, user_code) = issue("denial").await;
    assert_eq!(
        redeem(&code, "denial", false, 400).await["error"],
        "authorization_pending"
    );
    _ = decide("approve", &user_code).await;
    let rejected = redeem(&code, "denial", true, 403).await;
    assert_eq!(rejected["code"], "APPLICATION_PREPARE_REJECTED");
    assert_eq!(rows(&db, &code).await?, 1);
    assert_eq!(
        redeem(&code, "foreign-owner", false, 400).await["error"],
        "invalid_grant"
    );
    assert_eq!(rows(&db, &code).await?, 1);
    db.set_timestamp(
        "device_code",
        "expires_at",
        ("device_code", &code),
        chrono::Utc::now() - chrono::Duration::minutes(1),
    )
    .await?;
    assert_eq!(
        redeem(&code, "denial", false, 400).await["error"],
        "expired_token"
    );
    assert_eq!(rows(&db, &code).await?, 0);
    assert_eq!(
        redeem("unknown", "denial", false, 400).await["error"],
        "invalid_grant"
    );

    let (code, user_code) = issue("declined").await;
    _ = decide("deny", &user_code).await;
    assert_eq!(
        redeem(&code, "declined", false, 400).await["error"],
        "access_denied"
    );
    assert_eq!(rows(&db, &code).await?, 0);
    B::close(connection).await
}

async fn device_decision_and_issuance_edges<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(
            DeviceAuthorizationPlugin::new()
                .interval(chrono::Duration::zero())
                .device_code_length(12)
                .user_code_length(6)
                .verification_uri("https://app.example/device?user_code=old&x=1&user_code=dup"),
        )
        .build()
        .await?;
    for (value, received) in [(json!(null), "null"), (json!(true), "boolean")] {
        let rejected = call(
            &auth,
            request("/device/code", Some(json!({"client_id": value})), ""),
            400,
        )
        .await;
        assert_eq!(
            body(&rejected)["error_description"],
            format!("[body.client_id] Invalid input: expected string, received {received}")
        );
    }
    let issued = body(
        &call(
            &auth,
            request("/device/code", Some(json!({"client_id": "edge"})), ""),
            200,
        )
        .await,
    );
    let code = issued["device_code"].as_str().unwrap().to_owned();
    let user_code = issued["user_code"].as_str().unwrap().to_owned();
    assert_eq!((code.len(), user_code.len()), (12, 6));
    assert_eq!(
        issued["verification_uri_complete"],
        format!("https://app.example/device?user_code={user_code}&x=1")
    );

    let owner = cookies(&signup(&auth, "device-edges@example.com").await);
    let mut wrong_media = request(
        "/device/approve",
        Some(json!({"userCode": user_code})),
        &owner,
    );
    _ = wrong_media
        .headers
        .insert("content-type".into(), "text/plain".into());
    let wrong_media = call(&auth, wrong_media, 415).await;
    assert_eq!(body(&wrong_media)["code"], "UNSUPPORTED_MEDIA_TYPE");
    let mut review = request("/device", None, &owner);
    review.set_query_pairs([("user_code", user_code.as_str())]);
    _ = call(&auth, review, 200).await;
    _ = call(
        &auth,
        request(
            "/device/approve",
            Some(json!({"userCode": user_code})),
            &owner,
        ),
        200,
    )
    .await;
    _ = db.execute("DELETE FROM sessions", &[]).await?;
    _ = db.execute("DELETE FROM accounts", &[]).await?;
    _ = db.execute("DELETE FROM users", &[]).await?;
    let orphaned = call(
        &auth,
        request(
            "/device/token",
            Some(json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": code,
                "client_id": "edge",
            })),
            "",
        ),
        500,
    )
    .await;
    assert_eq!(body(&orphaned)["error"], "server_error");

    let owner = cookies(&signup(&auth, "device-expiry@example.com").await);
    let issued = body(
        &call(
            &auth,
            request("/device/code", Some(json!({"client_id": "edge"})), ""),
            200,
        )
        .await,
    );
    let user_code = issued["user_code"].as_str().unwrap();
    db.set_timestamp(
        "device_code",
        "expires_at",
        ("user_code", user_code),
        chrono::Utc::now() - chrono::Duration::minutes(1),
    )
    .await?;
    let expired = call(
        &auth,
        request("/device/deny", Some(json!({"userCode": user_code})), &owner),
        400,
    )
    .await;
    assert_eq!(body(&expired)["error"], "expired_token");
    B::close(connection).await
}

async fn device_missing_owner_preserves_approved_grant_for_recovery<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(DeviceAuthorizationPlugin::new().interval(chrono::Duration::zero()))
        .plugin(alibi::plugins::BearerPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let issue = body(
        &call(
            &auth,
            request(
                "/device/code",
                Some(json!({"client_id":"recover","scope":"read"})),
                "",
            ),
            200,
        )
        .await,
    );
    let code = issue["device_code"].as_str().unwrap();
    let user_code = issue["user_code"].as_str().unwrap();
    _ = call(
        &auth,
        get("/device", &[("user_code", user_code)], &cookies(&owner)),
        200,
    )
    .await;
    _ = call(
        &auth,
        request(
            "/device/approve",
            Some(json!({"userCode":user_code})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let grant = auth
        .store()
        .get_device_code_by_device_code(code)
        .await?
        .unwrap();
    _ = auth
        .store()
        .update_device_code(
            &grant.id,
            alibi::UpdateDeviceCode {
                user_id: Some(Some("11111111-1111-4111-8111-111111111111".into())),
                ..Default::default()
            },
        )
        .await?;
    let orphan = auth
        .store()
        .get_device_code_by_device_code(code)
        .await?
        .unwrap();
    let stable = db.tables(&["users", "accounts", "sessions"]).await?;
    let redemption = || {
        request(
            "/device/token",
            Some(
                json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":code,"client_id":"recover"}),
            ),
            "",
        )
    };
    let denied = call(&auth, redemption(), 500).await;
    assert_eq!(
        body(&denied),
        json!({"error":"server_error","error_description":"User not found"})
    );
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, stable);
    let retained = auth
        .store()
        .get_device_code_by_device_code(code)
        .await?
        .unwrap();
    assert!(retained.last_polled_at.is_some());
    let mut before = serde_json::to_value(&orphan)?;
    let mut after = serde_json::to_value(&retained)?;
    _ = before.as_object_mut().unwrap().remove("lastPolledAt");
    _ = after.as_object_mut().unwrap().remove("lastPolledAt");
    assert_eq!(after, before);
    _ = auth
        .store()
        .update_device_code(
            &retained.id,
            alibi::UpdateDeviceCode {
                user_id: Some(Some(owner_id.clone())),
                ..Default::default()
            },
        )
        .await?;
    let redeemed = body(&call(&auth, redemption(), 200).await);
    assert_eq!(redeemed["token_type"], "Bearer");
    assert_eq!(redeemed["scope"], "read");
    let token = redeemed["access_token"].as_str().unwrap();
    let mut current = request("/get-session", None, "");
    _ = current
        .headers
        .insert("authorization".into(), format!("Bearer {token}"));
    assert_eq!(
        body(&call(&auth, current, 200).await)["user"]["id"],
        owner_id
    );
    assert!(
        auth.store()
            .get_device_code_by_device_code(code)
            .await?
            .is_none()
    );
    let final_rows = db.tables(&["users", "accounts", "sessions"]).await?;
    assert_eq!(
        body(&call(&auth, redemption(), 400).await)["error"],
        "invalid_grant"
    );
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        final_rows
    );
    assert_eq!(final_rows[..2], stable[..2]);
    let old: Vec<Value> = serde_json::from_str(&stable[2])?;
    let new: Vec<Value> = serde_json::from_str(&final_rows[2])?;
    assert_eq!(new.len(), old.len() + 1);
    assert!(old.iter().all(|row| new.contains(row)));
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn device_empty_application_codes_complete_real_grant<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(
            DeviceAuthorizationPlugin::new()
                .interval(chrono::Duration::zero())
                .generate_device_code_async_with(|| async { Ok(String::new()) })
                .generate_user_code_async_with(|| async { Ok(String::new()) }),
        )
        .plugin(alibi::plugins::BearerPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let stable = db.tables(&["users", "accounts", "sessions"]).await?;
    let issued = body(
        &call(
            &auth,
            request(
                "/device/code",
                Some(json!({"client_id":"empty","scope":"read"})),
                "",
            ),
            200,
        )
        .await,
    );
    assert_eq!(issued["device_code"], "");
    assert_eq!(issued["user_code"], "");
    let grant = auth
        .store()
        .get_device_code_by_device_code("")
        .await?
        .unwrap();
    assert_eq!(grant.device_code, "");
    assert_eq!(grant.user_code, "");
    let redeem = |client: &str| {
        request(
            "/device/token",
            Some(
                json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":"","client_id":client}),
            ),
            "",
        )
    };
    let wrong = call(&auth, redeem("foreign"), 400).await;
    assert_eq!(
        body(&wrong),
        json!({"error":"invalid_grant","error_description":"Client ID mismatch"})
    );
    assert_eq!(
        serde_json::to_value(
            auth.store()
                .get_device_code_by_device_code("")
                .await?
                .unwrap()
        )?,
        serde_json::to_value(&grant)?
    );
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, stable);
    _ = call(
        &auth,
        get("/device", &[("user_code", "")], &cookies(&owner)),
        200,
    )
    .await;
    _ = call(
        &auth,
        request(
            "/device/approve",
            Some(json!({"userCode":""})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let token = body(&call(&auth, redeem("empty"), 200).await)["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut current = request("/get-session", None, "");
    _ = current
        .headers
        .insert("authorization".into(), format!("Bearer {token}"));
    assert_eq!(
        body(&call(&auth, current, 200).await)["user"]["id"],
        body(&owner)["user"]["id"]
    );
    assert!(
        auth.store()
            .get_device_code_by_device_code("")
            .await?
            .is_none()
    );
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    assert_eq!(
        body(&call(&auth, redeem("empty"), 400).await)["error"],
        "invalid_grant"
    );
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, after);
    assert_eq!(after[..2], stable[..2]);
    let old: Vec<Value> = serde_json::from_str(&stable[2])?;
    let new: Vec<Value> = serde_json::from_str(&after[2])?;
    assert_eq!(new.len(), old.len() + 1);
    assert!(old.iter().all(|row| new.contains(row)));
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn device_fractional_durations_preserve_persisted_milliseconds<B: Backend>(
    db: Db,
) -> TestResult {
    use chrono::{Duration, Utc};
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for (lifetime, interval, expires_seconds, interval_seconds) in [
        (1750, 250, 1, 0),
        (-1250, -250, -2, -1),
        (120000, -250, 120, -1),
    ] {
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(
                DeviceAuthorizationPlugin::new()
                    .expires_in(Duration::milliseconds(lifetime))
                    .interval(Duration::milliseconds(interval)),
            )
            .build()
            .await?;
        let stable = db.tables(&["users", "accounts", "sessions"]).await?;
        let start = Utc::now();
        let issued = body(
            &call(
                &auth,
                request("/device/code", Some(json!({"client_id":"fractional"})), ""),
                200,
            )
            .await,
        );
        let finish = Utc::now();
        assert_eq!(issued["expires_in"], expires_seconds);
        assert_eq!(issued["interval"], interval_seconds);
        let code = issued["device_code"].as_str().unwrap();
        let stored = auth
            .store()
            .get_device_code_by_device_code(code)
            .await?
            .unwrap();
        assert_eq!(stored.polling_interval, Some(interval));
        assert!(stored.expires_at >= start + Duration::milliseconds(lifetime));
        assert!(stored.expires_at <= finish + Duration::milliseconds(lifetime));
        let poll = || {
            request(
                "/device/token",
                Some(
                    json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":code,"client_id":"fractional"}),
                ),
                "",
            )
        };
        if lifetime < 0 {
            assert_eq!(
                body(&call(&auth, poll(), 400).await)["error"],
                "expired_token"
            );
            assert!(
                auth.store()
                    .get_device_code_by_device_code(code)
                    .await?
                    .is_none()
            );
            assert_eq!(
                body(&call(&auth, poll(), 400).await)["error"],
                "invalid_grant"
            );
        } else {
            assert_eq!(
                body(&call(&auth, poll(), 400).await)["error"],
                "authorization_pending"
            );
            if interval > 0 {
                _ = auth
                    .store()
                    .update_device_code(
                        &stored.id,
                        alibi::UpdateDeviceCode {
                            last_polled_at: Some(Some(Utc::now() + Duration::seconds(1))),
                            ..Default::default()
                        },
                    )
                    .await?;
                let before = db.table("device_code").await?;
                assert_eq!(body(&call(&auth, poll(), 400).await)["error"], "slow_down");
                assert_eq!(db.table("device_code").await?, before);
            } else {
                assert_eq!(
                    body(&call(&auth, poll(), 400).await)["error"],
                    "authorization_pending"
                );
                assert_eq!(
                    auth.store()
                        .get_device_code_by_device_code(code)
                        .await?
                        .unwrap()
                        .polling_interval,
                    Some(-250)
                );
            }
        }
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, stable);
    }
    B::close(connection).await
}

async fn revoked_compact_browser_claims_and_completes_only_its_device_grant<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::{CookieCacheConfig, CookieCacheStrategy};
    for decision in ["approve", "deny"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let config = AuthConfig::new(SECRET)
            .base_url(ORIGIN)
            .session_cookie_cache(CookieCacheConfig {
                enabled: true,
                strategy: CookieCacheStrategy::Compact,
                ..Default::default()
            });
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(DeviceAuthorizationPlugin::new().interval(chrono::Duration::zero()))
            .build()
            .await?;
        let foreign = signup(&auth, "foreign@example.test").await;
        let baseline = db.tables(&["users", "accounts", "sessions"]).await?;
        let owner = signup(&auth, "owner@example.test").await;
        let owner_value = body(&owner);
        let id = owner_value["user"]["id"].as_str().unwrap();
        let token = owner_value["token"].as_str().unwrap();
        let jar = cookies(&owner);
        let issued = body(
            &call(
                &auth,
                request(
                    "/device/code",
                    Some(json!({"client_id":"cache-client","scope":"read write"})),
                    "",
                ),
                200,
            )
            .await,
        );
        let code = issued["device_code"].as_str().unwrap();
        let user_code = issued["user_code"].as_str().unwrap();
        assert_eq!(
            db.execute("DELETE FROM sessions WHERE token=$1", &[token])
                .await?,
            1
        );
        let mut review = request("/device", None, &jar);
        review.set_query_pairs([("user_code", user_code)]);
        _ = call(&auth, review, 200).await;
        assert_eq!(
            db.text(
                "SELECT user_id FROM device_code WHERE device_code=$1",
                &[code]
            )
            .await?
            .as_deref(),
            Some(id)
        );
        let before = db
            .tables(&["device_code", "users", "accounts", "sessions"])
            .await?;
        _ = call(
            &auth,
            request(
                &format!("/device/{decision}"),
                Some(json!({"userCode":user_code})),
                &cookies(&foreign),
            ),
            403,
        )
        .await;
        assert_eq!(
            db.tables(&["device_code", "users", "accounts", "sessions"])
                .await?,
            before
        );
        let accepted = call(
            &auth,
            request(
                &format!("/device/{decision}"),
                Some(json!({"userCode":user_code})),
                &jar,
            ),
            200,
        )
        .await;
        assert_eq!(body(&accepted), json!({"success":true}));
        let decided = db
            .tables(&["device_code", "users", "accounts", "sessions"])
            .await?;
        _ = call(
            &auth,
            request(
                &format!("/device/{decision}"),
                Some(json!({"userCode":user_code})),
                &jar,
            ),
            400,
        )
        .await;
        assert_eq!(
            db.tables(&["device_code", "users", "accounts", "sessions"])
                .await?,
            decided
        );
        let redeemed=call(&auth,request("/device/token",Some(json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":code,"client_id":"cache-client"})),""),if decision=="approve"{200}else{400}).await;
        assert!(redeemed.headers.get_all("set-cookie").next().is_none());
        assert_eq!(rows(&db, code).await?, 0);
        let count = db
            .count_where("SELECT COUNT(*) FROM sessions WHERE user_id=$1", &[id])
            .await?;
        assert_eq!(count, if decision == "approve" { 1 } else { 0 });
        if decision == "approve" {
            let value = body(&redeemed);
            assert_eq!(value["token_type"], "Bearer");
            assert_eq!(value["scope"], "read write");
            assert_eq!(
                db.text("SELECT token FROM sessions WHERE user_id=$1", &[id])
                    .await?
                    .as_deref(),
                value["access_token"].as_str()
            );
        } else {
            assert_eq!(body(&redeemed)["error"], "access_denied");
        }
        let after = db.tables(&["users", "accounts", "sessions"]).await?;
        for (before, now) in baseline.iter().zip(after.iter()) {
            let before: Vec<Value> = serde_json::from_str(before)?;
            let now: Vec<Value> = serde_json::from_str(now)?;
            assert!(before.iter().all(|x| now.contains(x)));
        }
        authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn device_poller_session_metadata<B: Backend>(db: Db) -> TestResult {
    for disabled in [false, true] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.advanced.ip_address.trusted_proxies = vec!["10.0.0.0/8".into()];
        config.advanced.ip_address.disable_ip_tracking = disabled;
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(DeviceAuthorizationPlugin::new().interval(chrono::Duration::zero()))
            .build()
            .await?;
        let owner = signup(&auth, "owner@example.test").await;
        let foreign = signup(&auth, "foreign@example.test").await;
        let baseline = db.tables(&["users", "accounts", "sessions"]).await?;
        let issued = body(
            &call(
                &auth,
                request(
                    "/device/code",
                    Some(json!({"client_id":"metadata-client"})),
                    "",
                ),
                200,
            )
            .await,
        );
        let code = issued["device_code"].as_str().unwrap();
        let user_code = issued["user_code"].as_str().unwrap();
        let mut review = request("/device", None, &cookies(&owner));
        review.set_query_pairs([("user_code", user_code)]);
        _ = call(&auth, review, 200).await;
        _ = call(
            &auth,
            request(
                "/device/approve",
                Some(json!({"userCode":user_code})),
                &cookies(&owner),
            ),
            200,
        )
        .await;
        let grant = db.table("device_code").await?;
        _=call(&auth,request("/device/token",Some(json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":code,"client_id":"wrong-client"})),""),400).await;
        assert_eq!(db.table("device_code").await?, grant);
        assert_eq!(
            db.tables(&["users", "accounts", "sessions"]).await?,
            baseline
        );
        let mut poll = request(
            "/device/token",
            Some(
                json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":code,"client_id":"metadata-client"}),
            ),
            "",
        );
        poll.headers.extend([
            (
                "x-forwarded-for".into(),
                "203.0.113.99, 198.51.100.218, 10.2.3.4".into(),
            ),
            ("user-agent".into(), "device-poller".into()),
        ]);
        let redeemed = call(&auth, poll, 200).await;
        assert!(redeemed.headers.get_all("set-cookie").next().is_none());
        let token = body(&redeemed)["access_token"].as_str().unwrap().to_owned();
        assert_eq!(
            db.text("SELECT user_id FROM sessions WHERE token=$1", &[&token])
                .await?
                .as_deref(),
            body(&owner)["user"]["id"].as_str()
        );
        assert_eq!(
            db.text("SELECT ip_address FROM sessions WHERE token=$1", &[&token])
                .await?
                .as_deref(),
            Some(if disabled { "" } else { "198.51.100.218" })
        );
        assert_eq!(
            db.text("SELECT user_agent FROM sessions WHERE token=$1", &[&token])
                .await?
                .as_deref(),
            Some("device-poller")
        );
        assert_eq!(rows(&db, code).await?, 0);
        let after = db.tables(&["users", "accounts", "sessions"]).await?;
        for (before, now) in baseline.iter().zip(after.iter()) {
            let before: Vec<Value> = serde_json::from_str(before)?;
            let now: Vec<Value> = serde_json::from_str(now)?;
            assert!(before.iter().all(|r| now.contains(r)));
        }
        let replay=call(&auth,request("/device/token",Some(json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":code,"client_id":"metadata-client"})),""),400).await;
        assert_eq!(body(&replay)["error"], "invalid_grant");
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, after);
        _ = call(
            &auth,
            request(
                "/revoke-session",
                Some(json!({"token":token})),
                &cookies(&owner),
            ),
            200,
        )
        .await;
        assert_eq!(
            db.tables(&["users", "accounts", "sessions"]).await?,
            baseline
        );
        authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn device_overlapping_reviews_retain_first_claim_authority<B: Backend>(db: Db) -> TestResult {
    use alibi::{
        CacheVersionContext, CacheVersionSource, CookieCacheConfig, CookieCacheStrategy,
        CookieCacheVersion, CookieCacheVersionResolver,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Gate {
        armed: AtomicBool,
        ids: Mutex<Vec<String>>,
        entered: [tokio::sync::Notify; 2],
        release: [tokio::sync::Notify; 2],
    }
    #[async_trait::async_trait]
    impl CookieCacheVersionResolver for Gate {
        async fn resolve(&self, c: &CacheVersionContext) -> AuthResult<String> {
            if self.armed.load(Ordering::SeqCst) && c.source() == CacheVersionSource::Cached {
                let index = self
                    .ids
                    .lock()
                    .unwrap()
                    .iter()
                    .position(|id| id == &c.user().id)
                    .unwrap();
                self.entered[index].notify_one();
                self.release[index].notified().await;
            }
            Ok("v1".into())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let gate = Arc::new(Gate {
        armed: AtomicBool::new(false),
        ids: Mutex::new(Vec::new()),
        entered: Default::default(),
        release: Default::default(),
    });
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            strategy: CookieCacheStrategy::Compact,
            version: Some(CookieCacheVersion::Resolver(gate.clone())),
            ..Default::default()
        });
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(DeviceAuthorizationPlugin::new().interval(chrono::Duration::zero()))
        .build()
        .await?;
    let first = signup(&auth, "first@example.test").await;
    let second = signup(&auth, "second@example.test").await;
    let first_id = body(&first)["user"]["id"].as_str().unwrap().to_owned();
    let second_id = body(&second)["user"]["id"].as_str().unwrap().to_owned();
    *gate.ids.lock().unwrap() = vec![first_id.clone(), second_id];
    let baseline = db.tables(&["users", "accounts", "sessions"]).await?;
    let issued = body(
        &call(
            &auth,
            request(
                "/device/code",
                Some(json!({"client_id":"claim-client","scope":"openid private-scope"})),
                "",
            ),
            200,
        )
        .await,
    );
    let code = issued["device_code"].as_str().unwrap();
    let user_code = issued["user_code"].as_str().unwrap();
    let initial = db.table("device_code").await?;
    let review = |cookie: &str| {
        let mut r = request("/device", None, cookie);
        r.set_query_pairs([("user_code", user_code)]);
        r
    };
    gate.armed.store(true, Ordering::SeqCst);
    let mut a = Box::pin(auth.handle_request(review(&cookies(&first))));
    let mut b = Box::pin(auth.handle_request(review(&cookies(&second))));
    tokio::time::timeout(std::time::Duration::from_secs(10),async{tokio::select!{biased;_=gate.entered[0].notified()=>{},r=&mut a=>panic!("first review escaped before its gate: {r:?}")};tokio::select!{biased;_=gate.entered[1].notified()=>{},r=&mut b=>panic!("second review escaped before its gate: {r:?}")};}).await?;
    assert_eq!(db.table("device_code").await?, initial);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        baseline
    );
    gate.release[0].notify_one();
    let winner = tokio::time::timeout(std::time::Duration::from_secs(10), &mut a).await??;
    assert_eq!(winner.status, 200);
    assert_eq!(
        body(&winner),
        json!({"user_code":user_code,"status":"pending","client_id":"claim-client","scope":"openid private-scope"})
    );
    let claimed = db.table("device_code").await?;
    assert_eq!(
        db.text(
            "SELECT user_id FROM device_code WHERE device_code=$1",
            &[code]
        )
        .await?
        .as_deref(),
        Some(first_id.as_str())
    );
    gate.release[1].notify_one();
    let loser = tokio::time::timeout(std::time::Duration::from_secs(10), &mut b).await??;
    assert_eq!(loser.status, 200);
    assert_eq!(
        body(&loser),
        json!({"user_code":user_code,"status":"pending"})
    );
    assert_eq!(db.table("device_code").await?, claimed);
    gate.armed.store(false, Ordering::SeqCst);
    for decision in ["approve", "deny"] {
        _ = call(
            &auth,
            request(
                &format!("/device/{decision}"),
                Some(json!({"userCode":user_code})),
                &cookies(&second),
            ),
            403,
        )
        .await;
        assert_eq!(db.table("device_code").await?, claimed);
    }
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        baseline
    );
    _ = call(
        &auth,
        request(
            "/device/approve",
            Some(json!({"userCode":user_code})),
            &cookies(&first),
        ),
        200,
    )
    .await;
    let poll = request(
        "/device/token",
        Some(
            json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":code,"client_id":"claim-client"}),
        ),
        "",
    );
    let done = call(&auth, poll.clone(), 200).await;
    let token = body(&done)["access_token"].as_str().unwrap().to_owned();
    assert_eq!(
        db.text("SELECT user_id FROM sessions WHERE token=$1", &[&token])
            .await?
            .as_deref(),
        Some(first_id.as_str())
    );
    assert_eq!(rows(&db, code).await?, 0);
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    _ = call(&auth, poll, 400).await;
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, after);
    authenticated(&auth, &cookies(&second), "second@example.test").await;
    B::close(connection).await
}

async fn device_custom_user_codes_prefer_exact_lookup<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let exact = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(
            DeviceAuthorizationPlugin::new()
                .interval(chrono::Duration::zero())
                .generate_user_code_async_with(|| async { Ok(" café-Code! ".into()) }),
        )
        .build()
        .await?;
    let normal = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(DeviceAuthorizationPlugin::new().interval(chrono::Duration::zero()))
        .build()
        .await?;
    let owner = signup(&exact, "owner@example.test").await;
    let jar = cookies(&owner);
    let issue = body(
        &call(
            &exact,
            request(
                "/device/code",
                Some(json!({"client_id":"exact-client"})),
                "",
            ),
            200,
        )
        .await,
    );
    let code = issue["device_code"].as_str().unwrap();
    let uc = issue["user_code"].as_str().unwrap();
    assert_eq!(uc, " café-Code! ");
    let before = db.table("device_code").await?;
    let mut alias = request("/device", None, &jar);
    alias.set_query_pairs([("user_code", "CAFCODE")]);
    _ = call(&exact, alias, 400).await;
    assert_eq!(db.table("device_code").await?, before);
    let mut review = request("/device", None, &jar);
    review.set_query_pairs([("user_code", uc)]);
    let viewed = call(&exact, review, 200).await;
    assert_eq!(body(&viewed)["user_code"], uc);
    _ = call(
        &exact,
        request("/device/approve", Some(json!({"userCode":uc})), &jar),
        200,
    )
    .await;
    let poll = request(
        "/device/token",
        Some(
            json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":code,"client_id":"exact-client"}),
        ),
        "",
    );
    let done = call(&exact, poll.clone(), 200).await;
    assert_eq!(
        db.text(
            "SELECT user_id FROM sessions WHERE token=$1",
            &[body(&done)["access_token"].as_str().unwrap()]
        )
        .await?
        .as_deref(),
        body(&owner)["user"]["id"].as_str()
    );
    assert_eq!(rows(&db, code).await?, 0);
    _ = call(&exact, poll, 400).await;
    let generated = body(
        &call(
            &normal,
            request(
                "/device/code",
                Some(json!({"client_id":"normalized-client"})),
                "",
            ),
            200,
        )
        .await,
    );
    let uc = generated["user_code"].as_str().unwrap();
    let alias = uc
        .to_lowercase()
        .chars()
        .map(|c| format!("{c}."))
        .collect::<String>();
    let mut review = request("/device", None, &jar);
    review.set_query_pairs([("user_code", alias.as_str())]);
    let viewed = call(&normal, review, 200).await;
    assert_eq!(body(&viewed)["user_code"], alias);
    assert_eq!(
        db.text(
            "SELECT user_id FROM device_code WHERE device_code=$1",
            &[generated["device_code"].as_str().unwrap()]
        )
        .await?
        .as_deref(),
        body(&owner)["user"]["id"].as_str()
    );
    B::close(connection).await
}

async fn device_user_code_collision_retries_without_replacing_grant<B: Backend>(
    db: Db,
) -> TestResult {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let devices = Arc::new(Mutex::new(VecDeque::from([
        "original-device",
        "colliding-device",
        "new-device",
        "exhausted-one",
        "exhausted-two",
        "exhausted-three",
    ])));
    let users = Arc::new(Mutex::new(VecDeque::from([
        "ORIGINAL", "ORIGINAL", "NEWCODE", "ORIGINAL", "ORIGINAL", "ORIGINAL",
    ])));
    let calls = Arc::new(AtomicUsize::new(0));
    let (d, u, c) = (devices.clone(), users.clone(), calls.clone());
    let plugin = DeviceAuthorizationPlugin::new()
        .interval(chrono::Duration::zero())
        .generate_device_code_async_with(move || {
            let d = d.clone();
            async move { Ok(d.lock().unwrap().pop_front().unwrap().into()) }
        })
        .generate_user_code_async_with(move || {
            let u = u.clone();
            async move { Ok(u.lock().unwrap().pop_front().unwrap().into()) }
        })
        .on_device_auth_request(move |_, _| {
            let c = c.clone();
            async move {
                _ = c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(plugin)
        .build()
        .await?;
    let first = signup(&auth, "first@example.test").await;
    let second = signup(&auth, "second@example.test").await;
    let original = body(
        &call(
            &auth,
            request(
                "/device/code",
                Some(json!({"client_id":"collision-client","scope":"original-private"})),
                "",
            ),
            200,
        )
        .await,
    );
    let initial = db.table("device_code").await?;
    let new = body(
        &call(
            &auth,
            request(
                "/device/code",
                Some(json!({"client_id":"collision-client","scope":"new-private"})),
                "",
            ),
            200,
        )
        .await,
    );
    assert_eq!(new["device_code"], "new-device");
    assert_eq!(new["user_code"], "NEWCODE");
    assert_eq!(devices.lock().unwrap().len(), 3);
    assert_eq!(users.lock().unwrap().len(), 3);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let present: Vec<Value> = serde_json::from_str(&db.table("device_code").await?)?;
    let original_rows: Vec<Value> = serde_json::from_str(&initial)?;
    assert_eq!(present.len(), 2);
    assert!(original_rows.iter().all(|r| present.contains(r)));
    let before = db.table("device_code").await?;
    _ = call(
        &auth,
        request(
            "/device/code",
            Some(json!({"client_id":"collision-client"})),
            "",
        ),
        500,
    )
    .await;
    assert!(devices.lock().unwrap().is_empty());
    assert!(users.lock().unwrap().is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(db.table("device_code").await?, before);
    for (grant, owner, scope) in [
        (&original, &first, "original-private"),
        (&new, &second, "new-private"),
    ] {
        let code = grant["device_code"].as_str().unwrap();
        let uc = grant["user_code"].as_str().unwrap();
        let jar = cookies(owner);
        let mut review = request("/device", None, &jar);
        review.set_query_pairs([("user_code", uc)]);
        _ = call(&auth, review, 200).await;
        _ = call(
            &auth,
            request("/device/approve", Some(json!({"userCode":uc})), &jar),
            200,
        )
        .await;
        let poll = request(
            "/device/token",
            Some(
                json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":code,"client_id":"collision-client"}),
            ),
            "",
        );
        let done = call(&auth, poll.clone(), 200).await;
        assert_eq!(body(&done)["scope"], scope);
        assert_eq!(
            db.text(
                "SELECT user_id FROM sessions WHERE token=$1",
                &[body(&done)["access_token"].as_str().unwrap()]
            )
            .await?
            .as_deref(),
            body(owner)["user"]["id"].as_str()
        );
        assert_eq!(rows(&db, code).await?, 0);
        _ = call(&auth, poll, 400).await;
    }
    B::close(connection).await
}

async fn device_issuance_retains_prebound_owner_authority<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(DeviceAuthorizationPlugin::new().interval(chrono::Duration::zero()))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let baseline = db.tables(&["users", "accounts", "sessions"]).await?;
    for prebound in [owner_id.as_str(), "unknown-prebound-owner", ""] {
        let issued = body(
            &call(
                &auth,
                request(
                    "/device/code",
                    Some(
                        json!({"client_id":"prebound-client","scope":"private","user_id":prebound}),
                    ),
                    "",
                ),
                200,
            )
            .await,
        );
        let code = issued["device_code"].as_str().unwrap();
        let uc = issued["user_code"].as_str().unwrap();
        assert_eq!(
            db.text(
                "SELECT user_id FROM device_code WHERE device_code=$1",
                &[code]
            )
            .await?
            .as_deref(),
            (!prebound.is_empty()).then_some(prebound)
        );
        let original = db.table("device_code").await?;
        let mut review = request("/device", None, &cookies(&foreign));
        review.set_query_pairs([("user_code", uc)]);
        let viewed = call(&auth, review, 200).await;
        if prebound.is_empty() {
            assert_eq!(body(&viewed)["client_id"], "prebound-client");
            assert_eq!(
                db.text(
                    "SELECT user_id FROM device_code WHERE device_code=$1",
                    &[code]
                )
                .await?
                .as_deref(),
                Some(foreign_id.as_str())
            );
        } else {
            assert_eq!(body(&viewed), json!({"user_code":uc,"status":"pending"}));
            assert_eq!(db.table("device_code").await?, original);
            for decision in ["approve", "deny"] {
                _ = call(
                    &auth,
                    request(
                        &format!("/device/{decision}"),
                        Some(json!({"userCode":uc})),
                        &cookies(&foreign),
                    ),
                    403,
                )
                .await;
                assert_eq!(db.table("device_code").await?, original);
            }
        }
        if prebound == owner_id {
            _ = call(
                &auth,
                request(
                    "/device/approve",
                    Some(json!({"userCode":uc})),
                    &cookies(&owner),
                ),
                200,
            )
            .await;
            let poll = request(
                "/device/token",
                Some(
                    json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":code,"client_id":"prebound-client"}),
                ),
                "",
            );
            let done = call(&auth, poll.clone(), 200).await;
            assert_eq!(
                db.text(
                    "SELECT user_id FROM sessions WHERE token=$1",
                    &[body(&done)["access_token"].as_str().unwrap()]
                )
                .await?
                .as_deref(),
                Some(owner_id.as_str())
            );
            assert_eq!(rows(&db, code).await?, 0);
            _ = call(&auth, poll, 400).await;
        }
    }
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    for (before, now) in baseline.iter().zip(after.iter()) {
        let before: Vec<Value> = serde_json::from_str(before)?;
        let now: Vec<Value> = serde_json::from_str(now)?;
        assert!(before.iter().all(|r| now.contains(r)));
    }
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn device_application_result_owns_consumed_receipt_identity<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    _=db.execute("CREATE TABLE completion_receipts (grant_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, audience TEXT NOT NULL, nonce TEXT NOT NULL)",&[]).await?;
    let events = Events::default();
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(
            DeviceAuthorizationPlugin::new()
                .interval(chrono::Duration::zero())
                .grant(Grant(events)),
        )
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let baseline = db.tables(&["users", "accounts", "sessions"]).await?;
    for expired in [false, true] {
        let nonce = if expired {
            "expired-nonce"
        } else {
            "actual-nonce"
        };
        let issued = body(
            &call(
                &auth,
                request(
                    "/device/code",
                    Some(json!({"audience":"application-api","nonce":nonce})),
                    "",
                ),
                200,
            )
            .await,
        );
        let code = issued["device_code"].as_str().unwrap();
        let uc = issued["user_code"].as_str().unwrap();
        let id = db
            .text("SELECT id FROM device_code WHERE device_code=$1", &[code])
            .await?
            .unwrap();
        let mut review = request("/device", None, &cookies(&owner));
        review.set_query_pairs([("user_code", uc)]);
        _ = call(&auth, review, 200).await;
        _ = call(
            &auth,
            request(
                "/device/approve",
                Some(json!({"userCode":uc})),
                &cookies(&owner),
            ),
            200,
        )
        .await;
        if expired {
            db.set_timestamp(
                "device_code",
                "expires_at",
                ("device_code", code),
                chrono::Utc::now() - chrono::Duration::minutes(1),
            )
            .await?;
            assert!(
                redeem_device_code(
                    auth.context(),
                    code,
                    &Policy {
                        nonce: json!(nonce),
                        reject_preparation: false
                    }
                )
                .await
                .is_err()
            );
            assert_eq!(db.count("completion_receipts").await?, 1);
            assert_eq!(rows(&db, code).await?, 0);
            continue;
        }
        assert!(
            redeem_device_code(
                auth.context(),
                code,
                &Policy {
                    nonce: json!("foreign-nonce"),
                    reject_preparation: false
                }
            )
            .await
            .is_err()
        );
        assert_eq!(rows(&db, code).await?, 1);
        assert_eq!(db.count("completion_receipts").await?, 0);
        assert!(
            redeem_device_code(
                auth.context(),
                code,
                &Policy {
                    nonce: json!(nonce),
                    reject_preparation: true
                }
            )
            .await
            .is_err()
        );
        assert_eq!(rows(&db, code).await?, 1);
        assert_eq!(db.count("completion_receipts").await?, 0);
        let result = redeem_device_code(
            auth.context(),
            code,
            &Policy {
                nonce: json!(nonce),
                reject_preparation: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(result.claimed_device_code.device_code.id, id);
        assert_eq!(
            result.claimed_device_code.device_code.user_id.as_deref(),
            Some(owner_id.as_str())
        );
        assert_eq!(result.user.id(), owner_id);
        assert_eq!(
            result.claimed_device_code.fields,
            object(json!({"grantAudience":"application-api","grantNonce":nonce}))
        );
        assert_eq!(result.authorization_context, json!({"nonce":nonce}));
        assert_eq!(
            result.redemption_context,
            json!({"audience":"application-api"})
        );
        assert_eq!(rows(&db, code).await?, 0);
        assert_eq!(db.execute("INSERT INTO completion_receipts (grant_id,user_id,audience,nonce) VALUES ($1,$2,$3,$4)",&[&result.claimed_device_code.device_code.id,result.user.id().as_ref(),result.claimed_device_code.fields["grantAudience"].as_str().unwrap(),result.authorization_context["nonce"].as_str().unwrap()]).await?,1);
        assert_eq!(
            db.text("SELECT grant_id FROM completion_receipts", &[])
                .await?
                .as_deref(),
            Some(id.as_str())
        );
        assert!(
            redeem_device_code(
                auth.context(),
                code,
                &Policy {
                    nonce: json!(nonce),
                    reject_preparation: false
                }
            )
            .await
            .is_err()
        );
        assert_eq!(db.count("completion_receipts").await?, 1);
    }
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        baseline
    );
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}
