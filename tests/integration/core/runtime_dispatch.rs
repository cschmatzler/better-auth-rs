//! Core runtime edges: builtin `/error`, body admission, hook failure policy and rate-limit storage.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "tests assert independently specified wire fields and fixtures"
)]
use alibi::config::{BaseUrlProtocol, DynamicBaseUrl};
use alibi::endpoint::{
    BeforeEndpointAction, EndpointCall, EndpointContextPatch, EndpointHook, EndpointResponse,
};
use alibi::middleware::{
    CorsConfig, Middleware, RateLimitConfig, RateLimitDecision, RateLimitMiddleware,
};
use alibi::types::ParsedRequestBody;
use alibi::utils::json::JsValue;
use alibi::{AuthBuilder, AuthConfig, AuthError};
use alibi::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    CacheRateLimitStorage, EndpointRateLimit, HttpMethod, HttpRequestAction, RateLimitRule,
    RateLimitStorage,
};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Schema = alibi::store::StatelessSchema;

const SECRET: &str = "runtime-dispatch-secret-at-least-32-chars";
const BASE: &str = "http://runtime.test";

fn config() -> AuthConfig {
    AuthConfig::new(SECRET).base_url(BASE)
}

fn get(path: &str) -> AuthRequest {
    let mut request = AuthRequest::new(HttpMethod::Get, path);
    drop(request.headers.insert("origin".into(), BASE.into()));
    request
}

fn location(response: &AuthResponse) -> &str {
    response.headers.get("location").unwrap()
}

async fn error_redirect(url: &str, query: &[(&str, &str)]) -> AuthResult<AuthResponse> {
    let mut config = config();
    config.api_error_url = Some(url.into());
    let auth = AuthBuilder::without_database(config).build().await?;
    let mut request = get("/api/auth/error");
    request.set_query_pairs(
        query
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    auth.handle_request(request).await
}

#[tokio::test]
async fn error_endpoint_redirects_to_configured_url_preserving_existing_query() {
    let query = [("error", "BAD_THING"), ("error_description", "why")];
    let relative = error_redirect("/oops", &query).await.unwrap();
    assert_eq!(relative.status, 302);
    assert_eq!(
        location(&relative),
        "/oops?error=BAD_THING&error_description=why"
    );

    let absolute = error_redirect("https://app.test/err?x=1", &query)
        .await
        .unwrap();
    assert_eq!(
        location(&absolute),
        "https://app.test/err?x=1&error=BAD_THING&error_description=why"
    );

    let trailing = error_redirect("/oops?x=1&", &[("error", "E")])
        .await
        .unwrap();
    assert_eq!(location(&trailing), "/oops?x=1&error=E");

    let unnamed = error_redirect("/oops", &[]).await.unwrap();
    assert_eq!(location(&unnamed), "/oops?error=UNKNOWN");
}

#[tokio::test]
async fn error_endpoint_rejects_protocol_relative_and_unparseable_targets() {
    for target in ["//evil.test/x", "/\\evil.test", "http://"] {
        let response = error_redirect(target, &[("error", "E")]).await;
        let status = response.map_or_else(|error| error.status_code(), |response| response.status);
        assert_eq!(status, 500, "{target}");
    }
}

#[tokio::test]
async fn error_endpoint_renders_page_or_redirects_home() {
    let auth = AuthBuilder::without_database(config())
        .build()
        .await
        .unwrap();
    let mut request = get("/api/auth/error");
    request.set_query_pairs([
        ("error".to_owned(), "NOPE".to_owned()),
        ("error_description".to_owned(), "<b>".to_owned()),
    ]);
    let page = auth.handle_request(request).await.unwrap();
    assert_eq!(page.status, 200);
    let html = String::from_utf8(page.body).unwrap();
    assert!(html.contains("NOPE") && html.contains("&lt;b&gt;"));

    let mut quiet = config();
    quiet.render_error_page = false;
    let auth = AuthBuilder::without_database(quiet).build().await.unwrap();
    let mut request = get("/api/auth/error");
    request.set_query_pairs([("error".to_owned(), "NOPE".to_owned())]);
    let redirect = auth.handle_request(request).await.unwrap();
    assert_eq!(redirect.status, 302);
    assert!(location(&redirect).starts_with("/?error=NOPE"));
}

#[derive(Default)]
struct Edge;

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Edge {
    fn name(&self) -> &'static str {
        "runtime-edge"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/echo", "echo"),
            AuthRoute::post("/echo", "echoPost"),
            AuthRoute::post("/any", "any"),
            AuthRoute::get("/echo/{id}", "echoId").with_context_path("/echo/:id"),
        ]
    }
    fn allowed_media_types(&self, route: &AuthRoute) -> Vec<&'static str> {
        if route.path == "/any" {
            Vec::new()
        } else {
            vec!["application/json", "text/plain"]
        }
    }
    async fn on_http_request_action(
        &self,
        req: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<HttpRequestAction>> {
        Ok(match req.header("x-mode").map(String::as_str) {
            Some("early") => Some(HttpRequestAction::Respond(AuthResponse::json(
                200,
                &json!({"early":true}),
            )?)),
            Some("replace") => {
                let mut replacement = get("/api/auth/echo");
                replacement.set_query_pairs([("replaced".to_owned(), "yes".to_owned())]);
                Some(HttpRequestAction::ReplaceRequest(Box::new(replacement)))
            }
            _ => None,
        })
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match req.header("x-mode").map(String::as_str) {
            Some("boom") => return Err(AuthError::internal("private cause")),
            Some("api") => return Err(AuthError::forbidden("nope")),
            _ => {}
        }
        let parsed = req
            .extensions()
            .get::<ParsedRequestBody>()
            .map(|body| match body.as_ref() {
                ParsedRequestBody::Value(value) => value.to_json_value().unwrap(),
                ParsedRequestBody::Opaque(kind) => json!({"opaque":kind}),
            });
        let mut response = AuthResponse::json(
            200,
            &json!({
                "body": parsed,
                "query": req.query_values("tag"),
                "extra": req.query_values("extra"),
                "path": req.path(),
            }),
        )?;
        drop(response.headers.insert("x-edge", "kept"));
        Ok(Some(response))
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        _: &AuthContext<S>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        match req.header("x-after").map(String::as_str) {
            Some("callback") => Err(AuthError::CallbackFailure(Box::new(AuthError::internal(
                "after callback",
            )))),
            Some("api") => Err(AuthError::forbidden("after api")),
            _ => Ok(response),
        }
    }
}

async fn edge_auth(config: AuthConfig) -> alibi::Alibi<Schema> {
    AuthBuilder::without_database(config)
        .plugin(Edge)
        .build()
        .await
        .unwrap()
}

fn post(path: &str, content_type: Option<&str>, body: &[u8]) -> AuthRequest {
    let mut request = AuthRequest::new(HttpMethod::Post, path);
    drop(request.headers.insert("origin".into(), BASE.into()));
    if let Some(content_type) = content_type {
        drop(
            request
                .headers
                .insert("content-type".into(), content_type.into()),
        );
    }
    request.body = Some(body.to_vec());
    request
}

async fn body_of(auth: &alibi::Alibi<Schema>, request: AuthRequest) -> (u16, Value) {
    let response = auth.handle_request(request).await.unwrap();
    let body = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    (response.status, body)
}

#[tokio::test]
async fn body_admission_reports_allowed_types_and_classifies_opaque_bodies() {
    let auth = edge_auth(config()).await;
    let (status, body) = body_of(&auth, post("/api/auth/echo", None, b"{}")).await;
    assert_eq!(status, 415);
    assert_eq!(
        body["message"],
        "Content-Type is required. Allowed types: application/json, text/plain"
    );
    let (status, body) = body_of(&auth, post("/api/auth/echo", Some("image/png"), b"x")).await;
    assert_eq!(status, 415);
    assert_eq!(
        body["message"],
        "Content-Type \"image/png\" is not allowed. Allowed types: application/json, text/plain"
    );
    for (media, kind) in [
        ("application/pdf", "Blob"),
        ("image/png", "Blob"),
        ("video/mp4", "Blob"),
        ("application/octet-stream", "ArrayBuffer"),
        ("application/zip", "ReadableStream"),
    ] {
        let (status, body) = body_of(&auth, post("/api/auth/any", Some(media), b"x")).await;
        assert_eq!(
            (status, &body["body"]),
            (200, &json!({"opaque":kind})),
            "{media}"
        );
    }
}

#[tokio::test]
async fn json_suffix_media_types_are_parsed_only_for_valid_tokens() {
    let auth = edge_auth(config()).await;
    for media in [
        "application/vnd.api+json",
        "application/ld+json; charset=utf-8",
    ] {
        let (status, body) =
            body_of(&auth, post("/api/auth/any", Some(media), br#"{"a":1}"#)).await;
        assert_eq!((status, &body["body"]), (200, &json!({"a":1})), "{media}");
    }
    let (status, body) = body_of(
        &auth,
        post(
            "/api/auth/any",
            Some("application/bad token+json"),
            br#"{"a":1}"#,
        ),
    )
    .await;
    assert_eq!(
        (status, &body["body"]),
        (200, &json!({"opaque":"ReadableStream"}))
    );
}

#[tokio::test]
async fn query_values_reach_handlers_and_replacement_requests_keep_repeated_pairs() {
    let auth = edge_auth(config()).await;
    let mut request = get("/api/auth/echo");
    request.set_query_pairs([
        ("tag".to_owned(), "a".to_owned()),
        ("tag".to_owned(), "b".to_owned()),
    ]);
    let (status, body) = body_of(&auth, request).await;
    assert_eq!((status, &body["query"]), (200, &json!(["a", "b"])));

    let mut replace = get("/api/auth/ok");
    drop(replace.headers.insert("x-mode".into(), "replace".into()));
    let (status, body) = body_of(&auth, replace).await;
    assert_eq!((status, &body["path"]), (200, &json!("/echo")));

    let mut early = get("/api/auth/echo");
    drop(early.headers.insert("x-mode".into(), "early".into()));
    assert_eq!(body_of(&auth, early).await, (200, json!({"early":true})));
}

#[tokio::test]
async fn trailing_slash_is_trimmed_only_when_configured() {
    let plain = edge_auth(config()).await;
    assert_eq!(
        plain
            .handle_request(get("/api/auth/echo/"))
            .await
            .unwrap()
            .status,
        404
    );
    let mut tolerant = config();
    tolerant.advanced.skip_trailing_slashes = true;
    let auth = edge_auth(tolerant).await;
    assert_eq!(
        auth.handle_request(get("/api/auth/echo/"))
            .await
            .unwrap()
            .status,
        200
    );
}

#[tokio::test]
async fn handler_and_after_hook_failures_follow_throw_api_errors_policy() {
    let quiet = edge_auth(config()).await;
    let mut boom = get("/api/auth/echo");
    drop(boom.headers.insert("x-mode".into(), "boom".into()));
    let response = quiet.handle_request(boom).await.unwrap();
    assert_eq!(response.status, 500);
    assert!(!String::from_utf8_lossy(&response.body).contains("private cause"));

    let mut callback = get("/api/auth/echo");
    drop(callback.headers.insert("x-after".into(), "callback".into()));
    let response = quiet.handle_request(callback).await.unwrap();
    assert_eq!(response.status, 500);

    let mut api = get("/api/auth/echo");
    drop(api.headers.insert("x-after".into(), "api".into()));
    let response = quiet.handle_request(api).await.unwrap();
    assert_eq!(response.status, 403);
    assert_eq!(
        response.headers.get("x-edge").map(String::as_str),
        Some("kept")
    );

    let loud = edge_auth(config().throw_api_errors(true)).await;
    let mut boom = get("/api/auth/echo");
    drop(boom.headers.insert("x-mode".into(), "boom".into()));
    let error = loud.handle_request(boom).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        AuthError::internal("private cause").to_string()
    );

    let mut callback = get("/api/auth/echo");
    drop(callback.headers.insert("x-after".into(), "callback".into()));
    let error = loud.handle_request(callback).await.unwrap_err();
    assert!(matches!(error, AuthError::Internal(_)), "{error:?}");

    let mut api = get("/api/auth/echo");
    drop(api.headers.insert("x-mode".into(), "api".into()));
    assert_eq!(loud.handle_request(api).await.unwrap().status, 403);
}

#[tokio::test]
async fn unresolvable_dynamic_authority_yields_plain_500() {
    let mut config = AuthConfig::new(SECRET);
    config.dynamic_base_url = Some(DynamicBaseUrl {
        allowed_hosts: vec!["allowed.test".into()],
        protocol: Some(BaseUrlProtocol::Http),
        fallback: None,
    });
    let auth = edge_auth(config).await;
    let mut request = get("/api/auth/echo");
    drop(request.headers.insert("host".into(), "other.test".into()));
    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 500);
    assert_eq!(response.body, b"Something went wrong!");
}

#[tokio::test]
async fn cors_preflight_and_rate_limit_short_circuit_before_routing() {
    let auth = AuthBuilder::without_database(config())
        .cors(CorsConfig {
            enabled: true,
            allowed_origins: vec!["https://spa.test".into()],
            ..CorsConfig::default()
        })
        .build()
        .await
        .unwrap();
    let mut preflight = AuthRequest::new(HttpMethod::Options, "/api/auth/ok");
    drop(
        preflight
            .headers
            .insert("origin".into(), "https://spa.test".into()),
    );
    drop(
        preflight
            .headers
            .insert("access-control-request-method".into(), "GET".into()),
    );
    let response = auth.handle_request(preflight).await.unwrap();
    assert!(
        response.status == 204 || response.status == 200,
        "{}",
        response.status
    );
    assert_eq!(
        response
            .headers
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some("https://spa.test")
    );

    let limited = AuthBuilder::without_database(config())
        .rate_limit(RateLimitConfig::new().default_limit(Duration::from_secs(60), 1))
        .build()
        .await
        .unwrap();
    assert_eq!(
        limited
            .handle_request(get("/api/auth/ok"))
            .await
            .unwrap()
            .status,
        200
    );
    let blocked = limited.handle_request(get("/api/auth/ok")).await.unwrap();
    assert_eq!(blocked.status, 429);
    assert!(blocked.headers.contains_key("x-retry-after"));
}

struct PathHook {
    matches: bool,
    patch: Option<EndpointContextPatch>,
}

#[async_trait]
impl<S: AuthSchema> EndpointHook<S> for PathHook {
    fn matches_before(&self, call: &EndpointCall, _: &AuthContext<S>) -> AuthResult<bool> {
        assert_eq!(call.path(), Some("/echo/:id"));
        Ok(self.matches)
    }

    async fn before(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        assert_eq!(call.path(), Some("/echo/:id"));
        Ok(self
            .patch
            .clone()
            .map(|patch| BeforeEndpointAction::Patch(Box::new(patch))))
    }

    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        mut response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        let mut headers = alibi::Headers::new();
        drop(headers.insert("x-hook-path", call.path().unwrap()));
        response.merge_headers(headers);
        Ok(response)
    }
}

#[tokio::test]
async fn endpoint_hooks_preserve_concrete_paths_unless_explicitly_patched() {
    let cases = [
        (false, None, "/echo/google", "/echo/:id"),
        (true, None, "/echo/google", "/echo/:id"),
        (
            true,
            Some(EndpointContextPatch {
                headers: Some([("x-patched".into(), "yes".into())].into_iter().collect()),
                ..EndpointContextPatch::default()
            }),
            "/echo/google",
            "/echo/:id",
        ),
        (
            true,
            Some(EndpointContextPatch {
                path: Some("/echo/github".into()),
                ..EndpointContextPatch::default()
            }),
            "/echo/github",
            "/echo/github",
        ),
        (
            true,
            Some(EndpointContextPatch {
                path: Some("/echo/:id".into()),
                ..EndpointContextPatch::default()
            }),
            "/echo/:id",
            "/echo/:id",
        ),
    ];
    for (matches, patch, request_path, hook_path) in cases {
        let auth = AuthBuilder::without_database(config())
            .plugin(Edge)
            .endpoint_hook(PathHook { matches, patch })
            .build()
            .await
            .unwrap();
        let response = auth
            .handle_request(get("/api/auth/echo/google"))
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["path"], request_path);
        assert_eq!(response.headers.get("x-hook-path").unwrap(), hook_path);
    }
}

struct QueryPatch(Arc<Mutex<Vec<Value>>>);

#[async_trait]
impl<S: AuthSchema> EndpointHook<S> for QueryPatch {
    async fn before(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        self.0.lock().unwrap().push(json!({
            "query": call.query().map(|query| query.to_json_value().unwrap()),
            "has": [call.has_body(), call.has_query(), call.has_method()],
        }));
        let query = alibi::utils::json::parse_value(r#"{"tag":["x","y"],"n":3,"s":"z"}"#)?;
        Ok(Some(BeforeEndpointAction::Patch(Box::new(
            EndpointContextPatch {
                query: Some(query),
                ..EndpointContextPatch::default()
            },
        ))))
    }
    async fn after(
        &self,
        _: &EndpointCall,
        _: &AuthContext<S>,
        mut response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        response.replace(JsValue::String("replaced".into()));
        Ok(response)
    }
}

#[tokio::test]
async fn endpoint_hooks_see_repeated_query_pairs_and_patch_them_back_into_the_request() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let auth = AuthBuilder::without_database(config())
        .plugin(Edge)
        .endpoint_hook(QueryPatch(Arc::clone(&seen)))
        .build()
        .await
        .unwrap();
    let mut request = get("/api/auth/echo");
    request.set_query_pairs([
        ("tag".to_owned(), "a".to_owned()),
        ("tag".to_owned(), "b".to_owned()),
        ("solo".to_owned(), "1".to_owned()),
    ]);
    let (status, body) = body_of(&auth, request).await;
    assert_eq!(status, 200);
    assert_eq!(body, json!("replaced"));
    assert_eq!(
        seen.lock().unwrap()[0],
        json!({"query":{"tag":["a","b"],"solo":"1"},"has":[true,true,true]})
    );
}

#[derive(Debug)]
struct Plain;

#[async_trait]
impl alibi::store::secondary_storage::CacheAdapter for Plain {
    async fn set(&self, _: &str, _: &str, _: chrono::Duration) -> AuthResult<()> {
        Ok(())
    }
    async fn get(&self, _: &str) -> AuthResult<Option<String>> {
        Ok(None)
    }
    async fn delete(&self, _: &str) -> AuthResult<()> {
        Ok(())
    }
    async fn exists(&self, _: &str) -> AuthResult<bool> {
        Ok(false)
    }
    async fn expire(&self, _: &str, _: chrono::Duration) -> AuthResult<()> {
        Ok(())
    }
    async fn clear(&self) -> AuthResult<()> {
        Ok(())
    }
}

#[tokio::test]
async fn cache_backed_rate_limit_requires_an_incrementing_adapter() {
    let storage = CacheRateLimitStorage::new(Arc::new(Plain));
    let rule = EndpointRateLimit {
        window_seconds: 5.0,
        max_requests: 1.0,
    };
    let error = storage.consume("key", &rule).await.unwrap_err();
    assert!(matches!(error, AuthError::CallbackFailure(_)), "{error:?}");

    let middleware = RateLimitMiddleware::new(RateLimitConfig::new().storage(Arc::new(storage)));
    assert!(middleware.before_request(&get("/anything")).await.is_err());
}

#[derive(Debug, Default)]
struct Counter(Mutex<f64>);

#[async_trait]
impl alibi::store::secondary_storage::CacheAdapter for Counter {
    async fn set(&self, _: &str, _: &str, _: chrono::Duration) -> AuthResult<()> {
        Ok(())
    }
    async fn get(&self, _: &str) -> AuthResult<Option<String>> {
        Ok(None)
    }
    async fn increment(&self, _: &str, _: Duration) -> AuthResult<f64> {
        let mut count = self.0.lock().unwrap();
        *count += 1.0;
        Ok(*count)
    }
    async fn delete(&self, _: &str) -> AuthResult<()> {
        Ok(())
    }
    async fn exists(&self, _: &str) -> AuthResult<bool> {
        Ok(false)
    }
    async fn expire(&self, _: &str, _: chrono::Duration) -> AuthResult<()> {
        Ok(())
    }
    async fn clear(&self) -> AuthResult<()> {
        Ok(())
    }
}

#[tokio::test]
async fn cache_counter_blocks_with_full_window_and_nonpositive_windows_never_block() {
    let storage = CacheRateLimitStorage::new(Arc::new(Counter::default()));
    let rule = EndpointRateLimit {
        window_seconds: 30.0,
        max_requests: 2.0,
    };
    for _ in 0..2 {
        assert!(matches!(
            storage.consume("k", &rule).await.unwrap(),
            RateLimitDecision::Allowed
        ));
    }
    assert!(matches!(
        storage.consume("k", &rule).await.unwrap(),
        RateLimitDecision::Blocked { retry_after } if retry_after == 30.0
    ));

    let memory = RateLimitMiddleware::new(RateLimitConfig::new().rule(
        "/free",
        RateLimitRule::Limit(EndpointRateLimit {
            window_seconds: -1.0,
            max_requests: 1.0,
        }),
    ));
    for _ in 0..3 {
        assert!(
            memory
                .before_request(&get("/free"))
                .await
                .unwrap()
                .is_none()
        );
    }
}

struct QueryOnly(&'static str);

#[async_trait]
impl<S: AuthSchema> EndpointHook<S> for QueryOnly {
    async fn before(
        &self,
        _: &EndpointCall,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        Ok(Some(BeforeEndpointAction::Patch(Box::new(
            EndpointContextPatch {
                query: Some(alibi::utils::json::parse_value(self.0)?),
                ..EndpointContextPatch::default()
            },
        ))))
    }
}

#[tokio::test]
async fn successive_query_patches_merge_deeply_and_ignore_nulls_and_prototype_keys() {
    let auth = AuthBuilder::without_database(config())
        .plugin(Edge)
        .endpoint_hook(QueryOnly(r#"{"tag":"first","extra":"kept"}"#))
        .endpoint_hook(QueryOnly(
            r#"{"tag":"second","extra":null,"__proto__":{"x":"1"},"constructor":"c","added":"yes"}"#,
        ))
        .build()
        .await
        .unwrap();
    let (status, body) = body_of(&auth, get("/api/auth/echo")).await;
    assert_eq!(status, 200);
    assert_eq!(body["query"], json!(["second"]));
    assert_eq!(body["extra"], json!(["kept"]));
}

#[derive(Debug, Default)]
struct Windows(Mutex<Vec<f64>>);

#[async_trait]
impl RateLimitStorage for Windows {
    fn observe_window(&self, window_seconds: f64) {
        self.0.lock().unwrap().push(window_seconds);
    }
    async fn consume(&self, _: &str, _: &EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        Ok(RateLimitDecision::Allowed)
    }
}

#[tokio::test]
async fn disabled_rules_and_plugin_rules_resolve_before_storage_consumption() {
    let storage = Arc::new(Windows::default());
    let middleware = RateLimitMiddleware::new(
        RateLimitConfig::new()
            .storage(storage.clone())
            .rule("/free", RateLimitRule::Disabled),
    )
    .with_plugin_rules(vec![alibi::PluginRateLimit {
        matches: |path| path == "/plugin",
        limit: EndpointRateLimit {
            window_seconds: 77.0,
            max_requests: 1.0,
        },
    }]);
    for _ in 0..5 {
        assert!(
            middleware
                .before_request(&get("/free"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            middleware
                .before_request(&get("/plugin"))
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(storage.0.lock().unwrap().contains(&77.0));
}

#[tokio::test]
async fn csrf_infers_null_origins_skips_forms_when_origin_checks_are_off_and_names_bad_targets() {
    let auth = edge_auth(config()).await;

    let mut inferred = post("/api/auth/echo", Some("application/json"), b"{}");
    drop(inferred.headers.insert("origin".into(), "null".into()));
    drop(
        inferred
            .headers
            .insert("sec-fetch-site".into(), "same-origin".into()),
    );
    drop(inferred.headers.insert("cookie".into(), "a=b".into()));
    let inferred = inferred.with_url(url::Url::parse("http://runtime.test/api/auth/echo").unwrap());
    assert_eq!(auth.handle_request(inferred).await.unwrap().status, 200);

    let mut opaque = post("/api/auth/echo", Some("application/json"), b"{}");
    drop(opaque.headers.insert("origin".into(), "null".into()));
    drop(opaque.headers.insert("cookie".into(), "a=b".into()));
    assert_eq!(auth.handle_request(opaque).await.unwrap().status, 403);

    for (field, expected) in [
        ("callbackURL", "Invalid callbackURL"),
        ("redirectTo", "Invalid redirectURL"),
        ("errorCallbackURL", "Invalid errorCallbackURL"),
        ("newUserCallbackURL", "Invalid newUserCallbackURL"),
    ] {
        let payload = json!({ field: "https://evil.example/path" }).to_string();
        let (status, body) = body_of(
            &auth,
            post(
                "/api/auth/echo",
                Some("application/json"),
                payload.as_bytes(),
            ),
        )
        .await;
        assert_eq!(
            (status, body["message"].as_str()),
            (403, Some(expected)),
            "{field}"
        );
    }

    let mut lenient = config();
    lenient.advanced.disable_origin_check = true;
    let auth = edge_auth(lenient).await;
    let mut form = post(
        "/api/auth/any",
        Some("application/x-www-form-urlencoded"),
        b"a=b",
    );
    _ = form.headers.remove("origin");
    assert_eq!(auth.handle_request(form).await.unwrap().status, 200);
}

#[tokio::test]
async fn configured_error_url_keeps_fragment_and_render_precedence()
-> Result<(), Box<dyn std::error::Error>> {
    for render in [false, true] {
        let mut c = config();
        c.api_error_url = Some("/problem?keep=a%2Bb#error-panel".into());
        c.render_error_page = render;
        let auth = AuthBuilder::without_database(c).build().await?;
        for description in [None, Some("detail + & café")] {
            let mut input = get("/api/auth/error");
            let mut query = vec![("error", "BAD_CODE")];
            if let Some(d) = description {
                query.push(("error_description", d));
            }
            input.set_query_pairs(query);
            let response = auth.handle_request(input).await?;
            assert_eq!(response.status, 302);
            assert_eq!(
                location(&response),
                if description.is_none() {
                    "/problem?keep=a%2Bb&error=BAD_CODE#error-panel"
                } else {
                    "/problem?keep=a%2Bb&error=BAD_CODE&error_description=detail+%2B+%26+caf%C3%A9#error-panel"
                }
            );
            assert!(response.body.is_empty());
            assert!(!response.headers.contains_key("set-cookie"));
        }
    }
    Ok(())
}
