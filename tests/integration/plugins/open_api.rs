#![expect(
    clippy::indexing_slicing,
    reason = "Assert successful public metadata extension setup and independently specified document schemas"
)]
//! Public metadata extension contracts; HTTP differential evidence owns built-in schemas.

use alibi::plugin::{
    AuthContext, AuthPlugin, AuthRoute, OpenApiEndpoint, OpenApiField, OpenApiModel,
    PluginOpenApiMetadata,
};
use alibi::plugins::{OpenApiConfig, OpenApiPlugin};
use alibi::seaorm::store::entities::{account, session, user, verification};
use alibi::seaorm::{Database, SeaOrmStore};
use alibi::{Alibi, AuthBuilder, AuthConfig, AuthResult, AuthSchema};
use alibi::{AuthRequest, AuthResponse, HttpMethod};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::Arc;

struct AppSchema;

impl AuthSchema for AppSchema {
    type User = user::Model;
    type Session = session::Model;
    type Account = account::Model;
    type Verification = verification::Model;
    fn openapi_models() -> Vec<OpenApiModel> {
        let mut models = alibi::openapi::annotations::core_models();
        // This schema's concrete User has a metadata JSON field. Declaring its
        // documentation does not install a request parser or alter its persistence.
        models[0].fields.push(
            OpenApiField::new("metadata", json!({"type":"json","default":null}), true)
                .read_only()
                .hidden(),
        );
        models
    }
}

struct AppPlugin;

#[async_trait]
impl AuthPlugin<AppSchema> for AppPlugin {
    fn name(&self) -> &'static str {
        "application"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/items/:id", "ignored_dispatch_id"),
            AuthRoute::post("/items/:id", "ignored_post_id"),
            AuthRoute::get("/internal", "internal"),
            AuthRoute::get("/list-sessions", "private_sessions"),
            AuthRoute::get("/get-session", "application_session"),
        ]
    }
    fn static_openapi_metadata(&self) -> PluginOpenApiMetadata {
        let get = OpenApiEndpoint {
            document_path: Some("/items/:itemId".into()),
            operation_id: Some("items".into()),
            description: Some("Read an application item".into()),
            parameters: vec![json!({"name":"id","in":"query","schema":{"type":"string"}})],
            ..Default::default()
        };
        let post = OpenApiEndpoint {
            document_path: Some("/items/:itemId".into()),
            operation_id: Some("items".into()),
            tags: Some(vec!["Custom".into()]),
            request_body: Some(
                json!({"required":false,"content":{"application/json":{"schema":{"type":["array","null"],"items":{"anyOf":[{"type":"number"},{"type":"string","enum":["approved"]}]}}}}}),
            ),
            ..Default::default()
        };
        PluginOpenApiMetadata::default()
            .endpoint(
                HttpMethod::Get,
                "/list-sessions",
                OpenApiEndpoint {
                    server_only: true,
                    ..Default::default()
                },
            )
            .endpoint(
                HttpMethod::Get,
                "/get-session",
                OpenApiEndpoint {
                    operation_id: Some("applicationSession".into()),
                    ..Default::default()
                },
            )
            .endpoint(HttpMethod::Get, "/items/:id", get)
            .endpoint(HttpMethod::Post, "/items/:id", post)
            .endpoint(
                HttpMethod::Get,
                "/internal",
                OpenApiEndpoint {
                    server_only: true,
                    ..Default::default()
                },
            )
            .model(OpenApiModel::new(
                "Item",
                vec![
                    OpenApiField::new(
                        "labels",
                        json!({"type":"array","items":{"type":"string"}}),
                        true,
                    ),
                    OpenApiField::new("secret", json!({"type":"string"}), true).hidden(),
                ],
            ))
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<AppSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.method() == &HttpMethod::Get && req.path() == "/list-sessions" {
            return Ok(Some(AuthResponse::json(200, &json!({"private":true}))?));
        }
        if req.method() == &HttpMethod::Get && req.path() == "/get-session" {
            return Ok(Some(AuthResponse::json(
                200,
                &json!({"source":"application"}),
            )?));
        }
        if req.method() == &HttpMethod::Get && req.path().starts_with("/items/") {
            return Ok(Some(AuthResponse::json(
                200,
                &json!({"id":req.path().trim_start_matches("/items/")}),
            )?));
        }
        if req.method() == &HttpMethod::Post && req.path().starts_with("/items/") {
            let labels: Value = req.body_as_json()?;
            return Ok(Some(AuthResponse::json(
                200,
                &json!({"id":req.path().trim_start_matches("/items/"),"labels":labels}),
            )?));
        }
        Ok(None)
    }
}

async fn handle(auth: &Alibi<AppSchema>, request: AuthRequest) -> AuthResult<AuthResponse> {
    Box::pin(auth.handle_request(request)).await
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check the public schema; Result propagates fixture setup errors"
)]
async fn social_openapi_request_fields_match_the_reference() -> AuthResult<()> {
    let config =
        AuthConfig::new("native-social-open-api-secret-at-least-32").base_path("/identity");
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(|e| alibi::AuthError::internal(e.to_string()))?;
    let auth = AuthBuilder::<AppSchema>::new(config.clone())
        .store(SeaOrmStore::<AppSchema>::new(config, database))
        .plugin(alibi::plugins::OAuthPlugin::new())
        .plugin(OpenApiPlugin::new())
        .build()
        .await?;
    let response = handle(
        &auth,
        AuthRequest::new(HttpMethod::Get, "/identity/open-api/generate-schema"),
    )
    .await?;
    assert_eq!(response.status, 200);
    let document: Value = serde_json::from_slice(&response.body)?;
    for route in ["/sign-in/social", "/link-social"] {
        let operation = &document["paths"][route]["post"];
        let properties =
            &operation["requestBody"]["content"]["application/json"]["schema"]["properties"];
        assert_eq!(properties["additionalParams"]["type"], "object");
        assert_eq!(
            properties["additionalParams"]["additionalProperties"]["type"],
            "string"
        );
        assert!(properties.get("provider").is_some());
        assert!(properties.get("callbackURL").is_some());
        assert!(
            properties.get("authorizationParams").is_none(),
            "{route}: {properties}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn application_schema_and_plugin_annotations_reach_the_public_document_without_changing_routes()
     {
        let config = AuthConfig::new("native-open-api-fixture-secret-at-least-32-chars")
            .base_path("/identity");
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let default_auth = AuthBuilder::<AppSchema>::new(config.clone())
            .store(SeaOrmStore::<AppSchema>::new(config, database))
            .build()
            .await
            .unwrap();
        let absent = handle(
            &default_auth,
            AuthRequest::new(HttpMethod::Get, "/identity/__test/openapi.json"),
        )
        .await
        .unwrap();
        assert_eq!(absent.status, 404);
        assert!(absent.body.is_empty());
        assert!(
            default_auth
                .openapi_spec_with_native_extensions()
                .to_value()
                .unwrap()["paths"]
                .get("/__test/openapi.json")
                .is_none()
        );
        for include_native in [false, true] {
            let config = AuthConfig::new("native-open-api-fixture-secret-at-least-32-chars")
                .base_url("https://app.fixture.test")
                .base_path("/identity")
                .disabled_path("/error");
            let database = Database::connect("sqlite::memory:").await.unwrap();
            let auth = Arc::new(
                AuthBuilder::<AppSchema>::new(config.clone())
                    .store(SeaOrmStore::<AppSchema>::new(config, database))
                    .plugin(AppPlugin)
                    .plugin(OpenApiPlugin::with_config(
                        OpenApiConfig::default().include_native_extensions(include_native),
                    ))
                    .build()
                    .await
                    .unwrap(),
            );
            let item = handle(
                &auth,
                AuthRequest::new(HttpMethod::Get, "/identity/items/fixture-id"),
            )
            .await
            .unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&item.body).unwrap(),
                json!({"id":"fixture-id"})
            );
            let mut update_request =
                AuthRequest::new(HttpMethod::Post, "/identity/items/fixture-id");
            update_request.body = Some(serde_json::to_vec(&json!([7, "approved"])).unwrap());
            drop(
                update_request
                    .headers
                    .insert("content-type".into(), "application/json".into()),
            );
            let updated = handle(&auth, update_request).await.unwrap();
            assert_eq!(updated.status, 200);
            assert_eq!(
                serde_json::from_slice::<Value>(&updated.body).unwrap(),
                json!({"id":"fixture-id","labels":[7,"approved"]})
            );
            let private = handle(
                &auth,
                AuthRequest::new(HttpMethod::Get, "/identity/list-sessions"),
            )
            .await
            .unwrap();
            assert_eq!(
                private.status, 401,
                "the HTTP core route must not dispatch the application's server-only handler"
            );
            let session = handle(
                &auth,
                AuthRequest::new(HttpMethod::Get, "/identity/get-session"),
            )
            .await
            .unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&session.body).unwrap(),
                json!({"source":"application"})
            );
            let registered = auth.registered_routes();
            for path in [
                "/items/:id",
                "/internal",
                "/error",
                "/reference",
                "/open-api/generate-schema",
                "/__test/openapi.json",
            ] {
                assert!(
                    registered.iter().any(|route| route.path == path),
                    "actual registration must retain {path}"
                );
            }
            let embedded = handle(
                &auth,
                AuthRequest::new(HttpMethod::Get, "/identity/__test/openapi.json"),
            )
            .await
            .unwrap();
            assert_eq!(embedded.status, 200);
            assert_eq!(
                serde_json::from_slice::<Value>(&embedded.body).unwrap(),
                auth.openapi_spec().to_value().unwrap()
            );
            let response = handle(
                &auth,
                AuthRequest::new(HttpMethod::Get, "/identity/open-api/generate-schema"),
            )
            .await
            .unwrap();
            assert_eq!(response.status, 200);
            let document: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(
                document,
                if include_native {
                    auth.openapi_spec_with_native_extensions()
                } else {
                    auth.openapi_spec()
                }
                .to_value()
                .unwrap()
            );
            assert_eq!(
                document["paths"].get("/__test/openapi.json").is_some(),
                include_native
            );
            assert_eq!(
                document["servers"],
                json!([{"url":"https://app.fixture.test/identity"}])
            );
            assert!(document["paths"].get("/error").is_none());
            assert!(document["paths"].get("/internal").is_none());
            assert!(document["paths"].get("/reference").is_none());
            assert_eq!(
                document["paths"]["/get-session"]["get"]["operationId"],
                "applicationSession"
            );
            let path = &document["paths"]["/items/{itemId}"];
            assert_eq!(path["get"]["operationId"], "items");
            assert_eq!(path["post"]["operationId"], "itemsPost");
            assert_eq!(
                path["get"]["parameters"],
                json!([{"name":"id","in":"query","schema":{"type":"string"}},{"name":"itemId","in":"path","required":true,"schema":{"type":"string"}}])
            );
            assert_eq!(path["post"]["tags"], json!(["Custom"]));
            assert_eq!(
                path["post"]["requestBody"],
                json!({"required":false,"content":{"application/json":{"schema":{"type":["array","null"],"items":{"anyOf":[{"type":"number"},{"type":"string","enum":["approved"]}]}}}}})
            );
            assert!(path["get"].get("requestBody").is_none());
            assert_eq!(
                document["components"]["schemas"]["User"]["properties"]["metadata"],
                json!({"type":"json","default":null,"readOnly":true})
            );
            assert!(
                !document["components"]["schemas"]["User"]["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("metadata"))
            );
            assert_eq!(
                document["components"]["schemas"]["Item"]["required"],
                json!(["id", "labels"])
            );
            assert_eq!(
                document["components"]["schemas"]["Item"]["properties"]["secret"],
                json!({"type":"string"})
            );
        }
        for (path, disabled, theme, nonce) in [
            ("/reference", false, "default", None),
            ("/docs", false, "purple", Some("application-csp-nonce")),
            ("/reference", true, "default", None),
        ] {
            let config = AuthConfig::new("native-open-api-fixture-secret-at-least-32-chars")
                .base_url("https://app.fixture.test")
                .base_path("/identity");
            let database = Database::connect("sqlite::memory:").await.unwrap();
            let mut options = OpenApiConfig::default()
                .path(path)
                .theme(theme)
                .disable_default_reference(disabled);
            options.nonce = nonce.map(str::to_owned);
            let auth = AuthBuilder::<AppSchema>::new(config.clone())
                .store(SeaOrmStore::new(config, database))
                .plugin(AppPlugin)
                .plugin(OpenApiPlugin::with_config(options))
                .build()
                .await
                .unwrap();
            let response = handle(
                &auth,
                AuthRequest::new(HttpMethod::Get, format!("/identity{path}")),
            )
            .await
            .unwrap();
            assert_eq!(response.status, if disabled { 404 } else { 200 });
            if disabled {
                assert!(response.body.is_empty());
            } else {
                assert_eq!(
                    response.headers.get("content-type").map(String::as_str),
                    Some("text/html")
                );
                let html = String::from_utf8(response.body).unwrap();
                let embedded = html
                    .split_once("type=\"application/json\">")
                    .unwrap()
                    .1
                    .split_once("</script>")
                    .unwrap()
                    .0;
                let document: Value = serde_json::from_str(embedded).unwrap();
                assert_eq!(
                    document["servers"],
                    json!([{"url":"https://app.fixture.test/identity"}])
                );
                assert_eq!(
                    document["paths"]["/items/{itemId}"]["get"]["operationId"],
                    "items"
                );
                assert!(document["paths"].get("/internal").is_none());
                assert!(html.contains(&format!("theme: \"{theme}\"")));
                assert_eq!(
                    html.matches("nonce=\"application-csp-nonce\"").count(),
                    if nonce.is_some() { 2 } else { 0 }
                );
                assert!(html.contains("https://cdn.jsdelivr.net/npm/@scalar/api-reference"));
            }
            // Disabling the reference page leaves the JSON document available.
            let schema = handle(
                &auth,
                AuthRequest::new(HttpMethod::Get, "/identity/open-api/generate-schema"),
            )
            .await
            .unwrap();
            assert_eq!(schema.status, 200);
            assert!(
                serde_json::from_slice::<Value>(&schema.body).unwrap()["paths"]["/items/{itemId}"]
                    .is_object()
            );
            if path != "/reference" {
                assert_eq!(
                    handle(
                        &auth,
                        AuthRequest::new(HttpMethod::Get, "/identity/reference")
                    )
                    .await
                    .unwrap()
                    .status,
                    404
                );
            }
        }
    }
}

#[test]
fn embedded_builder_uses_plugin_owned_metadata_without_initialization() {
    let document = alibi::openapi::OpenApiBuilder::new("Application", "1")
        .plugin(&AppPlugin)
        .build()
        .to_value()
        .unwrap();
    assert_eq!(
        document["paths"]["/items/{itemId}"]["get"]["operationId"],
        "items"
    );
    assert_eq!(
        document["paths"]["/items/{itemId}"]["get"]["description"],
        "Read an application item"
    );
    assert!(document["paths"].get("/items/{id}").is_none());
    assert!(document["paths"].get("/internal").is_none());
    assert!(document["paths"].get("/list-sessions").is_none());
}
