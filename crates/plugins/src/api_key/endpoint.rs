use super::{
    ApiKeyCallbackContext, ApiKeyErrorCode, ApiKeyErrorMessage, ApiKeyPlugin, ApiKeyReferences,
    ApiKeyValidationError, ApiKeyVerificationError, CreateKeyRequest, CreateKeyResponse,
    DeleteExpiredApiKeysResponse, UpdateKeyRequest, VerifyApiKey,
};
use crate::endpoint::definition;
use alibi_core::endpoint::{
    BeforeEndpointAction, EndpointCall, EndpointContextPatch, EndpointDefinition, EndpointHook,
    EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::session::SessionRequest;
use alibi_core::utils::json::JsValue;
use alibi_core::wire::ApiKeyView;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthUser, HttpMethod};
use serde::{Deserialize, Serialize};

/// Input to the registered server-only verification operation.
#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyVerificationInput {
    pub key: String,
    pub config_id: Option<String>,
    pub permissions: Option<super::ApiKeyPermissions>,
}

#[derive(Debug, Deserialize)]
pub struct ApiKeyVerificationOutput {
    pub valid: bool,
    pub error: Option<JsValue>,
    pub key: Option<ApiKeyView>,
}

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        definition("verifyApiKey", "verifyApiKey", None, HttpMethod::Post),
        definition(
            "deleteAllExpiredApiKeys",
            "deleteAllExpiredApiKeys",
            None,
            HttpMethod::Post,
        ),
        definition(
            "createApiKey",
            "createApiKey",
            Some("/api-key/create"),
            HttpMethod::Post,
        ),
        definition(
            "updateApiKey",
            "updateApiKey",
            Some("/api-key/update"),
            HttpMethod::Post,
        ),
    ]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    let body = match call.operation_id() {
        "verifyApiKey" | "createApiKey" | "updateApiKey" => {
            Some(validate_key_body(call.body(), call.operation_id())?)
        }
        _ => call.body().cloned(),
    };
    Ok(EndpointInput {
        body,
        query: call.query().cloned(),
    })
}

#[derive(Clone, Copy)]
enum KeyFieldKind {
    String,
    Prefix,
    CoercedId,
    Boolean,
    Number(Option<f64>),
    Permissions,
    Any,
}

fn key_fields(operation: &str) -> &'static [(&'static str, KeyFieldKind, bool, bool)] {
    use KeyFieldKind::{Any, Boolean, CoercedId, Number, Permissions, Prefix, String};
    match operation {
        "verifyApiKey" => &[
            ("configId", String, false, false),
            ("key", String, true, false),
            ("permissions", Permissions, false, false),
        ],
        "createApiKey" => &[
            ("configId", String, false, false),
            ("name", String, false, false),
            ("expiresIn", Number(Some(1.0)), false, true),
            ("prefix", Prefix, false, false),
            ("remaining", Number(Some(0.0)), false, true),
            ("metadata", Any, false, true),
            ("refillAmount", Number(Some(1.0)), false, false),
            ("refillInterval", Number(None), false, false),
            ("rateLimitTimeWindow", Number(None), false, false),
            ("rateLimitMax", Number(None), false, false),
            ("rateLimitEnabled", Boolean, false, false),
            ("permissions", Permissions, false, false),
            ("userId", CoercedId, false, true),
            ("organizationId", CoercedId, false, true),
        ],
        _ => &[
            ("configId", String, false, false),
            ("keyId", String, true, false),
            ("userId", CoercedId, false, true),
            ("name", String, false, false),
            ("enabled", Boolean, false, false),
            ("remaining", Number(Some(1.0)), false, false),
            ("refillAmount", Number(None), false, false),
            ("refillInterval", Number(None), false, false),
            ("metadata", Any, false, true),
            ("expiresIn", Number(Some(1.0)), false, true),
            ("rateLimitEnabled", Boolean, false, false),
            ("rateLimitTimeWindow", Number(None), false, false),
            ("rateLimitMax", Number(None), false, false),
            ("permissions", Permissions, false, true),
        ],
    }
}

// Registered schemas validate after accumulated before-hook patches. Preserve
// Source's schema order and all nested issues before invoking the typed core.
fn validate_key_body(body: Option<&JsValue>, operation: &str) -> AuthResult<JsValue> {
    use KeyFieldKind::{Any, Boolean, CoercedId, Number, Permissions, Prefix, String};
    let fields = key_fields(operation);
    let object = body.and_then(JsValue::as_object).ok_or_else(|| {
        crate::endpoint::validation(format!(
            "[body] Invalid input: expected object, received {}",
            crate::authentication_helpers::json_type(body)
        ))
    })?;
    let mut issues = Vec::new();
    let mut output = indexmap::IndexMap::new();
    for &(name, kind, required, nullable) in fields {
        let value = object.get(name);
        if value.is_none() && !required {
            if operation == "createApiKey" && matches!(name, "expiresIn" | "remaining") {
                _ = output.insert(name.to_owned(), JsValue::Null);
            }
            continue;
        }
        let path = format!("body.{name}");
        if nullable && value.is_some_and(JsValue::is_null) && !matches!(kind, CoercedId) {
            _ = output.insert(name.to_owned(), JsValue::Null);
            continue;
        }
        if matches!(kind, CoercedId) {
            if let Some(value) = value {
                match value.coerce_string() {
                    Ok(value) => {
                        _ = output.insert(name.to_owned(), JsValue::String(value));
                    }
                    Err(_) => issues.push(format!(
                        "[{path}] Invalid input: expected string, received {}",
                        crate::authentication_helpers::json_type(Some(value))
                    )),
                }
            }
            continue;
        }
        let expected = match kind {
            String | Prefix | CoercedId => "string",
            Boolean => "boolean",
            Number(_) => "number",
            Permissions => "record",
            Any => "any",
        };
        let valid = value.is_some_and(|value| match kind {
            String | Prefix => value.is_string(),
            Boolean => value.is_boolean(),
            Number(_) => value.as_f64().is_some_and(f64::is_finite),
            Permissions => value.is_object(),
            Any => true,
            CoercedId => false,
        });
        if !valid {
            issues.push(format!(
                "[{path}] Invalid input: expected {expected}, received {}",
                key_field_type(value)
            ));
            continue;
        }
        let value = value.ok_or_else(|| crate::endpoint::validation("Missing validated input"))?;
        match kind {
            Number(Some(minimum)) if value.as_f64().is_some_and(|number|number<minimum)=>issues.push(format!("[{path}] Too small: expected number to be >={minimum}")),
            Prefix if value.as_str().is_some_and(|prefix|prefix.is_empty()||!prefix.bytes().all(|byte|byte.is_ascii_alphanumeric()||matches!(byte,b'_'|b'-')))=>issues.push(format!("[{path}] Invalid prefix format, must be alphanumeric and contain only underscores and hyphens.")),
            Permissions => validate_permissions(value,&path,&mut issues),
            _ => {}
        }
        _ = output.insert(name.to_owned(), value.clone());
    }
    if issues.is_empty() {
        Ok(JsValue::Object(output))
    } else {
        Err(crate::endpoint::validation(issues.join("; ")))
    }
}

fn validate_permissions(value: &JsValue, path: &str, issues: &mut Vec<String>) {
    if let Some(resources) = value.as_object() {
        for (resource, actions) in resources {
            let path = format!("{path}.{resource}");
            if let Some(actions) = actions.as_array() {
                for (index, action) in actions.iter().enumerate() {
                    if !action.is_string() {
                        issues.push(format!(
                            "[{path}.{index}] Invalid input: expected string, received {}",
                            key_field_type(Some(action))
                        ));
                    }
                }
            } else {
                issues.push(format!(
                    "[{path}] Invalid input: expected array, received {}",
                    key_field_type(Some(actions))
                ));
            }
        }
    }
}

fn key_field_type(value: Option<&JsValue>) -> &'static str {
    if value.and_then(JsValue::as_f64).is_some_and(f64::is_nan) {
        "NaN"
    } else {
        crate::authentication_helpers::json_type(value)
    }
}

impl ApiKeyPlugin {
    /// Verify and consume usage through the installed logical endpoint pipeline.
    /// # Errors
    /// Returns an error if input serialization fails.
    pub fn verify_endpoint(
        input: &ApiKeyVerificationInput,
    ) -> AuthResult<ServerEndpoint<ApiKeyVerificationOutput>> {
        ServerEndpoint::new("api-key", "verifyApiKey").with_body(input)
    }

    #[must_use]
    pub const fn delete_all_expired_endpoint() -> ServerEndpoint<DeleteExpiredApiKeysResponse> {
        ServerEndpoint::new("api-key", "deleteAllExpiredApiKeys")
    }

    /// Create a key through installed hooks and actual server/client context policy.
    /// # Errors
    /// Returns an error if input serialization fails.
    pub fn create_endpoint(
        body: &CreateKeyRequest,
    ) -> AuthResult<ServerEndpoint<CreateKeyResponse>> {
        ServerEndpoint::new("api-key", "createApiKey").with_body(body)
    }

    /// Update through installed hooks and owner checks after patched-body validation.
    /// # Errors
    /// Returns an error if input serialization fails.
    pub fn update_endpoint(body: &UpdateKeyRequest) -> AuthResult<ServerEndpoint<ApiKeyView>> {
        ServerEndpoint::new("api-key", "updateApiKey").with_body(body)
    }

    pub(super) async fn call_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        match call.operation_id() {
            "verifyApiKey" => {
                let body: ApiKeyVerificationInput = call.body_as()?;
                let permissions = body
                    .permissions
                    .as_ref()
                    .map(serde_json::to_value)
                    .transpose()?;
                let input = VerifyApiKey {
                    key: &body.key,
                    config_id: body.config_id.as_deref(),
                    permissions: permissions.as_ref(),
                };
                let value = match self
                    .verify_api_key_with_registration(&input, call.request(), ctx)
                    .await
                {
                    Ok(key) => serde_json::json!({"valid":true,"error":null,"key":key}),
                    Err(ApiKeyVerificationError::Validation(error)) => {
                        serde_json::json!({"valid":false,"error":error,"key":null})
                    }
                    Err(ApiKeyVerificationError::ExplicitValidator(error)) => return Err(error),
                    Err(ApiKeyVerificationError::Internal(error)) => {
                        tracing::error!(%error,"Failed to validate API key");
                        if alibi_core::endpoint::is_endpoint_api_error(&error) {
                            let (_, code, message) = error.error_payload();
                            serde_json::json!({"valid":false,"error":{"code":code,"message":message},"key":null})
                        } else {
                            serde_json::json!({"valid":false,"error":{"code":"INVALID_API_KEY","message":{"code":"INVALID_API_KEY","message":super::ApiKeyErrorCode::InvalidApiKey.message()}},"key":null})
                        }
                    }
                };
                EndpointResponse::json(&value)
            }
            "deleteAllExpiredApiKeys" => {
                EndpointResponse::json(&self.delete_all_expired_api_keys(ctx).await)
            }
            "createApiKey" => {
                let body: CreateKeyRequest = call.body_as()?;
                let config = self.resolve_configuration(body.config_id.as_deref())?;
                let mut resolution = call.clone();
                alibi_core::endpoint::EndpointContextPatch {
                    query: Some(JsValue::Object(
                        [("disableCookieCache".into(), JsValue::Bool(true))]
                            .into_iter()
                            .collect(),
                    )),
                    ..alibi_core::endpoint::EndpointContextPatch::default()
                }
                .apply(&mut resolution);
                let session = ctx.require_cached_session(&resolution).await.ok();
                if let Some((user, session)) = &session {
                    call.record_authenticated_session(
                        match user {
                            alibi_core::AuthenticatedUser::Stored(user) => ctx.user_view(user),
                            alibi_core::AuthenticatedUser::Cached(user) => (**user).clone(),
                        },
                        session.clone(),
                    );
                }
                let is_client = call.request().is_some() || call.headers().is_some();
                if is_client
                    && (body.refill_amount.is_some()
                        || body.refill_interval.is_some()
                        || body.rate_limit_max.is_some()
                        || body.rate_limit_time_window.is_some()
                        || body.rate_limit_enabled.is_some()
                        || body.permissions.is_some()
                        || body.remaining.is_some())
                {
                    return Err(super::api_key_error(ApiKeyErrorCode::ServerOnlyProperty));
                }
                if call.request().is_some() && body.user_id.is_some() {
                    return Err(super::api_key_error(ApiKeyErrorCode::UnauthorizedSession));
                }
                let user_id = if config.references == ApiKeyReferences::Organization {
                    session
                        .as_ref()
                        .map(|(user, _)| user.id().into_owned())
                        .or_else(|| body.user_id.clone())
                } else if is_client {
                    session.as_ref().map(|(user, _)| user.id().into_owned())
                } else {
                    if let Some((user, _)) = &session
                        && body
                            .user_id
                            .as_ref()
                            .is_some_and(|id| !id.is_empty() && user.id() != *id)
                    {
                        return Err(super::api_key_error(ApiKeyErrorCode::UnauthorizedSession));
                    }
                    session
                        .as_ref()
                        .map(|(user, _)| user.id().into_owned())
                        .or_else(|| body.user_id.clone())
                }
                .filter(|id| !id.is_empty())
                .ok_or_else(|| super::api_key_error(ApiKeyErrorCode::UnauthorizedSession))?;
                EndpointResponse::json(
                    &super::handlers::create_key_for_user(
                        &body,
                        &user_id,
                        self,
                        ctx,
                        call.request(),
                    )
                    .await?,
                )
            }
            "updateApiKey" => {
                let body: UpdateKeyRequest = call.body_as()?;
                let mut resolution = call.clone();
                alibi_core::endpoint::EndpointContextPatch {
                    query: Some(JsValue::Object(
                        [("disableCookieCache".into(), JsValue::Bool(true))]
                            .into_iter()
                            .collect(),
                    )),
                    ..alibi_core::endpoint::EndpointContextPatch::default()
                }
                .apply(&mut resolution);
                let session = ctx.require_cached_session(&resolution).await.ok();
                if let Some((user, session)) = &session {
                    call.record_authenticated_session(
                        match user {
                            alibi_core::AuthenticatedUser::Stored(user) => ctx.user_view(user),
                            alibi_core::AuthenticatedUser::Cached(user) => (**user).clone(),
                        },
                        session.clone(),
                    );
                }
                let is_client = call.request().is_some() || call.headers().is_some();
                let user_id = session
                    .as_ref()
                    .map(|(user, _)| user.id().into_owned())
                    .or_else(|| (!is_client).then(|| body.user_id.clone()).flatten())
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| super::api_key_error(ApiKeyErrorCode::UnauthorizedSession))?;
                if body
                    .user_id
                    .as_ref()
                    .is_some_and(|id| !id.is_empty() && *id != user_id)
                {
                    return Err(super::api_key_error(ApiKeyErrorCode::UnauthorizedSession));
                }
                if is_client {
                    EndpointResponse::json(
                        &super::handlers::update_key_core(&body, &user_id, self, ctx).await?,
                    )
                } else {
                    EndpointResponse::json(
                        &super::handlers::update_key_for_user(&body, &user_id, self, ctx).await?,
                    )
                }
            }
            _ => Err(AuthError::not_found("Unregistered API key operation")),
        }
    }
}

#[async_trait::async_trait]
impl<S: AuthSchema> EndpointHook<S> for ApiKeyPlugin {
    fn matches_before(&self, call: &EndpointCall, ctx: &AuthContext<S>) -> AuthResult<bool> {
        Ok(self
            .find_session_key_for_input(call.session_headers(), call.request(), Some(call), ctx)?
            .is_some())
    }

    async fn before(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        let (config, key) = self
            .find_session_key_for_input(call.session_headers(), call.request(), Some(call), ctx)?
            .ok_or_else(|| {
                AuthError::internal("API key getter did not return a key after matching")
            })?;
        if f64::from(
            u32::try_from(key.encode_utf16().count())
                .map_err(|error| AuthError::internal(error.to_string()))?,
        ) < config.key_length
        {
            return Ok(Some(BeforeEndpointAction::Reject(rejection(
                &ApiKeyValidationError::new(ApiKeyErrorCode::InvalidApiKey),
                Some(403),
            )?)));
        }
        if let Some(validator) = &config.custom_api_key_validator
            && !validator
                .validate(
                    &ApiKeyCallbackContext::new(call.request(), ctx, &config.config_id)
                        .with_endpoint(call),
                    &key,
                )
                .await?
        {
            return Ok(Some(BeforeEndpointAction::Reject(rejection(
                &ApiKeyValidationError::new(ApiKeyErrorCode::InvalidApiKey),
                Some(403),
            )?)));
        }
        let input = VerifyApiKey {
            key: &key,
            config_id: Some(&config.config_id),
            permissions: None,
        };
        let view = match self
            .verify_api_key_checked(&input, call.request(), ctx, false)
            .await
        {
            Ok(view) => view,
            Err(ApiKeyVerificationError::Validation(error)) => {
                return Ok(Some(BeforeEndpointAction::Reject(rejection(&error, None)?)));
            }
            Err(
                ApiKeyVerificationError::Internal(error)
                | ApiKeyVerificationError::ExplicitValidator(error),
            ) => return Err(error),
        };
        if config.defer_updates {
            self.register_expired_cleanup(ctx).await?;
        } else if let Err(error) = self.maybe_delete_expired(ctx).await {
            tracing::error!(%error,"Failed to delete expired API keys");
        }
        if config.references != ApiKeyReferences::User {
            return Ok(Some(BeforeEndpointAction::Reject(rejection(
                &ApiKeyValidationError::new(ApiKeyErrorCode::InvalidReferenceIdFromApiKey),
                None,
            )?)));
        }
        let Some(user) = ctx.database.get_user_by_id(&view.reference_id).await? else {
            return Ok(Some(BeforeEndpointAction::Reject(rejection(
                &ApiKeyValidationError::new(ApiKeyErrorCode::InvalidReferenceIdFromApiKey),
                None,
            )?)));
        };
        let session = Self::virtual_session_from_key(&view, &key, &user, call.request(), ctx)?;
        let user_view = ctx.user_view(&user);
        call.establish_session::<S>(user, user_view.clone(), session.clone(), ctx);
        if call.path() == Some("/get-session") {
            return Ok(Some(BeforeEndpointAction::Respond(EndpointResponse::json(
                &serde_json::json!({"user":user_view,"session":session}),
            )?)));
        }
        Ok(Some(BeforeEndpointAction::Patch(Box::new(
            EndpointContextPatch {
                path: call.path().map(str::to_owned),
                ..EndpointContextPatch::default()
            },
        ))))
    }
}

fn rejection(error: &ApiKeyValidationError, status: Option<u16>) -> AuthResult<EndpointResponse> {
    let status = status.unwrap_or_else(|| error.status());
    let message = match &error.message {
        ApiKeyErrorMessage::Text(message) | ApiKeyErrorMessage::CodeMessage { message, .. } => {
            message.clone()
        }
    };
    let body = alibi_core::utils::json::parse_value(&alibi_core::utils::json::to_string(error)?)?;
    Ok(EndpointResponse::error(AuthError::Api {
        status,
        code: Some(error.code.as_str().into()),
        message,
    })
    .with_error_body(body))
}
