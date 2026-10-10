//! Enumeration-safe duplicate responses and application callbacks.
use super::{EmailPasswordConfig, SignUpRequest, SignUpResponse};
use alibi_core::{AuthContext, AuthRequest, AuthResult, AuthSchema, wire::UserView};
use serde_json::{Map, Value, json};
use std::{future::Future, pin::Pin};

/// Observes the existing physical user and the real signup request.
/// Errors are logged while the generic duplicate response remains successful.
pub type ExistingUserSignupCallback = dyn Fn(UserView, AuthRequest) -> Pin<Box<dyn Future<Output = AuthResult<()>> + Send>>
    + Send
    + Sync;

/// Inputs to synthetic-user customization. These values are never persisted.
#[derive(Clone, Debug)]
pub struct SyntheticUserContext {
    pub core_fields: Map<String, Value>,
    pub additional_fields: Map<String, Value>,
    pub id: String,
}

/// Customizes a duplicate response before the registered public schema filters it.
/// Unknown and disabled-plugin fields are omitted; callback errors propagate.
pub type CustomSyntheticUserCallback =
    dyn Fn(SyntheticUserContext) -> AuthResult<Map<String, Value>> + Send + Sync;

pub(super) async fn notify_existing(
    user: UserView,
    request: &AuthRequest,
    config: &EmailPasswordConfig,
    context: &AuthContext<impl AuthSchema>,
) -> AuthResult<()> {
    let Some(callback) = config.on_existing_user_signup.clone() else {
        return Ok(());
    };
    let request = request.clone();
    super::super::authentication_helpers::run_owned_notification(
        context,
        async move {
            super::super::authentication_helpers::run_notification(callback(user, request)).await;
            Ok(())
        },
        context.config.awaited_notification_errors,
    )
    .await
}

pub(super) fn synthetic_response(
    body: &SignUpRequest,
    config: &EmailPasswordConfig,
    context: &AuthContext<impl AuthSchema>,
) -> AuthResult<(SignUpResponse<Value>, Option<Vec<String>>)> {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let core_fields = Map::from_iter([
        ("name".into(), json!(body.name)),
        ("email".into(), json!(body.email)),
        ("emailVerified".into(), json!(false)),
        ("image".into(), json!(body.image)),
        ("createdAt".into(), json!(now)),
        ("updatedAt".into(), json!(now)),
    ]);
    let input = SyntheticUserContext {
        core_fields,
        additional_fields: Map::new(),
        id: context
            .config
            .advanced
            .database
            .generated_id("user")?
            .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string()),
    };
    let mut candidate = if let Some(customize) = &config.custom_synthetic_user {
        customize(input)?
    } else {
        let mut fields = input.core_fields;
        _ = fields.insert("id".into(), json!(input.id));
        if config.enable_username {
            _ = fields.insert("username".into(), json!(body.username));
            _ = fields.insert("displayUsername".into(), json!(body.display_username));
        }
        fields
    };
    let mut result = Map::new();
    for field in ["id", "name", "email"] {
        if let Some(value) = candidate.remove(field) {
            _ = result.insert(field.into(), value);
        }
    }
    for (field, default) in [
        ("emailVerified", json!(false)),
        ("image", Value::Null),
        ("createdAt", json!(now)),
        ("updatedAt", json!(now)),
    ] {
        _ = result.insert(field.into(), candidate.remove(field).unwrap_or(default));
    }
    let mut defaults = Vec::new();
    let enabled = |key: &str| {
        context
            .get_metadata(key)
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    if config.enable_username {
        defaults.extend([("username", Value::Null), ("displayUsername", Value::Null)]);
    }
    if enabled("two_factor.enabled") {
        defaults.push(("twoFactorEnabled", json!(false)));
    }
    if enabled("admin.enabled") {
        let mut creation = alibi_core::CreateUser::new();
        super::super::helpers::apply_default_role(context, &mut creation);
        defaults.extend([
            ("role", json!(creation.role)),
            ("banned", json!(false)),
            ("banReason", Value::Null),
            ("banExpires", Value::Null),
        ]);
    }
    if enabled("anonymous.enabled") {
        defaults.push(("isAnonymous", json!(false)));
    }
    if enabled("phone-number.enabled") {
        defaults.extend([
            ("phoneNumber", Value::Null),
            ("phoneNumberVerified", Value::Null),
        ]);
    }
    if enabled("last-login-method.enabled") {
        defaults.push(("lastLoginMethod", Value::Null));
    }
    for (field, default) in defaults {
        _ = result.insert(field.into(), candidate.remove(field).unwrap_or(default));
    }
    Ok((
        SignUpResponse {
            token: None,
            user: Value::Object(result),
        },
        None,
    ))
}
