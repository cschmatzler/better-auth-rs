mod config;
mod http;
mod signin;
mod signup;
mod types;

use super::{email_verification::EmailVerificationPlugin, two_factor};
use crate::helpers::{SessionIssueError, apply_default_role};
use alibi_core::entity::{AuthAccount, AuthSession, AuthUser};
use alibi_core::field_policy::FieldValues;
use alibi_core::utils::cookie_utils::{
    create_session_cookie, create_session_cookie_with_max_age, create_session_like_cookie,
    related_cookie_name, sign_cookie_value,
};
use alibi_core::utils::password::{self as password_utils, PasswordHasher};
pub use alibi_core::utils::username::{
    UsernameConfig, UsernameNormalization, UsernameNormalizer, UsernameValidationOrder,
    UsernameValidator,
};
use alibi_core::wire::UserView;
use alibi_core::{AuthContext, AuthPlugin, AuthRoute};
use alibi_core::{AuthError, AuthResult};
use alibi_core::{
    AuthRequest, AuthResponse, CreateAccount, CreateSession, CreateUser, ErrorCodeMessageResponse,
    HttpMethod, RequestMeta,
};
use async_trait::async_trait;
pub use config::EmailPasswordConfig;
pub(crate) use config::password_length_limits;
pub(crate) use signin::sign_in_core;
pub(crate) use signin::sign_in_username_core;
pub use signup::{CustomSyntheticUserCallback, ExistingUserSignupCallback, SyntheticUserContext};
use std::io::Write;
use std::sync::Arc;
pub(crate) use types::SignInCoreResult;
pub(crate) use types::SignInResponse;
pub(crate) use types::SignUpRequest;
pub(crate) use types::SignUpResponse;

const MESSAGE_INVALID_USERNAME_OR_PASSWORD: &str = "Invalid username or password";

const MESSAGE_EMAIL_NOT_VERIFIED: &str = "Email not verified";

const MESSAGE_USERNAME_IS_ALREADY_TAKEN: &str = "Username is already taken. Please try another.";

/// Email and password authentication plugin
pub struct EmailPasswordPlugin {
    config: EmailPasswordConfig,
    /// Optional reference to the email-verification plugin so that
    /// `send_on_sign_in` can be triggered during the sign-in flow.
    email_verification: Option<Arc<EmailVerificationPlugin>>,
}

impl EmailPasswordPlugin {
    #[expect(
        clippy::new_without_default,
        reason = "plugin construction is intentionally explicit"
    )]
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: EmailPasswordConfig::default(),
            email_verification: None,
        }
    }

    #[must_use]
    pub const fn with_config(config: EmailPasswordConfig) -> Self {
        Self {
            config,
            email_verification: None,
        }
    }

    /// Attach an [`EmailVerificationPlugin`] so that `send_on_sign_in` is
    /// automatically called when a user signs in with an unverified email.
    #[must_use]
    pub fn with_email_verification(mut self, plugin: Arc<EmailVerificationPlugin>) -> Self {
        self.email_verification = Some(plugin);
        self
    }

    #[must_use]
    pub const fn enable_signup(mut self, enable: bool) -> Self {
        self.config.enable_signup = enable;
        self
    }

    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    #[must_use]
    pub fn on_existing_user_signup(mut self, callback: Arc<ExistingUserSignupCallback>) -> Self {
        self.config.on_existing_user_signup = Some(callback);
        self
    }

    #[must_use]
    pub fn custom_synthetic_user(mut self, callback: Arc<CustomSyntheticUserCallback>) -> Self {
        self.config.custom_synthetic_user = Some(callback);
        self
    }

    #[must_use]
    pub const fn enable_username(mut self, enable: bool) -> Self {
        self.config.enable_username = enable;
        self
    }

    /// Configure the installed username plugin's validation and normalization.
    #[must_use]
    pub fn username_config(mut self, policy: UsernameConfig) -> Self {
        self.config.username = policy;
        self
    }

    #[must_use]
    pub const fn require_email_verification(mut self, require: bool) -> Self {
        self.config.require_email_verification = require;
        self
    }

    #[must_use]
    pub const fn password_min_length(mut self, length: usize) -> Self {
        self.config.password_min_length = length;
        self
    }

    #[must_use]
    pub const fn password_max_length(mut self, length: usize) -> Self {
        self.config.password_max_length = length;
        self
    }

    #[must_use]
    pub const fn auto_sign_in(mut self, auto: bool) -> Self {
        self.config.auto_sign_in = auto;
        self
    }

    #[must_use]
    pub fn password_hasher(mut self, hasher: Arc<dyn PasswordHasher>) -> Self {
        self.config.password_hasher = Some(hasher);
        self
    }
}

#[async_trait]
impl<S: alibi_core::AuthSchema> AuthPlugin<S> for EmailPasswordPlugin {
    route_openapi_metadata!(S);

    fn name(&self) -> &'static str {
        "email-password"
    }

    async fn on_init(&self, ctx: &mut alibi_core::AuthInitContext<S>) -> AuthResult<()> {
        let mut config = self.config.clone();
        config.password_min_length = config.effective_min_length();
        config.password_max_length = config.effective_max_length();
        ctx.extensions.insert(config);
        if self.config.enable_username {
            ctx.extensions.insert(self.config.username.clone());
            let policy = self.config.username.clone();
            ctx.register_user_create_transform(move |mut data| {
                policy.normalize_fields(
                    &mut data.username,
                    &mut data.display_username,
                    &mut data.additional_fields,
                    true,
                )?;
                Ok(data)
            });
            let policy = self.config.username.clone();
            ctx.register_user_update_transform(move |_, mut data| {
                policy.normalize_fields(
                    &mut data.username,
                    &mut data.display_username,
                    &mut data.additional_fields,
                    false,
                )?;
                Ok(data)
            });
        }
        if self.config.enable_username {
            _ = ctx
                .metadata
                .insert("username.enabled".into(), serde_json::Value::Bool(true));
        }
        Ok(())
    }

    fn user_fields(&self) -> alibi_core::field_policy::FieldConfigs {
        if self.config.enable_username {
            self.config.username.fields()
        } else {
            indexmap::IndexMap::default()
        }
    }

    fn routes(&self) -> Vec<AuthRoute> {
        let mut routes = vec![AuthRoute::post("/sign-in/email", "sign_in_email")];
        if self.config.enable_username {
            routes.extend([
                AuthRoute::post("/sign-in/username", "sign_in_username"),
                AuthRoute::post("/is-username-available", "is_username_available"),
            ]);
        }

        routes.push(AuthRoute::post("/sign-up/email", "sign_up_email"));

        routes
    }

    fn allowed_media_types(&self, route: &AuthRoute) -> Vec<&'static str> {
        if matches!(route.path.as_str(), "/sign-up/email" | "/sign-in/email") {
            vec!["application/x-www-form-urlencoded", "application/json"]
        } else {
            vec!["application/json"]
        }
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/sign-up/email") => Ok(Some(self.handle_sign_up(req, ctx).await?)),
            (HttpMethod::Post, "/sign-in/email") => Ok(Some(self.handle_sign_in(req, ctx).await?)),
            (HttpMethod::Post, "/sign-in/username") if self.config.enable_username => {
                Ok(Some(self.handle_sign_in_username(req, ctx).await?))
            }
            (HttpMethod::Post, "/is-username-available") if self.config.enable_username => {
                Ok(Some(self.handle_is_username_available(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }

    async fn on_user_created(&self, user: &S::User, _ctx: &AuthContext<S>) -> AuthResult<()> {
        if self.config.require_email_verification
            && !user.email_verified()
            && let Some(email) = user.email()
        {
            _ = writeln!(
                std::io::stdout().lock(),
                "Email verification required for user: {email}"
            );
        }
        Ok(())
    }
}

impl std::fmt::Debug for EmailPasswordPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailPasswordPlugin")
            .finish_non_exhaustive()
    }
}

fn username_error_response(status: u16, code: &str, message: &str) -> AuthResult<AuthResponse> {
    AuthResponse::json(
        status,
        &ErrorCodeMessageResponse {
            code: Some(code.to_owned()),
            message: message.to_owned(),
        },
    )
    .map_err(AuthError::from)
}

fn create_session_cookie_for_remember_me(
    token: &str,
    remember_me: Option<bool>,
    config: &alibi_core::AuthConfig,
) -> AuthResult<String> {
    if remember_me == Some(false) {
        create_session_cookie_with_max_age(Some(token), None, config)
    } else {
        create_session_cookie(token, config)
    }
}

fn append_dont_remember_cookie(
    response: AuthResponse,
    remember_me: Option<bool>,
    config: &alibi_core::AuthConfig,
) -> AuthResult<AuthResponse> {
    Ok(if remember_me == Some(false) {
        response.with_appended_header(
            "Set-Cookie",
            create_session_like_cookie(
                &related_cookie_name(config, "dont_remember"),
                &sign_cookie_value("true", config.current_secret()),
                None,
                config,
            )?,
        )
    } else {
        response
    })
}

/// Core sign-up logic.
///
/// Returns the response and optional rendered session headers. Real automatic
/// sign-in renders once inside the signup transaction; synthetic duplicates
/// return no headers.
#[expect(
    clippy::too_many_lines,
    reason = "Keep signup validation, persistence, and provider callbacks in compatibility order"
)]
pub(crate) async fn sign_up_core<S: alibi_core::AuthSchema>(
    request: &AuthRequest,
    body: &SignUpRequest,
    config: &EmailPasswordConfig,
    meta: &RequestMeta,
    ctx: &AuthContext<S>,
) -> AuthResult<(SignUpResponse<serde_json::Value>, Option<Vec<String>>)> {
    if !config.enabled || !config.enable_signup {
        return Err(AuthError::Upstream {
            status: 400,
            code: "EMAIL_PASSWORD_SIGN_UP_DISABLED",
            message: "Email and password sign up is not enabled",
        });
    }

    password_utils::validate_password(
        &body.password,
        config.effective_min_length(),
        config.effective_max_length(),
        ctx,
    )?;

    let mut input_fields = body.additional_fields.clone();
    if config.enable_username {
        if let Some(value) = &body.username {
            _ = input_fields.insert(
                "username".into(),
                alibi_core::utils::json::JsValue::String(value.clone()),
            );
        }
        if config.username.include_display_username
            && let Some(value) = &body.display_username
        {
            _ = input_fields.insert(
                "displayUsername".into(),
                alibi_core::utils::json::JsValue::String(value.clone()),
            );
        }
    }
    let additional_fields =
        ctx.parse_user_fields(&input_fields, true)
            .map_err(|error| match error {
                alibi_core::field_policy::FieldInputError::Validation { code, message } => {
                    AuthError::Api {
                        status: 400,
                        code: Some(code.into()),
                        message,
                    }
                }
                alibi_core::field_policy::FieldInputError::Transform(error) => error,
            })?;

    super::last_login_method::reject_last_login_method_input(ctx, body.last_login_method.as_ref())?;

    let phone_enabled = ctx
        .get_metadata("phone-number.enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if phone_enabled {
        super::phone_number::reject_verified_input(body.phone_number_verified.as_ref())?;
    }

    if let Some(user) = ctx.database.get_user_by_email(&body.email).await? {
        if config.require_email_verification || !config.auto_sign_in {
            _ = ctx
                .hash_password(config.password_hasher.as_ref(), &body.password)
                .await?;
            signup::notify_existing(ctx.user_view(&user), request, config, ctx).await?;
            return signup::synthetic_response(body, &additional_fields, config, ctx);
        }
        // TS returns 422 UNPROCESSABLE_ENTITY for duplicate email
        return Err(AuthError::UnprocessableEntity(
            "User already exists. Use another email.".to_owned(),
        ));
    }

    let password_hash = ctx
        .hash_password(config.password_hasher.as_ref(), &body.password)
        .await?;

    let mut create_user = CreateUser::new()
        .with_email(&body.email)
        .with_name(&body.name);
    create_user.image = body.image.clone();
    let duplicate_fields = additional_fields.clone();
    create_user.additional_fields = additional_fields;
    create_user.email_verified = Some(false);
    super::authentication_helpers::apply_creation_input_defaults(ctx, &mut create_user);
    if phone_enabled {
        create_user.phone_number =
            super::phone_number::parse_signup_phone(ctx, body.phone_number.as_ref()).await?;
    }
    apply_default_role(ctx, &mut create_user);
    if config.enable_username {
        create_user.username = create_user
            .additional_fields
            .get("username")
            .and_then(alibi_core::utils::json::JsValue::as_str)
            .map(str::to_owned);
        if create_user.username.is_none()
            && let Some(value) = &body.username
        {
            create_user.username = Some(config.username.normalize(value)?);
        }
        if config.username.include_display_username {
            create_user.display_username = create_user
                .additional_fields
                .get("displayUsername")
                .and_then(alibi_core::utils::json::JsValue::as_str)
                .map(str::to_owned)
                .or_else(|| body.display_username.clone());
        }
    }
    let auto_sign_in = config.auto_sign_in && !config.require_email_verification;
    let expires_in = if body.remember_me == Some(false) {
        chrono::Duration::days(1)
    } else {
        ctx.config.session.expires_in
    };
    let ip_address = meta.ip_address.clone();
    let user_agent = meta.user_agent.clone();
    let database = Arc::clone(&ctx.database);
    let transaction_database = Arc::clone(&database);
    let require_email_verification = config.require_email_verification;
    let callback_url = body.callback_url.clone();
    let remember_me = body.remember_me;
    let duplicate_body = body.clone();
    let duplicate_config = config.clone();
    let signup_context = AuthContext {
        config: Arc::clone(&ctx.config),
        database: Arc::clone(&ctx.database),
        email_provider: ctx.email_provider.clone(),
        metadata: ctx.metadata.clone(),
        extensions: ctx.extensions.clone(),
    };

    alibi_core::store::transaction(database.as_ref(), move |tx| {
        let _database = Arc::clone(&transaction_database);
        Box::pin(async move {
            let user = match tx
                .create_user_with_source_record(
                    create_user,
                    alibi_core::user_validation::UserValidationSource::creation("email-password"),
                )
                .await
            {
                Ok(user) => user,
                Err(AuthError::UserCreationCancelled) => {
                    return Err(AuthError::bad_request("Failed to create user"));
                }
                Err(error) if error.status_code() == 403 && !auto_sign_in => {
                    return signup::synthetic_response(
                        &duplicate_body,
                        &duplicate_fields,
                        &duplicate_config,
                        &signup_context,
                    );
                }
                Err(AuthError::Database(_) | AuthError::CallbackFailure(_)) => {
                    return Err(AuthError::UnprocessableEntity(
                        "Failed to create user".to_owned(),
                    ));
                }
                Err(error) => return Err(error),
            };

            _ = tx
                .create_account_record(CreateAccount {
                    additional_fields: FieldValues::default(),
                    user_id: user.id().to_string(),
                    account_id: user.id().to_string(),
                    provider_id: "credential".to_owned(),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                    password: Some(password_hash.clone()),
                })
                .await?;

            super::email_verification::send_signup_verification(
                &user,
                callback_url.as_deref(),
                require_email_verification,
                &signup_context,
                tx,
            )
            .await?;

            if auto_sign_in {
                let session = tx
                    .create_session_record(CreateSession {
                        additional_fields: FieldValues::default(),
                        token: None,
                        active_team_id: None,
                        user_id: user.id().to_string(),
                        expires_at: chrono::Utc::now() + expires_in,
                        ip_address,
                        user_agent,
                        impersonated_by: None,
                        active_organization_id: None,
                    })
                    .await?;
                let token = session.token().to_owned();
                // Source sign-up emits inside its transaction. Serializer failure
                // rolls back these rows; sign-in retains its separate commit policy.
                let mut cookies = vec![create_session_cookie_for_remember_me(
                    &token,
                    remember_me,
                    &signup_context.config,
                )?];
                if remember_me == Some(false) {
                    cookies.push(create_session_like_cookie(
                        &related_cookie_name(&signup_context.config, "dont_remember"),
                        &sign_cookie_value("true", signup_context.config.current_secret()),
                        None,
                        &signup_context.config,
                    )?);
                }
                alibi_core::session::cookie_cache::runtime::emit_issuance_in_transaction(
                    &signup_context,
                    &user,
                    &session,
                    tx,
                )
                .await?;
                super::helpers::record_completed_session_record::<S>(&user, &session);

                Ok((
                    SignUpResponse {
                        token: Some(token.clone()),
                        user: password_utils::serialize_to_value(&signup_context.user_view(&user))?,
                    },
                    Some(cookies),
                ))
            } else {
                Ok((
                    SignUpResponse {
                        token: None,
                        user: password_utils::serialize_to_value(&signup_context.user_view(&user))?,
                    },
                    None,
                ))
            }
        })
    })
    .await
}

async fn load_credential_password_hash(
    user: &impl AuthUser,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<String> {
    super::helpers::get_credential_account(ctx, user.id())
        .await?
        .and_then(|account| account.password().map(str::to_owned))
        .ok_or(AuthError::InvalidCredentials)
}

async fn verify_user_password(
    user: &impl AuthUser,
    password: &str,
    config: &EmailPasswordConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<()> {
    let stored_hash = load_credential_password_hash(user, ctx).await?;
    password_utils::verify_password(config.password_hasher.as_ref(), password, &stored_hash).await
}

/// Shared sign-in finalization logic after user lookup and credential verification.
async fn finalize_sign_in_with_user_core<S: alibi_core::AuthSchema>(
    req: &AuthRequest,
    user: alibi_core::AdapterRecord<S::User>,
    remember_me: Option<bool>,
    _email_verification: Option<&EmailVerificationPlugin>,
    callback_url: Option<&str>,
    meta: &RequestMeta,
    ctx: &AuthContext<S>,
) -> AuthResult<SignInCoreResult<UserView>> {
    let mut set_cookie_headers = Vec::new();

    let mut issuing_config = (*ctx.config).clone();
    if remember_me == Some(false) {
        issuing_config.session.expires_in = chrono::Duration::days(1);
    }
    let issuing_context = AuthContext {
        config: Arc::new(issuing_config),
        database: Arc::clone(&ctx.database),
        email_provider: ctx.email_provider.clone(),
        metadata: ctx.metadata.clone(),
        extensions: ctx.extensions.clone(),
    };
    let issued = super::helpers::issue_selected_user_session_record(
        &issuing_context,
        user.clone(),
        meta.ip_address.clone(),
        meta.user_agent.clone(),
    )
    .await
    .map_err(SessionIssueError::into_auth_error)?;
    if two_factor::is_enabled(ctx) && user.two_factor_enabled() {
        let trusted_device = two_factor::inspect_trusted_device(req, &user, ctx).await?;
        if trusted_device.trusted {
            set_cookie_headers.extend(trusted_device.set_cookie_headers);
        } else {
            ctx.database.delete_session(issued.session.token()).await?;
            alibi_core::session::cookie_cache::runtime::discard_issuance(req);
            let redirect = two_factor::begin_sign_in_challenge(&user, remember_me, ctx).await?;
            let mut redirect_headers = trusted_device.set_cookie_headers;
            redirect_headers.extend(redirect.set_cookie_headers);
            return Ok(SignInCoreResult::TwoFactorRedirect {
                response: redirect.response,
                set_cookie_headers: redirect_headers,
            });
        }
    }

    let session = issued.session;
    let token = session.token().to_owned();

    let response = SignInResponse {
        redirect: callback_url.is_some_and(|url| !url.is_empty()),
        token: token.clone(),
        url: callback_url.map(str::to_owned),
        user: ctx.user_view(&issued.user),
    };
    Ok(SignInCoreResult::Success {
        response,
        token,
        set_cookie_headers,
    })
}

/// Core sign-in by email.
async fn send_required_sign_in_verification(
    user: &impl AuthUser,
    callback_url: Option<&str>,
    email_verification: Option<&EmailVerificationPlugin>,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<()> {
    if let Some(plugin) = email_verification {
        plugin
            .send_verification_on_sign_in(user, callback_url, ctx)
            .await?;
    } else if let Some(config) = ctx
        .extensions
        .get::<super::email_verification::EmailVerificationConfig>()
        && config.send_on_sign_in
    {
        EmailVerificationPlugin::with_config((*config).clone())
            .send_verification_on_sign_in(user, callback_url, ctx)
            .await?;
    }
    Ok(())
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use alibi_core::AuthContext;
    use alibi_core::config::AuthConfig;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type TestSchema = alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

    async fn create_test_context() -> AuthContext<TestSchema> {
        let config = AuthConfig::new("test-secret-key-at-least-32-chars-long");
        let config = Arc::new(config);
        let database = crate::test_helpers::create_test_database().await;
        AuthContext::new(config, database)
    }

    fn create_signup_request(email: &str, password: &str) -> AuthRequest {
        let body = serde_json::json!({
            "name": "Test User",
            "email": email,
            "password": password,
        });
        AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-up/email".to_owned(),
            HashMap::new(),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        )
    }

    // Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
    #[tokio::test]
    async fn test_auto_sign_in_false_returns_no_session() {
        let plugin = EmailPasswordPlugin::new().auto_sign_in(false);
        let ctx = create_test_context().await;

        let req = create_signup_request("auto@example.com", "Password123!");
        let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Response should NOT have a Set-Cookie header
        let has_cookie = response
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"));
        assert!(!has_cookie, "auto_sign_in=false should not set a cookie");

        // Response body token should be null
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            (*(body).get("token").unwrap_or(&serde_json::Value::Null)).is_null(),
            "auto_sign_in=false should return null token"
        );
        // But the user should still be created
        assert!(
            (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
                .get("id")
                .unwrap_or(&serde_json::Value::Null))
            .is_string()
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
    #[tokio::test]
    async fn test_auto_sign_in_true_returns_session() {
        let plugin = EmailPasswordPlugin::new(); // default auto_sign_in=true
        let ctx = create_test_context().await;

        let req = create_signup_request("autotrue@example.com", "Password123!");
        let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Response SHOULD have a Set-Cookie header
        let has_cookie = response
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"));
        assert!(has_cookie, "auto_sign_in=true should set a cookie");

        // Response body token should be a string
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            (*(body).get("token").unwrap_or(&serde_json::Value::Null)).is_string(),
            "auto_sign_in=true should return a session token"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
    #[tokio::test]
    async fn test_password_max_length_rejection() {
        let plugin = EmailPasswordPlugin::new().password_max_length(128);
        let ctx = create_test_context().await;

        // Password of exactly 129 chars should be rejected
        let long_password = format!("A1!{}", "a".repeat(126)); // 129 chars total
        let req = create_signup_request("long@example.com", &long_password);
        let err = plugin.handle_sign_up(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);

        // Password of exactly 128 chars should be accepted
        let ok_password = format!("A1!{}", "a".repeat(125)); // 128 chars total
        let req_2 = create_signup_request("ok@example.com", &ok_password);
        let response = plugin.handle_sign_up(&req_2, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
    }

    // Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
    #[tokio::test]
    async fn test_custom_password_hasher() {
        /// A simple test hasher that prefixes the password with "hashed:"
        struct TestHasher;

        #[async_trait]
        impl PasswordHasher for TestHasher {
            async fn hash(&self, password: &str) -> AuthResult<String> {
                Ok(format!("hashed:{password}"))
            }
            async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
                Ok(hash == format!("hashed:{password}"))
            }
        }

        let hasher: Arc<dyn PasswordHasher> = Arc::new(TestHasher);
        let plugin = EmailPasswordPlugin::new().password_hasher(hasher);
        let ctx = create_test_context().await;

        // Sign up with custom hasher
        let req = create_signup_request("hasher@example.com", "Password123!");
        let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Verify the stored hash uses our custom hasher
        let user = ctx
            .database
            .get_user_by_email("hasher@example.com")
            .await
            .unwrap()
            .unwrap();
        let stored_hash = ctx
            .database
            .get_user_accounts(&user.id())
            .await
            .unwrap()
            .into_iter()
            .find(|account| account.provider_id() == "credential")
            .and_then(|account| account.password().map(str::to_owned))
            .expect("credential account should store hashed password");
        assert_eq!(stored_hash, "hashed:Password123!");

        // Sign in should work with the custom hasher
        let signin_body = serde_json::json!({
            "email": "hasher@example.com",
            "password": "Password123!",
        });
        let signin_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-in/email".to_owned(),
            HashMap::new(),
            Some(signin_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response_2 = plugin.handle_sign_in(&signin_req, &ctx).await.unwrap();
        assert_eq!(response_2.status, 200);

        // Sign in with wrong password should fail
        let bad_body = serde_json::json!({
            "email": "hasher@example.com",
            "password": "WrongPassword!",
        });
        let bad_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-in/email".to_owned(),
            HashMap::new(),
            Some(bad_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let err = plugin.handle_sign_in(&bad_req, &ctx).await.unwrap_err();
        assert_eq!(err.to_string(), AuthError::InvalidCredentials.to_string());
    }

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts :: sign-in path verifies the password once before creating a session; adapted to ensure the Rust username path does not duplicate expensive password verification.
    #[tokio::test]
    async fn test_sign_in_username_verifies_password_once() {
        struct CountingHasher {
            verify_calls: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl PasswordHasher for CountingHasher {
            async fn hash(&self, password: &str) -> AuthResult<String> {
                Ok(format!("hashed:{password}"))
            }

            async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
                self.verify_calls.fetch_add(1, Ordering::SeqCst);
                Ok(hash == format!("hashed:{password}"))
            }
        }

        let verify_calls = Arc::new(AtomicUsize::new(0));
        let hasher: Arc<dyn PasswordHasher> = Arc::new(CountingHasher {
            verify_calls: std::sync::Arc::clone(&verify_calls),
        });
        let plugin = EmailPasswordPlugin::new().password_hasher(hasher);
        let ctx = create_test_context().await;

        let signup_body = serde_json::json!({
            "email": "username-counter@example.com",
            "password": "Password123!",
            "name": "Counter User",
            "username": "Counter_User",
        });
        let signup_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-up/email".to_owned(),
            HashMap::new(),
            Some(signup_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let signup_response = plugin.handle_sign_up(&signup_req, &ctx).await.unwrap();
        assert_eq!(signup_response.status, 200);

        verify_calls.store(0, Ordering::SeqCst);

        let signin_body = serde_json::json!({
            "username": "COUNTER_USER",
            "password": "Password123!",
        });
        let signin_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-in/username".to_owned(),
            HashMap::new(),
            Some(signin_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let signin_response = plugin
            .handle_sign_in_username(&signin_req, &ctx)
            .await
            .unwrap();
        assert_eq!(signin_response.status, 200);
        assert_eq!(verify_calls.load(Ordering::SeqCst), 1);
    }

    // Rust-specific surface: route-table registration for the endpoint declared in
    // packages/better-auth/src/plugins/username/index.ts :: isUsernameAvailable.
    #[tokio::test]
    async fn test_is_username_available_route_registered() {
        let plugin = EmailPasswordPlugin::new();
        let routes = <EmailPasswordPlugin as AuthPlugin<TestSchema>>::routes(&plugin);
        assert!(
            routes.iter().any(|r| r.path == "/is-username-available"),
            "route /is-username-available should be registered"
        );
    }

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
    // isUsernameAvailable returns `{ available: true }` when no user holds the
    // normalized username; adapted to the Rust email-password plugin.
    #[tokio::test]
    async fn test_is_username_available_fresh() {
        let plugin = EmailPasswordPlugin::new();
        let ctx = create_test_context().await;

        let body = serde_json::json!({ "username": "fresh_user" });
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/is-username-available".to_owned(),
            HashMap::new(),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin
            .handle_is_username_available(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(json).get("available").unwrap_or(&serde_json::Value::Null)),
            true
        );
    }

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
    // isUsernameAvailable returns `{ available: false }` when the adapter finds a
    // user on the normalized username; adapted to the Rust email-password plugin.
    #[tokio::test]
    async fn test_is_username_available_taken() {
        let plugin = EmailPasswordPlugin::new();
        let ctx = create_test_context().await;

        // Sign up a user with a username
        let signup_body = serde_json::json!({
            "name": "Taken User",
            "email": "taken@example.com",
            "password": "Password123!",
            "username": "taken_user",
        });
        let signup_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-up/email".to_owned(),
            HashMap::new(),
            Some(signup_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let resp = plugin.handle_sign_up(&signup_req, &ctx).await.unwrap();
        assert_eq!(resp.status, 200);

        let body = serde_json::json!({ "username": "taken_user" });
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/is-username-available".to_owned(),
            HashMap::new(),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin
            .handle_is_username_available(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(json).get("available").unwrap_or(&serde_json::Value::Null)),
            false
        );
    }

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
    // isUsernameAvailable throws UNPROCESSABLE_ENTITY with code USERNAME_TOO_SHORT
    // below `minUsernameLength` (default 3); adapted to the Rust email-password plugin.
    #[tokio::test]
    async fn test_is_username_available_too_short() {
        let plugin = EmailPasswordPlugin::new();
        let ctx = create_test_context().await;

        let body = serde_json::json!({ "username": "ab" });
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/is-username-available".to_owned(),
            HashMap::new(),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin
            .handle_is_username_available(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 422);
        let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(json).get("code").unwrap_or(&serde_json::Value::Null)),
            "USERNAME_TOO_SHORT"
        );
    }

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
    // isUsernameAvailable rejects usernames that fail `defaultUsernameValidator`
    // with UNPROCESSABLE_ENTITY; adapted to the Rust email-password plugin.
    #[tokio::test]
    async fn test_is_username_available_invalid_chars() {
        let plugin = EmailPasswordPlugin::new();
        let ctx = create_test_context().await;

        let body = serde_json::json!({ "username": "bad user!" });
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/is-username-available".to_owned(),
            HashMap::new(),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin
            .handle_is_username_available(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 422);
        let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(json).get("code").unwrap_or(&serde_json::Value::Null)),
            "INVALID_USERNAME"
        );
    }
}
// LCOV_EXCL_STOP
