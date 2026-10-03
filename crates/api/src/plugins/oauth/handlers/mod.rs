use super::encryption::{encrypt_provider_token_set, encrypt_token_set, provider_token_nulls};
use super::providers::{
    OAuthCallbackUserName, OAuthCallbackUserPayload, OAuthClientAssertionContext, OAuthConfig,
    OAuthProvider, OAuthScopeOrder, OAuthTokenEndpointAuth, OAuthTokenGrant, OAuthTokenSet,
    OAuthUserInfo, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use super::state::{
    AccountCookiePayload, OAuthStateLink, OAuthStatePayload, RecoveredOAuthServerContext,
    account_cookie_name, capture_server_context, create_account_cookie_value,
    create_cookie_state_value, create_database_state_cookie_value, decode_account_cookie_value,
    decode_cookie_state_value, decode_database_state_cookie_value, filter_additional_state_data,
    get_cookie, state_cookie_name, verified_server_context,
};
use super::types::{
    LinkSocialRequest, OAuthIdTokenRequest, SocialSignInRequest, SocialSignInResponse,
};
use crate::plugins::helpers::{
    SessionIssueError, apply_default_role, issue_selected_user_session_record,
};
use base64::Engine;
use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::user_validation::{
    UserValidationAction, UserValidationData, UserValidationSource, validate_user_info,
};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateAccount, CreateUser,
    CreateVerification, UpdateAccount, UpdateUser,
};
use chrono::{Duration, Utc};
use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub(in crate::plugins) struct ProcessOAuthUserResult {
    pub(in crate::plugins) session: SessionView,
    pub(in crate::plugins) user: UserView,
    pub(in crate::plugins) is_register: bool,
    pub(in crate::plugins) account_cookie: Option<AccountCookiePayload>,
}

pub(in crate::plugins) enum OAuthSignInError {
    Generic(String),
    AccountLookup(AuthError),
    SessionAuth(AuthError),
    IdentityDenied { code: String, message: String },
    Banned(String),
    EmailNotVerified,
}

impl OAuthSignInError {
    fn from_identity_denial(error: AuthError) -> Self {
        let (_, code, message) = error.error_payload();
        Self::IdentityDenied {
            code: code.unwrap_or_else(|| "validation_failed".into()),
            message,
        }
    }
    fn from_account_lookup(error: AuthError) -> Self {
        if matches!(
            error,
            AuthError::Database(better_auth_core::DatabaseError::AmbiguousAccount { .. })
        ) {
            Self::AccountLookup(error)
        } else {
            Self::Generic(error.to_string())
        }
    }

    pub(in crate::plugins) fn is_ambiguous_account(&self) -> bool {
        matches!(
            self,
            Self::AccountLookup(AuthError::Database(
                better_auth_core::DatabaseError::AmbiguousAccount { .. }
            ))
        )
    }

    pub(in crate::plugins) fn redirect_parts(&self) -> (String, Option<&str>) {
        match self {
            // Upstream turns a plain internal error string into the `error`
            // param verbatim, with no description.
            Self::Generic(message) => (message.replace(' ', "_"), None),
            Self::AccountLookup(error) | Self::SessionAuth(error) => {
                (error.to_string().replace(' ', "_"), None)
            }
            // An APIError instead redirects with its `code` and message, so the
            // param is the constant, not a lowercased word.
            Self::Banned(message) => ("BANNED_USER".to_owned(), Some(message.as_str())),
            Self::IdentityDenied { code, message } => (code.clone(), Some(message.as_str())),
            Self::EmailNotVerified => ("email_not_verified".to_owned(), None),
        }
    }
}

impl From<String> for OAuthSignInError {
    fn from(value: String) -> Self {
        Self::Generic(value)
    }
}

impl From<SessionIssueError> for OAuthSignInError {
    fn from(value: SessionIssueError) -> Self {
        match value {
            SessionIssueError::Auth(error) => Self::SessionAuth(error),
            SessionIssueError::Banned { message } => Self::Banned(message),
        }
    }
}

struct InitiatedOAuthFlow {
    response: SocialSignInResponse,
    state: String,
    payload: OAuthStatePayload,
}

struct FlowStartRequest<'a> {
    provider_name: &'a str,
    provider: &'a OAuthProvider,
    callback_url: &'a str,
    new_user_callback_url: Option<String>,
    error_callback_url: Option<String>,
    scopes: Option<&'a [String]>,
    login_hint: Option<&'a str>,
    additional_params: Option<&'a std::collections::BTreeMap<String, String>>,
    request_sign_up: Option<bool>,
    additional_data: serde_json::Map<String, serde_json::Value>,
    link: Option<OAuthStateLink>,
    disable_redirect: bool,
}

/// Normalized policy shared by social callbacks and One Tap.
#[derive(Clone, Default)]
pub(in crate::plugins) struct OAuthProcessPolicy {
    pub(in crate::plugins) override_user_info: bool,
    pub(in crate::plugins) require_email_verification: bool,
    pub(in crate::plugins) callback_url: Option<String>,
    pub(in crate::plugins) use_updated_user: bool,
}

impl OAuthProcessPolicy {
    const fn for_provider(provider: &OAuthProvider, callback_url: Option<String>) -> Self {
        Self {
            override_user_info: provider.override_user_info_on_sign_in
                && match &provider.authorization {
                    Some(policy) => policy.honor_factory_options,
                    None => true,
                },
            require_email_verification: provider.require_email_verification
                && match &provider.authorization {
                    Some(policy) => policy.honor_factory_options,
                    None => true,
                },
            callback_url,
            use_updated_user: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers (DRY)
// ---------------------------------------------------------------------------

/// Authenticate the current request and return the validated session.
async fn require_session<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> Result<better_auth_core::SessionView, AuthError> {
    ctx.require_cached_session(req)
        .await
        .map(|(_, session)| session)
}

fn generate_pkce() -> (String, String) {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    let mut random = thread_rng();
    let verifier: String = (0..128)
        .filter_map(|_| {
            ALPHABET
                .get(random.gen_range(0..ALPHABET.len()))
                .copied()
                .map(char::from)
        })
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
    (verifier, challenge)
}

fn build_authorization_url(
    provider: &OAuthProvider,
    callback_url: &str,
    scopes: Option<&[String]>,
    state: &str,
    code_challenge: &str,
    login_hint: Option<&str>,
    additional_params: Option<&std::collections::BTreeMap<String, String>>,
) -> AuthResult<String> {
    if provider
        .authorization
        .as_ref()
        .is_some_and(|policy| policy.require_client_secret)
        && (provider.client_id.is_empty() || provider.client_secret.is_empty())
    {
        return Err(AuthError::config(
            "Client ID and client secret are required",
        ));
    }
    if provider
        .authorization
        .as_ref()
        .is_some_and(|policy| policy.require_client_id)
        && provider.client_id.is_empty()
    {
        return Err(AuthError::config("Client ID is required"));
    }
    let effective_scopes: Vec<&str> = provider.authorization.as_ref().map_or_else(
        || {
            scopes.map_or_else(
                || provider.scopes.iter().map(String::as_str).collect(),
                |s| s.iter().map(String::as_str).collect(),
            )
        },
        |policy| {
            if policy.omit_scopes {
                return Vec::new();
            }
            let mut effective = Vec::new();
            if !policy.disable_default_scopes {
                effective.extend(provider.scopes.iter().map(String::as_str));
            }
            let configured = policy.configured_scopes.iter().map(String::as_str);
            let requested = scopes.unwrap_or_default().iter().map(String::as_str);
            match policy.scope_order {
                OAuthScopeOrder::ConfiguredThenRequested => {
                    effective.extend(configured);
                    effective.extend(requested);
                }
                OAuthScopeOrder::RequestedThenConfigured => {
                    effective.extend(requested);
                    effective.extend(configured);
                }
            }
            if policy.deduplicate_scopes {
                let mut seen = std::collections::HashSet::new();
                effective.retain(|scope| seen.insert(*scope));
            }
            effective
        },
    );
    let scope_str = effective_scopes.join(
        provider
            .authorization
            .as_ref()
            .map_or(" ", |policy| policy.scope_separator.as_str()),
    );

    let mut url = url::Url::parse(&provider.auth_url)
        .map_err(|error| AuthError::internal(format!("Invalid auth URL: {error}")))?;
    set_authorization_param(
        &mut url,
        "response_type",
        provider
            .authorization
            .as_ref()
            .map_or("code", |policy| policy.response_type.as_str()),
    );
    set_authorization_param(
        &mut url,
        provider
            .authorization
            .as_ref()
            .map_or("client_id", |policy| policy.client_id_parameter.as_str()),
        provider
            .authorization
            .as_ref()
            .and_then(|policy| policy.literal_client_id.as_deref())
            .unwrap_or(&provider.client_id),
    );
    set_authorization_param(&mut url, "state", state);
    if provider.authorization.is_none()
        || !effective_scopes.is_empty()
        || provider
            .authorization
            .as_ref()
            .is_some_and(|policy| policy.emit_empty_scope)
    {
        set_authorization_param(&mut url, "scope", &scope_str);
    }
    set_authorization_param(
        &mut url,
        "redirect_uri",
        provider
            .authorization
            .as_ref()
            .and_then(|policy| policy.redirect_uri.as_deref())
            .filter(|uri| !uri.is_empty())
            .unwrap_or(callback_url),
    );
    if provider
        .authorization
        .as_ref()
        .is_none_or(|policy| policy.pkce)
    {
        set_authorization_param(&mut url, "code_challenge_method", "S256");
        set_authorization_param(&mut url, "code_challenge", code_challenge);
    }
    if let Some(policy) = &provider.authorization {
        if let Some(mode) = policy
            .response_mode
            .as_deref()
            .filter(|mode| !mode.is_empty())
        {
            set_authorization_param(&mut url, "response_mode", mode);
        }
        if let Some(prompt) = policy
            .prompt
            .as_deref()
            .filter(|prompt| !prompt.is_empty())
            .or(policy.default_prompt.as_deref())
        {
            set_authorization_param(&mut url, "prompt", prompt);
        }
        if effective_scopes.contains(&"bot")
            && let Some(permissions) = policy.discord_permissions
        {
            let value = if permissions.is_nan() {
                "NaN".into()
            } else if permissions == f64::INFINITY {
                "Infinity".into()
            } else if permissions == f64::NEG_INFINITY {
                "-Infinity".into()
            } else {
                let number = serde_json::Number::from_f64(permissions)
                    .ok_or_else(|| AuthError::internal("Invalid Discord permissions number"))?;
                better_auth_core::utils::json::number_to_string(&number)?
            };
            set_authorization_param(&mut url, "permissions", &value);
        }
    }
    if let Some(login_hint) = login_hint.filter(|hint| {
        provider
            .authorization
            .as_ref()
            .is_none_or(|policy| policy.login_hint && !hint.is_empty())
    }) {
        set_authorization_param(&mut url, "login_hint", login_hint);
    }
    for (key, value) in &provider.authorization_params {
        set_authorization_param(&mut url, key, value);
    }
    if let Some(params) = additional_params {
        for (key, value) in params {
            if provider.authorization.as_ref().is_some_and(|policy| {
                policy.client_id_parameter != "client_id" && key == &policy.client_id_parameter
            }) {
                continue;
            }
            set_authorization_param(&mut url, key, value);
        }
    }
    if let Some(policy) = &provider.authorization {
        for (key, value) in &policy.fixed_authorization_params {
            set_authorization_param(&mut url, key, value);
        }
        if let Some(fragment) = &policy.authorization_fragment {
            url.set_fragment(Some(fragment));
        }
    }
    if provider.authorization.as_ref().is_some_and(|policy| {
        matches!(
            policy.scope_encoding,
            super::providers::OAuthScopeEncoding::UriComponent
        )
    }) && let Some(scope) = url
        .query_pairs()
        .find_map(|(key, value)| (key == "scope").then(|| value.into_owned()))
        .filter(|value| !value.is_empty())
    {
        let existing: Vec<_> = url
            .query_pairs()
            .filter(|(key, _)| key != "scope")
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        _ = url.query_pairs_mut().clear().extend_pairs(existing);
        let encoded = [
            ("%21", "!"),
            ("%27", "'"),
            ("%28", "("),
            ("%29", ")"),
            ("%2A", "*"),
        ]
        .into_iter()
        .fold(
            urlencoding::encode(&scope).into_owned(),
            |value, (encoded, literal)| value.replace(encoded, literal),
        );
        let query = format!("{}&scope={encoded}", url.query().unwrap_or_default());
        url.set_query(Some(&query));
    }
    Ok(url.to_string())
}

// URLSearchParams.set replaces duplicate values at the first occurrence;
// unrelated application-owned endpoint parameters retain their order.
fn set_authorization_param(url: &mut url::Url, key: &str, value: &str) {
    let mut replaced = false;
    let mut pairs = Vec::new();
    for (name, previous) in url.query_pairs() {
        if name == key {
            if !replaced {
                pairs.push((key.to_owned(), value.to_owned()));
                replaced = true;
            }
        } else {
            pairs.push((name.into_owned(), previous.into_owned()));
        }
    }
    if !replaced {
        pairs.push((key.to_owned(), value.to_owned()));
    }
    _ = url.query_pairs_mut().clear().extend_pairs(pairs);
}

fn validate_authorization_params(
    params: Option<&std::collections::BTreeMap<String, String>>,
) -> AuthResult<()> {
    const RESERVED: [&str; 8] = [
        "state",
        "client_id",
        "redirect_uri",
        "response_type",
        "code_challenge",
        "code_challenge_method",
        "nonce",
        "scope",
    ];
    if params.is_some_and(|params| params.keys().any(|key| RESERVED.contains(&key.as_str()))) {
        return Err(AuthError::Api {
            status: 400,
            code: Some("VALIDATION_ERROR".into()),
            message: format!(
                "[body.additionalParams] additionalParams cannot include reserved OAuth parameters: {}",
                RESERVED.join(", ")
            ),
        });
    }
    Ok(())
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) async fn refresh_tokens_via_provider(
    provider: &OAuthProvider,
    refresh_token: &str,
) -> AuthResult<OAuthTokenSet> {
    if let Some(handler) = &provider.refresh_access_token {
        return handler
            .refresh_access_token(refresh_token)
            .await
            .map_err(AuthError::internal);
    }

    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    if let Some(scope) = provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.refresh_scope.as_deref())
    {
        form.push(("scope", scope));
    }
    let request = provider_token_request(provider, &form, OAuthTokenGrant::RefreshToken).await?;
    let token_resp = request
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Token refresh failed: {e}")))?;

    if !token_resp.status().is_success() {
        let error_body = token_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_owned());
        return Err(AuthError::internal(format!(
            "Token refresh returned error: {error_body}"
        )));
    }

    let token_data: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse refresh response: {e}")))?;

    parse_token_response(
        token_data,
        provider
            .authorization
            .as_ref()
            .is_some_and(|policy| policy.allow_missing_access_token),
    )
}

async fn provider_token_request(
    provider: &OAuthProvider,
    fields: &[(&str, &str)],
    grant_type: OAuthTokenGrant,
) -> AuthResult<reqwest::RequestBuilder> {
    let mut form: Vec<_> = fields
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    if let Some(policy) = &provider.authorization {
        let additions = if grant_type == OAuthTokenGrant::RefreshToken {
            &policy.refresh_token_params
        } else {
            &policy.authorization_code_params
        };
        for (key, value) in additions {
            if grant_type == OAuthTokenGrant::RefreshToken {
                if matches!(key.as_str(), "grant_type" | "refresh_token" | "__proto__" | "constructor" | "prototype") {
                    continue;
                }
                form.retain(|(existing, _)| existing != key);
            } else if form.iter().any(|(existing, _)| existing == key) {
                continue;
            }
            form.push((key.clone(), value.clone()));
        }
    }
    let request = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| AuthError::internal(format!("Token HTTP client failed: {error}")))?
        .post(&provider.token_url)
        .header("Accept", "application/json");
    let mut request = request;
    if grant_type == OAuthTokenGrant::AuthorizationCode
        && let Some(policy) = &provider.authorization
    {
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in &policy.authorization_code_headers {
            let name =
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                    AuthError::config(format!("Invalid code grant header: {error}"))
                })?;
            let value = reqwest::header::HeaderValue::from_str(value).map_err(|error| {
                AuthError::config(format!("Invalid code grant header: {error}"))
            })?;
            drop(headers.insert(name, value));
        }
        request = request.headers(headers);
    }
    let authentication = provider.authorization.as_ref().and_then(|policy| {
        if grant_type == OAuthTokenGrant::RefreshToken {
            policy
                .refresh_token_endpoint_auth
                .or(policy.token_endpoint_auth)
        } else {
            policy.token_endpoint_auth
        }
    });
    let has_field = |name: &str| form.iter().any(|(key, _)| key == name);
    if has_field("client_assertion") != has_field("client_assertion_type") {
        return Err(AuthError::config("client_assertion and client_assertion_type must both be provided"));
    }
    if has_field("client_assertion") {
        if authentication.is_some() {
            return Err(AuthError::config("client_assertion body parameters cannot be combined with tokenEndpointAuth"));
        }
        if !provider.client_secret.is_empty() || has_field("client_secret") {
            return Err(AuthError::config("private_key_jwt token endpoint authentication cannot be combined with clientSecret"));
        }
        if !provider.client_id.is_empty() {
            form.retain(|(key, _)| key != "client_id");
            form.push(("client_id".into(), provider.client_id.clone()));
        }
        return Ok(request.form(&form));
    }
    let request = match authentication {
        None => {
            form.retain(|(key, _)| key != "client_id" && key != "client_secret");
            form.extend([
                ("client_id".into(), provider.client_id.clone()),
                ("client_secret".into(), provider.client_secret.clone()),
            ]);
            request
        }
        Some(OAuthTokenEndpointAuth::None) => {
            if provider.client_id.is_empty() || !provider.client_secret.is_empty() || has_field("client_secret") {
                return Err(AuthError::config(
                    "Public token authentication requires client ID and no secret",
                ));
            }
            form.retain(|(key, _)| key != "client_id");
            form.push(("client_id".into(), provider.client_id.clone()));
            request
        }
        Some(OAuthTokenEndpointAuth::PrivateKeyJwt) => {
            if provider.client_id.is_empty() || !provider.client_secret.is_empty() || has_field("client_secret") {
                return Err(AuthError::config(
                    "Client assertion requires client ID and no secret",
                ));
            }
            let assertion = provider
                .authorization
                .as_ref()
                .and_then(|policy| policy.client_assertion.as_ref())
                .ok_or_else(|| AuthError::config("Client assertion callback is required"))?
                .0
                .get_client_assertion(OAuthClientAssertionContext {
                    client_id: provider.client_id.clone(),
                    token_endpoint: provider.token_url.clone(),
                    grant_type,
                })
                .await
                .map_err(AuthError::internal)?;
            form.retain(|(key, _)| key != "client_id");
            form.extend([
                ("client_id".into(), provider.client_id.clone()),
                ("client_assertion".into(), assertion),
                (
                    "client_assertion_type".into(),
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
                ),
            ]);
            request
        }
        Some(OAuthTokenEndpointAuth::ClientKeyPost) => {
            form.retain(|(key, _)| key != "client_key" && key != "client_secret");
            form.extend([
                ("client_key".into(), provider.client_id.clone()),
                ("client_secret".into(), provider.client_secret.clone()),
            ]);
            request
        }
        Some(method) => {
            if provider.client_id.is_empty() || provider.client_secret.is_empty() {
                return Err(AuthError::config(
                    "Client ID and client secret are required",
                ));
            }
            if method == OAuthTokenEndpointAuth::ClientSecretBasic {
                if has_field("client_secret") {
                    return Err(AuthError::config("client_secret_basic token endpoint authentication cannot be combined with client_secret body parameters"));
                }
                let encode = |value: &str| {
                    url::form_urlencoded::Serializer::new(String::new())
                        .append_key_only(value)
                        .finish()
                };
                request.basic_auth(
                    encode(&provider.client_id),
                    Some(encode(&provider.client_secret)),
                )
            } else {
                form.retain(|(key, _)| key != "client_id" && key != "client_secret");
                form.extend([
                    ("client_id".into(), provider.client_id.clone()),
                    ("client_secret".into(), provider.client_secret.clone()),
                ]);
                request
            }
        }
    };
    Ok(request.form(&form))
}

fn parse_token_response(
    token_data: serde_json::Value,
    allow_missing_access_token: bool,
) -> AuthResult<OAuthTokenSet> {
    if token_data.is_null() {
        return Err(AuthError::internal("Missing token response"));
    }
    let access_token = token_data
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    if access_token.is_none() && !allow_missing_access_token {
        return Err(AuthError::internal(
            "Missing access_token in token response",
        ));
    }
    let refresh_token = token_data
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(String::from);
    let id_token = token_data
        .get("id_token")
        .and_then(|v| v.as_str())
        .map(String::from);
    let expiry = |field: &str| -> Option<chrono::DateTime<Utc>> {
        super::providers::remaining_profile::grant_expiry(token_data.get(field)?, true)
    };
    let access_token_expires_at = expiry("expires_in");
    let refresh_token_expires_at = expiry("refresh_token_expires_in");
    let scopes = match token_data.get("scope") {
        Some(serde_json::Value::String(scope)) => scope
            .split(super::providers::remaining_profile::js_whitespace)
            .filter(|value| !value.is_empty())
            .map(String::from)
            .collect(),
        Some(serde_json::Value::Array(scopes)) => scopes
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(|value| value.trim_matches(super::providers::remaining_profile::js_whitespace))
            .filter(|value| !value.is_empty())
            .map(String::from)
            .collect(),
        _ => Vec::new(),
    };

    Ok(OAuthTokenSet {
        token_type: token_data
            .get("token_type")
            .and_then(|v| v.as_str())
            .map(String::from),
        access_token,
        refresh_token,
        access_token_expires_at,
        refresh_token_expires_at,
        scopes,
        id_token,
        raw: Some(token_data),
    })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn validate_authorization_code_via_provider(
    provider: &OAuthProvider,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
    device_id: Option<&str>,
) -> AuthResult<OAuthTokenSet> {
    let redirect_uri = provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.redirect_uri.as_deref())
        .filter(|uri| !uri.is_empty())
        .unwrap_or(redirect_uri);
    if let Some(handler) = provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.authorization_code.as_ref())
    {
        return handler
            .0
            .validate_authorization_code(super::providers::OAuthAuthorizationCodeContext {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                code_verifier: code_verifier.map(str::to_owned),
                device_id: device_id.map(str::to_owned),
            })
            .await
            .map_err(AuthError::internal);
    }
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ];
    if let Some(client_key) = provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.authorization_code_client_key.as_deref())
        .filter(|value| !value.is_empty())
    {
        form.push(("client_key", client_key));
    }
    if let Some(code_verifier) = code_verifier {
        form.push(("code_verifier", code_verifier));
    }
    if let Some(device_id) = device_id {
        form.push(("device_id", device_id));
    }

    let request =
        provider_token_request(provider, &form, OAuthTokenGrant::AuthorizationCode).await?;
    let token_resp = request
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Token exchange failed: {e}")))?;

    if !token_resp.status().is_success() {
        let error_body = token_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_owned());
        return Err(AuthError::internal(format!(
            "Token exchange returned error: {error_body}"
        )));
    }

    let token_data: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse token response: {e}")))?;
    parse_token_response(
        token_data,
        provider
            .authorization
            .as_ref()
            .is_some_and(|policy| policy.allow_missing_access_token),
    )
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn fetch_user_info_from_provider(
    provider: &OAuthProvider,
    request: OAuthUserInfoRequest,
) -> AuthResult<OAuthUserInfoResponse> {
    if let Some(handler) = &provider.get_user_info {
        let response = handler.get_user_info(request).await.map_err(|error| {
            if provider
                .authorization
                .as_ref()
                .is_some_and(|policy| policy.source_profile_exceptions)
                && (handler.errors_are_exceptions()
                    || error
                        .starts_with(super::providers::remaining_profile::PROFILE_EXCEPTION_PREFIX))
            {
                AuthError::Api {
                    status: 500,
                    code: Some("OAUTH_PROFILE_EXCEPTION".into()),
                    message: "Provider profile callback failed".into(),
                }
            } else {
                AuthError::internal(error)
            }
        })?;
        return Ok(response);
    }

    if let Some(token) = request
        .id_token
        .as_deref()
        .filter(|_| provider.id_token.is_some())
    {
        // Direct sign-in verifies this immutable token before requesting its profile;
        // the code flow obtains it from the trusted provider token exchange.
        let payload = token
            .split('.')
            .nth(1)
            .ok_or_else(|| AuthError::internal("Missing ID-token payload"))?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let profile: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| AuthError::internal(error.to_string()))?;
        if !super::id_token::hosted_domain_allowed(
            provider,
            profile.get("hd").and_then(serde_json::Value::as_str),
        ) {
            return Err(AuthError::internal("Hosted domain mismatch"));
        }
        let mapper = provider
            .map_user_info
            .ok_or_else(|| AuthError::internal("Missing user-info mapper"))?;
        let user = mapper(profile.clone()).map_err(AuthError::internal)?;
        let response = OAuthUserInfoResponse {
            user_output: None,
            user,
            data: profile,
        };
        return Ok(response);
    }

    let user_info_url = provider
        .user_info_url
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing user_info_url for provider"))?;
    let access_token = request
        .access_token
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing access token for user-info lookup"))?;
    let mapper = provider
        .map_user_info
        .ok_or_else(|| AuthError::internal("Missing user-info mapper for provider"))?;

    let client = reqwest::Client::new();
    let user_info_resp = client
        .get(user_info_url)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to fetch user info: {e}")))?;

    if !user_info_resp.status().is_success() {
        let error_body = user_info_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_owned());
        return Err(AuthError::internal(format!(
            "User info request failed: {error_body}"
        )));
    }

    let user_info_json: serde_json::Value = user_info_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse user info: {e}")))?;

    let user = mapper(user_info_json.clone())
        .map_err(|e| AuthError::internal(format!("Failed to map user info: {e}")))?;

    let response = OAuthUserInfoResponse {
        user_output: None,
        user,
        data: user_info_json,
    };
    Ok(response)
}

fn resolve_account_subject(
    provider: &OAuthProvider,
    response: &mut OAuthUserInfoResponse,
) -> AuthResult<()> {
    if let Some(subject) = provider.account_subject {
        response.user.id = subject(&response.data).map_err(AuthError::internal)?;
    }
    Ok(())
}

pub(in crate::plugins) fn parse_callback_user_payload(
    user_data: Option<&str>,
) -> Option<OAuthCallbackUserPayload> {
    let value: serde_json::Value = serde_json::from_str(user_data?).ok()?;
    Some(OAuthCallbackUserPayload {
        name: value
            .get("name")
            .and_then(|value| value.as_object())
            .map(|name| OAuthCallbackUserName {
                first_name: name
                    .get("firstName")
                    .and_then(|value_2| value_2.as_str())
                    .map(String::from),
                last_name: name
                    .get("lastName")
                    .and_then(|value_3| value_3.as_str())
                    .map(String::from),
            }),
        email: value
            .get("email")
            .and_then(|value| value.as_str())
            .map(String::from),
    })
}

fn raw_truthy(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(false) => false,
        serde_json::Value::Number(number) => number.as_f64() != Some(0.0),
        serde_json::Value::String(value) => !value.is_empty(),
        serde_json::Value::Bool(true)
        | serde_json::Value::Array(_)
        | serde_json::Value::Object(_) => true,
    }
}

fn redirect_response(location: &str) -> AuthResponse {
    AuthResponse::new(302)
        .with_header("content-type", "application/json")
        .with_header("Location", location)
}

fn account_cookie_max_age(config: &better_auth_core::AuthConfig) -> f64 {
    if let Some(age) = config.account.cookie_max_age {
        return age;
    }
    config
        .advanced
        .cookies
        .get("account_data")
        .and_then(|cookie| cookie.attributes.max_age)
        .map_or_else(
            || {
                better_auth_core::cache::effective_max_age(
                    config
                        .session
                        .cookie_cache
                        .as_ref()
                        .map_or(300.0, |cache| cache.max_age),
                )
            },
            |age| age as f64,
        )
}

/// Emit the encrypted account snapshot and clear stale incoming chunks.
///
/// # Errors
/// Propagates encryption or cookie attribute errors.
pub(in crate::plugins) fn create_account_cookie_headers(
    config: &better_auth_core::AuthConfig,
    payload: &AccountCookiePayload,
    req: &AuthRequest,
) -> AuthResult<Vec<String>> {
    let max_age = account_cookie_max_age(config);
    let value = create_account_cookie_value(config, payload, max_age)?;
    better_auth_core::cache::runtime::chunked_cookie_headers(
        &account_cookie_name(config),
        &value,
        Some(max_age),
        config,
        &req.headers,
        true,
    )
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn decode_account_cookie(
    req: &AuthRequest,
    config: &better_auth_core::AuthConfig,
) -> AuthResult<Option<AccountCookiePayload>> {
    let Some(value) = better_auth_core::cache::runtime::chunked_cookie_value(
        &req.headers,
        &account_cookie_name(config),
    ) else {
        return Ok(None);
    };
    decode_account_cookie_value(config, &value).map(Some)
}

fn attach_state_cookie(
    response: AuthResponse,
    config: &better_auth_core::AuthConfig,
    secret: &str,
    state: &str,
) -> AuthResult<AuthResponse> {
    let value = create_database_state_cookie_value(secret, state);
    Ok(response.with_appended_header(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_cookie(
            &state_cookie_name(config),
            &value,
            Duration::minutes(5).num_seconds(),
            config,
        ),
    ))
}

fn attach_cookie_state_payload(
    response: AuthResponse,
    config: &better_auth_core::AuthConfig,
    payload: &OAuthStatePayload,
) -> AuthResult<AuthResponse> {
    let value = create_cookie_state_value(config, payload)?;
    Ok(response.with_appended_header(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_cookie(
            &state_cookie_name(config),
            &value,
            Duration::minutes(10).num_seconds(),
            config,
        ),
    ))
}

fn validate_redirect_target(
    target: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    error_message: &str,
) -> AuthResult<()> {
    if ctx.config.current_origin_check_disabled() {
        return Ok(());
    }
    if ctx.config.is_redirect_target_trusted(target) {
        Ok(())
    } else {
        Err(AuthError::forbidden(error_message.to_owned()))
    }
}

fn build_redirect_url(
    base_url: &str,
    callback_url: Option<&str>,
    params: &[(&str, &str)],
) -> AuthResult<String> {
    let base = url::Url::parse(base_url)
        .map_err(|error| AuthError::internal(format!("Invalid base URL: {error}")))?;
    let mut url = if let Some(callback_url) = callback_url {
        base.join(callback_url)
            .map_err(|error| AuthError::bad_request(format!("Invalid callbackURL: {error}")))?
    } else {
        base.join("/error")
            .map_err(|error| AuthError::internal(format!("Invalid error URL: {error}")))?
    };
    if !params.is_empty() {
        let mut query_segments = Vec::new();
        if let Some(existing_query) = url.query()
            && !existing_query.is_empty()
        {
            query_segments.push(existing_query.to_owned());
        }
        for (key, value) in params {
            query_segments.push(format!(
                "{}={}",
                urlencoding::encode(key),
                urlencoding::encode(value),
            ));
        }
        let query = query_segments.join("&");
        url.set_query(Some(&query));
    }
    Ok(url.to_string())
}

fn auth_base_url(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> String {
    format!(
        "{}{}",
        ctx.config.base_url.trim_end_matches('/'),
        ctx.config.base_path
    )
}

pub(in crate::plugins) fn ambiguous_account_sign_in_response(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResponse {
    redirect_response(&format!(
        "{}/error?error=internal_server_error",
        auth_base_url(ctx)
    ))
}

async fn finish_oauth_session<S: better_auth_core::AuthSchema>(
    user: &better_auth_core::AdapterRecord<S::User>,
    is_register: bool,
    policy: &OAuthProcessPolicy,
    meta: &better_auth_core::RequestMeta,
    ctx: &AuthContext<S>,
) -> Result<crate::plugins::helpers::IssuedSessionRecord<S>, OAuthSignInError> {
    if !user.email_verified() {
        let config = ctx
            .extensions
            .get::<crate::plugins::email_verification::EmailVerificationConfig>();
        let should_send = if is_register {
            config
                .as_ref()
                .and_then(|config| config.send_on_sign_up)
                .unwrap_or(policy.require_email_verification)
        } else {
            policy.require_email_verification
                && config.as_ref().is_some_and(|config| config.send_on_sign_in)
        };
        if should_send {
            if let Some(config) = config {
                // OAuth delivery completes after identity/account commit, before a session.
                if config.send_verification_email.is_some() {
                    if let Some(email) = user.email() {
                        let plugin = crate::plugins::email_verification::EmailVerificationPlugin::with_config((*config).clone());
                        plugin
                            .send_verification_email_for_user(
                                user,
                                email,
                                policy.callback_url.as_deref(),
                                ctx,
                            )
                            .await
                            .map_err(|error| error.to_string())?;
                    }
                } else if let Some(sender) = ctx.email_verification_override() {
                    crate::plugins::authentication_helpers::run_notification(sender.0.send(
                        &ctx.user_view(user),
                        None,
                        ctx,
                    ))
                    .await;
                }
            } else if let Some(sender) = ctx.email_verification_override() {
                crate::plugins::authentication_helpers::run_notification(sender.0.send(
                    &ctx.user_view(user),
                    None,
                    ctx,
                ))
                .await;
            }
        }
        if policy.require_email_verification {
            return Err(OAuthSignInError::EmailNotVerified);
        }
    }
    issue_selected_user_session_record(
        ctx,
        user.clone(),
        meta.ip_address.clone(),
        meta.user_agent.clone(),
    )
    .await
    .map_err(OAuthSignInError::from)
}

fn provider_fields(
    user_info: &OAuthUserInfo,
    creation: bool,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<better_auth_core::field_policy::FieldValues, OAuthSignInError> {
    let registered = ctx
        .extensions
        .get::<better_auth_core::field_policy::UserFields>();
    let fallback =
        better_auth_core::field_policy::SessionFields(ctx.config.user.additional_fields.clone());
    let fields = registered.as_ref().map_or(&fallback, |fields| &fields.0);
    let input = user_info
        .additional_fields
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "id" | "email" | "emailVerified" | "name" | "image"
            ) && fields.0.get(*name).is_some_and(|field| field.input)
        })
        .map(|(name, value)| {
            (
                name.clone(),
                better_auth_core::utils::json::JsValue::from(value.clone()),
            )
        })
        .collect();
    let result = if creation {
        fields.parse_create(&input)
    } else {
        fields.parse_update(&input)
    };
    result.map_err(|error| match error {
        better_auth_core::field_policy::FieldInputError::Validation { code, message } => {
            OAuthSignInError::IdentityDenied {
                code: code.into(),
                message,
            }
        }
        better_auth_core::field_policy::FieldInputError::Transform(error) => match error {
            AuthError::Api { .. } | AuthError::Upstream { .. } => {
                OAuthSignInError::from_identity_denial(error)
            }
            _ if creation => OAuthSignInError::Generic("unable to create user".into()),
            _ => OAuthSignInError::Generic(error.to_string()),
        },
    })
}

fn provider_candidate(user_info: &OAuthUserInfo, user_id: &str) -> CreateUser {
    let mut candidate = CreateUser::new();
    candidate.id = Some(user_id.to_owned());
    candidate.email = Some(user_info.email.to_lowercase());
    candidate.name = user_info.name.clone();
    candidate.image = user_info.image.clone();
    candidate.email_verified = Some(user_info.email_verified);
    candidate
}

async fn validate_provider_identity(
    provider: &str,
    profile: &serde_json::Value,
    user: &OAuthUserInfo,
    user_id: &str,
    action: UserValidationAction,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<(), OAuthSignInError> {
    let mut data = UserValidationData {
        user: provider_candidate(user, user_id),
        source: UserValidationSource::oauth(provider, profile, action),
    };
    // Sign-in completion supplies an empty name before the shared policy.
    // Explicit linking validates the original mapped optional name instead.
    data.user.name = Some(user.name.as_deref().unwrap_or_default().to_owned());
    validate_user_info(&ctx.config, &mut data)
        .await
        .map_err(OAuthSignInError::from_identity_denial)
}

/// Mapped provider identity together with its original provenance.
pub(in crate::plugins) struct OAuthIdentity<'a> {
    pub provider_name: &'a str,
    pub user: &'a OAuthUserInfo,
    pub profile: &'a serde_json::Value,
}

fn verification_override(
    user: &impl AuthUser,
    email: &str,
    incoming: Option<&serde_json::Value>,
) -> Option<serde_json::Value> {
    incoming.map(|incoming| {
        if user
            .email()
            .is_some_and(|stored| stored.eq_ignore_ascii_case(email))
            && user.email_verified()
        {
            user.adapter_snapshot()
                .and_then(|output| output.values().get("emailVerified"))
                .cloned()
                .unwrap_or(serde_json::Value::Bool(true))
        } else {
            incoming.clone()
        }
    })
}

pub(in crate::plugins) async fn process_oauth_sign_in(
    identity: OAuthIdentity<'_>,
    policy: &OAuthProcessPolicy,
    tokens: &OAuthTokenSet,
    disable_sign_up: bool,
    meta: &better_auth_core::RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<ProcessOAuthUserResult, OAuthSignInError> {
    process_oauth_sign_in_with_output(
        identity,
        policy,
        tokens,
        disable_sign_up,
        meta,
        ctx,
        (None, None),
    )
    .await
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep OAuth account matching, linking policy, and signup branches together for review"
)]
async fn process_oauth_sign_in_with_output(
    identity: OAuthIdentity<'_>,
    policy: &OAuthProcessPolicy,
    tokens: &OAuthTokenSet,
    disable_sign_up: bool,
    meta: &better_auth_core::RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    (raw_output, raw_policy): (
        Option<&better_auth_core::field_policy::FieldOutput>,
        Option<&super::providers::OAuthAuthorizationPolicy>,
    ),
) -> Result<ProcessOAuthUserResult, OAuthSignInError> {
    let raw_verification = raw_output.and_then(|output| output.get("emailVerified"));
    let OAuthIdentity {
        provider_name,
        user: user_info,
        profile,
    } = identity;
    if user_info.email.is_empty() {
        return Err(OAuthSignInError::Generic("email not found".to_owned()));
    }

    let linked_account = ctx
        .database
        .get_account_record(provider_name, &user_info.id)
        .await
        .map_err(OAuthSignInError::from_account_lookup)?;

    let token_bundle = encrypt_provider_token_set(ctx, tokens, raw_policy)
        .await
        .map_err(|error| error.to_string())?;

    if let Some(existing_account) = linked_account {
        let existing_user = ctx
            .database
            .get_user_by_id_record(&existing_account.user_id())
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "user not found".to_owned())?;
        validate_provider_identity(
            provider_name,
            profile,
            user_info,
            &existing_user.id(),
            UserValidationAction::SignIn,
            ctx,
        )
        .await?;
        if ctx.config.account.update_account_on_sign_in {
            drop(
                ctx.database
                    .update_account_record(
                        &existing_account.id(),
                        UpdateAccount {
                            provider_token_nulls: provider_token_nulls(tokens, raw_policy),
                            access_token: token_bundle.access_token.clone(),
                            refresh_token: token_bundle.refresh_token.clone(),
                            id_token: token_bundle.id_token.clone(),
                            access_token_expires_at: tokens.access_token_expires_at,
                            refresh_token_expires_at: tokens.refresh_token_expires_at,
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?,
            );
        }

        let mut user = existing_user;

        if user_info.email_verified
            && !user.email_verified()
            && user
                .email()
                .is_some_and(|email| email.eq_ignore_ascii_case(&user_info.email))
        {
            let updated = ctx
                .database
                .update_user_record(
                    &user.id(),
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
            if policy.use_updated_user {
                user = updated;
            }
        }

        if policy.override_user_info {
            let additional_fields = provider_fields(user_info, false, ctx)?;
            let verification = verification_override(&user, &user_info.email, raw_verification);
            user = ctx
                .database
                .update_user_record(
                    &user.id(),
                    UpdateUser {
                        name: user_info.name.clone(),
                        image: user_info.image.clone(),
                        email: Some(user_info.email.to_lowercase()),
                        additional_fields,
                        email_verified: Some(verification.as_ref().map_or_else(
                            || {
                                user.email().is_some_and(|email| {
                                    email.eq_ignore_ascii_case(&user_info.email)
                                }) && (user.email_verified() || user_info.email_verified)
                            },
                            raw_truthy,
                        )),
                        provider_email_verified: verification,
                        provider_name: raw_output.and_then(|output| output.get("name")).cloned(),
                        provider_image: raw_output.and_then(|output| output.get("image")).cloned(),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }

        let issued = finish_oauth_session(&user, false, policy, meta, ctx).await?;
        let account_cookie = ctx.config.account.store_account_cookie.then(|| {
            if !ctx.config.account.update_account_on_sign_in {
                return AccountCookiePayload::from_account(&existing_account);
            }
            AccountCookiePayload {
                id: Some(existing_account.id().to_string()),
                user_id: existing_account.user_id().to_string(),
                provider_id: provider_name.to_owned(),
                account_id: existing_account.account_id().to_owned(),
                access_token: token_bundle.access_token.or_else(|| {
                    (!provider_token_nulls(tokens, raw_policy)[0])
                        .then(|| existing_account.access_token().map(str::to_owned))
                        .flatten()
                }),
                refresh_token: token_bundle.refresh_token.or_else(|| {
                    (!provider_token_nulls(tokens, raw_policy)[1])
                        .then(|| existing_account.refresh_token().map(str::to_owned))
                        .flatten()
                }),
                id_token: token_bundle.id_token.or_else(|| {
                    (!provider_token_nulls(tokens, raw_policy)[2])
                        .then(|| existing_account.id_token().map(str::to_owned))
                        .flatten()
                }),
                access_token_expires_at: tokens
                    .access_token_expires_at
                    .or_else(|| existing_account.access_token_expires_at()),
                refresh_token_expires_at: tokens
                    .refresh_token_expires_at
                    .or_else(|| existing_account.refresh_token_expires_at()),
                scope: existing_account.scope().map(str::to_owned),
                password: existing_account.password().map(str::to_owned),
                created_at: Some(existing_account.created_at()),
                updated_at: Some(existing_account.updated_at()),
                ..AccountCookiePayload::from_account(&existing_account)
            }
        });

        return Ok(ProcessOAuthUserResult {
            session: ctx.session_view(&issued.session),
            user: if policy.use_updated_user {
                ctx.user_view(&issued.user)
            } else {
                ctx.user_view(&user)
            },
            is_register: false,
            account_cookie,
        });
    }

    let existing_user = ctx
        .database
        .get_user_by_email_record(&user_info.email.to_lowercase())
        .await
        .map_err(|error| error.to_string())?;

    if let Some(existing_user) = existing_user {
        let linking = &ctx.config.account.account_linking;
        let trusted_provider = linking
            .trusted_providers
            .iter()
            .any(|trusted| trusted == provider_name);

        // Mirrors upstream's linking guard, including the local-account check:
        // an unverified local account is not implicitly linkable.
        if !linking.enabled
            || linking.disable_implicit_linking
            || (!trusted_provider && !user_info.email_verified)
            || (linking.require_local_email_verified && !existing_user.email_verified())
        {
            return Err(OAuthSignInError::Generic("account not linked".to_owned()));
        }

        let mut linked_user = existing_user;
        validate_provider_identity(
            provider_name,
            profile,
            user_info,
            &linked_user.id(),
            UserValidationAction::LinkAccount,
            ctx,
        )
        .await?;
        let created_account = ctx
            .database
            .create_account_record(CreateAccount {
                additional_fields: Default::default(),
                user_id: linked_user.id().to_string(),
                account_id: user_info.id.clone(),
                provider_id: provider_name.to_owned(),
                access_token: token_bundle.access_token,
                refresh_token: token_bundle.refresh_token,
                id_token: token_bundle.id_token,
                access_token_expires_at: tokens.access_token_expires_at,
                refresh_token_expires_at: tokens.refresh_token_expires_at,
                scope: (tokens.raw.is_some() || !tokens.scopes.is_empty())
                    .then(|| tokens.scopes.join(",")),
                password: None,
            })
            .await
            .map_err(|_error| "unable to link account".to_owned())?;

        if user_info.email_verified
            && !linked_user.email_verified()
            && linked_user
                .email()
                .is_some_and(|email| email.eq_ignore_ascii_case(&user_info.email))
        {
            let updated = ctx
                .database
                .update_user_record(
                    &linked_user.id(),
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
            if policy.use_updated_user {
                linked_user = updated;
            }
        }

        if linking.update_user_info_on_link {
            match ctx
                .database
                .update_user_record(
                    &linked_user.id(),
                    UpdateUser {
                        name: user_info.name.clone(),
                        image: user_info.image.clone(),
                        ..Default::default()
                    },
                )
                .await
            {
                Ok(updated) => linked_user = updated,
                Err(error) => tracing::warn!(%error, "Could not update user info on account link"),
            }
        }

        if policy.override_user_info {
            let additional_fields = provider_fields(user_info, false, ctx)?;
            let verification =
                verification_override(&linked_user, &user_info.email, raw_verification);
            linked_user = ctx
                .database
                .update_user_record(
                    &linked_user.id(),
                    UpdateUser {
                        name: user_info.name.clone(),
                        image: user_info.image.clone(),
                        email: Some(user_info.email.to_lowercase()),
                        additional_fields,
                        email_verified: Some(verification.as_ref().map_or_else(
                            || {
                                linked_user.email().is_some_and(|email| {
                                    email.eq_ignore_ascii_case(&user_info.email)
                                }) && (linked_user.email_verified() || user_info.email_verified)
                            },
                            raw_truthy,
                        )),
                        provider_email_verified: verification,
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }

        let issued = finish_oauth_session(&linked_user, false, policy, meta, ctx).await?;
        let account_cookie = ctx
            .config
            .account
            .store_account_cookie
            .then(|| AccountCookiePayload::from_account(&created_account));

        Ok(ProcessOAuthUserResult {
            session: ctx.session_view(&issued.session),
            user: if policy.use_updated_user {
                ctx.user_view(&issued.user)
            } else {
                ctx.user_view(&linked_user)
            },
            is_register: false,
            account_cookie,
        })
    } else {
        if disable_sign_up {
            return Err(OAuthSignInError::Generic("signup disabled".to_owned()));
        }

        let mut create_user = CreateUser::new()
            .with_email(user_info.email.to_lowercase())
            .with_name(user_info.name.as_deref().unwrap_or_default())
            .with_email_verified(user_info.email_verified);
        crate::plugins::authentication_helpers::apply_creation_input_defaults(
            ctx,
            &mut create_user,
        );
        apply_default_role(ctx, &mut create_user);
        create_user.provider_email_verified =
            raw_verification.filter(|value| !value.is_null()).cloned();
        create_user.image = user_info.image.clone();
        create_user.additional_fields = provider_fields(user_info, true, ctx)?;

        let mut create_account = CreateAccount {
            additional_fields: Default::default(),
            user_id: String::new(),
            account_id: user_info.id.clone(),
            provider_id: provider_name.to_owned(),
            access_token: token_bundle.access_token,
            refresh_token: token_bundle.refresh_token,
            id_token: token_bundle.id_token,
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scope: (tokens.raw.is_some() || !tokens.scopes.is_empty())
                .then(|| tokens.scopes.join(",")),
            password: None,
        };
        let source =
            UserValidationSource::oauth(provider_name, profile, UserValidationAction::CreateUser);
        // OAuth registration commits its identity and provider binding together.
        // Notifications and session creation follow the committed transaction.
        let (persisted_user, persisted_account) =
            better_auth_core::store::transaction(ctx.database.as_ref(), move |tx| {
                Box::pin(async move {
                    let user = tx
                        .create_user_with_source_record(create_user, source)
                        .await?;
                    create_account.user_id = user.id().to_string();
                    let account = tx.create_account_record(create_account).await?;
                    Ok((user, account))
                })
            })
            .await
            .map_err(|error| {
                if error.status_code() == 403 {
                    OAuthSignInError::from_identity_denial(error)
                } else {
                    OAuthSignInError::Generic("unable to create user".to_owned())
                }
            })?;

        if ctx.config.account.store_account_cookie {
            let age = account_cookie_max_age(&ctx.config);
            // Published registration commits the identity first, then catches
            // account-cookie configuration failures before issuing a session.
            if !age.is_finite()
                || better_auth_core::utils::cookie_utils::create_account_cookie_header(
                    &account_cookie_name(&ctx.config),
                    &account_cookie_name(&ctx.config),
                    "",
                    age,
                    &ctx.config,
                )
                .is_err()
            {
                return Err(OAuthSignInError::Generic("unable to create user".into()));
            }
        }
        let issued = finish_oauth_session(&persisted_user, true, policy, meta, ctx).await?;
        let account_cookie = ctx
            .config
            .account
            .store_account_cookie
            .then(|| AccountCookiePayload::from_account(&persisted_account));

        Ok(ProcessOAuthUserResult {
            session: ctx.session_view(&issued.session),
            user: if policy.use_updated_user {
                ctx.user_view(&issued.user)
            } else {
                ctx.user_view(&persisted_user)
            },
            is_register: true,
            account_cookie,
        })
    }
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn complete_link_social(
    provider_name: &str,
    user_info: &OAuthUserInfo,
    profile: &serde_json::Value,
    tokens: &OAuthTokenSet,
    link: &OAuthStateLink,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<(), OAuthSignInError> {
    complete_link_social_with_raw_email(
        provider_name,
        user_info,
        profile,
        tokens,
        link,
        ctx,
        (None, None),
    )
    .await
    .map(|_| ())
}

enum LinkSocialOutcome {
    Linked,
    InvalidRawEmail,
}

async fn complete_link_social_with_raw_email(
    provider_name: &str,
    user_info: &OAuthUserInfo,
    profile: &serde_json::Value,
    tokens: &OAuthTokenSet,
    link: &OAuthStateLink,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    (raw_email, raw_policy): (
        Option<&serde_json::Value>,
        Option<&super::providers::OAuthAuthorizationPolicy>,
    ),
) -> Result<LinkSocialOutcome, OAuthSignInError> {
    // Explicit linking validates fresh provider data before its trust/email
    // guards or account lookup. The candidate retains the selected local ID.
    let mut candidate = provider_candidate(user_info, &link.user_id);
    candidate.email = (!user_info.email.is_empty()).then(|| user_info.email.clone());
    validate_user_info(
        &ctx.config,
        &mut UserValidationData {
            user: candidate,
            source: UserValidationSource::oauth(
                provider_name,
                profile,
                UserValidationAction::LinkAccount,
            ),
        },
    )
    .await
    .map_err(OAuthSignInError::from_identity_denial)?;
    let linking = &ctx.config.account.account_linking;
    let trusted_provider = linking
        .trusted_providers
        .iter()
        .any(|trusted| trusted == provider_name);

    if !linking.enabled || (!trusted_provider && !user_info.email_verified) {
        return Err("unable_to_link_account".to_owned().into());
    }

    if raw_email.is_some_and(|email| !email.is_null() && !email.is_string()) {
        return Ok(LinkSocialOutcome::InvalidRawEmail);
    }

    if !linking.allow_different_emails && !user_info.email.eq_ignore_ascii_case(&link.email) {
        return Err("email_does_not_match".to_owned().into());
    }

    if let Some(existing_account) = ctx
        .database
        .get_account(provider_name, &user_info.id)
        .await
        .map_err(OAuthSignInError::from_account_lookup)?
    {
        if existing_account.user_id() != link.user_id {
            return Err("account_already_linked_to_different_user".to_owned().into());
        }

        let token_bundle = encrypt_provider_token_set(ctx, tokens, raw_policy)
            .await
            .map_err(|error| error.to_string())?;

        drop(
            ctx.database
                .update_account_record(
                    &existing_account.id(),
                    UpdateAccount {
                        provider_token_nulls: provider_token_nulls(tokens, raw_policy),
                        access_token: token_bundle.access_token,
                        refresh_token: token_bundle.refresh_token,
                        id_token: token_bundle.id_token,
                        access_token_expires_at: tokens.access_token_expires_at,
                        refresh_token_expires_at: tokens.refresh_token_expires_at,
                        scope: (tokens.raw.is_some() || !tokens.scopes.is_empty())
                            .then(|| tokens.scopes.join(",")),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?,
        );

        return Ok(LinkSocialOutcome::Linked);
    }

    let token_bundle = encrypt_provider_token_set(ctx, tokens, raw_policy)
        .await
        .map_err(|error| error.to_string())?;

    drop(
        ctx.database
            .create_account_record(CreateAccount {
                additional_fields: Default::default(),
                user_id: link.user_id.clone(),
                account_id: user_info.id.clone(),
                provider_id: provider_name.to_owned(),
                access_token: token_bundle.access_token,
                refresh_token: token_bundle.refresh_token,
                id_token: token_bundle.id_token,
                access_token_expires_at: tokens.access_token_expires_at,
                refresh_token_expires_at: tokens.refresh_token_expires_at,
                scope: (tokens.raw.is_some() || !tokens.scopes.is_empty())
                    .then(|| tokens.scopes.join(",")),
                password: None,
            })
            .await
            .map_err(|_error| "unable_to_link_account".to_owned())?,
    );

    Ok(LinkSocialOutcome::Linked)
}

async fn sign_in_with_id_token_core(
    body: &SocialSignInRequest,
    id_token: &OAuthIdTokenRequest,
    provider: &OAuthProvider,
    meta: &better_auth_core::RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SocialSignInResponse> {
    if provider.disable_id_token_sign_in
        || provider.verify_id_token.is_none() && provider.id_token.is_none()
    {
        return Err(AuthError::Upstream {
            status: 404,
            code: "ID_TOKEN_NOT_SUPPORTED",
            message: "id_token not supported",
        });
    }
    if !super::id_token::verify_provider_token(provider, &id_token.token, id_token.nonce.as_deref())
        .await
    {
        return Err(AuthError::Upstream {
            status: 401,
            code: "INVALID_TOKEN",
            message: "Invalid token",
        });
    }

    let mut user_info = fetch_user_info_from_provider(
        provider,
        OAuthUserInfoRequest {
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            access_token_expires_at: id_token
                .expires_at
                .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)),
            scopes: id_token.scopes.clone().unwrap_or_default(),
            id_token: Some(id_token.token.clone()),
            user: id_token.user.clone(),
            ..Default::default()
        },
    )
    .await
    .map_err(|_error| AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    })?;

    if user_info.user.email.is_empty() {
        return Err(AuthError::Upstream {
            status: 401,
            code: "USER_EMAIL_NOT_FOUND",
            message: "User email not found",
        });
    }

    resolve_account_subject(provider, &mut user_info).map_err(|_error| AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    })?;

    let outcome = process_oauth_sign_in(
        OAuthIdentity {
            provider_name: &body.provider,
            user: &user_info.user,
            profile: &user_info.data,
        },
        &OAuthProcessPolicy::for_provider(provider, body.callback_url.clone()),
        &OAuthTokenSet {
            access_token: id_token.access_token.clone(),
            id_token: Some(id_token.token.clone()),
            ..Default::default()
        },
        provider.disable_implicit_sign_up && !body.request_sign_up.unwrap_or(false)
            || (provider.disable_sign_up
                && provider
                    .authorization
                    .as_ref()
                    .is_none_or(|policy| policy.honor_factory_options)),
        meta,
        ctx,
    )
    .await
    .map_err(|error| match error {
        OAuthSignInError::IdentityDenied { code, message } => AuthError::Api {
            status: 403,
            code: Some(code),
            message,
        },
        OAuthSignInError::AccountLookup(error) => error,
        OAuthSignInError::EmailNotVerified => AuthError::Upstream {
            status: 403,
            code: "EMAIL_NOT_VERIFIED",
            message: "Email not verified",
        },
        OAuthSignInError::Generic(message) | OAuthSignInError::Banned(message) => AuthError::Api {
            status: 401,
            code: Some("OAUTH_LINK_ERROR".into()),
            message,
        },
        OAuthSignInError::SessionAuth(error) => AuthError::Api {
            status: 401,
            code: Some("OAUTH_LINK_ERROR".into()),
            message: error.to_string(),
        },
    })?;

    Ok(SocialSignInResponse {
        url: None,
        redirect: false,
        status: None,
        token: Some(outcome.session.token().to_owned()),
        user: Some(outcome.user),
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep provider proof validation and account ownership checks adjacent to the linking write"
)]
async fn link_with_id_token_core(
    body: &LinkSocialRequest,
    id_token: &OAuthIdTokenRequest,
    provider: &OAuthProvider,
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SocialSignInResponse> {
    if provider.disable_id_token_sign_in
        || provider.verify_id_token.is_none() && provider.id_token.is_none()
    {
        return Err(AuthError::Upstream {
            status: 404,
            code: "ID_TOKEN_NOT_SUPPORTED",
            message: "id_token not supported",
        });
    }
    if !super::id_token::verify_provider_token(provider, &id_token.token, id_token.nonce.as_deref())
        .await
    {
        return Err(AuthError::Upstream {
            status: 401,
            code: "INVALID_TOKEN",
            message: "Invalid token",
        });
    }

    let mut response = fetch_user_info_from_provider(
        provider,
        OAuthUserInfoRequest {
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            access_token_expires_at: id_token
                .expires_at
                .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)),
            scopes: id_token.scopes.clone().unwrap_or_default(),
            id_token: Some(id_token.token.clone()),
            user: id_token.user.clone(),
            ..Default::default()
        },
    )
    .await
    .map_err(|_error| AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    })?;

    if response.user.email.is_empty() {
        return Err(AuthError::Upstream {
            status: 401,
            code: "USER_EMAIL_NOT_FOUND",
            message: "User email not found",
        });
    }

    resolve_account_subject(provider, &mut response).map_err(|_error| AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    })?;

    let linked_account = ctx
        .database
        .get_account(&body.provider, &response.user.id)
        .await?;
    if linked_account
        .as_ref()
        .is_some_and(|account| account.user_id() != session.user_id())
    {
        return Err(AuthError::Upstream {
            status: 409,
            code: "SOCIAL_ACCOUNT_ALREADY_LINKED",
            message: "Social account already linked",
        });
    }
    let existing_accounts = ctx.database.get_user_accounts(&session.user_id()).await?;
    if existing_accounts.iter().any(|account| {
        account.provider_id() == body.provider && account.account_id() == response.user.id
    }) {
        return Ok(SocialSignInResponse {
            url: Some(String::new()),
            redirect: false,
            status: Some(true),
            token: None,
            user: None,
        });
    }

    let current_user = ctx
        .session_user(session)
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let current_email = current_user
        .email()
        .ok_or_else(|| AuthError::forbidden("User email not found"))?;
    let linking = &ctx.config.account.account_linking;
    let trusted_provider = linking
        .trusted_providers
        .iter()
        .any(|trusted| trusted == &body.provider);

    if !linking.enabled || (!trusted_provider && !response.user.email_verified) {
        return Err(AuthError::forbidden(
            "Account not linked - linking not allowed",
        ));
    }
    if !linking.allow_different_emails && !response.user.email.eq_ignore_ascii_case(current_email) {
        return Err(AuthError::forbidden(
            "Account not linked - different emails not allowed",
        ));
    }

    let token_bundle = encrypt_token_set(
        ctx,
        id_token.access_token.clone(),
        id_token.refresh_token.clone(),
        Some(id_token.token.clone()),
    )?;
    drop(
        ctx.database
            .create_account_record(CreateAccount {
                additional_fields: Default::default(),
                user_id: session.user_id().to_string(),
                provider_id: body.provider.clone(),
                account_id: response.user.id,
                access_token: token_bundle.access_token,
                refresh_token: token_bundle.refresh_token,
                id_token: token_bundle.id_token,
                access_token_expires_at: id_token
                    .expires_at
                    .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)),
                refresh_token_expires_at: None,
                scope: id_token.scopes.as_ref().map(|scopes| scopes.join(",")),
                password: None,
            })
            .await
            .map_err(|_error| {
                AuthError::bad_request("Account not linked - unable to create account")
            })?,
    );

    if linking.update_user_info_on_link {
        drop(
            ctx.database
                .update_user_record(
                    &session.user_id(),
                    UpdateUser {
                        name: response.user.name.clone(),
                        image: response.user.image.clone(),
                        ..Default::default()
                    },
                )
                .await,
        );
    }

    Ok(SocialSignInResponse {
        url: Some(String::new()),
        redirect: false,
        status: Some(true),
        token: None,
        user: None,
    })
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

async fn social_sign_in_core(
    body: &SocialSignInRequest,
    config: &OAuthConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<InitiatedOAuthFlow> {
    let provider = config
        .providers
        .get(&body.provider)
        .ok_or_else(|| AuthError::not_found("Provider not found"))?;

    let callback_url = body
        .callback_url
        .clone()
        .unwrap_or_else(|| ctx.config.base_url.clone());
    validate_redirect_target(&callback_url, ctx, "Invalid callbackURL")?;
    if let Some(error_callback_url) = body.error_callback_url.as_deref() {
        validate_redirect_target(error_callback_url, ctx, "Invalid errorCallbackURL")?;
    }
    if let Some(new_user_callback_url) = body.new_user_callback_url.as_deref() {
        validate_redirect_target(new_user_callback_url, ctx, "Invalid newUserCallbackURL")?;
    }

    initiate_oauth_flow_core(
        ctx,
        FlowStartRequest {
            provider_name: &body.provider,
            provider,
            callback_url: &callback_url,
            new_user_callback_url: body.new_user_callback_url.clone(),
            error_callback_url: body.error_callback_url.clone(),
            scopes: body.scopes.as_deref(),
            login_hint: body.login_hint.as_deref(),
            additional_params: body.additional_params.as_ref(),
            request_sign_up: body.request_sign_up,
            additional_data: filter_additional_state_data(body.additional_data.clone()),
            link: None,
            disable_redirect: body.disable_redirect.unwrap_or(false),
        },
    )
    .await
}

async fn link_social_core(
    body: &LinkSocialRequest,
    session: &impl AuthSession,
    config: &OAuthConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<InitiatedOAuthFlow> {
    let provider = config
        .providers
        .get(&body.provider)
        .ok_or_else(|| AuthError::not_found("Provider not found"))?;

    let callback_url = body
        .callback_url
        .clone()
        .unwrap_or_else(|| ctx.config.base_url.clone());
    validate_redirect_target(&callback_url, ctx, "Invalid callbackURL")?;
    if let Some(error_callback_url) = body.error_callback_url.as_deref() {
        validate_redirect_target(error_callback_url, ctx, "Invalid errorCallbackURL")?;
    }

    let user = ctx
        .session_user(session)
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User email not found"))?;

    initiate_oauth_flow_core(
        ctx,
        FlowStartRequest {
            provider_name: &body.provider,
            provider,
            callback_url: &callback_url,
            new_user_callback_url: None,
            error_callback_url: body.error_callback_url.clone(),
            scopes: body.scopes.as_deref(),
            login_hint: None,
            additional_params: body.additional_params.as_ref(),
            request_sign_up: body.request_sign_up,
            additional_data: filter_additional_state_data(body.additional_data.clone()),
            link: Some(OAuthStateLink {
                email: email.to_lowercase(),
                user_id: session.user_id().to_string(),
            }),
            disable_redirect: body.disable_redirect.unwrap_or(false),
        },
    )
    .await
}

/// Shared logic for social sign-in and link-social flows.
///
/// Both flows build a verification payload, store it, construct the
/// authorization URL, and return a redirect response. The only difference
/// is `link_user_id` (None for sign-in, Some for linking).
async fn initiate_oauth_flow_core(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: FlowStartRequest<'_>,
) -> AuthResult<InitiatedOAuthFlow> {
    let (code_verifier, code_challenge) = generate_pkce();
    let state: String = {
        let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
        let mut random = thread_rng();
        (0..32)
            .filter_map(|_| {
                alphabet
                    .get(random.gen_range(0..alphabet.len()))
                    .copied()
                    .map(char::from)
            })
            .collect()
    };

    let proxy = better_auth_core::hooks::current_request_hook_context().and_then(|req| {
        req.extensions
            .get::<crate::plugins::oauth_proxy::OAuthProxyFlow>()
    });
    let mut payload = OAuthStatePayload::new(
        proxy
            .as_ref()
            .map_or(request.callback_url, |flow| flow.callback_url.as_str())
            .to_owned(),
        code_verifier,
        request.error_callback_url,
        request.new_user_callback_url,
        request.link,
        request.request_sign_up,
        request.additional_data,
    );
    capture_server_context(&mut payload, &state, ctx.config.current_secret())?;
    drop(payload.additional_data.insert(
        "oauthState".to_owned(),
        serde_json::Value::String(state.clone()),
    ));
    if proxy.is_some()
        && let Some(req) = better_auth_core::hooks::current_request_hook_context()
    {
        req.extensions
            .insert(crate::plugins::oauth_proxy::IssuedProxyState {
                state: state.clone(),
                payload: payload.clone(),
            });
    }

    match ctx.config.account.store_state_strategy {
        better_auth_core::OAuthStateStrategy::Database => {
            let created = ctx
                .verifications()
                .create(CreateVerification {
                    identifier: state.clone(),
                    value: serde_json::to_string(&payload)?,
                    expires_at: Utc::now() + Duration::minutes(10),
                })
                .await?;
            if created.is_none() {
                return Err(AuthError::internal("Unable to create verification"));
            }
        }
        better_auth_core::OAuthStateStrategy::Cookie => {}
    }

    let url = build_authorization_url(
        request.provider,
        &format!(
            "{}/callback/{}",
            proxy.as_ref().map_or_else(
                || auth_base_url(ctx),
                |flow| flow.effective_auth_base_url.clone()
            ),
            request.provider_name
        ),
        request.scopes,
        &state,
        &code_challenge,
        request.login_hint,
        request.additional_params,
    )?;

    Ok(InitiatedOAuthFlow {
        response: SocialSignInResponse {
            url: Some(url),
            redirect: !request.disable_redirect,
            status: None,
            token: None,
            user: None,
        },
        state,
        payload,
    })
}

// ---------------------------------------------------------------------------
// Old handlers (rewritten to call core)
// ---------------------------------------------------------------------------

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) async fn handle_social_sign_in(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let body: SocialSignInRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    validate_authorization_params(body.additional_params.as_ref())?;
    let meta = better_auth_core::RequestMeta::from_request(req);
    if let Some(id_token) = &body.id_token {
        let provider = config
            .providers
            .get(&body.provider)
            .ok_or_else(|| AuthError::not_found("Provider not found"))?;
        let response = match sign_in_with_id_token_core(&body, id_token, provider, &meta, ctx).await
        {
            Err(AuthError::Database(better_auth_core::DatabaseError::AmbiguousAccount {
                ..
            })) => return Ok(ambiguous_account_sign_in_response(ctx)),
            result => result?,
        };
        let mut auth_response = AuthResponse::json(200, &response).map_err(AuthError::from)?;
        if let Some(token) = response.token.as_deref() {
            auth_response = auth_response.with_appended_header(
                "Set-Cookie",
                better_auth_core::utils::cookie_utils::create_session_cookie(token, &ctx.config),
            );
        }
        return Ok(auth_response);
    }

    let flow = match social_sign_in_core(&body, config, ctx).await {
        Err(error @ AuthError::Config(_)) => {
            tracing::error!(%error, "OAuth authorization configuration failed");
            return Ok(AuthResponse::new(500));
        }
        result => result?,
    };
    let response = flow.response;
    let mut auth_response = AuthResponse::json(200, &response).map_err(AuthError::from)?;

    if let Some(url) = response.url.as_deref()
        && response.redirect
    {
        auth_response = auth_response.with_header("Location", url);
    }
    if let Some(token) = response.token.as_deref() {
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            better_auth_core::utils::cookie_utils::create_session_cookie(token, &ctx.config),
        );
    }

    match ctx.config.account.store_state_strategy {
        better_auth_core::OAuthStateStrategy::Database => {
            if response.token.is_some() {
                return Ok(auth_response);
            }
            attach_state_cookie(
                auth_response,
                &ctx.config,
                ctx.config.current_secret(),
                &flow.state,
            )
        }
        better_auth_core::OAuthStateStrategy::Cookie => {
            if response.token.is_some() {
                return Ok(auth_response);
            }
            attach_cookie_state_payload(auth_response, &ctx.config, &flow.payload)
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep OAuth state consumption, provider errors, and cookie cleanup in their required order"
)]
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) async fn handle_callback(
    config: &OAuthConfig,
    provider_name: &str,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let default_error_url = format!("{}/error", auth_base_url(ctx));
    let meta = better_auth_core::RequestMeta::from_request(req);

    let mut merged = HashMap::new();
    if req.method() == &better_auth_core::HttpMethod::Post {
        if let Some(body) = &req.body
            && !body.is_empty()
        {
            let body_text = String::from_utf8(body.clone()).map_err(|error| {
                AuthError::bad_request(format!("Invalid callback body: {error}"))
            })?;
            let parsed_body =
                serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&body_text)
                    .ok()
                    .map(|body_2| {
                        body_2
                            .into_iter()
                            .filter_map(|(key, value)| match value {
                                serde_json::Value::String(value) => Some((key, value)),
                                serde_json::Value::Null => None,
                                other @ (serde_json::Value::Bool(_)
                                | serde_json::Value::Number(_)
                                | serde_json::Value::Array(_)
                                | serde_json::Value::Object(_)) => Some((key, other.to_string())),
                            })
                            .collect::<HashMap<String, String>>()
                    })
                    .or_else(|| {
                        Some(
                            url::form_urlencoded::parse(body_text.as_bytes())
                                .into_owned()
                                .collect::<HashMap<String, String>>(),
                        )
                    })
                    .ok_or_else(|| AuthError::bad_request("Invalid callback request"))?;
            merged.extend(parsed_body);
        }

        // Match the TS callback route: POST body seeds the redirect, but
        // explicit query parameters win over conflicting body fields.
        merged.extend(req.query.clone());

        let mut params = url::form_urlencoded::Serializer::new(String::new());
        let mut pairs: Vec<_> = merged.iter().collect();
        pairs.sort_by_key(|(left, _)| *left);
        for (key, value) in pairs {
            _ = params.append_pair(key, value);
        }
        return Ok(redirect_response(&format!(
            "{}/callback/{}?{}",
            auth_base_url(ctx),
            provider_name,
            params.finish()
        )));
    }

    let merged_2 = req.query.clone();

    let error = merged_2.get("error").cloned();
    let Some(state_param) = merged_2.get("state").cloned() else {
        let separator = if default_error_url.contains('?') {
            '&'
        } else {
            '?'
        };
        return Ok(redirect_response(&format!(
            "{default_error_url}{separator}state=state_not_found"
        )));
    };
    let payload = match ctx.config.account.store_state_strategy {
        better_auth_core::OAuthStateStrategy::Database => {
            let verification = match ctx.verifications().find(&state_param).await {
                Ok(Some(verification)) => verification,
                Ok(None) => {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=state_mismatch"
                    )));
                }
                Err(_) => {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=internal_server_error"
                    )));
                }
            };

            let payload: OAuthStatePayload = match verification.value().and_then(|value| {
                serde_json::from_str(value)
                    .map_err(|error| AuthError::internal(format!("Invalid state payload: {error}")))
            }) {
                Ok(payload) => payload,
                Err(_) => {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=internal_server_error"
                    )));
                }
            };
            let state_error_url = payload.error_url.as_deref().unwrap_or(&default_error_url);
            let state_mismatch = || {
                redirect_response(
                    &build_redirect_url(
                        &auth_base_url(ctx),
                        Some(state_error_url),
                        &[("error", "state_mismatch")],
                    )
                    .unwrap_or_else(|_| format!("{default_error_url}?error=state_mismatch")),
                )
            };
            if payload
                .additional_data
                .get("oauthState")
                .is_some_and(|value| value.as_str() != Some(state_param.as_str()))
            {
                return Ok(state_mismatch());
            }
            if !ctx.config.account.skip_state_cookie_check {
                let persisted_state =
                    get_cookie(req, &state_cookie_name(&ctx.config)).and_then(|value| {
                        decode_database_state_cookie_value(ctx.config.current_secret(), &value).ok()
                    });
                if persisted_state.as_deref() != Some(state_param.as_str()) {
                    return Ok(state_mismatch());
                }
            }
            if ctx.verifications().delete(&state_param).await.is_err() {
                return Ok(redirect_response(&format!(
                    "{default_error_url}?error=internal_server_error"
                ))
                .with_appended_header(
                    "Set-Cookie",
                    better_auth_core::utils::cookie_utils::create_clear_cookie(
                        &state_cookie_name(&ctx.config),
                        &ctx.config,
                    ),
                ));
            }
            payload
        }
        better_auth_core::OAuthStateStrategy::Cookie => {
            let Some(cookie_value) = get_cookie(req, &state_cookie_name(&ctx.config)) else {
                return Ok(redirect_response(&format!(
                    "{default_error_url}?error=please_restart_the_process"
                )));
            };
            match decode_cookie_state_value(&ctx.config, &cookie_value) {
                Ok(payload)
                    if payload
                        .additional_data
                        .get("oauthState")
                        .and_then(serde_json::Value::as_str)
                        == Some(state_param.as_str()) =>
                {
                    payload
                }
                Ok(_) => {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=state_mismatch"
                    )));
                }
                Err(_) => {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=please_restart_the_process"
                    )));
                }
            }
        }
    };

    let clear_state_cookie = better_auth_core::utils::cookie_utils::create_clear_cookie(
        &state_cookie_name(&ctx.config),
        &ctx.config,
    );
    let error_url = payload
        .error_url
        .clone()
        .unwrap_or_else(|| default_error_url.clone());

    let redirect_on_error = |error_code: &str, description: Option<&str>| {
        let mut parameters = vec![("error", error_code)];
        if let Some(description) = description {
            parameters.push(("error_description", description));
        }
        redirect_response(
            &build_redirect_url(&auth_base_url(ctx), Some(&error_url), &parameters)
                .unwrap_or_else(|_error| format!("{default_error_url}?error={error_code}")),
        )
        .with_appended_header("Set-Cookie", clear_state_cookie.clone())
    };

    if payload.is_expired() {
        return Ok(redirect_on_error("state_mismatch", None));
    }
    if let Some(error) = error.as_deref() {
        return Ok(redirect_on_error(
            error,
            merged_2.get("error_description").map(String::as_str),
        ));
    }

    let authenticated_state_cookie = get_cookie(req, &state_cookie_name(&ctx.config));
    let context_secret = match ctx.config.account.store_state_strategy {
        better_auth_core::OAuthStateStrategy::Cookie => super::super::token_crypto::decryption_key(
            authenticated_state_cookie
                .as_deref()
                .ok_or_else(|| AuthError::internal("Authenticated state cookie disappeared"))?,
            &ctx.config,
        )?,
        better_auth_core::OAuthStateStrategy::Database => ctx.config.current_secret(),
    };
    if let Some(context) = verified_server_context(&payload, &state_param, context_secret) {
        req.extensions()
            .insert(RecoveredOAuthServerContext(context));
    }

    let Some(code) = merged_2.get("code").cloned() else {
        return Ok(redirect_on_error("no_code", None));
    };
    let Some(provider) = config.providers.get(provider_name) else {
        return Ok(redirect_on_error("oauth_provider_not_found", None));
    };

    let Ok(tokens) = validate_authorization_code_via_provider(
        provider,
        &code,
        &format!("{}/callback/{}", auth_base_url(ctx), provider_name),
        provider
            .authorization
            .as_ref()
            .is_none_or(|policy| policy.authorization_code_pkce.unwrap_or(policy.pkce))
            .then_some(payload.code_verifier.as_str()),
        merged_2.get("device_id").map(String::as_str),
    )
    .await
    else {
        return Ok(redirect_on_error("invalid_code", None));
    };

    let user_info_result = fetch_user_info_from_provider(
        provider,
        OAuthUserInfoRequest {
            token_type: tokens.token_type.clone(),
            access_token: tokens.access_token.clone(),
            refresh_token: tokens.refresh_token.clone(),
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scopes: tokens.scopes.clone(),
            id_token: tokens.id_token.clone(),
            raw: tokens.raw.clone(),
            user: parse_callback_user_payload(merged_2.get("user").map(String::as_str)),
        },
    )
    .await;
    let mut user_info = match user_info_result {
        Ok(user_info) => user_info,
        Err(error) => {
            if matches!(&error,AuthError::Api {code:Some(code),..} if code == "OAUTH_PROFILE_EXCEPTION")
            {
                return Ok(AuthResponse::new(500));
            }
            if provider
                .authorization
                .as_ref()
                .is_some_and(|policy| policy.propagate_grant_profile_errors)
                && tokens
                    .raw
                    .as_ref()
                    .and_then(|raw| raw.get("id_token"))
                    .is_some_and(raw_truthy)
            {
                // The published factory throws outside callback redirect handling.
                // State was consumed, but its pending clear-cookie is not emitted.
                return Ok(AuthResponse::new(500));
            }
            return Ok(redirect_on_error("unable_to_get_user_info", None));
        }
    };

    if resolve_account_subject(provider, &mut user_info).is_err() {
        return Ok(redirect_on_error("unable_to_get_user_info", None));
    }

    let raw_email = provider
        .authorization
        .as_ref()
        .filter(|policy| policy.preserve_raw_email_errors)
        .and(user_info.user_output.as_ref())
        .and_then(|output| output.get("email"));

    if let Some(link) = payload.link.as_ref() {
        let link_result = complete_link_social_with_raw_email(
            provider_name,
            &user_info.user,
            &user_info.data,
            &tokens,
            link,
            ctx,
            (raw_email, provider.authorization.as_ref()),
        )
        .await;
        if matches!(link_result, Ok(LinkSocialOutcome::InvalidRawEmail)) {
            return Ok(AuthResponse::new(500));
        }
        if let Err(error_3) = link_result {
            if error_3.is_ambiguous_account() {
                return Ok(AuthResponse::new(500));
            }
            let (code, description) = match &error_3 {
                OAuthSignInError::Generic(message) => (message.clone(), None),
                _ => error_3.redirect_parts(),
            };
            return Ok(redirect_on_error(&code, description));
        }

        return Ok(redirect_response(&payload.callback_url)
            .with_appended_header("Set-Cookie", clear_state_cookie));
    }

    if raw_email.is_some_and(|email| raw_truthy(email) && !email.is_string()) {
        // Source first resolves account ownership, then lowercases email either
        // in the caught email lookup (new identity) or uncaught validation (owned).
        let existing_account = ctx
            .database
            .get_account_record(provider_name, &user_info.user.id)
            .await;
        return Ok(match existing_account {
            Ok(Some(_)) => AuthResponse::new(500),
            Ok(None) | Err(_) => {
                redirect_response(&format!("{default_error_url}?error=internal_server_error"))
                    .with_appended_header("Set-Cookie", clear_state_cookie.clone())
            }
        });
    }

    let disable_sign_up = provider.disable_implicit_sign_up
        && !payload.request_sign_up.unwrap_or(false)
        || (provider.disable_sign_up
            && provider
                .authorization
                .as_ref()
                .is_none_or(|policy| policy.honor_factory_options));
    let outcome = match process_oauth_sign_in_with_output(
        OAuthIdentity {
            provider_name,
            user: &user_info.user,
            profile: &user_info.data,
        },
        &OAuthProcessPolicy::for_provider(provider, Some(payload.callback_url.clone())),
        &tokens,
        disable_sign_up,
        &meta,
        ctx,
        (
            provider
                .authorization
                .as_ref()
                .filter(|policy| policy.preserve_raw_profile_scalars)
                .and(user_info.user_output.as_ref()),
            provider.authorization.as_ref(),
        ),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error_4) => {
            if error_4.is_ambiguous_account() {
                return Ok(redirect_response(&format!(
                    "{default_error_url}?error=internal_server_error"
                ))
                .with_appended_header("Set-Cookie", clear_state_cookie.clone()));
            }
            let (code_2, description) = error_4.redirect_parts();
            return Ok(redirect_on_error(&code_2, description));
        }
    };

    let redirect_target = if outcome.is_register {
        payload
            .new_user_url
            .as_deref()
            .unwrap_or(&payload.callback_url)
            .to_owned()
    } else {
        payload.callback_url.clone()
    };
    let mut response = redirect_response(&redirect_target)
        .with_appended_header("Set-Cookie", clear_state_cookie)
        .with_appended_header(
            "Set-Cookie",
            better_auth_core::utils::cookie_utils::create_session_cookie(
                outcome.session.token(),
                &ctx.config,
            ),
        );
    if let Some(account_cookie) = outcome.account_cookie.as_ref() {
        for header in create_account_cookie_headers(&ctx.config, account_cookie, req)? {
            response.headers.append("Set-Cookie", header);
        }
    }
    Ok(response)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) async fn handle_link_social(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let session = require_session(req, ctx)
        .await
        .map_err(|error| match error {
            AuthError::Unauthenticated => AuthError::Api {
                status: 401,
                code: Some("UNAUTHORIZED".to_owned()),
                message: "Unauthorized".to_owned(),
            },
            error @ (AuthError::Api { .. }
            | AuthError::Upstream { .. }
            | AuthError::BadRequest(_)
            | AuthError::InvalidRequest(_)
            | AuthError::Validation(_)
            | AuthError::InvalidCredentials
            | AuthError::AuthenticationFailed(_)
            | AuthError::SessionNotFound
            | AuthError::Forbidden(_)
            | AuthError::SessionCreationCancelled
            | AuthError::UserCreationCancelled
            | AuthError::BannedUser(_)
            | AuthError::Unauthorized
            | AuthError::UserNotFound
            | AuthError::NotFound(_)
            | AuthError::Conflict(_)
            | AuthError::MethodNotAllowed(_)
            | AuthError::PayloadTooLarge(_)
            | AuthError::UnprocessableEntity(_)
            | AuthError::RateLimited
            | AuthError::NotImplemented(_)
            | AuthError::Config(_)
            | AuthError::Database(_)
            | AuthError::Serialization(_)
            | AuthError::Plugin { .. }
            | AuthError::CallbackFailure(_)
            | AuthError::Internal(_)
            | AuthError::Encryption(_)
            | AuthError::PasswordHash(_)
            | AuthError::Jwt(_)) => error,
        })?;
    let body: LinkSocialRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    validate_authorization_params(body.additional_params.as_ref())?;
    if let Some(id_token) = &body.id_token {
        let provider = config
            .providers
            .get(&body.provider)
            .ok_or_else(|| AuthError::not_found("Provider not found"))?;
        let response = match link_with_id_token_core(&body, id_token, provider, &session, ctx).await
        {
            Err(AuthError::Database(better_auth_core::DatabaseError::AmbiguousAccount {
                ..
            })) => return Ok(AuthResponse::new(500)),
            result => result?,
        };
        return AuthResponse::json(200, &response).map_err(AuthError::from);
    }

    let flow = match link_social_core(&body, &session, config, ctx).await {
        Err(error @ AuthError::Config(_)) => {
            tracing::error!(%error, "OAuth linking authorization configuration failed");
            return Ok(AuthResponse::new(500));
        }
        result => result?,
    };
    let response = flow.response;
    let mut auth_response = AuthResponse::json(200, &response).map_err(AuthError::from)?;

    if let Some(url) = response.url.as_deref()
        && response.redirect
    {
        auth_response = auth_response.with_header("Location", url);
    }

    match ctx.config.account.store_state_strategy {
        better_auth_core::OAuthStateStrategy::Database => attach_state_cookie(
            auth_response,
            &ctx.config,
            ctx.config.current_secret(),
            &flow.state,
        ),
        better_auth_core::OAuthStateStrategy::Cookie => {
            attach_cookie_state_payload(auth_response, &ctx.config, &flow.payload)
        }
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers;

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck respects ctx.context.skipOriginCheck.
    #[tokio::test]
    async fn validate_redirect_target_respects_disable_origin_check() {
        let config = test_helpers::create_test_config().disable_origin_check(true);
        let ctx = test_helpers::create_test_context_with_config(config).await;

        assert!(
            validate_redirect_target("https://evil.com/phish", &ctx, "Invalid callbackURL").is_ok()
        );
    }

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck rejects untrusted origins by default.
    #[tokio::test]
    async fn validate_redirect_target_rejects_untrusted_by_default() {
        let ctx = test_helpers::create_test_context().await;

        assert!(
            validate_redirect_target("https://evil.com/phish", &ctx, "Invalid callbackURL")
                .is_err()
        );
    }

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck allows relative paths.
    #[tokio::test]
    async fn validate_redirect_target_allows_relative() {
        let ctx = test_helpers::create_test_context().await;

        assert!(validate_redirect_target("/dashboard", &ctx, "Invalid callbackURL").is_ok());
    }

    #[test]
    fn build_redirect_url_preserves_plus_in_path_and_encodes_spaces_in_query() {
        let url = build_redirect_url(
            "http://localhost:3000/api/auth",
            Some("/dashboard+beta"),
            &[("error_description", "space value")],
        )
        .expect("redirect URL should build");

        assert_eq!(
            url,
            "http://localhost:3000/dashboard+beta?error_description=space%20value"
        );
    }
}
// LCOV_EXCL_STOP
