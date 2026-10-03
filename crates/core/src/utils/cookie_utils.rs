//! Shared cookie utilities for building `Set-Cookie` headers.
//!
//! This module centralises the session cookie construction that was previously
//! duplicated across every plugin (`email_password`, `passkey`, `two_factor`,
//! `admin`, `password_management`, `session_management`, `email_verification`).

use crate::config::{AuthConfig, CookieAttributes, SameSite};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt::Write as _;

/// Build a `Set-Cookie` header value for an arbitrary cookie using the auth
/// config's session cookie attributes for consistency.
#[must_use]
pub fn create_cookie(name: &str, value: &str, max_age_seconds: i64, config: &AuthConfig) -> String {
    create_session_like_cookie(name, value, Some(max_age_seconds), config)
}

/// Build a `Set-Cookie` header value for a signed session token.
#[must_use]
pub fn create_session_cookie(token: &str, config: &AuthConfig) -> String {
    create_session_cookie_with_max_age(
        Some(token),
        Some(config.session.expires_in.num_seconds()),
        config,
    )
}

/// Build a `Set-Cookie` header value for a session token using the session
/// cookie attributes, optionally omitting `Max-Age` / `Expires` to create a
/// browser-session cookie.
#[must_use]
pub fn create_session_cookie_with_max_age(
    token: Option<&str>,
    max_age_seconds: Option<i64>,
    config: &AuthConfig,
) -> String {
    let signed = token
        .filter(|token| !token.is_empty())
        .map(|token| sign_cookie_value(token, config.current_secret()));
    create_session_like_cookie(
        &related_cookie_name(config, "session_token"),
        signed.as_deref().unwrap_or(""),
        max_age_seconds,
        config,
    )
}

/// Sign and URI-encode a cookie value using Better Call's HMAC-SHA256 encoding.
#[expect(
    clippy::expect_used,
    reason = "HMAC-SHA256 accepts keys of every length"
)]
#[must_use]
#[expect(
    clippy::missing_panics_doc,
    reason = "HMAC accepts keys of every length, so key construction cannot fail"
)]
pub fn sign_cookie_value(value: &str, secret: &str) -> String {
    const COMPONENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'!')
        .remove(b'~')
        .remove(b'*')
        .remove(b'\'')
        .remove(b'(')
        .remove(b')');

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(value.as_bytes());
    let signed = format!("{value}.{}", STANDARD.encode(mac.finalize().into_bytes()));

    percent_encoding::utf8_percent_encode(&signed, COMPONENT).to_string()
}

/// Return a cookie's payload only when its signature verifies.
#[must_use]
pub fn verify_cookie_value(value: &str, secret: &str) -> Option<String> {
    let decoded = percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .ok()?;
    let (payload, signature) = decoded.rsplit_once('.')?;
    // Better Call's atob verifier discards unused bits before padding. They
    // do not change the authenticated HMAC bytes or weaken signature checks.
    let decoder = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    let signature = decoder.decode(signature).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&signature).ok()?;
    Some(payload.to_owned())
}

/// Build a `Set-Cookie` header value using the session cookie attributes for
/// an arbitrary cookie name.
#[must_use]
pub fn create_session_like_cookie(
    name: &str,
    value: &str,
    max_age_seconds: Option<i64>,
    config: &AuthConfig,
) -> String {
    let mut attributes = cookie_attributes(name, config);
    // setSessionCookie explicitly replaces the token's configured Max-Age,
    // including with undefined for a browser session. Other cookie producers
    // retain their configured age when they supply no override.
    if name == related_cookie_name(config, "session_token") || max_age_seconds.is_some() {
        attributes.max_age = max_age_seconds;
    }
    render_encoded_cookie(name, value, &attributes)
}

/// Build a derived cookie with the resolved session-token attributes.
/// Multiple-session proofs inherit the token's overrides as well as defaults.
#[must_use]
pub fn create_derived_session_cookie(
    name: &str,
    value: &str,
    clear: bool,
    config: &AuthConfig,
) -> String {
    let mut attributes = cookie_attributes(&related_cookie_name(config, "session_token"), config);
    attributes.max_age = Some(if clear {
        0
    } else {
        config
            .advanced
            .cookies
            .get("session_token")
            .and_then(|entry| entry.attributes.max_age)
            .unwrap_or(config.session.expires_in.num_seconds())
    });
    render_encoded_cookie(name, value, &attributes)
}

/// Build a `Set-Cookie` header value that clears the session cookie.
#[must_use]
pub fn create_clear_session_cookie(config: &AuthConfig) -> String {
    create_clear_cookie(&related_cookie_name(config, "session_token"), config)
}

/// Build a `Set-Cookie` header value that clears an arbitrary cookie by name,
/// using the session config's cookie attributes for consistency.
///
/// Mirrors the TypeScript `expireCookie`, which clears a cookie with `Max-Age=0`
/// while preserving its attributes, and emits no `Expires`.
#[must_use]
pub fn create_clear_cookie(name: &str, config: &AuthConfig) -> String {
    create_session_like_cookie(name, "", Some(0), config)
}

/// Build a Better Auth related cookie name using the configured session cookie
/// prefix. For example, `better-auth.session_token` + `session_data` becomes
/// `better-auth.session_data`.
#[must_use]
pub fn related_cookie_name(config: &AuthConfig, suffix: &str) -> String {
    let token_name = config
        .advanced
        .cookies
        .get("session_token")
        .and_then(|entry| entry.name.as_deref())
        .filter(|name| !name.is_empty())
        .unwrap_or(&config.session.cookie_name);
    let name = config
        .advanced
        .cookies
        .get(suffix)
        .and_then(|entry| entry.name.as_ref())
        .filter(|name| !name.is_empty())
        .cloned()
        .unwrap_or_else(|| {
            if let Some(prefix) = config
                .advanced
                .cookie_prefix
                .as_ref()
                .filter(|p| !p.is_empty())
            {
                format!("{prefix}.{suffix}")
            } else if suffix == "session_token" {
                token_name.to_owned()
            } else {
                token_name.strip_suffix("session_token").map_or_else(
                    || format!("better-auth.{suffix}"),
                    |prefix| format!("{prefix}{suffix}"),
                )
            }
        });
    if secure_cookie_policy(config) {
        format!("__Secure-{name}")
    } else {
        name
    }
}

// This is createCookieGetter's initial selection, not the final attributes.
// Dynamic URLs retain that selection unless cross-subdomain request resolution
// rebuilds cookies using the resolved origin (as in the published context).
fn secure_cookie_policy(config: &AuthConfig) -> bool {
    config.advanced.use_secure_cookies.unwrap_or_else(|| {
        if let Some(dynamic) = &config.dynamic_base_url {
            match dynamic.protocol {
                Some(crate::config::BaseUrlProtocol::Https) => true,
                Some(crate::config::BaseUrlProtocol::Http) => false,
                _ => std::env::var("NODE_ENV").is_ok_and(|env| env == "production"),
            }
        } else {
            config.base_url.starts_with("https://")
        }
    })
}

fn cookie_attributes(name: &str, config: &AuthConfig) -> CookieAttributes {
    let mut attributes = CookieAttributes {
        secure: Some(
            config
                .advanced
                .use_secure_cookies
                .unwrap_or_else(|| secure_cookie_policy(config) || config.session.cookie_secure),
        ),
        http_only: Some(config.session.cookie_http_only),
        same_site: Some(config.session.cookie_same_site.clone()),
        path: Some("/".into()),
        domain: config
            .advanced
            .cross_sub_domain_cookies
            .as_ref()
            .map(|cross| cross.domain.clone()),
        max_age: None,
    };
    apply_attributes(&mut attributes, &config.advanced.default_cookie_attributes);
    let logical = if name == related_cookie_name(config, "session_token") {
        Some("session_token")
    } else {
        config.advanced.cookies.keys().find_map(|logical| {
            (related_cookie_name(config, logical) == name).then_some(logical.as_str())
        })
    };
    if let Some(entry) = logical.and_then(|logical| config.advanced.cookies.get(logical)) {
        apply_attributes(&mut attributes, &entry.attributes);
    }
    attributes
}

/// Render an account cookie with resolved account attributes and numeric TTL.
/// Chunk names inherit the base cookie attributes.
///
/// # Errors
/// Returns an error when Max-Age exceeds the published serializer limit.
pub fn create_account_cookie_header(
    name: &str,
    base: &str,
    value: &str,
    max_age: f64,
    config: &AuthConfig,
) -> crate::AuthResult<String> {
    if max_age > 34_560_000.0 {
        return Err(crate::AuthError::internal(
            "Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration.",
        ));
    }
    let mut attributes = cookie_attributes(base, config);
    attributes.max_age = None;
    let header = render_encoded_cookie(name, value, &attributes);
    if max_age >= 0.0 {
        let (prefix, suffix) = header.split_once(';').unwrap_or((&header, ""));
        Ok(format!(
            "{prefix}; Max-Age={}{}{}",
            max_age.floor(),
            if suffix.is_empty() { "" } else { ";" },
            suffix
        ))
    } else {
        Ok(header)
    }
}

fn apply_attributes(target: &mut CookieAttributes, overrides: &CookieAttributes) {
    if overrides.secure.is_some() {
        target.secure = overrides.secure;
    }
    if overrides.http_only.is_some() {
        target.http_only = overrides.http_only;
    }
    if overrides.same_site.is_some() {
        target.same_site.clone_from(&overrides.same_site);
    }
    if overrides.path.is_some() {
        target.path.clone_from(&overrides.path);
    }
    if overrides.domain.is_some() {
        target.domain.clone_from(&overrides.domain);
    }
    if overrides.max_age.is_some() {
        target.max_age = overrides.max_age;
    }
}

// Values arrive already encoded (including signatures); encoding them again
// would change the credential. Keep Better Call's attribute order and omit
// synthetic Expires. The current public helpers have infallible integer ages.
fn render_encoded_cookie(name: &str, value: &str, attributes: &CookieAttributes) -> String {
    let host = name.starts_with("__Host-");
    let mut header = format!("{name}={value}");
    if let Some(age) = attributes.max_age.filter(|age| *age >= 0) {
        _ = write!(header, "; Max-Age={age}");
    }
    if !host
        && let Some(domain) = attributes
            .domain
            .as_ref()
            .filter(|domain| !domain.is_empty())
    {
        _ = write!(header, "; Domain={domain}");
    }
    let path = if host {
        Some("/")
    } else {
        attributes.path.as_deref().filter(|path| !path.is_empty())
    };
    if let Some(path) = path {
        _ = write!(header, "; Path={path}");
    }
    if attributes.http_only == Some(true) {
        header.push_str("; HttpOnly");
    }
    if attributes.secure == Some(true) || host || name.starts_with("__Secure-") {
        header.push_str("; Secure");
    }
    if let Some(same_site) = &attributes.same_site {
        header.push_str(match same_site {
            SameSite::Lax => "; SameSite=Lax",
            SameSite::Strict => "; SameSite=Strict",
            SameSite::None => "; SameSite=None",
        });
    }
    header
}

/// Clear all cookies associated with the current session.
#[must_use]
pub fn delete_session_cookie_headers(config: &AuthConfig) -> Vec<String> {
    let mut cookies = vec![
        create_clear_session_cookie(config),
        create_clear_cookie(&related_cookie_name(config, "session_data"), config),
    ];

    if config.account.store_account_cookie {
        cookies.push(create_clear_cookie(
            &related_cookie_name(config, "account_data"),
            config,
        ));
    }

    if matches!(
        config.account.store_state_strategy,
        crate::config::OAuthStateStrategy::Cookie
    ) {
        cookies.push(create_clear_cookie(
            &related_cookie_name(config, "oauth_state"),
            config,
        ));
    }

    cookies.push(create_clear_cookie(
        &related_cookie_name(config, "dont_remember"),
        config,
    ));
    cookies
}
