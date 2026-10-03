use super::AuthConfig;
use crate::{AuthError, AuthRequest, AuthResult};
use async_trait::async_trait;

/// Protocol used when resolving a dynamic base URL. `None` on the config
/// infers the request scheme, while trusting HTTPS (and HTTP loopback) origins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseUrlProtocol {
    Http,
    Https,
    Auto,
}

/// Better Auth 1.7.6 dynamic `baseURL` policy. Hosts include ports; `*` and `?`
/// patterns are supported. A fallback is used when the source host is absent
/// or outside the allowlist, and never makes that source host trusted.
#[derive(Clone, Debug)]
pub struct DynamicBaseUrl {
    pub allowed_hosts: Vec<String>,
    pub protocol: Option<BaseUrlProtocol>,
    pub fallback: Option<String>,
}

/// Async application policy evaluated with the original transport request.
/// Return additional trusted patterns; these never replace the configured
/// base-origin policy. Errors abort dispatch before authentication side effects.
#[async_trait]
pub trait TrustedOriginsResolver: Send + Sync {
    async fn resolve(&self, request: &AuthRequest) -> AuthResult<Vec<String>>;
}

impl AuthConfig {
    #[must_use]
    pub fn dynamic_base_url(mut self, config: DynamicBaseUrl) -> Self {
        self.dynamic_base_url = Some(config);
        self
    }

    #[must_use]
    pub fn trusted_origins_resolver(
        mut self,
        resolver: impl TrustedOriginsResolver + 'static,
    ) -> Self {
        self.trusted_origins_resolver = Some(std::sync::Arc::new(resolver));
        self
    }

    /// Resolve the URL and origin policy without mutating the shared instance.
    ///
    /// # Errors
    /// Fails when no permitted host or fallback exists, the fallback is invalid,
    /// or the application origin resolver fails.
    pub async fn resolve_request(&self, request: &AuthRequest) -> AuthResult<Self> {
        let mut config = self.clone();
        if let Some(dynamic) = &self.dynamic_base_url {
            let forwarded = self.advanced.trust_forwarded_host;
            let host = forwarded
                .then(|| header(request, "x-forwarded-host"))
                .flatten()
                .filter(|host| valid_host(host))
                .or_else(|| header(request, "host").filter(|host| valid_host(host)))
                .map(str::to_owned)
                .or_else(|| {
                    request.url().and_then(|url| {
                        url.host_str().map(|_| {
                            url[url::Position::BeforeHost..url::Position::AfterPort].to_owned()
                        })
                    })
                });
            let accepted = host.as_deref().filter(|host| {
                dynamic.allowed_hosts.iter().any(|pattern| {
                    wildcard(
                        &normalize_host_pattern(pattern),
                        &normalize_host_pattern(host),
                    )
                })
            });
            config.base_url = if let Some(host) = accepted {
                let protocol = match dynamic.protocol {
                    Some(BaseUrlProtocol::Http) => "http",
                    Some(BaseUrlProtocol::Https) => "https",
                    _ => forwarded
                        .then(|| header(request, "x-forwarded-proto"))
                        .flatten()
                        .filter(|value| matches!(*value, "http" | "https"))
                        .or_else(|| {
                            request
                                .url()
                                .map(url::Url::scheme)
                                .filter(|value| matches!(*value, "http" | "https"))
                        })
                        .unwrap_or_else(|| if loopback(host) { "http" } else { "https" }),
                };
                format!("{protocol}://{host}")
            } else {
                let fallback = dynamic.fallback.as_ref().ok_or_else(|| AuthError::config("Could not resolve base URL: host is not allowed and no fallback is configured"))?;
                let parsed = url::Url::parse(fallback)
                    .map_err(|_| AuthError::config("Invalid base URL fallback"))?;
                if !matches!(parsed.scheme(), "http" | "https") {
                    return Err(AuthError::config(
                        "Base URL fallback must use HTTP or HTTPS",
                    ));
                }
                fallback.clone()
            };
            config.session.cookie_secure = config.base_url.starts_with("https://");
            if self.advanced.cross_sub_domain_cookies.is_some()
                && self.advanced.use_secure_cookies.is_none()
            {
                config.advanced.use_secure_cookies = Some(config.session.cookie_secure);
            }
            config.session.cookie_name =
                crate::utils::cookie_utils::related_cookie_name(&config, "session_token");
            for host in &dynamic.allowed_hosts {
                if host.contains("://") {
                    config.trusted_origins.push(host.clone());
                } else {
                    if dynamic.protocol != Some(BaseUrlProtocol::Http) {
                        config.trusted_origins.push(format!("https://{host}"));
                    }
                    if matches!(
                        dynamic.protocol,
                        Some(BaseUrlProtocol::Http | BaseUrlProtocol::Auto)
                    ) || trusted_loopback(host)
                    {
                        config.trusted_origins.push(format!("http://{host}"));
                    }
                }
            }
            if let Some(fallback) = &dynamic.fallback
                && let Some(origin) = super::extract_origin(fallback)
            {
                config.trusted_origins.push(origin);
            }
        }
        if let Some(resolver) = &self.trusted_origins_resolver {
            config.trusted_origins.extend(
                resolver
                    .resolve(request)
                    .await?
                    .into_iter()
                    .filter(|origin| !origin.is_empty()),
            );
        }
        Ok(config)
    }
}

fn header<'a>(request: &'a AuthRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
}

fn normalize_host_pattern(value: &str) -> String {
    value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .unwrap_or(value)
        .split('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn loopback(host: &str) -> bool {
    let host = normalize_host_pattern(host);
    let hostname = host
        .trim_start_matches('[')
        .split(']')
        .next()
        .unwrap_or(&host);
    let hostname = if hostname.contains("::") {
        hostname
    } else {
        hostname.split(':').next().unwrap_or(hostname)
    };
    hostname == "localhost"
        || hostname.ends_with(".localhost")
        || hostname == "::1"
        || hostname.starts_with("127.")
}

// Trusted-origin generation uses the server classifier, rather than the
// deliberately permissive dev-scheme heuristic above (e.g. 127.example.test).
fn trusted_loopback(host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    let hostname = if let Some(bracketed) = host.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or(bracketed)
    } else if host.matches(':').count() == 1 {
        host.split(':').next().unwrap_or(&host)
    } else {
        &host
    };
    let hostname = hostname
        .split('%')
        .next()
        .unwrap_or(hostname)
        .trim_end_matches('.');
    hostname == "localhost"
        || hostname.ends_with(".localhost")
        || hostname
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| match ip {
                std::net::IpAddr::V4(ip) => ip.is_loopback(),
                std::net::IpAddr::V6(ip) => {
                    ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
                }
            })
}

fn valid_host(host: &str) -> bool {
    // Source validateProxyHeader: DNS labels, IPv4 or bracketed IPv6 and a
    // one-to-five digit port; no whitespace, userinfo, path or delimiter tricks.
    if host.contains("..") {
        return false;
    }
    regex::Regex::new(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*|(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\])(?::[0-9]{1,5})?$")
        .is_ok_and(|pattern| pattern.is_match(host))
}

// Source wildcardMatch defaults to slash/backslash separators. `**` is
// recursive only as a complete segment; ordinary `*` and `?` stay within it.
fn wildcard(pattern: &str, value: &str) -> bool {
    let separator = r"[/\\]";
    let wildcard = r"[^/\\]";
    let segments: Vec<_> = pattern.split('/').collect();
    let mut expression = String::from("\\A");
    for (index, segment) in segments.iter().enumerate() {
        if segment.is_empty() && index > 0 {
            continue;
        }
        let current_separator = if index + 1 == segments.len() {
            format!("{separator}*?")
        } else if segments.get(index + 1) != Some(&"**") {
            format!("{separator}+?")
        } else {
            String::new()
        };
        if *segment == "**" {
            if !current_separator.is_empty() {
                if index > 0 {
                    expression.push_str(&current_separator);
                }
                expression.push_str(&format!("(?:{wildcard}*?{current_separator})*?"));
            }
            continue;
        }
        let mut chars = segment.chars();
        while let Some(character) = chars.next() {
            match character {
                '*' => expression.push_str(&format!("{wildcard}*?")),
                '?' => expression.push_str(wildcard),
                '\\' => {
                    if let Some(escaped) = chars.next() {
                        expression.push_str(&regex::escape(&escaped.to_string()));
                    }
                }
                literal => expression.push_str(&regex::escape(&literal.to_string())),
            }
        }
        expression.push_str(&current_separator);
    }
    expression.push_str("\\z");
    regex::Regex::new(&expression).is_ok_and(|compiled| compiled.is_match(value))
}

pub(super) fn matches_origin(value: &str, pattern: &str) -> bool {
    if value.starts_with('/') {
        return false;
    }
    let parsed = url::Url::parse(value).ok();
    if pattern.contains(['*', '?']) {
        if pattern.contains("://") {
            let origin = parsed
                .as_ref()
                .filter(|url| matches!(url.origin(), url::Origin::Tuple(..)))
                .map(|url| url.origin().ascii_serialization());
            return wildcard(pattern, origin.as_deref().unwrap_or(value));
        }
        return parsed.is_some_and(|url| {
            url.host_str().is_some()
                && wildcard(
                    pattern,
                    &url[url::Position::BeforeHost..url::Position::AfterPort],
                )
        });
    }
    if parsed
        .as_ref()
        .is_none_or(|url| matches!(url.scheme(), "http" | "https"))
    {
        return parsed.is_some_and(|url| url.origin().ascii_serialization() == pattern);
    }
    let (Some((scheme, authority, path)), Some((pattern_scheme, pattern_authority, pattern_path))) =
        (custom_parts(value), custom_parts(pattern))
    else {
        return false;
    };
    scheme == pattern_scheme
        && (pattern_authority.is_empty() || authority == pattern_authority)
        && (pattern_path.is_empty()
            || path == pattern_path
            || path.starts_with(&format!("{pattern_path}/")))
}

fn custom_parts(value: &str) -> Option<(String, String, String)> {
    if value
        .chars()
        .any(|c| matches!(c, '\u{0000}'..='\u{001f}' | '\u{007f}'..='\u{009f}'))
    {
        return None;
    }
    let (scheme, mut rest) = value.split_once(':')?;
    if scheme.is_empty() {
        return None;
    }
    let mut authority = "";
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        authority = after.get(..end)?;
        rest = after.get(end..)?;
    }
    let path = rest.split(['?', '#']).next().unwrap_or_default();
    // decodeURIComponent leaves the entire input unchanged on invalid escapes.
    let valid_escapes = path.as_bytes().iter().enumerate().all(|(i, c)| {
        *c != b'%'
            || path
                .as_bytes()
                .get(i + 1)
                .is_some_and(u8::is_ascii_hexdigit)
                && path
                    .as_bytes()
                    .get(i + 2)
                    .is_some_and(u8::is_ascii_hexdigit)
    });
    let decoded = if valid_escapes {
        percent_encoding::percent_decode_str(path)
            .decode_utf8()
            .ok()
    } else {
        None
    };
    let mut segments = Vec::new();
    for segment in decoded.as_deref().unwrap_or(path).split('/') {
        match segment {
            ".." => {
                _ = segments.pop();
            }
            "." | "" => {}
            value => segments.push(value),
        }
    }
    let path = if segments.is_empty() {
        String::new()
    } else {
        format!("/{}", segments.join("/"))
    };
    Some((
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase(),
        path,
    ))
}
