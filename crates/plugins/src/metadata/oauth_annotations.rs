//! Core social authentication DTO schemas declared by Better Auth 1.7.6.
use super::OpenApiEndpoint;
use serde_json::{Map, Value, json};

fn response(description: &str, schema: &Value) -> Value {
    json!({"description":description,"content":{"application/json":{"schema":schema}}})
}
fn described(ty: &str, description: &str) -> Value {
    json!({"type":ty,"description":description})
}
fn providers() -> Value {
    // Upstream accepts the documented built-ins or any custom provider string.
    json!({"anyOf":[{"type":"string","enum":["apple","atlassian","cloudflare","cognito","discord","facebook","figma","github","microsoft","google","huggingface","slack","spotify","twitch","twitter","dropbox","kick","linear","linkedin","gitlab","tiktok","reddit","roblox","salesforce","vk","zoom","notion","kakao","naver","line","paybin","paypal","polar","railway","vercel","wechat"]},{"type":"string"}]})
}
fn id_token(linking: bool) -> Value {
    if linking {
        return json!({"type":"object","properties":{"token":{"type":"string"},"nonce":{"type":"string"},"accessToken":{"type":"string"},"refreshToken":{"type":"string"}},"required":["token"]});
    }
    json!({"type":"object","properties":{
  "token":{"type":"string","description":"ID token from the provider"},"nonce":{"type":"string","description":"Nonce used to generate the token"},"accessToken":{"type":"string","description":"Access token from the provider"},"refreshToken":{"type":"string","description":"Refresh token from the provider"},"expiresAt":{"type":"number","description":"Expiry date of the token"},
  "user":{"type":"object","properties":{"name":{"type":"object","properties":{"firstName":{"type":"string"},"lastName":{"type":"string"}}},"email":{"type":"string"}},"description":"The user object from the provider. Only available for some providers like Apple."}
 },"required":["token"]})
}
fn request(linking: bool) -> Value {
    let mut properties = Map::new();
    let names = if linking {
        vec![
            "callbackURL",
            "provider",
            "idToken",
            "requestSignUp",
            "scopes",
            "errorCallbackURL",
            "disableRedirect",
            "loginHint",
            "additionalParams",
            "additionalData",
        ]
    } else {
        vec![
            "callbackURL",
            "newUserCallbackURL",
            "errorCallbackURL",
            "provider",
            "disableRedirect",
            "idToken",
            "scopes",
            "requestSignUp",
            "loginHint",
            "additionalParams",
            "additionalData",
        ]
    };
    for name in names {
        let schema = match name {
            "callbackURL" => described(
                "string",
                if linking {
                    "The URL to redirect to after the user has signed in"
                } else {
                    "Callback URL to redirect to after the user has signed in"
                },
            ),
            "newUserCallbackURL" => json!({"type":"string"}),
            "errorCallbackURL" => described(
                "string",
                if linking {
                    "The URL to redirect to if there is an error during the link process"
                } else {
                    "Callback URL to redirect to if an error happens"
                },
            ),
            "provider" => providers(),
            "disableRedirect" => described(
                "boolean",
                "Disable automatic redirection to the provider. Useful for handling the redirection yourself",
            ),
            "idToken" => id_token(linking),
            "scopes" => {
                json!({"type":"array","items":{"type":"string"},"description":if linking {"Additional scopes to request from the provider"} else {"Array of scopes to request from the provider. This will override the default scopes passed."}})
            }
            "requestSignUp" => {
                if linking {
                    json!({"type":"boolean"})
                } else {
                    described(
                        "boolean",
                        "Explicitly request sign-up. Useful when disableImplicitSignUp is true for this provider",
                    )
                }
            }
            "loginHint" => described(
                "string",
                "The login hint to use for the authorization code request",
            ),
            "additionalParams" => {
                json!({"type":"object","propertyNames":{"type":"string"},"additionalProperties":{"type":"string"},"description":"Extra query parameters to append to the provider authorization URL (e.g. Cognito identity_provider, Google hd)."})
            }
            _ => {
                json!({"type":"object","propertyNames":{"type":"string"},"additionalProperties":{}})
            }
        };
        _ = properties.insert(name.into(), schema);
    }
    json!({"required":true,"content":{"application/json":{"schema":{"type":"object","properties":properties,"required":["provider"]}}}})
}
pub(super) fn endpoint(path: &str) -> Option<OpenApiEndpoint> {
    let linking = match path {
        "/sign-in/social" => false,
        "/link-social" => true,
        _ => return None,
    };
    let mut metadata = OpenApiEndpoint {
        operation_id: Some(
            if linking {
                "linkSocialAccount"
            } else {
                "socialSignIn"
            }
            .into(),
        ),
        description: Some(
            if linking {
                "Link a social account to the user"
            } else {
                "Sign in with a social provider"
            }
            .into(),
        ),
        request_body: Some(request(linking)),
        ..Default::default()
    };
    let schema = if linking {
        json!({"type":"object","properties":{"url":{"type":"string","description":"The authorization URL to redirect the user to"},"redirect":{"type":"boolean","description":"Indicates if the user should be redirected to the authorization URL"},"status":{"type":"boolean"}},"required":["redirect"]})
    } else {
        json!({"type":"object","description":"Returns session details when idToken is provided, or an authorize URL otherwise","properties":{"token":{"type":"string"},"user":{"type":"object","$ref":"#/components/schemas/User"},"url":{"type":"string"},"redirect":{"type":"boolean"}},"required":["redirect"]})
    };
    _ = metadata.responses.insert("200".into(),response(if linking {"Success"} else {"Success - Returns session details (idToken branch) or an authorize URL (redirect branch)"},&(schema)));
    Some(metadata)
}
