//! Passkey attestation shapes, registration option policy and stored-credential
//! authentication failures.
use super::passkey_matrix::{
    ATTESTED, Authenticator, BACKUP_ELIGIBLE, USER_PRESENT, USER_VERIFIED,
};
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::passkey::{
    PasskeyAuthenticatorSelection, PasskeyExtensions, PasskeyExtensionsResolver,
    PasskeyOptionsContext, PasskeyRegistrationContext, PasskeyRegistrationUser,
    PasskeyUserResolver,
};
use alibi::plugins::{PasskeyPlugin, passkey::PasskeyRegistrationConfig};
use alibi::{AuthError, AuthResult};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer as _;
use serde_cbor_2::Value as Cbor;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

backend_tests!(
    passkey_attestation_shapes,
    passkey_option_policy,
    passkey_stored_credential_failures,
    passkey_resolver_physical_request_context,
    passkey_extension_rejection_before_challenge_write
);

type Edit = Box<dyn Fn(&mut Value)>;

#[derive(Clone)]
pub(super) struct Shape {
    pub(super) fmt: &'static str,
    pub(super) alg: i128,
    pub(super) curve: i128,
    pub(super) flags: u8,
    pub(super) rp_id: &'static str,
    pub(super) extensions: Option<Cbor>,
    pub(super) trailing: bool,
    pub(super) statement_alg: Option<i128>,
    pub(super) signature: Signature,
    pub(super) key_override: Option<Vec<u8>>,
    pub(super) statement: Option<Cbor>,
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Signature {
    Valid,
    Corrupt,
    Missing,
}

impl Default for Shape {
    fn default() -> Self {
        Self {
            fmt: "none",
            alg: -8,
            curve: 6,
            flags: USER_PRESENT,
            rp_id: "localhost",
            extensions: None,
            trailing: false,
            statement_alg: Some(-8),
            signature: Signature::Valid,
            key_override: None,
            statement: None,
        }
    }
}

impl Shape {
    pub(super) fn build(&self, key: &Authenticator, client: &[u8]) -> Vec<u8> {
        let cose = self.key_override.clone().unwrap_or_else(|| {
            serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
                (Cbor::Integer(1), Cbor::Integer(1)),
                (Cbor::Integer(3), Cbor::Integer(self.alg)),
                (Cbor::Integer(-1), Cbor::Integer(self.curve)),
                (
                    Cbor::Integer(-2),
                    Cbor::Bytes(key.signing.verifying_key().as_bytes().to_vec()),
                ),
            ])))
            .unwrap()
        });
        let mut data = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        data.push(self.flags);
        data.extend_from_slice(&1_u32.to_be_bytes());
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&u16::try_from(key.id.len()).unwrap().to_be_bytes());
        data.extend_from_slice(&key.id);
        data.extend_from_slice(&cose);
        if let Some(extensions) = &self.extensions {
            data.extend_from_slice(&serde_cbor_2::to_vec(extensions).unwrap());
        }
        if self.trailing {
            data.push(0);
        }
        let mut statement = BTreeMap::new();
        if self.fmt == "packed" {
            if let Some(alg) = self.statement_alg {
                _ = statement.insert(Cbor::Text("alg".into()), Cbor::Integer(alg));
            }
            let mut signed = data.clone();
            signed.extend_from_slice(&Sha256::digest(client));
            let mut signature = key.signing.sign(&signed).to_bytes().to_vec();
            match self.signature {
                Signature::Valid => {}
                Signature::Corrupt => signature[0] ^= 0xff,
                Signature::Missing => signature.clear(),
            }
            if self.signature != Signature::Missing {
                _ = statement.insert(Cbor::Text("sig".into()), Cbor::Bytes(signature));
            }
        }
        serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
            (Cbor::Text("fmt".into()), Cbor::Text(self.fmt.into())),
            (
                Cbor::Text("attStmt".into()),
                self.statement.clone().unwrap_or(Cbor::Map(statement)),
            ),
            (Cbor::Text("authData".into()), Cbor::Bytes(data)),
        ])))
        .unwrap()
    }
}

pub(super) fn client(challenge: &Value) -> Value {
    json!({"type": "webauthn.create", "challenge": challenge, "origin": ORIGIN})
}

#[expect(
    clippy::too_many_arguments,
    reason = "each argument names one axis of the attestation matrix"
)]
async fn attestation_shapes_with<B: Backend>(
    auth: &Alibi<B::Schema>,
    owner: &str,
    trace: &mut Trace,
    label: &str,
    seed: u8,
    shape: Shape,
    edit: impl Fn(&mut Value),
    edit_client: impl Fn(&mut Value),
) {
    let key = Authenticator::new(seed, &format!("attest-{seed}"));
    let options = call(
        auth,
        request("/passkey/generate-register-options", None, owner),
        200,
    )
    .await;
    let mut client = client(&body(&options)["challenge"]);
    edit_client(&mut client);
    let bytes = serde_json::to_vec(&client).unwrap();
    let mut proof = key.registration(&client, &shape.build(&key, &bytes), false);
    edit(&mut proof);
    trace.response(
        label,
        &Box::pin(auth.handle_request(request(
            "/passkey/verify-registration",
            Some(json!({"response": proof, "name": label})),
            &format!("{owner}; {}", cookies(&options)),
        )))
        .await
        .unwrap(),
    );
}

async fn passkey_attestation_shapes<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(PasskeyPlugin::new().origins(vec![ORIGIN.into()]))
        .build()
        .await?;
    let owner = cookies(&signup(&auth, "attestation@example.com").await);
    let mut trace = Trace::default();
    let nothing = |_: &mut Value| {};
    let extension = |value: Cbor| Shape {
        extensions: Some(value),
        flags: USER_PRESENT | 0x80,
        ..Default::default()
    };
    let text = |value: &str| Cbor::Text(value.into());
    let mismatched = Shape {
        fmt: "packed",
        alg: -7,
        ..Default::default()
    };
    let shapes: Vec<(&str, Shape)> = vec![
        ("packed mismatched key", mismatched.clone()),
        (
            "packed statement alg -7",
            Shape {
                statement_alg: Some(-7),
                ..mismatched.clone()
            },
        ),
        (
            "packed unsupported statement alg",
            Shape {
                statement_alg: Some(-257),
                ..mismatched.clone()
            },
        ),
        (
            "packed missing statement alg",
            Shape {
                statement_alg: None,
                ..mismatched.clone()
            },
        ),
        (
            "packed corrupt signature",
            Shape {
                signature: Signature::Corrupt,
                ..mismatched.clone()
            },
        ),
        (
            "packed missing signature",
            Shape {
                signature: Signature::Missing,
                ..mismatched.clone()
            },
        ),
        (
            "packed non-map statement",
            Shape {
                statement: Some(text("x")),
                ..mismatched.clone()
            },
        ),
        (
            "packed with certificate chain",
            Shape {
                statement: Some(Cbor::Map(BTreeMap::from([
                    (text("alg"), Cbor::Integer(-8)),
                    (text("sig"), Cbor::Bytes(vec![0; 64])),
                    (text("x5c"), Cbor::Array(vec![Cbor::Bytes(vec![1, 2, 3])])),
                ]))),
                ..mismatched.clone()
            },
        ),
        (
            "none on curve 8",
            Shape {
                curve: 8,
                ..Default::default()
            },
        ),
        (
            "none with a statement",
            Shape {
                statement: Some(Cbor::Map(BTreeMap::from([(text("a"), Cbor::Integer(1))]))),
                ..Default::default()
            },
        ),
        (
            "none with a null statement",
            Shape {
                statement: Some(Cbor::Null),
                ..Default::default()
            },
        ),
        (
            "unsupported key algorithm",
            Shape {
                alg: -999,
                ..Default::default()
            },
        ),
        (
            "key is not a map",
            Shape {
                key_override: Some(serde_cbor_2::to_vec(&Cbor::Array(vec![])).unwrap()),
                ..Default::default()
            },
        ),
        (
            "wrong relying party",
            Shape {
                rp_id: "elsewhere.example",
                ..Default::default()
            },
        ),
        (
            "attested flag missing",
            Shape {
                flags: USER_PRESENT,
                ..Default::default()
            },
        ),
        (
            "extensions map",
            extension(Cbor::Map(BTreeMap::from([
                (text("credProps"), Cbor::Bool(true)),
                (
                    text("nested"),
                    Cbor::Map(BTreeMap::from([(text("a"), Cbor::Integer(1))])),
                ),
                (Cbor::Integer(0), Cbor::Float(0.0)),
            ]))),
        ),
        (
            "extensions array",
            extension(Cbor::Array(vec![
                Cbor::Array(vec![text("k"), Cbor::Map(BTreeMap::new())]),
                text("entry"),
            ])),
        ),
        ("extensions text", extension(text("abc"))),
        ("extensions scalar", extension(Cbor::Integer(5))),
        (
            "extensions array with scalar",
            extension(Cbor::Array(vec![Cbor::Integer(1)])),
        ),
        (
            "extensions float and tag",
            extension(Cbor::Map(BTreeMap::from([
                (text("f"), Cbor::Float(1.5)),
                (text("g"), Cbor::Float(0.1)),
                (text("h"), Cbor::Float(3.0)),
                (text("t"), Cbor::Tag(1, Box::new(Cbor::Integer(1)))),
                (text("n"), Cbor::Null),
            ]))),
        ),
        (
            "trailing authenticator bytes",
            Shape {
                trailing: true,
                ..Default::default()
            },
        ),
        (
            "extension flag without extension",
            Shape {
                flags: USER_PRESENT | 0x80,
                ..Default::default()
            },
        ),
    ];
    for (index, (label, mut shape)) in shapes.into_iter().enumerate() {
        shape.flags |= ATTESTED;
        if label == "attested flag missing" {
            shape.flags &= !ATTESTED;
        }
        attestation_shapes_with::<B>(
            &auth,
            &owner,
            &mut trace,
            label,
            u8::try_from(60 + index)?,
            shape,
            nothing,
            nothing,
        )
        .await;
    }

    let default = || Shape {
        flags: USER_PRESENT | ATTESTED,
        ..Default::default()
    };
    let client_edits: Vec<(&str, Edit)> = vec![
        (
            "wrong client type",
            Box::new(|client| client["type"] = json!("webauthn.get")),
        ),
        (
            "wrong challenge",
            Box::new(|client| client["challenge"] = json!("other")),
        ),
        (
            "token binding unsupported status",
            Box::new(|client| client["tokenBinding"] = json!({"status": "nope"})),
        ),
        (
            "token binding string",
            Box::new(|client| client["tokenBinding"] = json!("present")),
        ),
        (
            "token binding supported",
            Box::new(|client| client["tokenBinding"] = json!({"status": "supported"})),
        ),
    ];
    for (index, (label, edit)) in client_edits.into_iter().enumerate() {
        attestation_shapes_with::<B>(
            &auth,
            &owner,
            &mut trace,
            label,
            u8::try_from(100 + index)?,
            default(),
            nothing,
            edit,
        )
        .await;
    }
    let response_edits: Vec<(&str, Edit)> = vec![
        (
            "raw id differs",
            Box::new(|proof| proof["rawId"] = json!("other")),
        ),
        (
            "empty id",
            Box::new(|proof| {
                proof["id"] = json!("");
                proof["rawId"] = json!("");
            }),
        ),
        (
            "not a public key",
            Box::new(|proof| proof["type"] = json!("password")),
        ),
        (
            "attestation is not CBOR",
            Box::new(|proof| {
                proof["response"]["attestationObject"] = json!(URL_SAFE_NO_PAD.encode([1, 2]));
            }),
        ),
        (
            "transports not a list",
            Box::new(|proof| proof["response"]["transports"] = json!("usb")),
        ),
        (
            "transports null",
            Box::new(|proof| proof["response"]["transports"] = json!(null)),
        ),
        (
            "transports with a null",
            Box::new(|proof| proof["response"]["transports"] = json!(["usb", null])),
        ),
        (
            "transports with an object",
            Box::new(|proof| proof["response"]["transports"] = json!([{"a": 1}])),
        ),
    ];
    for (index, (label, edit)) in response_edits.into_iter().enumerate() {
        attestation_shapes_with::<B>(
            &auth,
            &owner,
            &mut trace,
            label,
            u8::try_from(120 + index)?,
            default(),
            edit,
            nothing,
        )
        .await;
    }
    trace.assert("passkey/attestation-shapes");
    B::close(connection).await
}

struct Resolver(&'static str);

#[async_trait::async_trait]
impl PasskeyUserResolver for Resolver {
    async fn resolve_user(
        &self,
        _: &PasskeyRegistrationContext<'_>,
        _: Option<&str>,
    ) -> AuthResult<Option<PasskeyRegistrationUser>> {
        match self.0 {
            "fail" => Err(AuthError::internal("resolver unavailable")),
            "invalid" => Ok(None),
            _ => Ok(Some(PasskeyRegistrationUser {
                id: "external-user".into(),
                name: "external".into(),
                display_name: None,
            })),
        }
    }
}

struct Extensions(&'static str);

#[async_trait::async_trait]
impl PasskeyExtensionsResolver for Extensions {
    async fn resolve(&self, context: &PasskeyOptionsContext<'_>) -> AuthResult<Value> {
        match self.0 {
            "fail" => Err(AuthError::internal("extensions unavailable")),
            "deny" => Err(AuthError::forbidden("extensions denied")),
            "scalar" => Ok(json!(5)),
            _ => Ok(json!({"user": context.user.map(|user| user.email.clone())})),
        }
    }
}

async fn passkey_option_policy<B: Backend>(db: Db) -> TestResult {
    let mut trace = Trace::default();
    let variants: Vec<(&str, PasskeyPlugin)> = vec![
        (
            "required selection",
            PasskeyPlugin::new().authenticator_selection(PasskeyAuthenticatorSelection {
                resident_key: Some("required".into()),
                user_verification: Some("required".into()),
                authenticator_attachment: Some("platform".into()),
            }),
        ),
        (
            "discouraged selection",
            PasskeyPlugin::new().authenticator_selection(PasskeyAuthenticatorSelection {
                resident_key: Some("discouraged".into()),
                user_verification: Some("discouraged".into()),
                authenticator_attachment: None,
            }),
        ),
        (
            "static extensions",
            PasskeyPlugin::new()
                .registration(PasskeyRegistrationConfig {
                    extensions: Some(PasskeyExtensions::Static(json!({"appid": "x"}))),
                    ..Default::default()
                })
                .authentication(alibi::plugins::passkey::PasskeyAuthenticationConfig {
                    extensions: Some(PasskeyExtensions::Static(json!({"appid": "y"}))),
                    after_verification: None,
                }),
        ),
        ("resolved extensions", extension_plugin("resolve")),
        ("scalar extensions", extension_plugin("scalar")),
        ("failing extensions", extension_plugin("fail")),
        ("denying extensions", extension_plugin("deny")),
        (
            "static scalar extensions",
            PasskeyPlugin::new()
                .registration(PasskeyRegistrationConfig {
                    extensions: Some(PasskeyExtensions::Static(json!([]))),
                    ..Default::default()
                })
                .authentication(alibi::plugins::passkey::PasskeyAuthenticationConfig {
                    extensions: Some(PasskeyExtensions::Static(json!("x"))),
                    after_verification: None,
                }),
        ),
        ("sessionless without resolver", sessionless(None)),
        ("sessionless resolver", sessionless(Some("ok"))),
        ("sessionless invalid user", sessionless(Some("invalid"))),
        ("sessionless failing resolver", sessionless(Some("fail"))),
    ];
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for (index, (label, plugin)) in variants.into_iter().enumerate() {
        let auth = builder::<B>(&connection).plugin(plugin).build().await?;
        let owner = cookies(&signup(&auth, &format!("options-{index}@example.com")).await);
        for (name, cookie) in [("session", owner.as_str()), ("anonymous", "")] {
            let register = Box::pin(auth.handle_request(request(
                "/passkey/generate-register-options",
                None,
                cookie,
            )))
            .await?;
            trace.response(&format!("{label} register {name}"), &register);
            let authenticate = Box::pin(auth.handle_request(request(
                "/passkey/generate-authenticate-options",
                None,
                cookie,
            )))
            .await?;
            trace.response(&format!("{label} authenticate {name}"), &authenticate);
        }
    }
    trace.assert("passkey/option-policy");
    B::close(connection).await
}

fn extension_plugin(mode: &'static str) -> PasskeyPlugin {
    PasskeyPlugin::new()
        .registration(PasskeyRegistrationConfig {
            extensions: Some(PasskeyExtensions::Resolver(Arc::new(Extensions(mode)))),
            ..Default::default()
        })
        .authentication(alibi::plugins::passkey::PasskeyAuthenticationConfig {
            extensions: Some(PasskeyExtensions::Resolver(Arc::new(Extensions(mode)))),
            after_verification: None,
        })
}

fn sessionless(resolver: Option<&'static str>) -> PasskeyPlugin {
    PasskeyPlugin::new().registration(PasskeyRegistrationConfig {
        require_session: false,
        resolve_user: resolver.map(|mode| Arc::new(Resolver(mode)) as _),
        ..Default::default()
    })
}

async fn passkey_stored_credential_failures<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(PasskeyPlugin::new().origins(vec![ORIGIN.into()]))
        .build()
        .await?;
    let owner = cookies(&signup(&auth, "stored@example.com").await);
    let mut trace = Trace::default();
    let flags = USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | ATTESTED;
    let register = async |trace: &mut Trace, label: &str, key: &Authenticator, shape: Shape| {
        let options = call(
            &auth,
            request("/passkey/generate-register-options", None, &owner),
            200,
        )
        .await;
        let client = client(&body(&options)["challenge"]);
        let bytes = serde_json::to_vec(&client).unwrap();
        let proof = key.registration(&client, &shape.build(key, &bytes), false);
        let registered = call(
            &auth,
            request(
                "/passkey/verify-registration",
                Some(json!({"response": proof, "name": label})),
                &format!("{owner}; {}", cookies(&options)),
            ),
            200,
        )
        .await;
        trace.response(label, &registered);
    };
    let core = Authenticator::new(7, "stored-core");
    let raw = Authenticator::new(9, "stored-raw");
    let curve_eight = Authenticator::new(10, "stored-curve-eight");
    register(
        &mut trace,
        "registered core credential",
        &core,
        Shape {
            flags,
            ..Default::default()
        },
    )
    .await;
    register(
        &mut trace,
        "registered raw credential",
        &raw,
        Shape {
            flags,
            fmt: "packed",
            alg: -7,
            ..Default::default()
        },
    )
    .await;
    register(
        &mut trace,
        "registered curve 8 credential",
        &curve_eight,
        Shape {
            flags,
            curve: 8,
            ..Default::default()
        },
    )
    .await;

    let authenticate = async |trace: &mut Trace,
                              label: &str,
                              authenticator: &Authenticator,
                              flags: u8,
                              counter: u32,
                              edit: &dyn Fn(&mut Value, &mut Value)| {
        let options = call(
            &auth,
            request("/passkey/generate-authenticate-options", None, ""),
            200,
        )
        .await;
        let mut client = json!({"type": "webauthn.get", "challenge": body(&options)["challenge"], "origin": ORIGIN});
        let mut assertion = authenticator.assertion(&client, "localhost", flags, counter);
        let original = client.clone();
        edit(&mut client, &mut assertion);
        if client != original {
            let signed = authenticator.assertion(&client, "localhost", flags, counter);
            assertion["response"]["clientDataJSON"] = signed["response"]["clientDataJSON"].clone();
            assertion["response"]["signature"] = signed["response"]["signature"].clone();
        }
        trace.response(
            label,
            &Box::pin(auth.handle_request(request(
                "/passkey/verify-authentication",
                Some(json!({"response": assertion})),
                &cookies(&options),
            )))
            .await
            .unwrap(),
        );
    };
    let nothing = |_: &mut Value, _: &mut Value| {};
    let rewrite_data = |assertion: &mut Value, edit: &dyn Fn(&mut Vec<u8>)| {
        let mut data = URL_SAFE_NO_PAD
            .decode(assertion["response"]["authenticatorData"].as_str().unwrap())
            .unwrap();
        edit(&mut data);
        assertion["response"]["authenticatorData"] = json!(URL_SAFE_NO_PAD.encode(data));
    };
    authenticate(
        &mut trace,
        "unknown credential",
        &Authenticator::new(8, "stranger"),
        USER_PRESENT,
        2,
        &nothing,
    )
    .await;
    for (name, key) in [("core", &core), ("raw", &raw)] {
        let label = |text: &str| format!("{name}: {text}");
        authenticate(
            &mut trace,
            &label("corrupt signature"),
            key,
            USER_PRESENT,
            2,
            &|_, assertion| {
                let mut signature = URL_SAFE_NO_PAD
                    .decode(assertion["response"]["signature"].as_str().unwrap())
                    .unwrap();
                signature[0] ^= 0xff;
                assertion["response"]["signature"] = json!(URL_SAFE_NO_PAD.encode(signature));
            },
        )
        .await;
        authenticate(
            &mut trace,
            &label("short signature"),
            key,
            USER_PRESENT,
            2,
            &|_, assertion| {
                assertion["response"]["signature"] = json!(URL_SAFE_NO_PAD.encode([1, 2, 3]));
            },
        )
        .await;
        authenticate(
            &mut trace,
            &label("other relying party"),
            key,
            USER_PRESENT,
            2,
            &|_, assertion| rewrite_data(assertion, &|data| data[0] ^= 1),
        )
        .await;
        authenticate(
            &mut trace,
            &label("extension flag without extension"),
            key,
            USER_PRESENT | 0x80,
            2,
            &nothing,
        )
        .await;
        authenticate(
            &mut trace,
            &label("extension data"),
            key,
            USER_PRESENT | 0x80,
            2,
            &|_, assertion| {
                rewrite_data(assertion, &|data| {
                    data.extend(serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::new())).unwrap());
                });
            },
        )
        .await;
        authenticate(
            &mut trace,
            &label("attested flag in assertion"),
            key,
            USER_PRESENT | ATTESTED,
            2,
            &nothing,
        )
        .await;
        authenticate(
            &mut trace,
            &label("backed up without eligibility"),
            key,
            USER_PRESENT | 0x10,
            2,
            &nothing,
        )
        .await;
        authenticate(
            &mut trace,
            &label("user not present"),
            key,
            USER_VERIFIED,
            2,
            &nothing,
        )
        .await;
        for (text, edit) in [
            ("client type", json!({"type": "webauthn.create"})),
            ("challenge", json!({"challenge": "other"})),
            ("origin", json!({"origin": "https://evil.example"})),
            (
                "token binding",
                json!({"tokenBinding": {"status": "unknown"}}),
            ),
            ("token binding string", json!({"tokenBinding": "present"})),
        ] {
            authenticate(
                &mut trace,
                &label(text),
                key,
                USER_PRESENT,
                2,
                &|client, _| {
                    client
                        .as_object_mut()
                        .unwrap()
                        .extend(edit.as_object().unwrap().clone());
                },
            )
            .await;
        }
        authenticate(
            &mut trace,
            &label("stale counter"),
            key,
            USER_PRESENT,
            0,
            &nothing,
        )
        .await;
        authenticate(
            &mut trace,
            &label("mismatched raw id"),
            key,
            USER_PRESENT,
            2,
            &|_, assertion| assertion["rawId"] = json!(URL_SAFE_NO_PAD.encode("elsewhere")),
        )
        .await;
        authenticate(
            &mut trace,
            &label("success with token binding"),
            key,
            USER_PRESENT,
            2,
            &|client, _| client["tokenBinding"] = json!({"status": "supported"}),
        )
        .await;
        authenticate(
            &mut trace,
            &label("assertion type"),
            key,
            USER_PRESENT,
            3,
            &|_, assertion| assertion["type"] = json!("password"),
        )
        .await;
        authenticate(
            &mut trace,
            &label("replayed counter"),
            key,
            USER_PRESENT,
            2,
            &nothing,
        )
        .await;
    }
    authenticate(
        &mut trace,
        "curve 8 credential",
        &curve_eight,
        USER_PRESENT,
        2,
        &nothing,
    )
    .await;
    trace.value(
        "stored counters",
        json!(
            db.text(
                "SELECT GROUP_CONCAT(CAST(counter AS TEXT), ',') FROM passkeys",
                &[]
            )
            .await?
        ),
    );
    trace.assert("passkey/stored-credential-failures");
    B::close(connection).await
}

async fn passkey_resolver_physical_request_context<B: Backend>(db: Db) -> TestResult {
    struct Capture(Mutex<Vec<Value>>);
    #[async_trait::async_trait]
    impl PasskeyExtensionsResolver for Capture {
        async fn resolve(&self, c: &PasskeyOptionsContext<'_>) -> AuthResult<Value> {
            let marker = c.request.headers.get("x-option-marker").unwrap();
            self.0.lock().unwrap().push(json!({"path":c.request.path,"method":format!("{:?}",c.request.method),"marker":marker,"user":c.user,"baseURL":c.auth_config.base_url}));
            Ok(if c.request.path.ends_with("generate-register-options") {
                json!({"credProps":false,"minPinLength":true,"appid":marker})
            } else {
                json!({"appid":marker})
            })
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let capture = Arc::new(Capture(Mutex::new(Vec::new())));
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(
            PasskeyPlugin::new()
                .origins(vec![ORIGIN.into()])
                .registration(PasskeyRegistrationConfig {
                    extensions: Some(PasskeyExtensions::Resolver(capture.clone())),
                    ..Default::default()
                })
                .authentication(alibi::plugins::passkey::PasskeyAuthenticationConfig {
                    extensions: Some(PasskeyExtensions::Resolver(capture.clone())),
                    after_verification: None,
                }),
        )
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let jar = cookies(&owner);
    for (path, marker, cookie) in [
        (
            "/passkey/generate-register-options",
            "real-registration",
            jar.as_str(),
        ),
        (
            "/passkey/generate-authenticate-options",
            "real-authentication",
            jar.as_str(),
        ),
        (
            "/passkey/generate-authenticate-options",
            "guest-authentication",
            "",
        ),
    ] {
        let mut r = request(path, None, cookie);
        _ = r.headers.insert("x-option-marker".into(), marker.into());
        let options = call(&auth, r, 200).await;
        assert_eq!(body(&options)["extensions"]["appid"], marker);
        if path.ends_with("register-options") {
            assert_eq!(body(&options)["extensions"]["credProps"], true);
            assert_eq!(body(&options)["extensions"]["minPinLength"], true);
        }
        let receipt = capture.0.lock().unwrap().last().cloned().unwrap();
        assert_eq!(receipt["path"], path);
        assert_eq!(receipt["method"], "Get");
        assert_eq!(receipt["marker"], marker);
        assert_eq!(receipt["baseURL"], ORIGIN);
        assert_eq!(
            receipt["user"],
            if cookie.is_empty() {
                Value::Null
            } else {
                body(&owner)["user"].clone()
            }
        );
        assert!(options.headers.get_all("set-cookie").next().is_some());
    }
    assert_eq!(capture.0.lock().unwrap().len(), 3);
    authenticated(&auth, &jar, "owner@example.test").await;
    B::close(connection).await
}

async fn passkey_extension_rejection_before_challenge_write<B: Backend>(db: Db) -> TestResult {
    struct Resolver(Mutex<&'static str>);
    #[async_trait::async_trait]
    impl PasskeyExtensionsResolver for Resolver {
        async fn resolve(&self, _: &PasskeyOptionsContext<'_>) -> AuthResult<Value> {
            match *self.0.lock().unwrap() {
                "internal" => Err(AuthError::internal("private resolver error")),
                "coded" => Err(AuthError::Api {
                    status: 403,
                    code: Some("APPLICATION_EXTENSIONS_DENIED".into()),
                    message: "Application option policy denied".into(),
                }),
                _ => Ok(json!({})),
            }
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let resolver = Arc::new(Resolver(Mutex::new("ok")));
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(
            PasskeyPlugin::new()
                .origins(vec![ORIGIN.into()])
                .registration(PasskeyRegistrationConfig {
                    extensions: Some(PasskeyExtensions::Resolver(resolver.clone())),
                    ..Default::default()
                })
                .authentication(alibi::plugins::passkey::PasskeyAuthenticationConfig {
                    extensions: Some(PasskeyExtensions::Resolver(resolver.clone())),
                    after_verification: None,
                }),
        )
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let jar = cookies(&owner);
    let before = db
        .tables(&["users", "accounts", "sessions", "passkeys", "verifications"])
        .await?;
    for mode in ["internal", "coded"] {
        *resolver.0.lock().unwrap() = mode;
        for path in [
            "/passkey/generate-register-options",
            "/passkey/generate-authenticate-options",
        ] {
            let denied = call(
                &auth,
                request(path, None, &jar),
                if mode == "internal" { 500 } else { 403 },
            )
            .await;
            if mode == "internal" {
                assert!(denied.body.is_empty());
            } else {
                assert_eq!(body(&denied)["code"], "APPLICATION_EXTENSIONS_DENIED");
            }
            assert!(denied.headers.get_all("set-cookie").next().is_none());
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "passkeys", "verifications"])
                    .await?,
                before
            );
            authenticated(&auth, &jar, "owner@example.test").await;
        }
    }
    *resolver.0.lock().unwrap() = "ok";
    let options = call(
        &auth,
        request("/passkey/generate-register-options", None, &jar),
        200,
    )
    .await;
    let key = Authenticator::new(107, "recovered-option-key");
    let shape = Shape {
        flags: USER_PRESENT | USER_VERIFIED | ATTESTED,
        ..Default::default()
    };
    let client = client(&body(&options)["challenge"]);
    let bytes = serde_json::to_vec(&client)?;
    let proof = key.registration(&client, &shape.build(&key, &bytes), false);
    _ = call(
        &auth,
        request(
            "/passkey/verify-registration",
            Some(json!({"response":proof,"name":"Recovered Ceremony"})),
            &format!("{jar}; {}", cookies(&options)),
        ),
        200,
    )
    .await;
    assert_eq!(db.count("passkeys").await?, 1);
    assert_eq!(db.count("verifications").await?, 0);
    B::close(connection).await
}
