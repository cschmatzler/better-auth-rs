//! Compromised-password and CAPTCHA admission against varied provider replies.
use super::*;
use crate::snapshot::Trace;
use alibi::AuthResult;
use alibi::plugins::captcha::{
    BotIdConfig, BotIdVerification, CaptchaConfig, CaptchaPlugin, CaptchaProvider, CheckBotId,
    RecaptchaConfig, SiteKeyCaptchaConfig, TurnstileConfig, ValidateBotIdRequest,
};
use alibi::plugins::haveibeenpwned::{
    HaveIBeenPwnedConfig, HaveIBeenPwnedPlugin, PwnedPasswordClient,
};

backend_tests!(
    pwned_range_reply_matrix,
    captcha_reply_and_path_matrix,
    captcha_normalized_physical_paths_reject_before_json_and_origin_validation,
    captcha_botid_validator_receives_actual_request_and_full_verification,
    captcha_botid_validator_error_preserves_all_existing_principals,
    captcha_slow_successful_response_body_still_authenticates_existing_owner,
    captcha_physical_method_admission
);

const SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

fn client(provider: &Provider) -> PwnedPasswordClient {
    PwnedPasswordClient::new(
        reqwest::Client::builder().no_proxy().build().unwrap(),
        provider.url.clone(),
    )
}

async fn pwned_range_reply_matrix<B: Backend>(db: Db) -> TestResult {
    let provider = Provider::start("text/plain", "").await;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(HaveIBeenPwnedPlugin::with_config(HaveIBeenPwnedConfig {
            client: client(&provider),
            custom_password_compromised_message: Some("Pick another password".into()),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let hit = format!("{SUFFIX}:42");
    let escaped = format!(r#""\ud800A\b\f\r\t\/\\\"\n{hit}\r\n""#);
    let replies: Vec<(&str, &'static str, String)> = vec![
        ("plain hit", "text/plain", format!("{hit}\r\n")),
        ("json string hit", "application/json", format!("\"{hit}\"")),
        ("escaped surrogate lines", "application/json", escaped),
        (
            "lone surrogate array",
            "application/json",
            r#"["\ud800"]"#.into(),
        ),
        (
            "lone surrogate object",
            "application/json",
            r#"{"a":"\ud800"}"#.into(),
        ),
        ("json number", "application/json", "42".into()),
        (
            "vendor json",
            "application/vnd.api+json",
            format!("{hit}\n"),
        ),
        ("mixed case json", "Application/JSON", format!("{hit}\n")),
        ("svg media", "image/svg", format!("{hit}\n")),
        (
            "binary media",
            "application/octet-stream",
            format!("{hit}\n"),
        ),
        (
            "invalid vendor suffix",
            "application/vnd ai+json",
            format!("{hit}\n"),
        ),
        (
            "other lines first",
            "text/plain",
            format!("0000:1\nABC\n{}:5\n", &SUFFIX[..10]),
        ),
        (
            "lowercase suffix",
            "text/plain",
            format!("{}:1\n", SUFFIX.to_lowercase()),
        ),
        (
            "bare newline terminator",
            "text/plain",
            format!("x:1\n{hit}\n"),
        ),
        ("zero count", "text/plain", format!("{SUFFIX}:0\r\n")),
        ("absent suffix", "text/plain", "FFFFF:1\n".into()),
        ("empty count", "text/plain", format!("{SUFFIX}:\n")),
        ("non digit count", "text/plain", format!("{SUFFIX}:4x\n")),
        (
            "leading zero count",
            "text/plain",
            format!("{SUFFIX}:007\n"),
        ),
        (
            "count above safe integer",
            "text/plain",
            format!("{SUFFIX}:9007199254740992\n"),
        ),
        (
            "count above u64",
            "text/plain",
            format!("{SUFFIX}:99999999999999999999999\n"),
        ),
    ];
    for (index, (label, content_type, text)) in replies.into_iter().enumerate() {
        provider.respond(200, content_type, text);
        let input = json!({"email":format!("pwned{index}@example.test"),"password":"password","name":"Owner"});
        trace.response(
            label,
            &Box::pin(auth.handle_request(request("/sign-up/email", Some(input), ""))).await?,
        );
    }
    trace.value("users", json!(db.count("users").await?));

    provider.respond(200, "text/plain", format!("{hit}\n"));
    for (label, paths, enabled) in [
        (
            "custom path included",
            Some(vec!["/sign-up/email".to_owned()]),
            true,
        ),
        (
            "custom path excluded",
            Some(vec!["/change-password".to_owned()]),
            true,
        ),
        ("disabled", None, false),
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = builder::<B>(&connection)
            .plugin(HaveIBeenPwnedPlugin::with_config(HaveIBeenPwnedConfig {
                enabled,
                paths,
                client: client(&provider),
                ..Default::default()
            }))
            .build()
            .await?;
        let input = json!({"email":"scoped@example.test","password":"password","name":"Owner"});
        trace.response(
            label,
            &Box::pin(auth.handle_request(request("/sign-up/email", Some(input), ""))).await?,
        );
        B::close(connection).await?;
    }
    trace.assert("screening/pwned-reply-matrix");
    B::close(connection).await
}

struct Bot(Result<bool, &'static str>);
#[async_trait::async_trait]
impl CheckBotId for Bot {
    async fn check(&self) -> AuthResult<BotIdVerification> {
        self.0
            .map(|is_bot| BotIdVerification {
                is_bot,
                is_verified_bot: Some(!is_bot),
                verified_bot_name: None,
                verified_bot_category: None,
            })
            .map_err(alibi::AuthError::internal)
    }
}
struct Judge(bool);
#[async_trait::async_trait]
impl ValidateBotIdRequest for Judge {
    async fn validate(&self, _: &AuthRequest, _: &BotIdVerification) -> AuthResult<bool> {
        Ok(self.0)
    }
}

async fn captcha_reply_and_path_matrix<B: Backend>(db: Db) -> TestResult {
    let provider = Provider::start("application/json", "").await;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    let sign_in = |token: Option<&str>| {
        let mut input = request(
            "/sign-in/email",
            Some(json!({"email":"nobody@example.test","password":PASSWORD})),
            "",
        );
        if let Some(token) = token {
            _ = input
                .headers
                .insert("x-captcha-response".into(), token.into());
        }
        input
    };
    let http = || reqwest::Client::builder().no_proxy().build().unwrap();
    let mut turnstile = TurnstileConfig::new("provider-secret");
    turnstile.http.site_verify_url = Some(provider.url.clone());
    let auth = builder::<B>(&connection)
        .plugin(
            CaptchaPlugin::new(CaptchaConfig::new(CaptchaProvider::CloudflareTurnstile(
                turnstile,
            )))
            .with_http_client(http()),
        )
        .build()
        .await?;
    trace.response(
        "missing header",
        &Box::pin(auth.handle_request(sign_in(None))).await?,
    );
    trace.response(
        "empty header",
        &Box::pin(auth.handle_request(sign_in(Some("")))).await?,
    );
    let replies: [(&str, u16, &'static str, &str); 12] = [
        ("success", 200, "application/json", r#"{"success":true}"#),
        (
            "provider 500",
            500,
            "application/json",
            r#"{"success":true}"#,
        ),
        ("binary media", 200, "image/png", r#"{"success":true}"#),
        ("invalid json text", 200, "text/plain", "not json"),
        ("empty body", 200, "text/plain", ""),
        ("json null", 200, "application/json", "null"),
        ("json zero", 200, "application/json", "0"),
        ("json array", 200, "application/json", "[]"),
        (
            "numeric success",
            200,
            "application/json",
            r#"{"success":1}"#,
        ),
        (
            "empty string success",
            200,
            "application/json",
            r#"{"success":""}"#,
        ),
        (
            "object success",
            200,
            "application/json",
            r#"{"success":{}}"#,
        ),
        (
            "string success",
            200,
            "application/json",
            r#"{"success":"x"}"#,
        ),
    ];
    for (label, status, content_type, text) in replies {
        provider.respond(status, content_type, text);
        trace.response(
            label,
            &Box::pin(auth.handle_request(sign_in(Some("proof")))).await?,
        );
    }
    let _ = provider.take();

    let site_key = |url: &url::Url| {
        let mut options = SiteKeyCaptchaConfig::new("provider-secret");
        options.http.site_verify_url = Some(url.clone());
        options
    };
    let mut recaptcha = RecaptchaConfig::new("provider-secret");
    recaptcha.http.site_verify_url = Some(provider.url.clone());
    let mut empty = SiteKeyCaptchaConfig::new("");
    empty.http.site_verify_url = Some(provider.url.clone());
    let paths = |patterns: &[&str]| patterns.iter().map(|path| (*path).to_owned()).collect();
    let scenarios: Vec<(&str, CaptchaProvider, Vec<String>, &str)> = vec![
        (
            "recaptcha low score",
            CaptchaProvider::GoogleRecaptcha(recaptcha),
            Vec::new(),
            "/sign-in/email",
        ),
        (
            "empty secret",
            CaptchaProvider::HCaptcha(empty),
            Vec::new(),
            "/sign-in/email",
        ),
        (
            "wildcard segment",
            CaptchaProvider::CaptchaFox(site_key(&provider.url)),
            paths(&["/sign-in/e?ail", "/sign-up/*"]),
            "/sign-in/email",
        ),
        (
            "globstar descendants",
            CaptchaProvider::HCaptcha(site_key(&provider.url)),
            paths(&["/sign-in/**"]),
            "/sign-in/email",
        ),
        (
            "unprotected path",
            CaptchaProvider::HCaptcha(site_key(&provider.url)),
            paths(&["/sign-up/*"]),
            "/sign-in/email",
        ),
        (
            "oversized pattern",
            CaptchaProvider::HCaptcha(site_key(&provider.url)),
            paths(&[&"*a".repeat(5000)]),
            "/sign-in/email",
        ),
    ];
    provider.respond(200, "application/json", r#"{"success":true,"score":0.1}"#);
    for (label, kind, endpoints, path) in scenarios {
        let mut config = CaptchaConfig::new(kind);
        config.endpoints = endpoints;
        let auth = builder::<B>(&connection)
            .plugin(CaptchaPlugin::new(config).with_http_client(http()))
            .build()
            .await?;
        let mut input = sign_in(None);
        input.path = format!("/api/auth{path}");
        trace.response(label, &Box::pin(auth.handle_request(input)).await?);
        let mut input = sign_in(Some("proof"));
        input.path = format!("/api/auth{path}");
        trace.response(
            &format!("{label} with token"),
            &Box::pin(auth.handle_request(input)).await?,
        );
    }

    let bots: [(&str, Bot, Option<bool>); 5] = [
        ("human", Bot(Ok(false)), None),
        ("bot", Bot(Ok(true)), None),
        ("check failure", Bot(Err("down")), None),
        ("validator accepts bot", Bot(Ok(true)), Some(true)),
        ("validator rejects human", Bot(Ok(false)), Some(false)),
    ];
    for (label, bot, judge) in bots {
        let auth = builder::<B>(&connection)
            .plugin(CaptchaPlugin::new(CaptchaConfig::new(
                CaptchaProvider::VercelBotId(BotIdConfig {
                    check_bot_id: Arc::new(bot),
                    validate_request: judge.map(|verdict| Arc::new(Judge(verdict)) as _),
                }),
            )))
            .build()
            .await?;
        trace.response(label, &Box::pin(auth.handle_request(sign_in(None))).await?);
    }
    trace.assert("screening/captcha-reply-path-matrix");
    B::close(connection).await
}

async fn captcha_normalized_physical_paths_reject_before_json_and_origin_validation<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let base = super::auth_probe::fast_builder::<B>(&connection)
        .build()
        .await?;
    let owner = signup(&base, "owner@example.test").await;
    let foreign = signup(&base, "foreign@example.test").await;
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for (patterns, paths, control) in [
        (
            vec![],
            vec!["/sign-in//email", "/sign-in/email/", "//sign-in///email//"],
            "/sign-in/email/extended",
        ),
        (
            vec!["/guarded".into()],
            vec!["/guarded/", "//guarded//"],
            "/sign-in/email",
        ),
        (
            vec!["/guard/*".into()],
            vec!["/guard//leaf/"],
            "/guard/leaf/deeper",
        ),
        (
            vec!["/guard/**".into()],
            vec!["/guard//leaf/deeper/"],
            "/unguarded/leaf",
        ),
    ] {
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(CaptchaPlugin::new(CaptchaConfig {
                provider: CaptchaProvider::CloudflareTurnstile(TurnstileConfig::new("secret")),
                endpoints: patterns,
            }))
            .build()
            .await?;
        for path in paths {
            let mut input = request(path, Some(json!({})), &cookies(&owner));
            input.body = Some(b"not-json".to_vec());
            _ = input
                .headers
                .insert("origin".into(), "https://foreign.invalid".into());
            let denied = call(&auth, input, 400).await;
            assert_eq!(body(&denied)["code"], "MISSING_RESPONSE");
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "verifications"])
                    .await?,
                before
            );
        }
        let mut input = request(control, Some(json!({})), &cookies(&owner));
        input.body = Some(b"not-json".to_vec());
        _ = input
            .headers
            .insert("origin".into(), "https://foreign.invalid".into());
        let control = Box::pin(auth.handle_request(input)).await?;
        let code = serde_json::from_slice::<Value>(&control.body).ok();
        assert!(code.is_none_or(|value| value["code"] != "MISSING_RESPONSE"));
    }
    authenticated(&base, &cookies(&owner), "owner@example.test").await;
    authenticated(&base, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn captcha_botid_validator_receives_actual_request_and_full_verification<B: Backend>(
    db: Db,
) -> TestResult {
    struct Policy(Mutex<Vec<(AuthRequest, Value)>>);
    #[async_trait::async_trait]
    impl CheckBotId for Policy {
        async fn check(&self) -> AuthResult<BotIdVerification> {
            Ok(BotIdVerification {
                is_bot: true,
                is_verified_bot: Some(true),
                verified_bot_name: Some("SearchBot".into()),
                verified_bot_category: Some("search".into()),
            })
        }
    }
    #[async_trait::async_trait]
    impl ValidateBotIdRequest for Policy {
        async fn validate(
            &self,
            request: &AuthRequest,
            result: &BotIdVerification,
        ) -> AuthResult<bool> {
            self.0
                .lock()
                .unwrap()
                .push((request.clone(), serde_json::to_value(result).unwrap()));
            Ok(request
                .header("x-app-marker")
                .is_some_and(|value| value == "allowed")
                && result.is_bot
                && result.is_verified_bot == Some(true)
                && result.verified_bot_name.as_deref() == Some("SearchBot")
                && result.verified_bot_category.as_deref() == Some("search"))
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(Policy(Mutex::new(Vec::new())));
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(CaptchaPlugin::new(CaptchaConfig {
            provider: CaptchaProvider::VercelBotId(BotIdConfig {
                check_bot_id: policy.clone(),
                validate_request: Some(policy.clone()),
            }),
            endpoints: vec!["/sign-in/email".into()],
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let mut input = request(
        "/sign-in/email",
        Some(json!({"email":"owner@example.test","password":PASSWORD})),
        "",
    );
    let denied = call(&auth, input.clone(), 403).await;
    assert_eq!(body(&denied)["code"], "VERIFICATION_FAILED");
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    _ = input
        .headers
        .insert("x-app-marker".into(), "allowed".into());
    let accepted = call(&auth, input.clone(), 200).await;
    assert_eq!(body(&accepted)["user"]["id"], body(&owner)["user"]["id"]);
    {
        let events = policy.0.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].0.path, input.path);
        assert_eq!(events[1].0.body, input.body);
        assert_eq!(
            events[1].0.header("x-app-marker").map(String::as_str),
            Some("allowed")
        );
        assert_eq!(
            events[1].1,
            json!({"isBot":true,"isVerifiedBot":true,"verifiedBotName":"SearchBot","verifiedBotCategory":"search"})
        );
    }
    authenticated(&auth, &cookies(&accepted), "owner@example.test").await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn captcha_botid_validator_error_preserves_all_existing_principals<B: Backend>(
    db: Db,
) -> TestResult {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Policy(AtomicBool);
    #[async_trait::async_trait]
    impl ValidateBotIdRequest for Policy {
        async fn validate(&self, _: &AuthRequest, _: &BotIdVerification) -> AuthResult<bool> {
            if self.0.load(Ordering::SeqCst) {
                Err(alibi::AuthError::internal("validator unavailable"))
            } else {
                Ok(true)
            }
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(Policy(AtomicBool::new(true)));
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(CaptchaPlugin::new(CaptchaConfig {
            provider: CaptchaProvider::VercelBotId(BotIdConfig {
                check_bot_id: Arc::new(Bot(Ok(false))),
                validate_request: Some(policy.clone()),
            }),
            endpoints: vec!["/sign-in/email".into()],
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    let input = request(
        "/sign-in/email",
        Some(json!({"email":"owner@example.test","password":PASSWORD})),
        "",
    );
    let denied = call(&auth, input.clone(), 500).await;
    assert_eq!(body(&denied)["code"], "UNKNOWN_ERROR");
    assert!(denied.headers.get_all("set-cookie").next().is_none());
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before
    );
    authenticated(&auth, &cookies(&owner), "owner@example.test").await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    policy.0.store(false, Ordering::SeqCst);
    let restored = call(&auth, input, 200).await;
    assert_eq!(body(&restored)["user"]["id"], body(&owner)["user"]["id"]);
    B::close(connection).await
}

async fn captcha_slow_successful_response_body_still_authenticates_existing_owner<B: Backend>(
    db: Db,
) -> TestResult {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let received = Arc::new(tokio::sync::Notify::new());
    let sent = received.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 8192];
        _ = stream.read(&mut buffer).await.unwrap();
        let body = r#"{"success":true}"#;
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        sent.notify_one();
        tokio::time::sleep(std::time::Duration::from_millis(10_100)).await;
        stream.write_all(body.as_bytes()).await.unwrap();
    });
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut options = TurnstileConfig::new("secret");
    options.http.site_verify_url = Some(format!("http://{address}/verify").parse()?);
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(
            CaptchaPlugin::new(CaptchaConfig {
                provider: CaptchaProvider::CloudflareTurnstile(options),
                endpoints: vec!["/sign-in/email".into()],
            })
            .with_http_client(reqwest::Client::builder().no_proxy().build()?),
        )
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let accounts = db.table("accounts").await?;
    let mut input = request(
        "/sign-in/email",
        Some(json!({"email":"owner@example.test","password":PASSWORD})),
        "",
    );
    _ = input
        .headers
        .insert("x-captcha-response".into(), "answer".into());
    let pending = Box::pin(auth.handle_request(input));
    tokio::pin!(pending);
    tokio::select! { response=&mut pending=>panic!("authentication completed before response body: {response:?}"),()=received.notified()=>{} }
    let response = pending.await?;
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(body(&response)["user"]["id"], body(&owner)["user"]["id"]);
    assert_eq!(db.table("accounts").await?, accounts);
    assert_eq!(db.count("sessions").await?, 3);
    authenticated(&auth, &cookies(&response), "owner@example.test").await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    server.await?;
    B::close(connection).await
}

#[tokio::test(flavor = "current_thread")]
async fn captcha_botid_deadline_rejects_authentication_without_cancelling_callbacks() -> TestResult
{
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Check {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }
    #[async_trait::async_trait]
    impl CheckBotId for Check {
        async fn check(&self) -> AuthResult<BotIdVerification> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(BotIdVerification {
                is_bot: false,
                is_verified_bot: Some(false),
                verified_bot_name: None,
                verified_bot_category: None,
            })
        }
    }
    struct Finish {
        completed: tokio::sync::Notify,
        count: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl ValidateBotIdRequest for Finish {
        async fn validate(&self, _: &AuthRequest, _: &BotIdVerification) -> AuthResult<bool> {
            _ = self.count.fetch_add(1, Ordering::SeqCst);
            self.completed.notify_one();
            Ok(true)
        }
    }
    let check = Arc::new(Check {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let finish = Arc::new(Finish {
        completed: tokio::sync::Notify::new(),
        count: AtomicUsize::new(0),
    });
    let auth = Arc::new(
        AuthBuilder::without_database(
            AuthConfig::new(SECRET)
                .base_url(ORIGIN)
                .trusted_origin(ORIGIN),
        )
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(CaptchaPlugin::new(CaptchaConfig {
            provider: CaptchaProvider::VercelBotId(BotIdConfig {
                check_bot_id: check.clone(),
                validate_request: Some(finish.clone()),
            }),
            endpoints: vec!["/sign-in/email".into()],
        }))
        .build()
        .await?,
    );
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let before = body(
        &call(
            &auth,
            request("/list-sessions", None, &cookies(&owner)),
            200,
        )
        .await,
    );
    let running = auth.clone();
    let pending = tokio::spawn(async move {
        Box::pin(running.handle_request(request(
            "/sign-in/email",
            Some(json!({"email":"owner@example.test","password":PASSWORD})),
            "",
        )))
        .await
    });
    check.entered.notified().await;
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(11)).await;
    let denied = pending.await??;
    tokio::time::resume();
    assert_eq!(denied.status, 500);
    assert_eq!(body(&denied)["code"], "UNKNOWN_ERROR");
    assert!(denied.headers.get_all("set-cookie").next().is_none());
    assert_eq!(finish.count.load(Ordering::SeqCst), 0);
    assert_eq!(
        body(
            &call(
                &auth,
                request("/list-sessions", None, &cookies(&owner)),
                200
            )
            .await
        ),
        before
    );
    check.release.notify_one();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        finish.completed.notified(),
    )
    .await?;
    assert_eq!(finish.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        body(
            &call(
                &auth,
                request("/list-sessions", None, &cookies(&owner)),
                200
            )
            .await
        ),
        before
    );
    authenticated(&auth, &cookies(&owner), "owner@example.test").await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    Ok(())
}

async fn captcha_physical_method_admission<B: Backend>(db: Db) -> TestResult {
    struct Observer {
        label: &'static str,
        events: Arc<Mutex<Vec<&'static str>>>,
    }
    #[async_trait::async_trait]
    impl<S: AuthSchema> alibi::AuthPlugin<S> for Observer {
        async fn on_request(
            &self,
            _: &AuthRequest,
            _: &alibi::AuthContext<S>,
        ) -> AuthResult<Option<AuthResponse>> {
            Ok(None)
        }
        fn name(&self) -> &'static str {
            self.label
        }
        fn routes(&self) -> Vec<alibi::AuthRoute> {
            Vec::new()
        }
        async fn on_http_request(
            &self,
            r: &AuthRequest,
            _: &alibi::AuthContext<S>,
        ) -> AuthResult<Option<AuthResponse>> {
            if r.path == "/api/auth/sign-in/email" {
                self.events.lock().unwrap().push(self.label);
            }
            Ok(None)
        }
    }
    let provider = Provider::start("application/json", r#"{"success":true}"#).await;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let setup = super::auth_probe::fast_builder::<B>(&connection)
        .build()
        .await?;
    let owner = signup(&setup, "method-captcha-owner@example.test").await;
    let foreign = signup(&setup, "method-captcha-foreign@example.test").await;
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut options = TurnstileConfig::new("actual-captcha-secret");
    options.http.site_verify_url = Some(provider.url.clone());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(Observer {
            label: "early",
            events: events.clone(),
        })
        .plugin(CaptchaPlugin::new(CaptchaConfig::new(
            CaptchaProvider::CloudflareTurnstile(options),
        )))
        .plugin(Observer {
            label: "late",
            events: events.clone(),
        })
        .build()
        .await?;
    for method in [HttpMethod::Get, HttpMethod::Options, HttpMethod::Put] {
        events.lock().unwrap().clear();
        let mut input = request("/sign-in/email", None, "");
        input.method = method;
        _ = input
            .headers
            .insert("origin".into(), "https://foreign.fixture.test".into());
        _ = input
            .headers
            .insert("access-control-request-method".into(), "POST".into());
        let rejected = call(&auth, input, 400).await;
        assert_eq!(
            body(&rejected),
            json!({"message":"Missing CAPTCHA response","code":"MISSING_RESPONSE"})
        );
        assert_eq!(*events.lock().unwrap(), ["early"]);
        assert!(provider.take().is_empty());
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
    }
    authenticated(&auth, &cookies(&owner), "method-captcha-owner@example.test").await;
    authenticated(
        &auth,
        &cookies(&foreign),
        "method-captcha-foreign@example.test",
    )
    .await;
    B::close(connection).await
}
