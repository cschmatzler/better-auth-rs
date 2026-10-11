//! Explicit application background-task integration around the real store.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::api_key::{
    ApiKeyConfig, ApiKeyGenerationOptions, ApiKeyGenerator, RateLimitDefaults,
};
use alibi::plugins::{ApiKeyPlugin, EmailPasswordPlugin, SessionManagementPlugin};
use alibi::seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use alibi::{
    AuthBuilder, AuthConfig, AuthError, AuthResult, BackgroundTaskCompletion, BackgroundTaskHandler,
};
use axum::{
    Json, Router,
    extract::Query,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, watch};
#[path = "api_key_background_store.rs"]
mod controlled;
use controlled::ControlledStore;

#[derive(Default)]
struct Observations {
    events: Vec<Value>,
    serial: usize,
    generated: usize,
    hold: bool,
    observe_usage: bool,
    observer: String,
    generator: String,
    blocked: HashMap<usize, oneshot::Sender<()>>,
    last_admission: Option<Instant>,
    active: usize,
}
#[derive(Clone)]
pub(crate) struct Application {
    state: Arc<Mutex<Observations>>,
    changed: watch::Sender<u64>,
}
impl Application {
    fn event(&self, event: Value) {
        self.state.lock().unwrap().events.push(event);
        self.changed.send_modify(|value| *value += 1);
    }
    async fn begin(&self, profile: &'static str) -> usize {
        let (id, receiver) = {
            let mut state = self.state.lock().unwrap();
            state.serial += 1;
            state.active += 1;
            state.last_admission = Some(Instant::now());
            let id = state.serial;
            let receiver = if state.hold {
                let (sender, receiver) = oneshot::channel();
                state.blocked.insert(id, sender);
                Some(receiver)
            } else {
                None
            };
            (id, receiver)
        };
        self.event(json!({"kind":"cleanup-enter","profile":profile,"serial":id,"createdAt":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis,true)}));
        if let Some(receiver) = receiver {
            let _ = receiver.await;
        }
        id
    }
    async fn begin_delete(&self, profile: &'static str, key_id: &str) -> usize {
        let (id, receiver) = {
            let mut state = self.state.lock().unwrap();
            state.serial += 1;
            state.active += 1;
            let id = state.serial;
            let receiver = if state.hold {
                let (sender, receiver) = oneshot::channel();
                state.blocked.insert(id, sender);
                Some(receiver)
            } else {
                None
            };
            (id, receiver)
        };
        self.event(
            json!({"kind":"row-delete-enter","profile":profile,"serial":id,"key":{"id":key_id}}),
        );
        if let Some(receiver) = receiver {
            let _ = receiver.await;
        }
        id
    }
    fn finish_delete(&self, id: usize, success: bool) {
        self.event(json!({"kind":"row-delete-complete","serial":id,"success":success}));
        self.state.lock().unwrap().active -= 1;
        self.changed.send_modify(|value| *value += 1);
    }
    async fn begin_usage(&self, profile: &'static str, key_id: &str) -> Option<usize> {
        let (id, receiver) = {
            let mut state = self.state.lock().unwrap();
            if !state.observe_usage {
                return None;
            }
            state.serial += 1;
            state.active += 1;
            let id = state.serial;
            let receiver = if state.hold {
                let (sender, receiver) = oneshot::channel();
                state.blocked.insert(id, sender);
                Some(receiver)
            } else {
                None
            };
            (id, receiver)
        };
        self.event(json!({"kind":"usage-enter","profile":profile,"serial":id,"key":{"id":key_id}}));
        if let Some(receiver) = receiver {
            let _ = receiver.await;
        }
        Some(id)
    }
    fn finish_usage(&self, id: usize, success: bool) {
        self.event(json!({"kind":"usage-complete","serial":id,"success":success}));
        self.state.lock().unwrap().active -= 1;
        self.changed.send_modify(|value| *value += 1);
    }
    fn finish(&self, id: usize, success: bool) {
        self.event(json!({"kind":"cleanup-complete","serial":id,"success":success}));
        self.state.lock().unwrap().active -= 1;
        self.changed.send_modify(|value| *value += 1);
    }
    async fn wait(&self, kind: &str, count: usize) {
        let mut changed = self.changed.subscribe();
        loop {
            if self
                .state
                .lock()
                .unwrap()
                .events
                .iter()
                .filter(|event| event["kind"] == kind)
                .count()
                >= count
            {
                return;
            }
            if changed.changed().await.is_err() {
                return;
            }
        }
    }
    fn snapshot(&self) -> Value {
        json!(self.state.lock().unwrap().events)
    }
}
impl BackgroundTaskHandler for Application {
    fn handle(&self, completion: BackgroundTaskCompletion) -> AuthResult<()> {
        self.event(json!({"kind":"background-register"}));
        let observer = self.state.lock().unwrap().observer.clone();
        match observer.as_str() {
            "api" => Err(AuthError::Api {
                status: 403,
                code: Some("BACKGROUND_TASK_DENIED".into()),
                message: "Application background observer denied".into(),
            }),
            "throw" => Err(AuthError::internal(
                "application background observer rejected",
            )),
            "ignore" => {
                drop(completion);
                Ok(())
            }
            _ => {
                let application = self.clone();
                self.state.lock().unwrap().active += 1;
                tokio::spawn(async move {
                    let fulfilled = completion.await.is_ok();
                    application.event(json!({"kind":"background-complete","fulfilled":fulfilled}));
                    application.state.lock().unwrap().active -= 1;
                    application.changed.send_modify(|value| *value += 1);
                });
                Ok(())
            }
        }
    }
}
#[async_trait::async_trait]
impl ApiKeyGenerator for Application {
    async fn generate_key(&self, options: &ApiKeyGenerationOptions<'_>) -> AuthResult<String> {
        self.event(json!({"kind":"generator","length":options.length,"prefix":options.prefix}));
        if self.state.lock().unwrap().generator == "throw" {
            return Err(AuthError::internal("application generator rejected"));
        }
        let generated = {
            let mut state = self.state.lock().unwrap();
            state.generated += 1;
            state.generated
        };
        Ok(format!(
            "public-fixture-automatic-cleanup-credential-{generated:016}-stable-fixture-key"
        ))
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Control {
    action: String,
    #[serde(default)]
    hold: bool,
    #[serde(default)]
    observe_usage: bool,
    #[serde(default)]
    observer: String,
    #[serde(default)]
    generator: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    count: usize,
    key_id: Option<String>,
    remaining: Option<f64>,
    serial: Option<usize>,
    dates: Option<HashMap<String, String>>,
    phase: Option<String>,
}
#[derive(Deserialize)]
struct Verify {
    key: String,
    permissions: Option<Value>,
}
#[derive(Deserialize)]
struct Profile {
    profile: String,
}

pub(crate) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let (changed, _) = watch::channel(0);
    let application = Application {
        state: Arc::new(Mutex::new(Observations::default())),
        changed,
    };
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    for (name, defer_updates, rate_enabled) in [
        ("api-key-automatic", false, false),
        ("api-key-automatic-deferred", true, false),
        ("api-key-automatic-other", true, false),
        ("api-key-usage-rate", false, true),
        ("api-key-usage-rate-deferred", true, true),
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let config = base
            .clone()
            .base_path(&path)
            .background_tasks(Arc::new(application.clone()));
        let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
            enable_session_for_api_keys: true,
            defer_updates,
            custom_key_generator: Some(Arc::new(application.clone())),
            rate_limit: RateLimitDefaults {
                enabled: rate_enabled,
                ..Default::default()
            },
            ..Default::default()
        });
        let store = ControlledStore {
            inner: crate::backend::store::<TestSchema>(config.clone(), database.clone()),
            application: application.clone(),
            profile: name,
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config)
                .store(store)
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(plugin.clone())
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        profiles.insert(name.to_owned(), (auth, plugin));
    }
    let profiles = Arc::new(profiles);
    let state_db = database.clone();
    router=router.route("/__test/api-key-background/state",get(move |Query(query):Query<HashMap<String,String>>| {
        let database=state_db.clone();
        async move {
            let rows=database.query_all_raw(Statement::from_string(DbBackend::Sqlite,"SELECT id,name,reference_id,config_id,key,remaining,request_count,expires_at,created_at,updated_at,last_request,last_refill_at,refill_amount,refill_interval,rate_limit_enabled,rate_limit_time_window,rate_limit_max FROM api_keys ORDER BY name")).await.unwrap();
            let values:Vec<_>=rows.iter().map(|row|json!({"id":row.try_get::<String>("","id").unwrap(),"name":row.try_get::<Option<String>>("","name").unwrap(),"referenceId":row.try_get::<String>("","reference_id").unwrap(),"configId":row.try_get::<String>("","config_id").unwrap(),"key":row.try_get::<String>("","key").unwrap(),"remaining":row.try_get::<Option<f64>>("","remaining").unwrap(),"requestCount":row.try_get::<Option<f64>>("","request_count").unwrap(),"expiresAt":row.try_get::<Option<String>>("","expires_at").unwrap(),"createdAt":row.try_get::<String>("","created_at").unwrap(),"updatedAt":row.try_get::<String>("","updated_at").unwrap(),"lastRequest":row.try_get::<Option<String>>("","last_request").unwrap(),"lastRefillAt":row.try_get::<Option<String>>("","last_refill_at").unwrap()})).collect();
            let mut values=values;
            if query.get("usage").map(String::as_str)==Some("true") {
                for (value,row) in values.iter_mut().zip(&rows) {
                    value.as_object_mut().unwrap().extend(json!({"lastRefillAt":row.try_get::<Option<String>>("","last_refill_at").unwrap(),"refillAmount":row.try_get::<Option<f64>>("","refill_amount").unwrap(),"refillInterval":row.try_get::<Option<f64>>("","refill_interval").unwrap(),"rateLimitEnabled":row.try_get::<bool>("","rate_limit_enabled").unwrap(),"rateLimitTimeWindow":row.try_get::<Option<f64>>("","rate_limit_time_window").unwrap(),"rateLimitMax":row.try_get::<Option<f64>>("","rate_limit_max").unwrap()}).as_object().unwrap().clone());
                }
            }
            if query.get("rawDates").map(String::as_str)!=Some("true") {
                for value in &mut values {
                    for field in ["createdAt","updatedAt","expiresAt","lastRequest","lastRefillAt"] {
                        if let Some(serde_json::Value::String(date))=value.get_mut(field) {
                            *date=chrono::DateTime::parse_from_rfc3339(date).unwrap().with_timezone(&chrono::Utc).to_rfc3339_opts(chrono::SecondsFormat::Millis,true);
                        }
                    }
                }
            }
            Json(values)
        }
    }));
    let control_app = application.clone();
    router=router.route("/__test/api-key-background/control",post(move |Json(input):Json<Control>|{
        let application=control_app.clone();let database=database.clone();
        async move {
            match input.action.as_str() {
                "reset"=>{
                    let senders={let mut state=application.state.lock().unwrap();std::mem::take(&mut state.blocked)};
                    for (_,sender) in senders {let _=sender.send(());}
                    let mut changed=application.changed.subscribe();
                    loop {
                        if application.state.lock().unwrap().active==0 {break;}
                        if changed.changed().await.is_err() {break;}
                    }
                    *application.state.lock().unwrap()=Observations::default();
                },
                "configure"=>{let mut state=application.state.lock().unwrap();state.hold=input.hold;state.observer=input.observer;state.generator=input.generator;state.observe_usage=input.observe_usage;},
                "release"=>{
                    if let Some(serial)=input.serial {
                        if let Some(sender)=application.state.lock().unwrap().blocked.remove(&serial) {let _=sender.send(());}
                    } else {
                        let senders=std::mem::take(&mut application.state.lock().unwrap().blocked);
                        for (_,sender) in senders {let _=sender.send(());}
                    }
                },
                "wait"=>application.wait(&input.kind,input.count).await,
                "window"=>{
                    let anchor=application.state.lock().unwrap().last_admission.expect("actual cleanup receipt required");
                    tokio::time::sleep_until(tokio::time::Instant::from_std(anchor+Duration::from_millis(10020))).await;
                },
                "remaining"=>{database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"UPDATE api_keys SET remaining=11 WHERE id=?",[input.key_id.unwrap().into()])).await.unwrap();},
                "quota"=>{database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"UPDATE api_keys SET remaining=? WHERE id=?",[input.remaining.unwrap().into(),input.key_id.unwrap().into()])).await.unwrap();},
                "refill"=>{database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"UPDATE api_keys SET remaining=0,refill_amount=3,refill_interval=60000,last_refill_at=? WHERE id=?",[chrono::DateTime::<chrono::Utc>::UNIX_EPOCH.into(),input.key_id.unwrap().into()])).await.unwrap();},
                "phase-refill"=>{database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"UPDATE api_keys SET remaining=0,refill_amount=3,refill_interval=60000,last_refill_at=?,last_request=NULL,request_count=0,rate_limit_enabled=1,rate_limit_max=3,rate_limit_time_window=60000 WHERE id=?",[chrono::DateTime::<chrono::Utc>::UNIX_EPOCH.into(),input.key_id.unwrap().into()])).await.unwrap();},
                "usage-veto"=>{
                    let condition=match input.phase.as_deref(){Some("rate")=>"NEW.request_count<>OLD.request_count",Some("final")=>"NEW.remaining IS OLD.remaining AND NEW.request_count IS OLD.request_count AND NEW.last_request IS OLD.last_request AND NEW.last_refill_at IS OLD.last_refill_at",_=>panic!("actual phase required")};
                    database.execute_raw(Statement::from_string(DbBackend::Sqlite,format!("CREATE TRIGGER usage_phase_veto BEFORE UPDATE ON api_keys WHEN OLD.name='phase-target' AND ({condition}) BEGIN SELECT RAISE(ABORT,'actual phase storage veto'); END"))).await.unwrap();
                },
                "usage-restore"=>{database.execute_raw(Statement::from_string(DbBackend::Sqlite,"DROP TRIGGER IF EXISTS usage_phase_veto")).await.unwrap();database.execute_raw(Statement::from_string(DbBackend::Sqlite,"DROP TRIGGER IF EXISTS usage_current_read")).await.unwrap();},
                "usage-current-read"=>{database.execute_raw(Statement::from_string(DbBackend::Sqlite,"CREATE TRIGGER usage_current_read AFTER UPDATE ON api_keys WHEN OLD.name='phase-target' AND NEW.last_request IS NOT OLD.last_request AND NEW.updated_at IS OLD.updated_at BEGIN UPDATE api_keys SET remaining=77,name='current-row' WHERE id=NEW.id; END")).await.unwrap();},
                "timestamps"=>{
                    let key_id=input.key_id.unwrap();
                    assert!(database.query_one_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"SELECT id FROM api_keys WHERE id=?",[key_id.clone().into()])).await.unwrap().is_some(),"actual API key required");
                    let dates=input.dates.unwrap();
                    let mut values=Vec::new();
                    for field in ["createdAt","updatedAt","lastRequest","lastRefillAt","expiresAt"] {
                        let date=dates.get(field).unwrap();
                        let _=chrono::DateTime::parse_from_rfc3339(date).unwrap();
                        values.push(date.clone().into());
                    }
                    values.push(key_id.into());
                    database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"UPDATE api_keys SET created_at=?,updated_at=?,last_request=?,last_refill_at=?,expires_at=? WHERE id=?",values)).await.unwrap();
                },
                "expire"=>{database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"UPDATE api_keys SET expires_at=? WHERE id=?",["1970-01-01T00:00:00.000Z".into(),input.key_id.unwrap().into()])).await.unwrap();},
                "veto"=>{database.execute_raw(Statement::from_string(DbBackend::Sqlite,"CREATE TRIGGER automatic_cleanup_veto BEFORE DELETE ON api_keys BEGIN SELECT RAISE(ABORT,'actual cleanup storage veto'); END")).await.unwrap();},
                "restore"=>{database.execute_raw(Statement::from_string(DbBackend::Sqlite,"DROP TRIGGER IF EXISTS automatic_cleanup_veto")).await.unwrap();},
                _=>panic!("unknown application control"),
            }
            Json(application.snapshot())
        }
    }));
    let cleanup_profiles = profiles.clone();
    router = router.route(
        "/__test/api-key-background/cleanup",
        post(move |Query(query): Query<Profile>| {
            let profiles = cleanup_profiles.clone();
            async move {
                let (auth, plugin) = profiles.get(&query.profile).unwrap();
                Json(plugin.delete_all_expired_api_keys(auth.context()).await)
            }
        }),
    );
    Ok(router.route(
        "/__test/api-key-background/verify",
        post(
            move |Query(query): Query<Profile>, Json(input): Json<Verify>| {
                let profiles = profiles.clone();
                async move {
                    let (auth, _) = profiles.get(&query.profile).unwrap();
                    let endpoint = ApiKeyPlugin::verify_endpoint(
                        &alibi::plugins::api_key::ApiKeyVerificationInput {
                            key: input.key,
                            config_id: None,
                            permissions: input
                                .permissions
                                .map(serde_json::from_value)
                                .transpose()
                                .unwrap(),
                        },
                    )
                    .unwrap();
                    let response =
                        Box::pin(auth.dispatch_endpoint(
                            endpoint,
                            alibi::endpoint::EndpointOptions::default(),
                        ))
                        .await
                        .unwrap();
                    let result = response.decode().unwrap();
                    Json(json!({"valid":result.valid,"error":result.error,"key":result.key}))
                        .into_response()
                }
            },
        ),
    ))
}
