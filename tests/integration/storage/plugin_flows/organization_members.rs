//! Member authority, dynamic roles, server-side admission and selection
//! cookies of the organization plugin.
use super::*;
use crate::snapshot::Trace;
use alibi::AuthResult;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::organization::{
    DynamicAccessControlConfig, MembershipLimit, OrganizationCreationHooks,
    OrganizationLimitResolver, OrganizationMemberAdditionHooks, OrganizationMemberCreatePatch,
    OrganizationMembershipLimitResolver, TeamsConfig, default_organization_statements,
};
use alibi::plugins::{OrganizationConfig, OrganizationPlugin};
use alibi::wire::UserView;
use std::collections::BTreeMap;

backend_tests!(
    organization_member_authority,
    organization_dynamic_roles,
    organization_server_admission,
    organization_plugin_helpers,
    organization_trusted_addition_preserves_literal_role_arrays_and_session_scope,
    fractional_organization_membership_limit_uses_actual_physical_count,
    organization_membership_resolver_keeps_target_snapshots_and_raw_falsy_results,
    organization_creation_raw_quota,
    organization_creation_policy_principal,
    organization_creation_policy_error,
    organization_raw_team_count_quota,
    organization_raw_team_seat_endpoint_policy
);

fn merge(first: &str, second: &str) -> String {
    let mut jar = BTreeMap::new();
    for pair in first.split("; ").chain(second.split("; ")) {
        if let Some((name, value)) = pair.split_once('=') {
            _ = jar.insert(name.to_owned(), value.to_owned());
        }
    }
    jar.into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn raw(path: &str, text: &str, cookie: &str) -> AuthRequest {
    let mut request = request(path, None, cookie);
    request.method = HttpMethod::Post;
    request.body = Some(text.as_bytes().to_vec());
    request
}

fn get(path: &str, query: &[(&str, &str)], cookie: &str) -> AuthRequest {
    let mut request = request(path, None, cookie);
    request.set_query_pairs(query.iter().copied());
    request
}

struct Account {
    id: String,
    cookie: String,
}

async fn account<S: AuthSchema>(auth: &Alibi<S>, email: &str) -> Account {
    let response = signup(auth, email).await;
    Account {
        id: body(&response)["user"]["id"].as_str().unwrap().to_owned(),
        cookie: cookies(&response),
    }
}

async fn organization<S: AuthSchema>(auth: &Alibi<S>, owner: &mut Account, slug: &str) -> String {
    let created = call(
        auth,
        request(
            "/organization/create",
            Some(json!({"name": slug, "slug": slug})),
            &owner.cookie,
        ),
        200,
    )
    .await;
    owner.cookie = merge(&owner.cookie, &cookies(&created));
    body(&created)["id"].as_str().unwrap().to_owned()
}

async fn add<S: AuthSchema>(
    auth: &Alibi<S>,
    organization_id: &str,
    user_id: &str,
    role: &str,
) -> Value {
    let response = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::add_member_endpoint(
                &serde_json::from_value(
                    json!({"userId": user_id, "role": role, "organizationId": organization_id}),
                )
                .unwrap(),
            )
            .unwrap(),
            EndpointOptions::default(),
        ),
    )
    .await
    .unwrap();
    serde_json::to_value(response.decode().unwrap()).unwrap()
}

async fn organization_member_authority<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            teams: TeamsConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let mut owner = account(&auth, "authority-owner@example.com").await;
    let mut other_owner = account(&auth, "authority-other@example.com").await;
    let member = account(&auth, "authority-member@example.com").await;
    let outsider = account(&auth, "authority-outsider@example.com").await;
    for id in [&owner.id, &other_owner.id, &member.id, &outsider.id] {
        trace.mask(id);
    }
    let organization_id = organization(&auth, &mut owner, "authority").await;
    let other_id = organization(&auth, &mut other_owner, "authority-other").await;
    trace.mask(&organization_id);
    trace.mask(&other_id);
    let added = add(&auth, &organization_id, &member.id, "member").await;
    trace.mask(added["id"].as_str().unwrap());
    let foreign = add(&auth, &other_id, &outsider.id, "member").await;
    let foreign_member = foreign["id"].as_str().unwrap().to_owned();
    trace.mask(&foreign_member);
    let owner_member = db
        .text(
            "SELECT id FROM member WHERE user_id = $1 AND organization_id = $2",
            &[&owner.id, &organization_id],
        )
        .await?
        .unwrap();
    trace.mask(&owner_member);

    let membership = member.cookie.clone();
    for (label, query, cookie) in [
        (
            "role of a member",
            vec![
                ("organizationId", organization_id.as_str()),
                ("userId", member.id.as_str()),
            ],
            &owner.cookie,
        ),
        (
            "role of a stranger",
            vec![
                ("organizationId", organization_id.as_str()),
                ("userId", outsider.id.as_str()),
            ],
            &owner.cookie,
        ),
        (
            "own role by slug",
            vec![("organizationSlug", "authority")],
            &owner.cookie,
        ),
        (
            "role as outsider",
            vec![("organizationId", organization_id.as_str())],
            &outsider.cookie,
        ),
    ] {
        trace.response(
            &format!("get-active-member-role {label}"),
            &Box::pin(auth.handle_request(get(
                "/organization/get-active-member-role",
                &query,
                cookie,
            )))
            .await?,
        );
    }

    for (label, path, input, cookie) in [
        (
            "remove a member of another organization",
            "/organization/remove-member",
            json!({"organizationId": organization_id, "memberIdOrEmail": foreign_member}),
            owner.cookie.clone(),
        ),
        (
            "demote the only owner",
            "/organization/update-member-role",
            json!({"organizationId": organization_id, "memberId": owner_member, "role": "admin"}),
            owner.cookie.clone(),
        ),
        (
            "owner leaves as the only owner",
            "/organization/leave",
            json!({"organizationId": organization_id}),
            owner.cookie.clone(),
        ),
        (
            "anonymous role update",
            "/organization/update-member-role",
            json!({"memberId": "x", "role": "admin"}),
            String::new(),
        ),
        (
            "anonymous removal",
            "/organization/remove-member",
            json!({"memberIdOrEmail": "x"}),
            String::new(),
        ),
    ] {
        trace.response(
            label,
            &Box::pin(auth.handle_request(request(path, Some(input), &cookie))).await?,
        );
    }
    for (path, text) in [
        ("/organization/remove-member", "[]"),
        ("/organization/remove-member", r#"{"memberIdOrEmail":5}"#),
        ("/organization/update-member-role", "[]"),
        (
            "/organization/update-member-role",
            r#"{"memberId":"x","role":5}"#,
        ),
        (
            "/organization/update-member-role",
            r#"{"memberId":"x","role":[1]}"#,
        ),
        ("/organization/update", "[]"),
        ("/organization/delete", "[]"),
        ("/organization/set-active", "[]"),
        ("/organization/set-active", r#"{"organizationId":5}"#),
    ] {
        trace.response(
            &format!("{path} {text}"),
            &Box::pin(auth.handle_request(raw(path, text, &owner.cookie))).await?,
        );
    }
    trace.response(
        "delete an organization of someone else",
        &Box::pin(auth.handle_request(request(
            "/organization/delete",
            Some(json!({"organizationId": other_id})),
            &owner.cookie,
        )))
        .await?,
    );

    let selected = call(
        &auth,
        request(
            "/organization/set-active",
            Some(json!({"organizationId": organization_id})),
            &membership,
        ),
        200,
    )
    .await;
    trace.response("member selects an organization", &selected);
    let joined = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email": "authority-member@example.com", "password": PASSWORD, "rememberMe": false})),
            "",
        ),
        200,
    )
    .await;
    let remembered = cookies(&joined);
    let selected = call(
        &auth,
        request(
            "/organization/set-active",
            Some(json!({"organizationId": organization_id})),
            &remembered,
        ),
        200,
    )
    .await;
    assert!(cookies(&selected).contains("dont_remember"));
    trace.response("select with remember-me", &selected);
    trace.response(
        "keep the active selection",
        &Box::pin(auth.handle_request(raw("/organization/set-active", "{}", &remembered))).await?,
    );
    let fresh = account(&auth, "authority-fresh@example.com").await;
    trace.response(
        "empty selection without an active organization",
        &Box::pin(auth.handle_request(raw("/organization/set-active", "{}", &fresh.cookie)))
            .await?,
    );

    let left = call(
        &auth,
        request(
            "/organization/leave",
            Some(json!({"organizationId": organization_id})),
            &remembered,
        ),
        200,
    )
    .await;
    trace.response("member leaves the active organization", &left);
    assert_eq!(
        db.text(
            "SELECT active_organization_id FROM sessions WHERE token = $1",
            &[body(&joined)["token"].as_str().unwrap()]
        )
        .await?,
        None
    );

    let admin = account(&auth, "authority-admin@example.com").await;
    let admin_member = add(&auth, &organization_id, &admin.id, "admin").await;
    let admin_member = admin_member["id"].as_str().unwrap().to_owned();
    trace.mask(&admin_member);
    _ = db
        .execute(
            "CREATE TRIGGER fail_member_delete BEFORE DELETE ON member BEGIN SELECT RAISE(ABORT, 'forced'); END",
            &[],
        )
        .await?;
    trace.response(
        "remove with storage failure",
        &Box::pin(auth.handle_request(request(
            "/organization/remove-member",
            Some(json!({"organizationId": organization_id, "memberIdOrEmail": admin_member})),
            &owner.cookie,
        )))
        .await?,
    );
    _ = db.execute("DROP TRIGGER fail_member_delete", &[]).await?;
    trace.assert("organization/member-authority");
    B::close(connection).await
}

async fn organization_dynamic_roles<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            access_control: Some(default_organization_statements()),
            dynamic_access_control: DynamicAccessControlConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let mut owner = account(&auth, "roles-owner@example.com").await;
    let organization_id = organization(&auth, &mut owner, "roles").await;
    trace.mask(&organization_id);
    let created = call(
        &auth,
        request(
            "/organization/create-role",
            Some(json!({
                "organizationId": organization_id,
                "role": "editor",
                "permission": {"team": ["create"]},
            })),
            &owner.cookie,
        ),
        200,
    )
    .await;
    let role_id = body(&created)["roleData"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    trace.mask(&role_id);
    for (label, stored, name) in [
        ("rename", None, "Renamed"),
        ("rename an empty permission", Some(""), "Again"),
        ("rename a false permission", Some("false"), "Third"),
        ("rename a zero permission", Some("0"), "Fourth"),
    ] {
        if let Some(stored) = stored {
            _ = db
                .execute("UPDATE organization_role SET permission = $1", &[stored])
                .await?;
        }
        trace.response(
            label,
            &Box::pin(auth.handle_request(request(
                "/organization/update-role",
                Some(json!({
                    "organizationId": organization_id,
                    "roleId": role_id,
                    "data": {"roleName": name},
                })),
                &owner.cookie,
            )))
            .await?,
        );
    }
    trace.value(
        "stored role",
        json!(db.text("SELECT role FROM organization_role", &[]).await?),
    );
    B::close(connection).await?;

    let fresh = db.fresh().await?;
    let (connection, _) = fresh.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            dynamic_access_control: DynamicAccessControlConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    let mut owner = account(&auth, "no-ac-owner@example.com").await;
    let organization_id = organization(&auth, &mut owner, "no-ac").await;
    trace.mask(&organization_id);
    for (path, input) in [
        (
            "/organization/create-role",
            json!({"organizationId": organization_id, "role": "x", "permission": {}}),
        ),
        (
            "/organization/update-role",
            json!({"organizationId": organization_id, "roleId": "x", "data": {}}),
        ),
    ] {
        trace.response(
            &format!("without an access control instance {path}"),
            &Box::pin(auth.handle_request(request(path, Some(input), &owner.cookie))).await?,
        );
    }
    trace.assert("organization/dynamic-roles");
    B::close(connection).await
}

#[derive(Debug)]
struct Admission;

#[async_trait::async_trait]
impl OrganizationMemberAdditionHooks for Admission {
    async fn before_add_member(
        &self,
        context: &alibi::plugins::organization::OrganizationMemberAdditionContext,
    ) -> AuthResult<Option<OrganizationMemberCreatePatch>> {
        Ok(Some(OrganizationMemberCreatePatch {
            organization_id: Some(context.member.organization_id.clone()),
            user_id: Some(context.member.user_id.clone()),
            role: Some("admin".into()),
        }))
    }
}

#[derive(Debug)]
struct Capacity(f64);

#[async_trait::async_trait]
impl OrganizationMembershipLimitResolver for Capacity {
    async fn maximum_members(
        &self,
        _: &UserView,
        organization: &alibi::plugins::organization::types::OrganizationResponse,
    ) -> AuthResult<f64> {
        assert!(!organization.id.is_empty());
        Ok(self.0)
    }
}

#[derive(Debug)]
struct Seats;

#[async_trait::async_trait]
impl OrganizationLimitResolver for Seats {
    async fn maximum_team_members(
        &self,
        context: &alibi::plugins::organization::extensions::TeamLimitContext,
    ) -> AuthResult<Option<f64>> {
        assert!(context.session.is_some());
        Ok(Some(3.0))
    }
}

#[derive(Debug)]
struct Quiet;

#[async_trait::async_trait]
impl OrganizationCreationHooks for Quiet {}

async fn organization_server_admission<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            membership_limit: Some(MembershipLimit::Resolver(Arc::new(Capacity(10.0)))),
            member_addition_hooks: Some(Arc::new(Admission)),
            creation_hooks: Some(Arc::new(Quiet)),
            teams: TeamsConfig {
                enabled: true,
                create_default_team: false,
                limit_resolver: Some(Arc::new(Seats)),
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let mut owner = account(&auth, "admission-owner@example.com").await;
    let joiner = account(&auth, "admission-joiner@example.com").await;
    let organization_id = organization(&auth, &mut owner, "admission").await;
    trace.mask(&joiner.id);
    trace.mask(&organization_id);
    let team = call(
        &auth,
        request(
            "/organization/create-team",
            Some(json!({"name": "Seats"})),
            &owner.cookie,
        ),
        200,
    )
    .await;
    let team_id = body(&team)["id"].as_str().unwrap().to_owned();
    trace.mask(&team_id);

    let session_options = EndpointOptions {
        headers: Some([("cookie".into(), owner.cookie.clone())].into()),
        ..Default::default()
    };
    let admitted = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::add_member_endpoint(&serde_json::from_value(
            json!({"userId": joiner.id, "role": "member", "teamId": team_id}),
        )?)?,
        session_options,
    ))
    .await;
    trace.value(
        "admit with the active organization and a team",
        match admitted {
            Ok(response) => json!({"role": serde_json::to_value(response.decode()?)?["role"]}),
            Err(error) => json!({"error": error.to_string()}),
        },
    );
    let missing = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::add_member_endpoint(&serde_json::from_value(
            json!({"userId": joiner.id, "role": "member"}),
        )?)?,
        EndpointOptions::default(),
    ))
    .await;
    trace.value(
        "admit without an organization",
        json!({"error": missing.err().map(|error| error.to_string())}),
    );

    let user = body(&signup(&auth, "admission-trusted@example.com").await)["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    trace.mask(&user);
    let invalid = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::create_endpoint(
            &serde_json::from_value(json!({"name": "", "slug": "", "metadata": 5}))?,
            Some(&user),
        )?,
        EndpointOptions::default(),
    ))
    .await;
    trace.value(
        "trusted creation with invalid input",
        json!({"error": invalid.err().map(|error| error.to_string())}),
    );
    let deleted = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::delete_endpoint(&serde_json::from_value(
            json!({"organizationId": ""}),
        )?)?,
        EndpointOptions {
            headers: Some([("cookie".into(), owner.cookie.clone())].into()),
            ..Default::default()
        },
    ))
    .await;
    trace.value(
        "deletion without an organization",
        json!({"error": deleted.err().map(|error| error.to_string())}),
    );
    trace.assert("organization/server-admission");
    B::close(connection).await
}

async fn organization_plugin_helpers<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = OrganizationConfig {
        creator_role: String::new(),
        disable_organization_deletion: true,
        ..Default::default()
    };
    let auth = builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(config.clone()))
        .build()
        .await?;
    let plugin = OrganizationPlugin::with_config(config);
    let mut trace = Trace::default();
    let mut owner = account(&auth, "helper-owner@example.com").await;
    let created = organization(&auth, &mut owner, "helpers").await;
    trace.mask(&owner.id);
    trace.mask(&created);
    let creator = db.text("SELECT role FROM member", &[]).await?;
    trace.value("creator role", json!(creator));

    for (label, input) in [
        ("invalid", json!({"name": "", "slug": "", "metadata": 5})),
        ("empty name only", json!({"name": "", "slug": "valid"})),
        ("valid", json!({"name": "Trusted", "slug": "trusted"})),
    ] {
        let result = plugin
            .create_organization_for_user(
                auth.context(),
                &owner.id,
                &serde_json::from_value(input)?,
            )
            .await;
        trace.value(
            &format!("trusted creation {label}"),
            match result {
                Ok(response) => {
                    json!({"role": response.members.first().map(|member| member.role.clone())})
                }
                Err(error) => json!({"error": error.to_string()}),
            },
        );
    }
    let headers = std::collections::HashMap::from([("cookie".to_owned(), owner.cookie.clone())]);
    let deleted = plugin
        .delete_organization_with_headers(
            auth.context(),
            &headers,
            &serde_json::from_value(json!({"organizationId": created}))?,
        )
        .await;
    trace.value(
        "deletion with headers",
        json!({"error": deleted.err().map(|error| error.to_string())}),
    );
    let removed = plugin
        .remove_member_with_headers(
            auth.context(),
            &headers,
            &serde_json::from_value(
                json!({"memberIdOrEmail": "missing@example.com", "organizationId": created}),
            )?,
        )
        .await;
    trace.value(
        "removal with headers",
        json!({"error": removed.err().map(|error| error.to_string())}),
    );
    trace.assert("organization/plugin-helpers");
    B::close(connection).await
}

async fn organization_trusted_addition_preserves_literal_role_arrays_and_session_scope<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    use alibi::plugins::organization::{
        OrganizationMemberAddedContext, OrganizationMemberAdditionContext,
    };
    #[derive(Debug, Default)]
    struct Hooks(Mutex<Vec<(String, String)>>);
    #[async_trait::async_trait]
    impl OrganizationMemberAdditionHooks for Hooks {
        async fn before_add_member(
            &self,
            c: &OrganizationMemberAdditionContext,
        ) -> AuthResult<Option<OrganizationMemberCreatePatch>> {
            self.0
                .lock()
                .unwrap()
                .push((c.member.role.clone(), c.user.id.clone()));
            Ok(None)
        }
        async fn after_add_member(&self, c: &OrganizationMemberAddedContext) -> AuthResult<()> {
            self.0
                .lock()
                .unwrap()
                .push((c.member.role.clone(), c.user.id.clone()));
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let hooks = Arc::new(Hooks::default());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            member_addition_hooks: Some(hooks.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut owner = account(&auth, "owner@example.test").await;
    let target = account(&auth, "target@example.test").await;
    let org = organization(&auth, &mut owner, "literal-roles").await;
    let before = db
        .tables(&["users", "accounts", "sessions", "organization"])
        .await?;
    let result = serde_json::to_value(auth.dispatch_endpoint(OrganizationPlugin::add_member_endpoint(&serde_json::from_value(json!({"userId":target.id,"organizationId":org,"role":[" member ","member","admin"]}))?)?,EndpointOptions::default()).await?.decode()?)?;
    assert_eq!(result["role"], " member ,member,admin");
    assert_eq!(result["userId"], target.id);
    assert_eq!(
        *hooks.0.lock().unwrap(),
        vec![
            (" member ,member,admin".into(), target.id.clone()),
            (" member ,member,admin".into(), target.id.clone())
        ]
    );
    assert_eq!(
        db.text(
            "SELECT role FROM member WHERE id=$1",
            &[result["id"].as_str().unwrap()]
        )
        .await?
        .as_deref(),
        Some(" member ,member,admin")
    );
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "organization"])
            .await?,
        before
    );
    authenticated(&auth, &target.cookie, "target@example.test").await;
    B::close(connection).await
}

async fn fractional_organization_membership_limit_uses_actual_physical_count<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            membership_limit: Some(MembershipLimit::Fixed(1.5)),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut owner = account(&auth, "owner@example.test").await;
    let first = account(&auth, "first@example.test").await;
    let second = account(&auth, "second@example.test").await;
    let org = organization(&auth, &mut owner, "fractional").await;
    let admitted = add(&auth, &org, &first.id, "member").await;
    assert_eq!(admitted["userId"], first.id);
    assert_eq!(db.count("member").await?, 2);
    let before = db
        .tables(&["users", "accounts", "sessions", "organization", "member"])
        .await?;
    let endpoint = OrganizationPlugin::add_member_endpoint(&serde_json::from_value(
        json!({"userId":second.id,"organizationId":org,"role":"member"}),
    )?)?;
    let denied = auth
        .dispatch_endpoint(endpoint, EndpointOptions::default())
        .await
        .unwrap_err();
    assert_eq!(denied.error.status_code(), 403);
    assert!(matches!(
        denied.error,
        alibi::AuthError::Upstream {
            code: "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
            ..
        }
    ));
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "organization", "member"])
            .await?,
        before
    );
    authenticated(&auth, &first.cookie, "first@example.test").await;
    authenticated(&auth, &second.cookie, "second@example.test").await;
    B::close(connection).await
}

async fn organization_membership_resolver_keeps_target_snapshots_and_raw_falsy_results<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    use alibi::plugins::organization::types::OrganizationResponse;
    #[derive(Debug, Default)]
    struct Policy {
        mode: Mutex<usize>,
        seen: Mutex<Vec<(UserView, OrganizationResponse)>>,
    }
    #[async_trait::async_trait]
    impl OrganizationMembershipLimitResolver for Policy {
        async fn maximum_members(
            &self,
            user: &UserView,
            org: &OrganizationResponse,
        ) -> AuthResult<f64> {
            self.seen.lock().unwrap().push((user.clone(), org.clone()));
            match *self.mode.lock().unwrap() {
                0 => Ok(0.0),
                1 => Err(alibi::AuthError::Api {
                    status: 400,
                    code: Some("MEMBERSHIP_POLICY_REJECTED".into()),
                    message: "membership rejected".into(),
                }),
                _ => Ok(f64::NAN),
            }
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(Policy::default());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            membership_limit: Some(MembershipLimit::Resolver(policy.clone())),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut owner = account(&auth, "owner@example.test").await;
    let target = account(&auth, "target@example.test").await;
    let org = organization(&auth, &mut owner, "resolved").await;
    _ = call(
        &auth,
        request(
            "/organization/update",
            Some(json!({"organizationId":org,"data":{"metadata":{"policy":"raw"}}})),
            &owner.cookie,
        ),
        200,
    )
    .await;
    let raw = db
        .text(
            "SELECT CAST(metadata AS TEXT) FROM organization WHERE id=$1",
            &[&org],
        )
        .await?
        .unwrap();
    let before = db
        .tables(&["users", "accounts", "sessions", "organization", "member"])
        .await?;
    for mode in 0..3 {
        *policy.mode.lock().unwrap() = mode;
        let endpoint = OrganizationPlugin::add_member_endpoint(&serde_json::from_value(
            json!({"userId":target.id,"organizationId":org,"role":"member"}),
        )?)?;
        let result = auth
            .dispatch_endpoint(endpoint, EndpointOptions::default())
            .await;
        if mode < 2 {
            let error = result.unwrap_err().error;
            assert_eq!(error.status_code(), if mode == 0 { 403 } else { 400 });
            if mode == 0 {
                assert!(matches!(
                    error,
                    alibi::AuthError::Upstream {
                        code: "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
                        ..
                    }
                ));
            } else {
                assert!(
                    matches!(error,alibi::AuthError::Api{code:Some(ref code),..}if code=="MEMBERSHIP_POLICY_REJECTED")
                );
            }
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "organization", "member"])
                    .await?,
                before
            );
        } else {
            assert_eq!(result?.decode()?.user_id, target.id);
        }
        let seen = policy.seen.lock().unwrap().last().unwrap().clone();
        assert_eq!(seen.0.id, target.id);
        assert_eq!(seen.0.email.as_deref(), Some("target@example.test"));
        assert_eq!(seen.1.metadata, Some(json!(raw)));
        assert_eq!(policy.seen.lock().unwrap().len(), mode + 1);
    }
    let count = policy.seen.lock().unwrap().len();
    let endpoint = OrganizationPlugin::add_member_endpoint(&serde_json::from_value(
        json!({"userId":target.id,"organizationId":org,"role":"member"}),
    )?)?;
    assert!(
        auth.dispatch_endpoint(endpoint, EndpointOptions::default())
            .await
            .is_err()
    );
    assert_eq!(policy.seen.lock().unwrap().len(), count);
    assert_eq!(db.count("member").await?, 2);
    B::close(connection).await
}

async fn organization_creation_raw_quota<B: Backend>(db: Db) -> TestResult {
    for (limit, allowed) in [
        (1.5, false),
        (-0.5, false),
        (f64::NAN, true),
        (f64::INFINITY, true),
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let setup = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(OrganizationPlugin::new())
            .build()
            .await?;
        let mut owner = account(&setup, "creation-quota-owner@example.test").await;
        let mut foreign = account(&setup, "creation-quota-foreign@example.test").await;
        let own = organization(&setup, &mut owner, "quota-own").await;
        let other = organization(&setup, &mut foreign, "quota-other").await;
        _ = add(&setup, &other, &owner.id, "member").await;
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                organization_limit: Some(limit),
                ..Default::default()
            }))
            .build()
            .await?;
        let before = db
            .tables(&["users", "accounts", "sessions", "organization", "member"])
            .await?;
        let response=call(&auth,request("/organization/create",Some(json!({"name":"Quota request","slug":if allowed {"quota-new"} else {"quota-own"},"userId":foreign.id})),&owner.cookie),if allowed {200} else {403}).await;
        if allowed {
            assert_eq!(body(&response)["members"][0]["userId"], owner.id);
        } else {
            assert_eq!(
                body(&response)["code"],
                "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS"
            );
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "organization", "member"])
                    .await?,
                before
            );
        }
        let before_trusted = db
            .tables(&["users", "accounts", "sessions", "organization", "member"])
            .await?;
        let sessions = db.table("sessions").await?;
        let result = Box::pin(auth.dispatch_endpoint(
            OrganizationPlugin::create_endpoint(
                &serde_json::from_value(
                    json!({"name":"Trusted quota","slug":"quota-trusted","userId":owner.id}),
                )?,
                Some(&owner.id),
            )?,
            EndpointOptions::default(),
        ))
        .await;
        if allowed {
            let created = serde_json::to_value(result?.decode()?)?;
            assert_eq!(created["members"][0]["userId"], owner.id);
            assert_eq!(db.count("organization").await?, 4);
            assert_eq!(db.table("sessions").await?, sessions);
        } else {
            assert_eq!(result.unwrap_err().error.status_code(), 403);
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "organization", "member"])
                    .await?,
                before_trusted
            );
        }
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM member WHERE organization_id=$1 AND user_id=$2",
                &[&own, &owner.id]
            )
            .await?,
            1
        );
        authenticated(
            &auth,
            &foreign.cookie,
            "creation-quota-foreign@example.test",
        )
        .await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn organization_creation_policy_principal<B: Backend>(db: Db) -> TestResult {
    use alibi::plugins::organization::OrganizationCreationPolicy;
    #[derive(Debug)]
    struct Policy {
        reached: std::sync::atomic::AtomicBool,
        events: Mutex<Vec<(&'static str, String)>>,
    }
    #[async_trait::async_trait]
    impl OrganizationCreationPolicy for Policy {
        async fn allow_creation(&self, user: &UserView) -> AuthResult<Option<bool>> {
            self.events.lock().unwrap().push(("allow", user.id.clone()));
            Ok(Some(user.name.as_deref() == Some("Paid")))
        }
        async fn limit_reached(&self, user: &UserView) -> AuthResult<Option<bool>> {
            self.events.lock().unwrap().push(("limit", user.id.clone()));
            Ok(Some(self.reached.load(std::sync::atomic::Ordering::SeqCst)))
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(Policy {
        reached: std::sync::atomic::AtomicBool::new(false),
        events: Mutex::new(Vec::new()),
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            creation_policy: Some(policy.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let free = account(&auth, "creation-free@example.test").await;
    let paid = account(&auth, "creation-paid@example.test").await;
    _ = db
        .execute("UPDATE users SET name='Paid' WHERE id=$1", &[&paid.id])
        .await?;
    let before = db
        .tables(&["users", "accounts", "sessions", "organization", "member"])
        .await?;
    assert_eq!(
        body(
            &call(
                &auth,
                request(
                    "/organization/create",
                    Some(json!({"name":"Free denied","slug":"free-denied","userId":paid.id})),
                    &free.cookie
                ),
                403
            )
            .await
        )["code"],
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION"
    );
    assert_eq!(*policy.events.lock().unwrap(), [("allow", free.id.clone())]);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "organization", "member"])
            .await?,
        before
    );
    policy.events.lock().unwrap().clear();
    let accepted = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Paid allowed","slug":"paid-allowed","userId":free.id})),
            &paid.cookie,
        ),
        200,
    )
    .await;
    assert_eq!(body(&accepted)["members"][0]["userId"], paid.id);
    assert_eq!(
        *policy.events.lock().unwrap(),
        [("allow", paid.id.clone()), ("limit", paid.id.clone())]
    );
    policy.events.lock().unwrap().clear();
    policy
        .reached
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let before = db
        .tables(&["users", "accounts", "sessions", "organization", "member"])
        .await?;
    _ = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Paid capped","slug":"paid-capped"})),
            &paid.cookie,
        ),
        403,
    )
    .await;
    assert_eq!(
        *policy.events.lock().unwrap(),
        [("allow", paid.id.clone()), ("limit", paid.id.clone())]
    );
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "organization", "member"])
            .await?,
        before
    );
    policy
        .reached
        .store(false, std::sync::atomic::Ordering::SeqCst);
    policy.events.lock().unwrap().clear();
    let sessions = db.table("sessions").await?;
    let input = serde_json::from_value(
        json!({"name":"Trusted free","slug":"trusted-free","userId":free.id}),
    )?;
    let created = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::create_endpoint(&input, Some(&free.id))?,
        EndpointOptions::default(),
    ))
    .await?
    .decode()?;
    assert_eq!(
        serde_json::to_value(created)?["members"][0]["userId"],
        free.id
    );
    assert_eq!(
        *policy.events.lock().unwrap(),
        [("allow", free.id.clone()), ("limit", free.id.clone())]
    );
    assert_eq!(db.table("sessions").await?, sessions);
    policy
        .reached
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let before = db
        .tables(&["users", "accounts", "sessions", "organization", "member"])
        .await?;
    let rejected = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::create_endpoint(
            &serde_json::from_value(
                json!({"name":"Trusted capped","slug":"trusted-capped","userId":free.id}),
            )?,
            Some(&free.id),
        )?,
        EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(rejected.error.status_code(), 403);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "organization", "member"])
            .await?,
        before
    );
    B::close(connection).await
}

async fn organization_creation_policy_error<B: Backend>(db: Db) -> TestResult {
    use alibi::plugins::organization::OrganizationCreationPolicy;
    #[derive(Debug)]
    struct Policy {
        failure: &'static str,
        events: Mutex<Vec<&'static str>>,
    }
    impl Policy {
        fn phase(&self, phase: &'static str) -> AuthResult<()> {
            self.events.lock().unwrap().push(phase);
            if self.failure == phase {
                Err(alibi::AuthError::Api {
                    status: 403,
                    code: Some(format!("CREATION_{}_REJECTED", phase.to_uppercase())),
                    message: "Application creation policy rejected".into(),
                })
            } else {
                Ok(())
            }
        }
    }
    #[async_trait::async_trait]
    impl OrganizationCreationPolicy for Policy {
        async fn allow_creation(&self, _: &UserView) -> AuthResult<Option<bool>> {
            self.phase("allow")?;
            Ok(Some(true))
        }
        async fn limit_reached(&self, _: &UserView) -> AuthResult<Option<bool>> {
            self.phase("limit")?;
            Ok(Some(false))
        }
    }
    for failure in ["allow", "limit"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let policy = Arc::new(Policy {
            failure,
            events: Mutex::new(Vec::new()),
        });
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                creation_policy: Some(policy.clone()),
                ..Default::default()
            }))
            .build()
            .await?;
        let owner = account(&auth, "creation-error-owner@example.test").await;
        let foreign = account(&auth, "creation-error-foreign@example.test").await;
        let before = db
            .tables(&["users", "accounts", "sessions", "organization", "member"])
            .await?;
        let code = format!("CREATION_{}_REJECTED", failure.to_uppercase());
        let expected = if failure == "allow" {
            vec!["allow"]
        } else {
            vec!["allow", "limit"]
        };
        let denied = call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"Policy rejected","slug":"policy-rejected"})),
                &owner.cookie,
            ),
            403,
        )
        .await;
        assert_eq!(
            body(&denied),
            json!({"code":code,"message":"Application creation policy rejected"})
        );
        assert_eq!(*policy.events.lock().unwrap(), expected);
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "organization", "member"])
                .await?,
            before
        );
        policy.events.lock().unwrap().clear();
        let result = Box::pin(auth.dispatch_endpoint(
            OrganizationPlugin::create_endpoint(
                &serde_json::from_value(
                    json!({"name":"Trusted rejected","slug":"trusted-rejected","userId":owner.id}),
                )?,
                Some(&owner.id),
            )?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert!(
            matches!(result.error,alibi::AuthError::Api {status:403,code:Some(ref actual),ref message} if actual==&code && message=="Application creation policy rejected")
        );
        assert_eq!(*policy.events.lock().unwrap(), expected);
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "organization", "member"])
                .await?,
            before
        );
        authenticated(
            &auth,
            &foreign.cookie,
            "creation-error-foreign@example.test",
        )
        .await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn organization_raw_team_count_quota<B: Backend>(db: Db) -> TestResult {
    use alibi::plugins::organization::OrganizationTeamHooks;
    use alibi::plugins::organization::extensions::TeamHookContext;
    use alibi::plugins::organization::extensions::TeamLimitContext;
    #[derive(Debug)]
    struct Policy {
        maximum: Option<f64>,
        events: Mutex<Vec<&'static str>>,
    }
    #[async_trait::async_trait]
    impl OrganizationLimitResolver for Policy {
        async fn maximum_teams(&self, c: &TeamLimitContext) -> AuthResult<Option<f64>> {
            assert_eq!(
                c.session.as_ref().unwrap().user_id,
                c.user.as_ref().unwrap().id
            );
            assert!(
                c.request
                    .as_ref()
                    .unwrap()
                    .path
                    .ends_with("/organization/create-team")
            );
            self.events.lock().unwrap().push("quota");
            Ok(self.maximum)
        }
    }
    #[async_trait::async_trait]
    impl OrganizationTeamHooks for Policy {
        async fn before_create(
            &self,
            _: &mut alibi::CreateTeam,
            c: &TeamHookContext,
        ) -> AuthResult<()> {
            assert!(c.user.is_some());
            self.events.lock().unwrap().push("before");
            Ok(())
        }
        async fn after_create(&self, _: &alibi::Team, _: &TeamHookContext) -> AuthResult<()> {
            self.events.lock().unwrap().push("after");
            Ok(())
        }
    }
    for resolved in [false, true] {
        for (maximum, allowed) in [
            (Some(0.0), 3),
            (Some(f64::NAN), 3),
            (Some(1.5), 2),
            (Some(-1.0), 0),
            (Some(f64::NEG_INFINITY), 0),
            (Some(f64::INFINITY), 3),
            (None, 3),
        ] {
            let db = db.fresh().await?;
            let (connection, _) = db.migrated::<B>(SECRET).await?;
            let policy = Arc::new(Policy {
                maximum,
                events: Mutex::new(Vec::new()),
            });
            let auth = super::auth_probe::fast_builder::<B>(&connection)
                .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                    teams: TeamsConfig {
                        enabled: true,
                        create_default_team: false,
                        maximum_teams: maximum,
                        limit_resolver: resolved
                            .then(|| policy.clone() as Arc<dyn OrganizationLimitResolver>),
                        hooks: Some(policy.clone()),
                        ..Default::default()
                    },
                    ..Default::default()
                }))
                .build()
                .await?;
            let mut owner = account(&auth, "raw-team-owner@example.test").await;
            let org = organization(&auth, &mut owner, "raw-team").await;
            let protected = db
                .tables(&["users", "accounts", "sessions", "organization", "member"])
                .await?;
            for index in 0..3 {
                policy.events.lock().unwrap().clear();
                let accepted = index < allowed;
                let response = call(
                    &auth,
                    request(
                        "/organization/create-team",
                        Some(json!({"name":format!("Team {index}"),"organizationId":org})),
                        &owner.cookie,
                    ),
                    if accepted { 200 } else { 400 },
                )
                .await;
                if accepted {
                    assert_eq!(body(&response)["organizationId"], org);
                } else {
                    assert_eq!(
                        body(&response)["code"],
                        "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS"
                    );
                }
                let mut expected = if resolved { vec!["quota"] } else { Vec::new() };
                if accepted {
                    expected.extend(["before", "after"]);
                }
                assert_eq!(*policy.events.lock().unwrap(), expected);
                assert_eq!(
                    db.tables(&["users", "accounts", "sessions", "organization", "member"])
                        .await?,
                    protected
                );
            }
            assert_eq!(db.count("team").await?, allowed);
            B::close(connection).await?;
        }
    }
    Ok(())
}

async fn organization_raw_team_seat_endpoint_policy<B: Backend>(db: Db) -> TestResult {
    use alibi::plugins::organization::OrganizationTeamHooks;
    use alibi::plugins::organization::extensions::TeamHookContext;
    use alibi::plugins::organization::extensions::TeamLimitContext;
    #[derive(Debug)]
    struct Policy {
        maximum: Option<f64>,
        events: Mutex<Vec<&'static str>>,
    }
    #[async_trait::async_trait]
    impl OrganizationLimitResolver for Policy {
        async fn maximum_team_members(&self, c: &TeamLimitContext) -> AuthResult<Option<f64>> {
            assert!(c.team_id.is_some());
            assert_eq!(
                c.session.as_ref().unwrap().user_id,
                c.user.as_ref().unwrap().id
            );
            self.events.lock().unwrap().push("quota");
            Ok(self.maximum)
        }
    }
    #[async_trait::async_trait]
    impl OrganizationTeamHooks for Policy {
        async fn before_add_member(
            &self,
            _: &alibi::Team,
            _: &UserView,
            c: &TeamHookContext,
        ) -> AuthResult<()> {
            assert!(c.user.is_some());
            self.events.lock().unwrap().push("before");
            Ok(())
        }
        async fn after_add_member(
            &self,
            _: &alibi::TeamMember,
            _: &alibi::Team,
            _: &UserView,
            _: &TeamHookContext,
        ) -> AuthResult<()> {
            self.events.lock().unwrap().push("after");
            Ok(())
        }
    }
    for resolved in [false, true] {
        for (maximum, allowed) in [
            (Some(0.0), 0),
            (Some(f64::NAN), 0),
            (Some(1.5), 2),
            (Some(-1.0), 0),
            (Some(f64::NEG_INFINITY), 0),
            (Some(f64::INFINITY), 3),
            (None, 3),
        ] {
            let db = db.fresh().await?;
            let (connection, _) = db.migrated::<B>(SECRET).await?;
            let policy = Arc::new(Policy {
                maximum,
                events: Mutex::new(Vec::new()),
            });
            let auth = super::auth_probe::fast_builder::<B>(&connection)
                .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                    teams: TeamsConfig {
                        enabled: true,
                        create_default_team: false,
                        maximum_members_per_team: maximum,
                        limit_resolver: resolved
                            .then(|| policy.clone() as Arc<dyn OrganizationLimitResolver>),
                        hooks: Some(policy.clone()),
                        ..Default::default()
                    },
                    ..Default::default()
                }))
                .build()
                .await?;
            let mut owner = account(&auth, "raw-seat-owner@example.test").await;
            let first = account(&auth, "raw-seat-first@example.test").await;
            let second = account(&auth, "raw-seat-second@example.test").await;
            let org = organization(&auth, &mut owner, "raw-seat").await;
            _ = add(&auth, &org, &first.id, "member").await;
            _ = add(&auth, &org, &second.id, "member").await;
            let team = body(
                &call(
                    &auth,
                    request(
                        "/organization/create-team",
                        Some(json!({"name":"Seat team","organizationId":org})),
                        &owner.cookie,
                    ),
                    200,
                )
                .await,
            )["id"]
                .as_str()
                .unwrap()
                .to_owned();
            let protected = db
                .tables(&["users", "accounts", "sessions", "organization", "member"])
                .await?;
            for (index, target) in [&owner.id, &first.id, &second.id, &owner.id]
                .into_iter()
                .enumerate()
            {
                policy.events.lock().unwrap().clear();
                let accepted = index < usize::try_from(allowed)? || (index == 3 && allowed > 0);
                let response = call(
                    &auth,
                    request(
                        "/organization/add-team-member",
                        Some(json!({"teamId":team,"userId":target,"organizationId":org})),
                        &owner.cookie,
                    ),
                    if accepted { 200 } else { 403 },
                )
                .await;
                if !accepted {
                    assert_eq!(body(&response)["code"], "TEAM_MEMBER_LIMIT_REACHED");
                }
                let mut expected = vec!["before"];
                if resolved {
                    expected.push("quota");
                }
                if accepted {
                    expected.push("after");
                }
                assert_eq!(*policy.events.lock().unwrap(), expected);
                assert_eq!(
                    db.tables(&["users", "accounts", "sessions", "organization", "member"])
                        .await?,
                    protected
                );
            }
            assert_eq!(db.count("team_member").await?, allowed);
            assert_eq!(
                db.text(
                    "SELECT CAST(member_count AS TEXT) FROM team WHERE id=$1",
                    &[&team]
                )
                .await?,
                Some(allowed.to_string())
            );
            B::close(connection).await?;
        }
    }
    Ok(())
}
