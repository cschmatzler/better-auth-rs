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
    organization_full_member_user_page_split
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

async fn organization_full_member_user_page_split<B: Backend>(db: Db) -> TestResult {
    use alibi::plugins::organization::types::OrganizationResponse;
    #[derive(Debug)]
    struct Policy(std::sync::atomic::AtomicUsize);
    #[async_trait::async_trait]
    impl OrganizationMembershipLimitResolver for Policy {
        async fn maximum_members(&self, _: &UserView, _: &OrganizationResponse) -> AuthResult<f64> {
            _ = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(alibi::AuthError::internal(
                "admission must not run during reads",
            ))
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let setup = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::new())
        .build()
        .await?;
    let mut owner = account(&setup, "page-split-owner@example.test").await;
    let target = account(&setup, "page-split-target@example.test").await;
    let foreign = account(&setup, "page-split-foreign@example.test").await;
    let org = organization(&setup, &mut owner, "split-pages").await;
    _ = add(&setup, &org, &target.id, "member").await;
    let before = db
        .tables(&["users", "accounts", "sessions", "organization", "member"])
        .await?;
    let policy = Arc::new(Policy(std::sync::atomic::AtomicUsize::new(0)));
    for (limit, page, list_count, full_count) in [
        (Some(MembershipLimit::Fixed(1.0)), 100, 1, None),
        (Some(MembershipLimit::Fixed(0.0)), 100, 2, Some(2)),
        (Some(MembershipLimit::Fixed(f64::NAN)), 100, 2, Some(2)),
        (
            Some(MembershipLimit::Resolver(policy.clone())),
            100,
            2,
            Some(2),
        ),
        (None, 1, 2, Some(1)),
        (None, 0, 2, Some(0)),
    ] {
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.advanced.database.default_find_many_limit = page;
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                membership_limit: limit,
                ..Default::default()
            }))
            .build()
            .await?;
        let listed = call(
            &auth,
            get(
                "/organization/list-members",
                &[("organizationId", &org)],
                &owner.cookie,
            ),
            200,
        )
        .await;
        assert_eq!(body(&listed)["total"], 2);
        assert_eq!(
            body(&listed)["members"].as_array().unwrap().len(),
            list_count
        );
        let full = call(
            &auth,
            get(
                "/organization/get-full-organization",
                &[("organizationId", &org)],
                &owner.cookie,
            ),
            if full_count.is_some() { 200 } else { 500 },
        )
        .await;
        if let Some(count) = full_count {
            assert_eq!(body(&full)["members"].as_array().unwrap().len(), count);
        } else {
            assert!(full.body.is_empty());
            let limited = call(
                &auth,
                get(
                    "/organization/get-full-organization",
                    &[("organizationId", &org), ("membersLimit", "1")],
                    &owner.cookie,
                ),
                200,
            )
            .await;
            assert_eq!(body(&limited)["members"].as_array().unwrap().len(), 1);
            let foreign_read = call(
                &auth,
                get(
                    "/organization/get-full-organization",
                    &[("organizationId", &org)],
                    &foreign.cookie,
                ),
                500,
            )
            .await;
            assert!(foreign_read.body.is_empty());
        }
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "organization", "member"])
                .await?,
            before
        );
    }
    assert_eq!(policy.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    B::close(connection).await
}
