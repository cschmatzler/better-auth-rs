//! Invitation admission, team quotas, remember-me acceptance, anonymous access
//! and storage failures on SQLite.
use super::*;
use crate::snapshot::Trace;
use alibi::AuthResult;
use alibi::plugins::organization::extensions::TeamLimitContext;
use alibi::plugins::organization::{
    MembershipLimit, OrganizationInvitationCreatePatch, OrganizationInvitationCreationContext,
    OrganizationInvitationDelivery, OrganizationInvitationEmailSender, OrganizationInvitationHooks,
    OrganizationLimitResolver, OrganizationTeamHooks, TeamsConfig,
};
use alibi::plugins::{OrganizationConfig, OrganizationPlugin};
use std::collections::BTreeMap;

backend_tests!(
    organization_invitation_policy,
    organization_anonymous_and_failures,
    organization_invitation_stamps,
    processed_invitation_cancellation_keeps_members_and_original_callback_status,
    organization_invitation_raw_quota,
    organization_invitation_raw_expiry
);

#[derive(Debug, Default)]
struct Limits(Mutex<Option<f64>>);

#[async_trait::async_trait]
impl OrganizationLimitResolver for Limits {
    async fn maximum_team_members(&self, context: &TeamLimitContext) -> AuthResult<Option<f64>> {
        assert!(!context.organization_id.is_empty());
        Ok(*self.0.lock().unwrap())
    }
}

#[derive(Debug)]
struct PlainHooks;

#[async_trait::async_trait]
impl OrganizationTeamHooks for PlainHooks {}

#[derive(Debug, Default)]
struct Sender(Mutex<Vec<String>>);

#[async_trait::async_trait]
impl OrganizationInvitationEmailSender for Sender {
    async fn send_invitation_email(
        &self,
        delivery: &OrganizationInvitationDelivery,
        _: &alibi::CallbackContext,
    ) -> AuthResult<()> {
        self.0.lock().unwrap().push(delivery.invitation.id.clone());
        Ok(())
    }
}

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

async fn add_member<B: Backend>(auth: &Alibi<B::Schema>, organization_id: &str, user_id: &str) {
    _ = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::add_member_endpoint(
                &serde_json::from_value(
                    json!({"userId": user_id, "role": "member", "organizationId": organization_id}),
                )
                .unwrap(),
            )
            .unwrap(),
            alibi::endpoint::EndpointOptions::default(),
        ),
    )
    .await
    .unwrap();
}

async fn organization_invitation_policy<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let limits = Arc::new(Limits::default());
    let sender = Arc::new(Sender::default());
    let auth = builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            membership_limit: Some(MembershipLimit::Fixed(3.0)),
            invitation_limit: None,
            send_invitation_email: Some(sender.clone()),
            teams: TeamsConfig {
                enabled: true,
                create_default_team: false,
                limit_resolver: Some(limits.clone()),
                hooks: Some(Arc::new(PlainHooks)),
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let owner = signup(&auth, "invite-owner@example.com").await;
    let member = signup(&auth, "invite-member@example.com").await;
    let member_id = body(&member)["user"]["id"].as_str().unwrap().to_owned();
    trace.mask(&member_id);
    let mut accounts = Vec::new();
    for name in ["one", "two", "three"] {
        let email = format!("invitee-{name}@example.com");
        _ = signup(&auth, &email).await;
        let signed_in = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email": email, "password": PASSWORD, "rememberMe": false})),
                "",
            ),
            200,
        )
        .await;
        assert!(cookies(&signed_in).contains("dont_remember"));
        accounts.push((
            email,
            cookies(&signed_in),
            body(&signed_in)["user"]["id"].clone(),
        ));
    }
    let owner = cookies(&owner);
    let created = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name": "Invites", "slug": "invites"})),
            &owner,
        ),
        200,
    )
    .await;
    let organization_id = body(&created)["id"].as_str().unwrap().to_owned();
    trace.mask(&organization_id);
    let owner = merge(&owner, &cookies(&created));
    add_member::<B>(&auth, &organization_id, &member_id).await;
    let team = |name: &'static str| {
        let (auth, owner) = (&auth, owner.clone());
        async move {
            body(
                &call(
                    auth,
                    request(
                        "/organization/create-team",
                        Some(json!({"name": name})),
                        &owner,
                    ),
                    200,
                )
                .await,
            )["id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    let first_team = team("First").await;
    let second_team = team("Second").await;
    trace.mask(&first_team);
    trace.mask(&second_team);
    let invite = |email: &str, extra: Value, cookie: &str| {
        let mut input =
            json!({"email": email, "role": "member", "organizationId": organization_id});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        request("/organization/invite-member", Some(input), cookie)
    };
    let post = async |trace: &mut Trace, label: &str, request: AuthRequest| {
        let response = Box::pin(auth.handle_request(request)).await.unwrap();
        trace.response(label, &response);
        response
    };

    _ = post(
        &mut trace,
        "invite without permission",
        invite("invitee-one@example.com", json!({}), &cookies(&member)),
    )
    .await;
    let invited = post(
        &mut trace,
        "invite with team",
        invite(
            "invitee-one@example.com",
            json!({"teamId": first_team}),
            &owner,
        ),
    )
    .await;
    let first_invitation = body(&invited)["id"].as_str().unwrap().to_owned();
    trace.mask(&first_invitation);
    _ = post(
        &mut trace,
        "invite again",
        invite(
            "invitee-one@example.com",
            json!({"teamId": first_team}),
            &owner,
        ),
    )
    .await;
    let resent = post(
        &mut trace,
        "resend",
        invite("invitee-one@example.com", json!({"resend": true}), &owner),
    )
    .await;
    assert_eq!(body(&resent)["id"], first_invitation);
    assert_eq!(sender.0.lock().unwrap().len(), 2);
    *limits.0.lock().unwrap() = Some(0.0);
    _ = post(
        &mut trace,
        "team quota on invitation",
        invite(
            "invitee-two@example.com",
            json!({"teamId": first_team}),
            &owner,
        ),
    )
    .await;
    *limits.0.lock().unwrap() = None;

    let accepted_two = post(
        &mut trace,
        "invite for a team that will vanish",
        invite(
            "invitee-two@example.com",
            json!({"teamId": second_team}),
            &owner,
        ),
    )
    .await;
    let second_invitation = body(&accepted_two)["id"].as_str().unwrap().to_owned();
    trace.mask(&second_invitation);
    let accept = |id: &str, cookie: &str| {
        request(
            "/organization/accept-invitation",
            Some(json!({"invitationId": id})),
            cookie,
        )
    };
    _ = db
        .execute("DELETE FROM team WHERE id = $1", &[&second_team])
        .await?;
    _ = post(
        &mut trace,
        "accept with a missing team",
        accept(&second_invitation, &accounts[1].1),
    )
    .await;
    assert_eq!(
        db.text(
            "SELECT status FROM invitation WHERE id = $1",
            &[&second_invitation]
        )
        .await?
        .as_deref(),
        Some("pending")
    );
    _ = post(
        &mut trace,
        "accept as someone else",
        accept(&first_invitation, &accounts[1].1),
    )
    .await;
    *limits.0.lock().unwrap() = Some(5.0);
    let accepted = post(
        &mut trace,
        "accept with team and remember-me",
        accept(&first_invitation, &accounts[0].1),
    )
    .await;
    assert!(cookies(&accepted).contains("dont_remember"));
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM team_member WHERE team_id = $1",
            &[&first_team]
        )
        .await?,
        1
    );
    let third = post(
        &mut trace,
        "invite beyond the membership limit",
        invite("invitee-three@example.com", json!({}), &owner),
    )
    .await;
    _ = post(
        &mut trace,
        "accept at the membership limit",
        accept(body(&third)["id"].as_str().unwrap(), &accounts[2].1),
    )
    .await;

    trace.assert("organization/invitation-policy");
    B::close(connection).await
}

async fn organization_anonymous_and_failures<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            cancel_pending_invitations_on_reinvite: true,
            teams: TeamsConfig {
                enabled: true,
                create_default_team: false,
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let owner = signup(&auth, "failure-owner@example.com").await;
    let owner_cookie = cookies(&owner);
    let created = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name": "Failures", "slug": "failures"})),
            &owner_cookie,
        ),
        200,
    )
    .await;
    let organization_id = body(&created)["id"].as_str().unwrap().to_owned();
    trace.mask(&organization_id);
    let owner = merge(&owner_cookie, &cookies(&created));
    let invitee = signup(&auth, "failure-invitee@example.com").await;
    let invitee_cookie = cookies(&invitee);
    let team = call(
        &auth,
        request(
            "/organization/create-team",
            Some(json!({"name": "Core"})),
            &owner,
        ),
        200,
    )
    .await;
    let team_id = body(&team)["id"].as_str().unwrap().to_owned();
    trace.mask(&team_id);

    for (path, input) in [
        (
            "/organization/create",
            Some(json!({"name": "A", "slug": "a"})),
        ),
        ("/organization/update", Some(json!({"data": {"name": "A"}}))),
        (
            "/organization/delete",
            Some(json!({"organizationId": organization_id})),
        ),
        (
            "/organization/set-active",
            Some(json!({"organizationId": organization_id})),
        ),
        ("/organization/get-organization", None),
        ("/organization/get-invitation", None),
        ("/organization/list-user-invitations", None),
        (
            "/organization/accept-invitation",
            Some(json!({"invitationId": "x"})),
        ),
        ("/organization/check-slug", Some(json!({"slug": "x"}))),
    ] {
        trace.response(
            &format!("anonymous {path}"),
            &Box::pin(auth.handle_request(request(path, input, ""))).await?,
        );
    }
    let mut email_query = request("/organization/list-user-invitations", None, &invitee_cookie);
    email_query.set_query_pairs([("email", "failure-invitee@example.com")]);
    trace.response(
        "list user invitations with email",
        &Box::pin(auth.handle_request(email_query)).await?,
    );
    for (label, query) in [
        ("no selector", vec![]),
        ("missing slug", vec![("organizationSlug", "missing")]),
        ("slug", vec![("organizationSlug", "failures")]),
        ("outsider slug", vec![("organizationSlug", "failures")]),
        (
            "outsider id",
            vec![("organizationId", organization_id.as_str())],
        ),
    ] {
        let cookie = if label.starts_with("outsider") || label == "no selector" {
            &invitee_cookie
        } else {
            &owner_cookie
        };
        let mut get = request("/organization/get-organization", None, cookie);
        get.set_query_pairs(query.iter().copied());
        trace.response(
            &format!("get-organization {label}"),
            &Box::pin(auth.handle_request(get)).await?,
        );
    }

    let invite = |cookie: &str, team: Option<&str>| {
        let mut input = json!({
            "email": "failure-invitee@example.com",
            "role": "member",
            "organizationId": organization_id,
        });
        if let Some(team) = team {
            input["teamId"] = json!(team);
        }
        request("/organization/invite-member", Some(input), cookie)
    };
    let trigger = async |name: &str, event: &str, table: &str| {
        _ = db
            .execute(
                &format!("CREATE TRIGGER {name} BEFORE {event} ON {table} BEGIN SELECT RAISE(ABORT, 'forced'); END"),
                &[],
            )
            .await
            .unwrap();
    };
    let untrigger = async |name: &str| {
        _ = db
            .execute(&format!("DROP TRIGGER {name}"), &[])
            .await
            .unwrap();
    };

    trigger("fail_invitation_insert", "INSERT", "invitation").await;
    trace.response(
        "invite storage failure",
        &Box::pin(auth.handle_request(invite(&owner, None))).await?,
    );
    untrigger("fail_invitation_insert").await;
    let first = body(&call(&auth, invite(&owner, None), 200).await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    trace.mask(&first);
    trigger("fail_invitation_update", "UPDATE", "invitation").await;
    for path in ["reject-invitation", "cancel-invitation"] {
        let cookie = if path.starts_with("reject") {
            &invitee_cookie
        } else {
            &owner
        };
        trace.response(
            &format!("{path} storage failure"),
            &Box::pin(auth.handle_request(request(
                &format!("/organization/{path}"),
                Some(json!({"invitationId": first})),
                cookie,
            )))
            .await?,
        );
    }
    trace.response(
        "accept storage failure",
        &Box::pin(auth.handle_request(request(
            "/organization/accept-invitation",
            Some(json!({"invitationId": first})),
            &invitee_cookie,
        )))
        .await?,
    );
    untrigger("fail_invitation_update").await;

    trigger("fail_organization_update", "UPDATE", "organization").await;
    trace.response(
        "update storage failure",
        &Box::pin(auth.handle_request(request(
            "/organization/update",
            Some(json!({"data": {"name": "Renamed"}, "organizationId": organization_id})),
            &owner,
        )))
        .await?,
    );
    untrigger("fail_organization_update").await;

    let remembered = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email": "failure-invitee@example.com", "password": PASSWORD, "rememberMe": false})),
            "",
        ),
        200,
    )
    .await;
    let remembered_cookie = cookies(&remembered);
    let with_team = body(&call(&auth, invite(&owner, Some(&team_id)), 200).await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    trace.mask(&with_team);
    trigger("fail_member_insert", "INSERT", "member").await;
    let failed = Box::pin(auth.handle_request(request(
        "/organization/accept-invitation",
        Some(json!({"invitationId": with_team})),
        &remembered_cookie,
    )))
    .await?;
    trace.response("accept membership failure with cookies", &failed);
    assert!(failed.headers.get_all("set-cookie").next().is_none());
    untrigger("fail_member_insert").await;
    assert_eq!(
        db.text("SELECT status FROM invitation WHERE id = $1", &[&with_team])
            .await?
            .as_deref(),
        Some("pending")
    );
    trace.assert("organization/anonymous-and-failures");
    B::close(connection).await
}

#[derive(Debug)]
struct Stamp;

#[async_trait::async_trait]
impl OrganizationInvitationHooks for Stamp {
    async fn before_create_invitation(
        &self,
        _: &OrganizationInvitationCreationContext,
    ) -> AuthResult<Option<OrganizationInvitationCreatePatch>> {
        Ok(Some(OrganizationInvitationCreatePatch {
            id: Some("stamped-invitation".into()),
            status: Some(alibi::InvitationStatus::Pending),
            created_at: Some(chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap()),
            ..Default::default()
        }))
    }
}

struct Refuse;

impl alibi::BackgroundTaskHandler for Refuse {
    fn handle(&self, completion: alibi::BackgroundTaskCompletion) -> AuthResult<()> {
        drop(completion);
        Err(alibi::AuthError::internal("background tasks are closed"))
    }
}

async fn organization_invitation_stamps<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let sender = Arc::new(Sender::default());
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .background_tasks(Arc::new(Refuse));
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(alibi::plugins::EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            invitation_hooks: Some(Arc::new(Stamp)),
            send_invitation_email: Some(sender.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut owner = signup(&auth, "stamp-owner@example.com").await;
    let cookie = cookies(&owner);
    owner = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name": "Stamps", "slug": "stamps"})),
            &cookie,
        ),
        200,
    )
    .await;
    let cookie = merge(&cookie, &cookies(&owner));
    let invited = call(
        &auth,
        request(
            "/organization/invite-member",
            Some(json!({"email": "stamped@example.com", "role": "member"})),
            &cookie,
        ),
        200,
    )
    .await;
    assert_eq!(body(&invited)["id"], "stamped-invitation");
    assert!(
        db.text("SELECT created_at FROM invitation", &[])
            .await?
            .is_some()
    );
    B::close(connection).await
}

async fn processed_invitation_cancellation_keeps_members_and_original_callback_status<
    B: Backend,
>(
    parent: Db,
) -> TestResult {
    use alibi::plugins::organization::OrganizationInvitationContext;
    #[derive(Debug, Default)]
    struct Hooks(Mutex<Vec<Value>>);
    #[async_trait::async_trait]
    impl OrganizationInvitationHooks for Hooks {
        async fn before_cancel_invitation(
            &self,
            c: &OrganizationInvitationContext,
        ) -> AuthResult<()> {
            self.0
                .lock()
                .unwrap()
                .push(json!({"phase":"before","status":c.invitation.status,"actor":c.user.id}));
            Ok(())
        }
        async fn after_cancel_invitation(
            &self,
            c: &OrganizationInvitationContext,
        ) -> AuthResult<()> {
            self.0
                .lock()
                .unwrap()
                .push(json!({"phase":"after","status":c.invitation.status,"actor":c.user.id}));
            Ok(())
        }
    }
    for accepted in [true, false] {
        let db = parent.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let hooks = Arc::new(Hooks::default());
        let sender = Arc::new(Sender::default());
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                invitation_hooks: Some(hooks.clone()),
                send_invitation_email: Some(sender),
                require_email_verification_on_invitation: Some(false),
                ..Default::default()
            }))
            .build()
            .await?;
        let owner = signup(&auth, "owner@example.test").await;
        let target = signup(&auth, "target@example.test").await;
        let foreign = signup(&auth, "foreign@example.test").await;
        let org = body(
            &call(
                &auth,
                request(
                    "/organization/create",
                    Some(json!({"name":"Owned","slug":"owned"})),
                    &cookies(&owner),
                ),
                200,
            )
            .await,
        );
        let invited=body(&call(&auth,request("/organization/invite-member",Some(json!({"organizationId":org["id"],"email":"target@example.test","role":"member"})),&cookies(&owner)),200).await);
        let id = invited["id"].as_str().unwrap();
        let path = if accepted {
            "/organization/accept-invitation"
        } else {
            "/organization/reject-invitation"
        };
        _ = call(
            &auth,
            request(path, Some(json!({"invitationId":id})), &cookies(&target)),
            200,
        )
        .await;
        let before = db
            .tables(&["users", "accounts", "sessions", "organization", "member"])
            .await?;
        let canceled = body(
            &call(
                &auth,
                request(
                    "/organization/cancel-invitation",
                    Some(json!({"invitationId":id})),
                    &cookies(&owner),
                ),
                200,
            )
            .await,
        );
        assert_eq!(canceled["id"], id);
        assert_eq!(canceled["status"], "canceled");
        assert_eq!(
            db.text("SELECT status FROM invitation WHERE id=$1", &[id])
                .await?
                .as_deref(),
            Some("canceled")
        );
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "organization", "member"])
                .await?,
            before
        );
        let actor = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
        assert_eq!(
            *hooks.0.lock().unwrap(),
            vec![
                json!({"phase":"before","status":if accepted{"accepted"}else{"rejected"},"actor":actor}),
                json!({"phase":"after","status":"canceled","actor":actor})
            ]
        );
        assert_eq!(db.count("member").await?, if accepted { 2 } else { 1 });
        authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn organization_invitation_raw_quota<B: Backend>(db: Db) -> TestResult {
    use alibi::plugins::organization::{
        InvitationLimit, OrganizationInvitationLimitContext, OrganizationInvitationLimitResolver,
    };
    #[derive(Debug)]
    struct Policy(f64, Mutex<Vec<Value>>);
    #[async_trait::async_trait]
    impl OrganizationInvitationLimitResolver for Policy {
        async fn invitation_limit(
            &self,
            c: &OrganizationInvitationLimitContext,
            callback: &alibi::CallbackContext,
        ) -> AuthResult<f64> {
            let request = callback.request.as_ref().expect("physical invite request");
            assert_eq!(request.path(), "/api/auth/organization/invite-member");
            assert_eq!(c.user.id, c.member.user_id);
            assert_eq!(c.member_user.id, c.user.id);
            assert_eq!(c.member.organization_id, c.organization.id);
            self.1
                .lock()
                .unwrap()
                .push(json!({"user":c.user.id,"organization":c.organization.id}));
            Ok(self.0)
        }
    }
    for limit in [
        Some(0.0),
        Some(-0.5),
        Some(1.5),
        Some(f64::NAN),
        Some(f64::INFINITY),
        None,
    ] {
        for resolved in [false, true] {
            if resolved && limit.is_none() {
                continue;
            }
            let db = db.fresh().await?;
            let policy = Arc::new(Policy(limit.unwrap_or(100.0), Mutex::new(Vec::new())));
            let organization = OrganizationConfig {
                invitation_limit: limit.map(|n| {
                    if resolved {
                        InvitationLimit::Resolver(policy.clone())
                    } else {
                        InvitationLimit::Fixed(n)
                    }
                }),
                ..Default::default()
            };

            let (connection, _) = db.migrated::<B>(SECRET).await?;
            let config = AuthConfig::new(SECRET).base_url(ORIGIN);
            let auth = AuthBuilder::new(config.clone())
                .store(B::store(Arc::new(config), &connection))
                .plugin(super::auth_probe::fast_password())
                .plugin(SessionManagementPlugin::new())
                .plugin(OrganizationPlugin::with_config(organization))
                .build()
                .await?;
            let owner = signup(&auth, "invitation-life-owner@example.test").await;
            let foreign = signup(&auth, "invitation-life-foreign@example.test").await;
            let target = signup(&auth, "invitation-life-target@example.test").await;
            let created = call(
                &auth,
                request(
                    "/organization/create",
                    Some(json!({"name":"Life","slug":"invitation-life"})),
                    &cookies(&owner),
                ),
                200,
            )
            .await;
            let org = body(&created)["id"].as_str().unwrap().to_owned();
            let jar = merge(&cookies(&owner), &cookies(&created));

            if limit.is_none() {
                for index in 0..100 {
                    drop(
                        auth.store()
                            .create_invitation(alibi::CreateInvitation::new(
                                &org,
                                format!("quota-seed-{index}@example.test"),
                                "member",
                                body(&owner)["user"]["id"].as_str().unwrap(),
                                chrono::Utc::now() + chrono::Duration::days(1),
                            ))
                            .await?,
                    );
                }
            }
            let before = db
                .tables(&[
                    "users",
                    "accounts",
                    "sessions",
                    "member",
                    "organization",
                    "team",
                    "team_member",
                ])
                .await?;
            let (expected, allowed) = match limit {
                None => (100, 0),
                Some(n) if n <= 0.0 => (0, 0),
                Some(1.5) => (2, 2),
                _ => (3, 3),
            };
            for index in 0..3 {
                let response=call(&auth,request("/organization/invite-member",Some(json!({"organizationId":org,"email":format!("quota-{index}@example.test"),"role":"member"})),&jar),if index<allowed {200} else {403}).await;
                if index >= allowed {
                    assert_eq!(body(&response)["code"], "INVITATION_LIMIT_REACHED");
                }
                assert!(cookies(&response).is_empty());
            }
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM invitation WHERE organization_id=$1",
                    &[&org]
                )
                .await?,
                expected
            );
            assert_eq!(policy.1.lock().unwrap().len(), if resolved { 3 } else { 0 });
            assert_eq!(
                db.tables(&[
                    "users",
                    "accounts",
                    "sessions",
                    "member",
                    "organization",
                    "team",
                    "team_member"
                ])
                .await?,
                before
            );
            authenticated(
                &auth,
                &cookies(&foreign),
                "invitation-life-foreign@example.test",
            )
            .await;
            authenticated(
                &auth,
                &cookies(&target),
                "invitation-life-target@example.test",
            )
            .await;
            B::close(connection).await?;
        }
    }
    Ok(())
}

async fn organization_invitation_raw_expiry<B: Backend>(db: Db) -> TestResult {
    for (seconds, span) in [
        (0.0, 172800000_i64),
        (-0.5, -500),
        (0.125, 125),
        (f64::NAN, 172800000),
    ] {
        let db = db.fresh().await?;
        let organization = OrganizationConfig {
            invitation_expires_in: Some(seconds),
            ..Default::default()
        };

        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(OrganizationPlugin::with_config(organization))
            .build()
            .await?;
        let owner = signup(&auth, "invitation-life-owner@example.test").await;
        let foreign = signup(&auth, "invitation-life-foreign@example.test").await;
        let target = signup(&auth, "invitation-life-target@example.test").await;
        let created = call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"Life","slug":"invitation-life"})),
                &cookies(&owner),
            ),
            200,
        )
        .await;
        let org = body(&created)["id"].as_str().unwrap().to_owned();
        let jar = merge(&cookies(&owner), &cookies(&created));

        let before = db
            .tables(&[
                "users",
                "accounts",
                "sessions",
                "member",
                "team",
                "team_member",
            ])
            .await?;
        let start = chrono::Utc::now().timestamp_millis();
        let response=call(&auth,request("/organization/invite-member",Some(json!({"organizationId":org,"email":"invitation-life-target@example.test","role":"member"})),&jar),200).await;
        let end = chrono::Utc::now().timestamp_millis();
        let returned = body(&response);
        let expiry = chrono::DateTime::parse_from_rfc3339(returned["expiresAt"].as_str().unwrap())?
            .timestamp_millis();
        assert!((start + span..=end + span).contains(&expiry));
        let physical = auth
            .store()
            .get_invitation_by_id(returned["id"].as_str().unwrap())
            .await?
            .unwrap();
        assert_eq!(physical.expires_at.timestamp_millis(), expiry);
        if seconds < 0.0 {
            let rejected = call(
                &auth,
                request(
                    "/organization/accept-invitation",
                    Some(json!({"invitationId":physical.id})),
                    &cookies(&target),
                ),
                400,
            )
            .await;
            assert_eq!(body(&rejected)["code"], "INVITATION_NOT_FOUND");
            assert_eq!(
                auth.store()
                    .get_invitation_by_id(&physical.id)
                    .await?
                    .unwrap(),
                physical
            );
        }
        assert_eq!(
            db.tables(&[
                "users",
                "accounts",
                "sessions",
                "member",
                "team",
                "team_member"
            ])
            .await?,
            before
        );
        authenticated(
            &auth,
            &cookies(&foreign),
            "invitation-life-foreign@example.test",
        )
        .await;
        B::close(connection).await?;
    }
    Ok(())
}
