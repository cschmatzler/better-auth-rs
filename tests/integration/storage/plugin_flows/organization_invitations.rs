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
    organization_invitation_reset_write_failure
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

async fn organization_invitation_reset_write_failure<B: Backend>(db: Db) -> TestResult {
    use alibi::plugins::organization::{
        OrganizationInvitationAcceptanceContext, OrganizationInvitationAcceptanceHooks,
    };
    #[derive(Debug, Default)]
    struct Receipt(Mutex<usize>);
    #[async_trait::async_trait]
    impl OrganizationInvitationAcceptanceHooks for Receipt {
        async fn before_accept_invitation(
            &self,
            _: &OrganizationInvitationAcceptanceContext,
        ) -> AuthResult<()> {
            *self.0.lock().unwrap() += 1;
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let receipt = Arc::new(Receipt::default());
    let organization = OrganizationConfig {
        teams: TeamsConfig {
            enabled: true,
            create_default_team: false,
            ..Default::default()
        },
        ..Default::default()
    };

    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(OrganizationPlugin::with_config(organization))
        .build()
        .await?;
    let owner = signup(&auth, "staged-invitation-owner@example.test").await;
    let target = signup(&auth, "staged-invitation-target@example.test").await;
    let foreign = signup(&auth, "staged-invitation-foreign@example.test").await;
    let sibling = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"staged-invitation-target@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let created = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Stage","slug":"invitation-stage"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let org = body(&created)["id"].as_str().unwrap().to_owned();
    let jar = merge(&cookies(&owner), &cookies(&created));

    let created_team = call(
        &auth,
        request(
            "/organization/create-team",
            Some(json!({"organizationId":org,"name":"Invited team"})),
            &jar,
        ),
        200,
    )
    .await;
    let team = body(&created_team)["id"].as_str().unwrap().to_owned();
    let invited=call(&auth,request("/organization/invite-member",Some(json!({"organizationId":org,"email":"staged-invitation-target@example.test","role":"member","teamId":team})),&jar),200).await;
    let invitation = body(&invited)["id"].as_str().unwrap().to_owned();

    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            invitation_acceptance_hooks: Some(receipt.clone()),
            teams: TeamsConfig {
                enabled: true,
                create_default_team: false,
                maximum_members_per_team: Some(0.0),
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    _ = db.execute("CREATE TRIGGER fail_invitation_reset BEFORE UPDATE ON invitation WHEN OLD.status='accepted' AND NEW.status='pending' BEGIN SELECT RAISE(ABORT,'reset denied'); END",&[]).await?;
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
    let mut expected = auth
        .store()
        .get_invitation_by_id(&invitation)
        .await?
        .unwrap();
    expected.status = alibi::InvitationStatus::Accepted;
    let rejected = call(
        &auth,
        request(
            "/organization/accept-invitation",
            Some(json!({"invitationId":invitation})),
            &cookies(&target),
        ),
        500,
    )
    .await;
    assert!(rejected.body.is_empty());
    assert!(cookies(&rejected).is_empty());
    assert_eq!(
        auth.store()
            .get_invitation_by_id(&invitation)
            .await?
            .unwrap(),
        expected
    );
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
    assert_eq!(*receipt.0.lock().unwrap(), 1);
    let replay = call(
        &auth,
        request(
            "/organization/accept-invitation",
            Some(json!({"invitationId":invitation})),
            &cookies(&target),
        ),
        400,
    )
    .await;
    assert_eq!(body(&replay)["code"], "INVITATION_NOT_FOUND");
    assert_eq!(*receipt.0.lock().unwrap(), 1);
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
    _ = db
        .execute("DROP TRIGGER fail_invitation_reset", &[])
        .await?;
    authenticated(
        &auth,
        &cookies(&foreign),
        "staged-invitation-foreign@example.test",
    )
    .await;
    authenticated(
        &auth,
        &cookies(&sibling),
        "staged-invitation-target@example.test",
    )
    .await;
    B::close(connection).await
}
