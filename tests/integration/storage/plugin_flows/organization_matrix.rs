//! Organization route validation, membership and team limits, slug policy
//! and JavaScript-compatible query numbers.
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::organization::{MembershipLimit, TeamsConfig};
use alibi::plugins::{OrganizationConfig, OrganizationPlugin};

backend_tests!(
    organization_route_matrix,
    organization_without_teams_or_deletion,
    organization_mixed_selectors_only_update_current_token_selection,
    organization_selection_returns_stored_metadata_text_without_rewriting_rows,
    revoked_cache_identity_retains_physical_organization_membership_checks
);

fn get(path: &str, query: &[(&str, &str)], cookie: &str) -> AuthRequest {
    let mut request = request(path, None, cookie);
    request.set_query_pairs(query.iter().copied());
    request
}

fn raw(path: &str, text: &str, cookie: &str) -> AuthRequest {
    let mut request = request(path, None, cookie);
    request.method = alibi::HttpMethod::Post;
    request.body = Some(text.as_bytes().to_vec());
    request
}

async fn organization_route_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let plugin = OrganizationPlugin::with_config(OrganizationConfig {
        membership_limit: Some(MembershipLimit::Fixed(3.0)),
        teams: TeamsConfig {
            enabled: true,
            maximum_members_per_team: Some(1.0),
            ..Default::default()
        },
        ..Default::default()
    });
    let auth = builder::<B>(&connection).plugin(plugin).build().await?;
    let mut trace = Trace::default();
    let owner_response = signup(&auth, "org-owner@example.com").await;
    let owner = cookies(&owner_response);
    let member = signup(&auth, "org-member@example.com").await;
    let member_id = body(&member)["user"]["id"].as_str().unwrap().to_owned();
    let extra = signup(&auth, "org-extra@example.com").await;
    let extra_id = body(&extra)["user"]["id"].as_str().unwrap().to_owned();
    trace.mask(&member_id);
    trace.mask(&extra_id);

    trace.response(
        "no active organization",
        &Box::pin(auth.handle_request(get("/organization/get-full-organization", &[], &owner)))
            .await?,
    );
    let created = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name": "Matrix", "slug": "matrix"})),
            &owner,
        ),
        200,
    )
    .await;
    let organization_id = body(&created)["id"].as_str().unwrap().to_owned();
    trace.mask(&organization_id);
    let owner = [owner, cookies(&created)]
        .into_iter()
        .filter(|cookie| !cookie.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    let other = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name": "Other", "slug": "other", "keepCurrentActiveOrganization": true})),
            &owner,
        ),
        200,
    )
    .await;
    trace.mask(body(&other)["id"].as_str().unwrap());
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

    let bodies = [
        ("/organization/create", r#"[]"#),
        ("/organization/create", r#"{"name":"","slug":""}"#),
        ("/organization/create", r#"{"name":"Dup","slug":"matrix"}"#),
        (
            "/organization/create",
            r#"{"name":"Meta","slug":"meta","metadata":"text"}"#,
        ),
        ("/organization/create", r#"{"name":5,"slug":null}"#),
        ("/organization/update", r#"{"data":{"slug":"other"}}"#),
        (
            "/organization/update",
            r#"{"data":{"name":"Renamed","slug":"matrix"}}"#,
        ),
        ("/organization/update", r#"{"data":[]}"#),
        ("/organization/update", r#"{"data":{"name":1}}"#),
        (
            "/organization/invite-member",
            r#"{"email":"invitee@example.com","role":"member","resend":"yes"}"#,
        ),
        (
            "/organization/invite-member",
            r#"{"email":"invitee@example.com","role":["member",1]}"#,
        ),
        (
            "/organization/invite-member",
            r#"{"email":"invitee@example.com","role":"member","teamId":[1]}"#,
        ),
        (
            "/organization/invite-member",
            r#"{"email":"invitee@example.com","role":"member","teamId":["missing"]}"#,
        ),
        (
            "/organization/invite-member",
            r#"{"email":"invitee@example.com","role":"ghost"}"#,
        ),
        (
            "/organization/set-active",
            r#"{"organizationSlug":"missing"}"#,
        ),
        ("/organization/set-active-team", r#"{"teamId":"missing"}"#),
        (
            "/organization/update-member-role",
            r#"{"memberId":"missing","role":"admin"}"#,
        ),
        (
            "/organization/remove-member",
            r#"{"memberIdOrEmail":"nobody@example.com"}"#,
        ),
        ("/organization/leave", r#"{"organizationId":"missing"}"#),
        (
            "/organization/has-permission",
            r#"{"permissions":{"member":["create"]}}"#,
        ),
        (
            "/organization/has-permission",
            r#"{"permission":{"member":["create"]},"permissions":{"member":["create"]}}"#,
        ),
    ];
    for (path, text) in bodies {
        trace.response(
            &format!("{path} {text}"),
            &Box::pin(auth.handle_request(raw(path, text, &owner))).await?,
        );
    }

    let add = async |user_id: &str, team_id: Option<&str>| {
        let mut input =
            json!({"userId": user_id, "role": "member", "organizationId": organization_id});
        if let Some(team_id) = team_id {
            input["teamId"] = json!(team_id);
        }
        match Box::pin(
            auth.dispatch_endpoint(
                OrganizationPlugin::add_member_endpoint(&serde_json::from_value(input).unwrap())
                    .unwrap(),
                alibi::endpoint::EndpointOptions::default(),
            ),
        )
        .await
        {
            Ok(response) => json!({"added": response.decode().is_ok()}),
            Err(error) => json!({"error": error.to_string(), "status": error.error.status_code()}),
        }
    };
    trace.value(
        "add to missing team",
        add(&member_id, Some("missing")).await,
    );
    trace.value("add to team", add(&member_id, Some(&team_id)).await);
    trace.value("team at capacity", add(&extra_id, Some(&team_id)).await);
    trace.value("add without team", add(&extra_id, None).await);
    let fourth = signup(&auth, "org-fourth@example.com").await;
    trace.value(
        "membership limit",
        add(body(&fourth)["user"]["id"].as_str().unwrap(), None).await,
    );

    for query in [
        vec![("limit", "0x2")],
        vec![("limit", "0b11"), ("offset", "0o1")],
        vec![("limit", " 2e0 ")],
        vec![("limit", "Infinity")],
        vec![("limit", "-Infinity")],
        vec![("limit", "")],
        vec![("limit", "0x")],
        vec![("limit", "0xZZ")],
        vec![("limit", "1_000")],
        vec![("limit", "0x1fffffffffffff1")],
        vec![("sortBy", "createdAt"), ("sortDirection", "desc")],
    ] {
        trace.response(
            &format!("list-members {query:?}"),
            &Box::pin(auth.handle_request(get("/organization/list-members", &query, &owner)))
                .await?,
        );
    }
    for query in [
        vec![("membersLimit", "0x1")],
        vec![("membersLimit", "-0x1")],
        vec![("membersLimit", "+2abc")],
        vec![("organizationSlug", "missing")],
        vec![("organizationSlug", "other")],
    ] {
        trace.response(
            &format!("get-full-organization {query:?}"),
            &Box::pin(auth.handle_request(get(
                "/organization/get-full-organization",
                &query,
                &owner,
            )))
            .await?,
        );
    }
    let outsider = cookies(&extra);
    trace.response(
        "outsider full organization",
        &Box::pin(auth.handle_request(get(
            "/organization/get-full-organization",
            &[("organizationId", &organization_id)],
            &outsider,
        )))
        .await?,
    );
    trace.response(
        "unauthenticated check slug",
        &Box::pin(auth.handle_request(request(
            "/organization/check-slug",
            Some(json!({"slug": "matrix"})),
            "",
        )))
        .await?,
    );
    trace.response(
        "clear active organization",
        &Box::pin(auth.handle_request(raw(
            "/organization/set-active",
            r#"{"organizationId":null}"#,
            &owner,
        )))
        .await?,
    );
    trace.response(
        "list user teams",
        &Box::pin(auth.handle_request(get("/organization/list-user-teams", &[], &owner))).await?,
    );
    trace.assert("organization/route-matrix");
    B::close(connection).await
}

async fn organization_without_teams_or_deletion<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let plugin = OrganizationPlugin::with_config(OrganizationConfig {
        disable_organization_deletion: true,
        ..Default::default()
    });
    let auth = builder::<B>(&connection).plugin(plugin).build().await?;
    let mut trace = Trace::default();
    let owner = cookies(&signup(&auth, "solo-owner@example.com").await);
    let created = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name": "Solo", "slug": "solo"})),
            &owner,
        ),
        200,
    )
    .await;
    let organization_id = body(&created)["id"].as_str().unwrap().to_owned();
    trace.mask(&organization_id);
    let member = signup(&auth, "solo-member@example.com").await;
    let member_id = body(&member)["user"]["id"].as_str().unwrap().to_owned();
    trace.mask(&member_id);
    let added = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::add_member_endpoint(&serde_json::from_value(json!({
            "userId": member_id,
            "role": "member",
            "organizationId": organization_id,
            "teamId": "any",
        }))?)?,
        alibi::endpoint::EndpointOptions::default(),
    ))
    .await;
    trace.value(
        "teams disabled",
        json!(added.err().map(|error| error.to_string())),
    );
    for (path, input) in [
        (
            "/organization/delete",
            json!({"organizationId": organization_id}),
        ),
        (
            "/organization/update",
            json!({"data": {"name": "Renamed"}, "organizationId": "missing"}),
        ),
        (
            "/organization/set-active",
            json!({"organizationId": organization_id}),
        ),
    ] {
        trace.response(
            path,
            &Box::pin(auth.handle_request(request(path, Some(input), &cookies(&member)))).await?,
        );
    }
    trace.response(
        "set active none",
        &Box::pin(auth.handle_request(request(
            "/organization/set-active",
            Some(json!({"organizationId": null})),
            &owner,
        )))
        .await?,
    );
    trace.response(
        "active member without organization",
        &Box::pin(auth.handle_request(get("/organization/get-active-member", &[], &owner))).await?,
    );
    trace.assert("organization/without-teams");
    B::close(connection).await
}

async fn organization_mixed_selectors_only_update_current_token_selection<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let sibling = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let first = body(
        &call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"First","slug":"first"})),
                &cookies(&owner),
            ),
            200,
        )
        .await,
    );
    let second = body(
        &call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"Second","slug":"second"})),
                &cookies(&sibling),
            ),
            200,
        )
        .await,
    );
    let sibling_token = body(&sibling)["token"].as_str().unwrap().to_owned();
    let token = body(&owner)["token"].as_str().unwrap().to_owned();
    let before = db
        .tables(&["organization", "member", "users", "accounts"])
        .await?;
    for (input, selected) in [
        (
            json!({"organizationId":"","organizationSlug":"second"}),
            Some(second["id"].as_str().unwrap()),
        ),
        (
            json!({"organizationId":first["id"],"organizationSlug":"second"}),
            Some(first["id"].as_str().unwrap()),
        ),
        (
            json!({"organizationId":null,"organizationSlug":"second"}),
            None,
        ),
    ] {
        let response = call(
            &auth,
            request("/organization/set-active", Some(input), &cookies(&owner)),
            200,
        )
        .await;
        if let Some(id) = selected {
            assert_eq!(body(&response)["id"], id);
        } else {
            assert!(body(&response).is_null());
        }
        assert_eq!(
            db.text(
                "SELECT active_organization_id FROM sessions WHERE token=$1",
                &[&token]
            )
            .await?
            .as_deref(),
            selected
        );
        assert_eq!(
            db.text(
                "SELECT active_organization_id FROM sessions WHERE token=$1",
                &[&sibling_token]
            )
            .await?
            .as_deref(),
            second["id"].as_str()
        );
        assert_eq!(
            db.tables(&["organization", "member", "users", "accounts"])
                .await?,
            before
        );
    }
    let sessions = db.table("sessions").await?;
    let denied = call(
        &auth,
        request(
            "/organization/set-active",
            Some(json!({"organizationId":"","organizationSlug":"missing"})),
            &cookies(&owner),
        ),
        400,
    )
    .await;
    assert!(!denied.headers.contains_key("set-cookie"));
    assert_eq!(db.table("sessions").await?, sessions);
    _ = call(
        &auth,
        request(
            "/organization/set-active",
            Some(json!({"organizationId":first["id"]})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    authenticated(&auth, &cookies(&sibling), "owner@example.test").await;
    B::close(connection).await
}

async fn organization_selection_returns_stored_metadata_text_without_rewriting_rows<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let sibling = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let metadata = json!({"2":"second","1":"first","nested":{"array":[null,true,"literal"]},"$serde_json::private::RawValue":"application-key"});
    let record = body(
        &call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"Record","slug":"record","metadata":metadata})),
                &cookies(&owner),
            ),
            200,
        )
        .await,
    );
    let empty = body(
        &call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"Empty","slug":"empty","metadata":{}})),
                &cookies(&sibling),
            ),
            200,
        )
        .await,
    );
    let before = db
        .tables(&["organization", "member", "users", "accounts"])
        .await?;
    let sibling_token = body(&sibling)["token"].as_str().unwrap().to_owned();
    for (input, id) in [
        (
            json!({"organizationId":empty["id"]}),
            empty["id"].as_str().unwrap(),
        ),
        (
            json!({"organizationSlug":"record"}),
            record["id"].as_str().unwrap(),
        ),
    ] {
        let selected = body(
            &call(
                &auth,
                request("/organization/set-active", Some(input), &cookies(&owner)),
                200,
            )
            .await,
        );
        assert_eq!(
            selected["metadata"].as_str(),
            db.text(
                "SELECT CAST(metadata AS TEXT) FROM organization WHERE id=$1",
                &[id]
            )
            .await?
            .as_deref()
        );
        assert!(selected.get("members").is_none());
        assert!(selected.get("invitations").is_none());
        assert_eq!(
            db.tables(&["organization", "member", "users", "accounts"])
                .await?,
            before
        );
        assert_eq!(
            db.text(
                "SELECT active_organization_id FROM sessions WHERE token=$1",
                &[&sibling_token]
            )
            .await?
            .as_deref(),
            empty["id"].as_str()
        );
    }
    let updated = body(
        &call(
            &auth,
            request(
                "/organization/update",
                Some(
                    json!({"organizationId":record["id"],"data":{"metadata":{"replacement":true}}}),
                ),
                &cookies(&owner),
            ),
            200,
        )
        .await,
    );
    assert_eq!(updated["metadata"], json!({"replacement":true}));
    let selected = body(
        &call(
            &auth,
            request(
                "/organization/set-active",
                Some(json!({"organizationId":record["id"]})),
                &cookies(&owner),
            ),
            200,
        )
        .await,
    );
    assert_eq!(
        serde_json::from_str::<Value>(selected["metadata"].as_str().unwrap())?,
        json!({"replacement":true})
    );
    B::close(connection).await
}

async fn revoked_cache_identity_retains_physical_organization_membership_checks<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::{CookieCacheConfig, CookieCacheStrategy};
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            strategy: CookieCacheStrategy::Compact,
            ..Default::default()
        });
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(OrganizationPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "retained-org-owner@example.test").await;
    let foreign = signup(&auth, "retained-org-foreign@example.test").await;
    let org=call(&auth,request("/organization/create",Some(json!({"name":"Owner","slug":"retained-owner","keepCurrentActiveOrganization":true})),&cookies(&owner)),200).await;
    let other=call(&auth,request("/organization/create",Some(json!({"name":"Foreign","slug":"retained-foreign","keepCurrentActiveOrganization":true})),&cookies(&foreign)),200).await;
    let id = body(&org)["id"].as_str().unwrap().to_owned();
    let other_id = body(&other)["id"].as_str().unwrap().to_owned();
    _ = db
        .execute(
            "DELETE FROM sessions WHERE token=$1",
            &[body(&owner)["token"].as_str().unwrap()],
        )
        .await?;
    let before = db
        .tables(&["users", "accounts", "sessions", "organization", "member"])
        .await?;
    let policy = json!({"organizationId":id,"permissions":{"organization":["update"]}});
    let retained = call(
        &auth,
        request(
            "/organization/has-permission",
            Some(policy.clone()),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert_eq!(body(&retained), json!({"success":true,"error":null}));
    let mut target = policy.clone();
    target["organizationId"] = json!(other_id);
    _ = call(
        &auth,
        request(
            "/organization/has-permission",
            Some(target),
            &cookies(&owner),
        ),
        401,
    )
    .await;
    let mut bypass = request(
        "/organization/has-permission",
        Some(policy),
        &cookies(&owner),
    );
    bypass.set_query_pairs([("disableCookieCache", "true")]);
    _ = call(&auth, bypass, 401).await;
    for (response, organization_id) in [(&owner, id.as_str()), (&foreign, other_id.as_str())] {
        let full = call(
            &auth,
            get(
                "/organization/get-full-organization",
                &[("organizationId", organization_id)],
                &cookies(response),
            ),
            200,
        )
        .await;
        assert_eq!(
            body(&full)["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["userId"].clone())
                .collect::<Vec<_>>(),
            [body(response)["user"]["id"].clone()]
        );
    }
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "organization", "member"])
            .await?,
        before
    );
    authenticated(
        &auth,
        &cookies(&foreign),
        "retained-org-foreign@example.test",
    )
    .await;
    B::close(connection).await
}
