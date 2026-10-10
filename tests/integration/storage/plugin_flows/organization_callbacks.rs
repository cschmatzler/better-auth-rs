//! Organization callbacks surround real writes, with intentionally partial effects.
use super::*;
use alibi::plugins::organization::*;
use alibi::{AuthError, AuthResult};
use async_trait::async_trait;

backend_tests!(
    organization_lifecycle_callbacks_preserve_patch_authority_and_committed_phases,
    organization_invitation_and_member_callbacks_preserve_actor_and_commit_order,
    organization_role_hook_empty_and_absent_patches_retain_normalized_request,
    organization_role_after_hook_retains_original_target_across_independent_writes,
    organization_role_hook_target_deletion_rejects_before_after_callback,
    organization_update_hook_demotion_keeps_original_context_and_rechecks_next_request,
    organization_update_hook_deleted_row_returns_null_and_original_authority,
    organization_update_hooks_preserve_empty_values_and_input_field_fallback,
    organization_creation_hooks_preserve_trusted_empty_values_and_omitted_fields,
    organization_creation_retains_original_member_after_independent_role_write,
    organization_creator_patch_retargeting_keeps_team_and_selection_actor,
    organization_addition_after_hook_keeps_original_target_after_user_write,
    organization_self_removal_after_rejection_clears_only_current_org_selection,
    organization_removal_callback_500_identity
);
postgres_tests!(
    organization_lifecycle_callbacks_preserve_patch_authority_and_committed_phases,
    organization_invitation_and_member_callbacks_preserve_actor_and_commit_order
);

#[derive(Debug, Default)]
struct Lifecycle {
    failure: Mutex<&'static str>,
    events: Mutex<Vec<&'static str>>,
    actor: Mutex<String>,
    delete_requests: Mutex<Vec<bool>>,
    target: Mutex<String>,
    delivered: Mutex<Vec<Value>>,
    previous_role: Mutex<String>,
    removal_joins: Mutex<Vec<bool>>,
}
impl Lifecycle {
    fn phase(&self, name: &'static str) -> AuthResult<()> {
        self.events.lock().unwrap().push(name);
        if *self.failure.lock().unwrap() == name {
            return Err(AuthError::bad_request(format!("{name} veto")));
        }
        Ok(())
    }
    fn reset(&self, failure: &'static str) {
        *self.failure.lock().unwrap() = failure;
        self.events.lock().unwrap().clear();
    }
}
#[async_trait]
impl OrganizationCreationHooks for Lifecycle {
    async fn before_create(
        &self,
        ctx: &OrganizationDraftContext,
    ) -> AuthResult<Option<OrganizationCreatePatch>> {
        assert_eq!(ctx.user.id, *self.actor.lock().unwrap());
        assert_eq!(ctx.organization.name, "Submitted");
        self.phase("before-create")?;
        Ok(Some(OrganizationCreatePatch {
            id: Some("hook-organization".into()),
            name: Some("Patched organization".into()),
            slug: Some("hook-slug".into()),
            logo: Some(None),
            metadata: Some(None),
        }))
    }
    async fn before_add_member(
        &self,
        ctx: &OrganizationMemberDraftContext,
    ) -> AuthResult<Option<OrganizationMemberCreatePatch>> {
        assert_eq!(ctx.organization.id, "hook-organization");
        assert_eq!(ctx.member.user_id, *self.actor.lock().unwrap());
        self.phase("before-member")?;
        Ok(Some(OrganizationMemberCreatePatch {
            role: Some("owner,admin".into()),
            ..Default::default()
        }))
    }
    async fn after_add_member(&self, ctx: &OrganizationCreatedContext) -> AuthResult<()> {
        assert_eq!(ctx.member.role, "owner,admin");
        assert_eq!(ctx.member.organization_id, ctx.organization.id);
        self.phase("after-member")
    }
    async fn after_create(&self, ctx: &OrganizationCreatedContext) -> AuthResult<()> {
        assert_eq!(ctx.user.id, ctx.member.user_id);
        self.phase("after-create")
    }
}
#[async_trait]
impl OrganizationUpdateHooks for Lifecycle {
    async fn before_update(
        &self,
        ctx: &OrganizationUpdateContext,
    ) -> AuthResult<Option<OrganizationUpdatePatch>> {
        assert_eq!(ctx.user.id, *self.actor.lock().unwrap());
        assert_eq!(ctx.organization.name.as_deref(), Some("Submitted update"));
        self.phase("before-update")?;
        Ok(Some(OrganizationUpdatePatch {
            name: Some("Hook updated".into()),
            logo: Some(None),
            metadata: Some(None),
            ..Default::default()
        }))
    }
    async fn after_update(&self, ctx: &OrganizationUpdatedContext) -> AuthResult<()> {
        assert_eq!(ctx.organization.as_ref().unwrap().name, "Hook updated");
        assert_eq!(ctx.user.id, ctx.member.user_id);
        self.phase("after-update")
    }
}
#[async_trait]
impl OrganizationDeletionHooks for Lifecycle {
    async fn before_delete(&self, ctx: &OrganizationDeleteContext) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.actor.lock().unwrap());
        assert_eq!(
            ctx.session.active_organization_id.as_deref(),
            Some("hook-organization")
        );
        assert!(
            ctx.headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("cookie"))
        );
        self.delete_requests
            .lock()
            .unwrap()
            .push(ctx.request.is_some());
        self.phase("before-delete")
    }
    async fn after_delete(&self, ctx: &OrganizationDeleteContext) -> AuthResult<()> {
        assert_eq!(ctx.organization.id, "hook-organization");
        self.phase("after-delete")
    }
}

async fn organization_lifecycle_callbacks_preserve_patch_authority_and_committed_phases<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    for failure in [
        "before-create",
        "before-member",
        "after-member",
        "after-create",
        "",
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let callbacks = Arc::new(Lifecycle::default());
        callbacks.reset(failure);
        let auth = builder::<B>(&connection)
            .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                creation_hooks: Some(callbacks.clone()),
                update_hooks: Some(callbacks.clone()),
                deletion_hooks: Some(callbacks.clone()),
                ..Default::default()
            }))
            .build()
            .await?;
        let owner = signup(&auth, "lifecycle@example.test").await;
        *callbacks.actor.lock().unwrap() = body(&owner)["user"]["id"].as_str().unwrap().into();
        let result = call(&auth, request("/organization/create", Some(json!({"name":"Submitted","slug":"submitted","logo":"https://image.test/original","metadata":{"input":true}})), &cookies(&owner)), if failure.is_empty() { 200 } else { 400 }).await;
        let stages = [
            "before-create",
            "before-member",
            "after-member",
            "after-create",
        ];
        let executed = stages
            .iter()
            .position(|phase| *phase == failure)
            .map_or(4, |position| position + 1);
        assert_eq!(*callbacks.events.lock().unwrap(), stages[..executed]);
        assert_eq!(
            db.count("organization").await?,
            i64::from(failure != "before-create")
        );
        assert_eq!(
            db.count("member").await?,
            i64::from(!matches!(failure, "before-create" | "before-member"))
        );
        let token = body(&owner)["token"].as_str().unwrap().to_owned();
        let active = db
            .text(
                "SELECT active_organization_id FROM sessions WHERE token=$1",
                &[&token],
            )
            .await?;
        if !failure.is_empty() {
            assert!(active.is_none());
            B::close(connection).await?;
            continue;
        }
        assert_eq!(active.as_deref(), Some("hook-organization"));
        assert_eq!(body(&result)["id"], "hook-organization");
        assert_eq!(body(&result)["name"], "Patched organization");
        assert_eq!(
            db.text("SELECT slug FROM organization", &[])
                .await?
                .as_deref(),
            Some("hook-slug")
        );
        assert!(
            db.text("SELECT logo FROM organization", &[])
                .await?
                .is_none()
        );
        assert!(
            db.text("SELECT CAST(metadata AS TEXT) FROM organization", &[])
                .await?
                .is_none(),
            "creation's null patch omits metadata"
        );
        for phase in ["before-update", "after-update", ""] {
            callbacks.reset(phase);
            let before = db.table("organization").await?;
            let _ = call(&auth, request("/organization/update", Some(json!({"organizationId":"hook-organization","data":{"name":"Submitted update","metadata":{"input":true}}})), &cookies(&owner)), if phase.is_empty() { 200 } else { 400 }).await;
            assert_eq!(
                *callbacks.events.lock().unwrap(),
                if phase == "before-update" {
                    vec!["before-update"]
                } else {
                    vec!["before-update", "after-update"]
                }
            );
            if phase == "before-update" {
                assert_eq!(db.table("organization").await?, before);
            } else {
                assert_eq!(
                    db.text("SELECT name FROM organization", &[])
                        .await?
                        .as_deref(),
                    Some("Hook updated")
                );
                assert_eq!(
                    db.text("SELECT CAST(metadata AS TEXT) FROM organization", &[])
                        .await?
                        .as_deref(),
                    Some("null"),
                    "update's null patch persists JSON null"
                );
            }
        }
        callbacks.reset("before-delete");
        let before = db.tables(&["organization", "member"]).await?;
        let _ = call(
            &auth,
            request(
                "/organization/delete",
                Some(json!({"organizationId":"hook-organization"})),
                &cookies(&owner),
            ),
            400,
        )
        .await;
        assert_eq!(db.tables(&["organization", "member"]).await?, before);
        assert!(
            db.text(
                "SELECT active_organization_id FROM sessions WHERE token=$1",
                &[&token]
            )
            .await?
            .is_none(),
            "selection clearing precedes the veto"
        );
        assert_eq!(*callbacks.events.lock().unwrap(), vec!["before-delete"]);
        let _ = call(
            &auth,
            request(
                "/organization/set-active",
                Some(json!({"organizationId":"hook-organization"})),
                &cookies(&owner),
            ),
            200,
        )
        .await;
        callbacks.reset("after-delete");
        let helper = OrganizationPlugin::with_config(OrganizationConfig {
            deletion_hooks: Some(callbacks.clone()),
            ..Default::default()
        });
        let headers = [("Cookie".into(), cookies(&owner))].into_iter().collect();
        let error = helper
            .delete_organization_with_headers(
                auth.context(),
                &headers,
                &alibi::plugins::organization::types::DeleteOrganizationRequest {
                    organization_id: "hook-organization".into(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.status_code(), 400);
        assert_eq!(
            *callbacks.events.lock().unwrap(),
            vec!["before-delete", "after-delete"]
        );
        assert_eq!(
            *callbacks.delete_requests.lock().unwrap(),
            vec![true, false]
        );
        assert_eq!(db.count("organization").await?, 0);
        assert_eq!(db.count("member").await?, 0);
        assert!(
            db.text(
                "SELECT active_organization_id FROM sessions WHERE token=$1",
                &[&token]
            )
            .await?
            .is_none()
        );
        B::close(connection).await?;
    }
    Ok(())
}

#[async_trait]
impl OrganizationInvitationLimitResolver for Lifecycle {
    async fn invitation_limit(
        &self,
        ctx: &OrganizationInvitationLimitContext,
        _: &alibi::CallbackContext,
    ) -> AuthResult<f64> {
        assert_eq!(ctx.user.id, *self.actor.lock().unwrap());
        assert_eq!(ctx.member.user_id, ctx.member_user.id);
        assert_eq!(ctx.member_user.id, ctx.user.id);
        self.phase("limit")?;
        Ok(if *self.failure.lock().unwrap() == "limit-zero" {
            0.0
        } else {
            100.0
        })
    }
}
#[async_trait]
impl OrganizationInvitationHooks for Lifecycle {
    async fn before_create_invitation(
        &self,
        ctx: &OrganizationInvitationCreationContext,
    ) -> AuthResult<Option<OrganizationInvitationCreatePatch>> {
        assert_eq!(ctx.inviter.id, *self.actor.lock().unwrap());
        assert_eq!(ctx.invitation.organization_id, ctx.organization.id);
        self.phase("before-invite")?;
        Ok(Some(OrganizationInvitationCreatePatch {
            email: Some(
                if self.failure.lock().unwrap().is_empty() {
                    "target@example.test"
                } else {
                    "TARGET@EXAMPLE.TEST"
                }
                .into(),
            ),
            role: Some("admin".into()),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            ..Default::default()
        }))
    }
    async fn after_create_invitation(&self, ctx: &OrganizationInvitationContext) -> AuthResult<()> {
        assert_eq!(ctx.invitation.role.as_deref(), Some("admin"));
        assert_eq!(ctx.user.id, *self.actor.lock().unwrap());
        assert!(!ctx.invitation.id.is_empty());
        self.phase("after-invite")
    }
    async fn before_reject_invitation(
        &self,
        ctx: &OrganizationInvitationContext,
    ) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        self.phase("before-reject")
    }
    async fn after_reject_invitation(&self, ctx: &OrganizationInvitationContext) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        self.phase("after-reject")
    }
    async fn before_cancel_invitation(
        &self,
        ctx: &OrganizationInvitationContext,
    ) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.actor.lock().unwrap());
        self.phase("before-cancel")
    }
    async fn after_cancel_invitation(&self, ctx: &OrganizationInvitationContext) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.actor.lock().unwrap());
        self.phase("after-cancel")
    }
}
#[async_trait]
impl OrganizationInvitationEmailSender for Lifecycle {
    async fn send_invitation_email(
        &self,
        delivery: &OrganizationInvitationDelivery,
        _: &alibi::CallbackContext,
    ) -> AuthResult<()> {
        assert_eq!(delivery.email(), "target@example.test");
        assert_eq!(delivery.user.id, *self.actor.lock().unwrap());
        assert_eq!(delivery.inviter.user_id, delivery.user.id);
        assert_eq!(
            delivery.organization.id,
            delivery.invitation.organization_id
        );
        self.delivered
            .lock()
            .unwrap()
            .push(serde_json::to_value(&delivery.invitation)?);
        self.phase("send")
    }
}
#[async_trait]
impl OrganizationInvitationAcceptanceHooks for Lifecycle {
    async fn before_accept_invitation(
        &self,
        ctx: &OrganizationInvitationAcceptanceContext,
    ) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        assert_eq!(ctx.invitation.email, "target@example.test");
        assert_eq!(ctx.invitation.status, alibi::InvitationStatus::Pending);
        assert_eq!(ctx.invitation.organization_id, ctx.organization.id);
        self.phase("before-accept")
    }
    async fn after_accept_invitation(
        &self,
        ctx: &OrganizationInvitationAcceptedContext,
    ) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        assert_eq!(ctx.member.user_id, ctx.user.id);
        assert_eq!(ctx.member.organization_id, ctx.organization.id);
        assert_eq!(ctx.invitation.organization_id, ctx.organization.id);
        self.phase("after-accept")
    }
}
#[async_trait]
impl OrganizationMemberRoleHooks for Lifecycle {
    async fn before_update(
        &self,
        ctx: &OrganizationMemberRoleContext,
    ) -> AuthResult<Option<OrganizationMemberRolePatch>> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        assert_eq!(ctx.member.user_id, ctx.user.id);
        assert_eq!(ctx.new_role, "member");
        *self.previous_role.lock().unwrap() = ctx.member.role.clone();
        self.phase("before-role")?;
        Ok(Some(OrganizationMemberRolePatch {
            role: Some("admin".into()),
        }))
    }
    async fn after_update(&self, ctx: &OrganizationMemberRoleUpdatedContext) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        assert_eq!(ctx.member.role, "admin");
        assert_eq!(ctx.previous_role, *self.previous_role.lock().unwrap());
        self.phase("after-role")
    }
}
#[async_trait]
impl OrganizationMemberRemovalHooks for Lifecycle {
    async fn before_remove(&self, ctx: &OrganizationMemberRemovalContext) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        assert_eq!(ctx.member.member.user_id, ctx.user.id);
        self.removal_joins
            .lock()
            .unwrap()
            .push(ctx.member.user.is_some());
        self.phase("before-remove")
    }
    async fn after_remove(&self, ctx: &OrganizationMemberRemovalContext) -> AuthResult<()> {
        assert_eq!(ctx.user.id, *self.target.lock().unwrap());
        self.phase("after-remove")
    }
}
async fn organization_invitation_and_member_callbacks_preserve_actor_and_commit_order<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    for failure in ["before-invite", "send", "after-invite", ""] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let callbacks = Arc::new(Lifecycle::default());
        let auth = builder::<B>(&connection)
            .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                invitation_hooks: Some(callbacks.clone()),
                invitation_acceptance_hooks: Some(callbacks.clone()),
                send_invitation_email: Some(callbacks.clone()),
                invitation_limit: Some(InvitationLimit::Resolver(callbacks.clone())),
                cancel_pending_invitations_on_reinvite: true,
                member_role_hooks: Some(callbacks.clone()),
                member_removal_hooks: Some(callbacks.clone()),
                ..Default::default()
            }))
            .build()
            .await?;
        let owner = signup(&auth, "inviter@example.test").await;
        let target = signup(&auth, "target@example.test").await;
        *callbacks.actor.lock().unwrap() = body(&owner)["user"]["id"].as_str().unwrap().into();
        let target_id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
        *callbacks.target.lock().unwrap() = target_id.clone();
        drop(
            auth.store()
                .update_user(
                    &target_id,
                    alibi::UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await?,
        );
        let created = call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"Invitations","slug":"invitations"})),
                &cookies(&owner),
            ),
            200,
        )
        .await;
        let org = body(&created)["id"].as_str().unwrap().to_owned();
        let invite = || {
            request(
                "/organization/invite-member",
                Some(json!({"organizationId":org,"email":"target@example.test","role":"member"})),
                &cookies(&owner),
            )
        };
        callbacks.reset(failure);
        let result = call(
            &auth,
            invite(),
            if matches!(failure, "before-invite" | "after-invite") {
                400
            } else {
                200
            },
        )
        .await;
        assert_eq!(
            *callbacks.events.lock().unwrap(),
            if failure == "before-invite" {
                vec!["limit", "before-invite"]
            } else {
                vec!["limit", "before-invite", "send", "after-invite"]
            }
        );
        assert_eq!(
            db.count("invitation").await?,
            i64::from(failure != "before-invite")
        );
        assert_eq!(db.count("member").await?, 1);
        if failure != "before-invite" {
            let delivered = callbacks.delivered.lock().unwrap()[0].clone();
            assert_eq!(
                db.text("SELECT id FROM invitation", &[]).await?.as_deref(),
                delivered["id"].as_str()
            );
            assert_eq!(
                db.text("SELECT role FROM invitation", &[])
                    .await?
                    .as_deref(),
                Some("admin")
            );
        }
        if !failure.is_empty() {
            B::close(connection).await?;
            continue;
        }
        let id = body(&result)["id"].as_str().unwrap().to_owned();
        callbacks.reset("limit-zero");
        let _ = call(&auth, invite(), 403).await;
        assert_eq!(*callbacks.events.lock().unwrap(), vec!["limit"]);
        assert_eq!(db.count("invitation").await?, 1);
        assert_eq!(
            db.text("SELECT status FROM invitation WHERE id=$1", &[&id])
                .await?
                .as_deref(),
            Some("canceled"),
            "reinvite cancellation precedes limit admission"
        );
        for (route, before_phase, after_phase, status, credential) in [
            (
                "reject-invitation",
                "before-reject",
                "after-reject",
                "rejected",
                cookies(&target),
            ),
            (
                "cancel-invitation",
                "before-cancel",
                "after-cancel",
                "canceled",
                cookies(&owner),
            ),
        ] {
            callbacks.reset("");
            let invited = call(&auth, invite(), 200).await;
            let id = body(&invited)["id"].as_str().unwrap().to_owned();
            for phase in [before_phase, after_phase] {
                callbacks.reset(phase);
                let before = db.table("invitation").await?;
                let _ = call(
                    &auth,
                    request(
                        &format!("/organization/{route}"),
                        Some(json!({"invitationId":id})),
                        &credential,
                    ),
                    400,
                )
                .await;
                if phase == before_phase {
                    assert_eq!(db.table("invitation").await?, before);
                    assert_eq!(*callbacks.events.lock().unwrap(), vec![before_phase]);
                } else {
                    assert_eq!(
                        db.text("SELECT status FROM invitation WHERE id=$1", &[&id])
                            .await?
                            .as_deref(),
                        Some(status)
                    );
                    assert_eq!(
                        *callbacks.events.lock().unwrap(),
                        vec![before_phase, after_phase]
                    );
                }
                assert_eq!(db.count("member").await?, 1);
            }
        }
        callbacks.reset("");
        let invited = call(&auth, invite(), 200).await;
        for phase in ["before-accept", "after-accept"] {
            callbacks.reset(phase);
            let before = db.table("sessions").await?;
            let _ = call(
                &auth,
                request(
                    "/organization/accept-invitation",
                    Some(json!({"invitationId":body(&invited)["id"]})),
                    &cookies(&target),
                ),
                400,
            )
            .await;
            let invitation_id = body(&invited)["id"].as_str().unwrap().to_owned();
            assert_eq!(
                db.text(
                    "SELECT status FROM invitation WHERE id=$1",
                    &[&invitation_id]
                )
                .await?
                .as_deref(),
                Some(if phase == "before-accept" {
                    "pending"
                } else {
                    "accepted"
                })
            );
            assert_eq!(
                db.count("member").await?,
                if phase == "before-accept" { 1 } else { 2 }
            );
            if phase == "before-accept" {
                assert_eq!(db.table("sessions").await?, before);
            } else {
                let token = body(&target)["token"].as_str().unwrap().to_owned();
                assert_eq!(
                    db.text(
                        "SELECT active_organization_id FROM sessions WHERE token=$1",
                        &[&token]
                    )
                    .await?
                    .as_deref(),
                    Some(org.as_str())
                );
            }
            assert_eq!(
                *callbacks.events.lock().unwrap(),
                if phase == "before-accept" {
                    vec!["before-accept"]
                } else {
                    vec!["before-accept", "after-accept"]
                }
            );
        }
        let member = db
            .text(
                "SELECT id FROM member WHERE user_id=$1 AND organization_id=$2",
                &[&target_id, &org],
            )
            .await?
            .unwrap();
        for phase in ["before-role", "after-role", ""] {
            callbacks.reset(phase);
            let before = db.table("member").await?;
            let _ = call(
                &auth,
                request(
                    "/organization/update-member-role",
                    Some(json!({"organizationId":org,"memberId":member,"role":"member"})),
                    &cookies(&owner),
                ),
                if phase.is_empty() { 200 } else { 400 },
            )
            .await;
            if phase == "before-role" {
                assert_eq!(db.table("member").await?, before);
            } else {
                assert_eq!(
                    db.text("SELECT role FROM member WHERE id=$1", &[&member])
                        .await?
                        .as_deref(),
                    Some("admin")
                );
            }
            assert_eq!(
                *callbacks.events.lock().unwrap(),
                if phase == "before-role" {
                    vec!["before-role"]
                } else {
                    vec!["before-role", "after-role"]
                }
            );
        }
        for (phase, selector) in [
            ("before-remove", "target@example.test"),
            ("after-remove", member.as_str()),
        ] {
            callbacks.reset(phase);
            let before = db.table("member").await?;
            let _ = call(
                &auth,
                request(
                    "/organization/remove-member",
                    Some(json!({"organizationId":org,"memberIdOrEmail":selector})),
                    &cookies(&owner),
                ),
                400,
            )
            .await;
            if phase == "before-remove" {
                assert_eq!(db.table("member").await?, before);
            } else {
                assert_eq!(
                    db.count_where("SELECT COUNT(*) FROM member WHERE id=$1", &[&member])
                        .await?,
                    0
                );
            }
            assert_eq!(
                *callbacks.events.lock().unwrap(),
                if phase == "before-remove" {
                    vec!["before-remove"]
                } else {
                    vec!["before-remove", "after-remove"]
                }
            );
        }
        assert_eq!(*callbacks.removal_joins.lock().unwrap(), vec![true, false]);
        B::close(connection).await?;
    }
    Ok(())
}

async fn organization_role_hook_empty_and_absent_patches_retain_normalized_request<B: Backend>(
    db: Db,
) -> TestResult {
    #[derive(Debug, Default)]
    struct Hooks {
        mode: Mutex<usize>,
        before: Mutex<Vec<OrganizationMemberRoleContext>>,
        after: Mutex<Vec<OrganizationMemberRoleUpdatedContext>>,
    }
    #[async_trait]
    impl OrganizationMemberRoleHooks for Hooks {
        async fn before_update(
            &self,
            c: &OrganizationMemberRoleContext,
        ) -> AuthResult<Option<OrganizationMemberRolePatch>> {
            self.before.lock().unwrap().push(c.clone());
            Ok(match *self.mode.lock().unwrap() {
                0 => None,
                1 => Some(OrganizationMemberRolePatch::default()),
                2 => Some(OrganizationMemberRolePatch {
                    role: Some(String::new()),
                }),
                _ => Some(OrganizationMemberRolePatch {
                    role: Some("hook-unregistered-role".into()),
                }),
            })
        }
        async fn after_update(&self, c: &OrganizationMemberRoleUpdatedContext) -> AuthResult<()> {
            self.after.lock().unwrap().push(c.clone());
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let hooks = Arc::new(Hooks::default());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            member_role_hooks: Some(hooks.clone()),
            ..Default::default()
        }))
        .build()
        .await?;

    let owner = signup(&auth, "owner@example.test").await;
    let target = signup(&auth, "target@example.test").await;
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
    let target_id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let added = auth
        .dispatch_endpoint(
            OrganizationPlugin::add_member_endpoint(&serde_json::from_value(
                json!({"organizationId":org["id"],"userId":target_id,"role":"member"}),
            )?)?,
            alibi::endpoint::EndpointOptions::default(),
        )
        .await?
        .decode()?;

    let unchanged = db
        .tables(&["users", "accounts", "sessions", "organization"])
        .await?;
    for mode in 0..4 {
        *hooks.mode.lock().unwrap() = mode;
        let previous = db
            .text("SELECT role FROM member WHERE id=$1", &[&added.id])
            .await?
            .unwrap();
        _=call(&auth,request("/organization/update-member-role",Some(json!({"organizationId":org["id"],"memberId":added.id,"role":[" admin ,member ","admin"]})),&cookies(&owner)),200).await;
        let expected = if mode == 3 {
            "hook-unregistered-role"
        } else {
            "admin,member,admin"
        };
        assert_eq!(
            db.text("SELECT role FROM member WHERE id=$1", &[&added.id])
                .await?
                .as_deref(),
            Some(expected)
        );
        let before = hooks.before.lock().unwrap().last().unwrap().clone();
        let after = hooks.after.lock().unwrap().last().unwrap().clone();
        assert_eq!(before.user.id, target_id);
        assert_eq!(before.new_role, "admin,member,admin");
        assert_eq!(after.member.role, expected);
        assert_eq!(after.previous_role, previous);
        assert_eq!(after.user.id, target_id);
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "organization"])
                .await?,
            unchanged
        );
    }
    B::close(connection).await
}

async fn organization_role_after_hook_retains_original_target_across_independent_writes<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    struct Hooks<S: AuthSchema> {
        store: Arc<dyn alibi::AuthStore<S>>,
        before: Mutex<Vec<OrganizationMemberRoleContext>>,
        after: Mutex<Vec<OrganizationMemberRoleUpdatedContext>>,
    }
    impl<S: AuthSchema> std::fmt::Debug for Hooks<S> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("TargetRoleCallbacks")
        }
    }
    #[async_trait]
    impl<S: AuthSchema> OrganizationMemberRoleHooks for Hooks<S> {
        async fn before_update(
            &self,
            c: &OrganizationMemberRoleContext,
        ) -> AuthResult<Option<OrganizationMemberRolePatch>> {
            self.before.lock().unwrap().push(c.clone());
            _ = self
                .store
                .update_user(
                    &c.user.id,
                    alibi::UpdateUser {
                        name: Some("Stored Target Name".into()),
                        ..Default::default()
                    },
                )
                .await?;
            _ = self
                .store
                .update_member_role(&c.member.id, "member")
                .await?;
            Ok(None)
        }
        async fn after_update(&self, c: &OrganizationMemberRoleUpdatedContext) -> AuthResult<()> {
            self.after.lock().unwrap().push(c.clone());
            Ok(())
        }
    }
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let hooks = Arc::new(Hooks {
        store: Arc::new(store),
        before: Mutex::new(Vec::new()),
        after: Mutex::new(Vec::new()),
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            member_role_hooks: Some(hooks.clone()),
            ..Default::default()
        }))
        .build()
        .await?;

    let owner = signup(&auth, "owner@example.test").await;
    let target = signup(&auth, "target@example.test").await;
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
    let target_id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let added = auth
        .dispatch_endpoint(
            OrganizationPlugin::add_member_endpoint(&serde_json::from_value(
                json!({"organizationId":org["id"],"userId":target_id,"role":"member"}),
            )?)?,
            alibi::endpoint::EndpointOptions::default(),
        )
        .await?
        .decode()?;

    let sessions = db.table("sessions").await?;
    for (role, original_name, previous) in [
        (
            "admin",
            body(&target)["user"]["name"].as_str().unwrap().to_owned(),
            "member",
        ),
        ("member", "Stored Target Name".into(), "admin"),
    ] {
        _ = call(
            &auth,
            request(
                "/organization/update-member-role",
                Some(json!({"organizationId":org["id"],"memberId":added.id,"role":role})),
                &cookies(&owner),
            ),
            200,
        )
        .await;
        let before = hooks.before.lock().unwrap().last().unwrap().clone();
        let after = hooks.after.lock().unwrap().last().unwrap().clone();
        assert_eq!(before.user.name.as_deref(), Some(original_name.as_str()));
        assert_eq!(after.user.name, before.user.name);
        assert_eq!(after.user.id, target_id);
        assert_eq!(after.previous_role, previous);
        assert_eq!(after.member.role, role);
        assert_eq!(
            db.text("SELECT name FROM users WHERE id=$1", &[&target_id])
                .await?
                .as_deref(),
            Some("Stored Target Name")
        );
        assert_eq!(
            db.text("SELECT role FROM member WHERE id=$1", &[&added.id])
                .await?
                .as_deref(),
            Some(role)
        );
        assert_eq!(db.table("sessions").await?, sessions);
    }
    authenticated(&auth, &cookies(&owner), "owner@example.test").await;
    B::close(connection).await
}

async fn organization_role_hook_target_deletion_rejects_before_after_callback<B: Backend>(
    db: Db,
) -> TestResult {
    struct Hooks<S: AuthSchema> {
        store: Arc<dyn alibi::AuthStore<S>>,
        calls: Mutex<Vec<&'static str>>,
    }
    impl<S: AuthSchema> std::fmt::Debug for Hooks<S> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("DeleteTargetCallback")
        }
    }
    #[async_trait]
    impl<S: AuthSchema> OrganizationMemberRoleHooks for Hooks<S> {
        async fn before_update(
            &self,
            c: &OrganizationMemberRoleContext,
        ) -> AuthResult<Option<OrganizationMemberRolePatch>> {
            self.calls.lock().unwrap().push("before");
            self.store.delete_member(&c.member.id).await?;
            Ok(None)
        }
        async fn after_update(&self, _: &OrganizationMemberRoleUpdatedContext) -> AuthResult<()> {
            self.calls.lock().unwrap().push("after");
            Ok(())
        }
    }
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let hooks = Arc::new(Hooks {
        store: Arc::new(store),
        calls: Mutex::new(Vec::new()),
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            member_role_hooks: Some(hooks.clone()),
            ..Default::default()
        }))
        .build()
        .await?;

    let owner = signup(&auth, "owner@example.test").await;
    let target = signup(&auth, "target@example.test").await;
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
    let target_id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let added = auth
        .dispatch_endpoint(
            OrganizationPlugin::add_member_endpoint(&serde_json::from_value(
                json!({"organizationId":org["id"],"userId":target_id,"role":"member"}),
            )?)?,
            alibi::endpoint::EndpointOptions::default(),
        )
        .await?
        .decode()?;

    let before = db
        .tables(&["users", "accounts", "sessions", "organization"])
        .await?;
    let response = call(
        &auth,
        request(
            "/organization/update-member-role",
            Some(json!({"organizationId":org["id"],"memberId":added.id,"role":"admin"})),
            &cookies(&owner),
        ),
        400,
    )
    .await;
    assert_eq!(body(&response)["code"], "MEMBER_NOT_FOUND");
    assert_eq!(*hooks.calls.lock().unwrap(), vec!["before"]);
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM member WHERE id=$1", &[&added.id])
            .await?,
        0
    );
    assert_eq!(db.count("member").await?, 1);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "organization"])
            .await?,
        before
    );
    authenticated(&auth, &cookies(&target), "target@example.test").await;
    B::close(connection).await
}

async fn organization_update_hook_demotion_keeps_original_context_and_rechecks_next_request<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    struct Hooks<S: AuthSchema> {
        store: Arc<dyn alibi::AuthStore<S>>,
        after: Mutex<Vec<OrganizationUpdatedContext>>,
        before: std::sync::atomic::AtomicUsize,
    }
    impl<S: AuthSchema> std::fmt::Debug for Hooks<S> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("DemotingUpdateCallback")
        }
    }
    #[async_trait]
    impl<S: AuthSchema> OrganizationUpdateHooks for Hooks<S> {
        async fn before_update(
            &self,
            c: &OrganizationUpdateContext,
        ) -> AuthResult<Option<OrganizationUpdatePatch>> {
            _ = self
                .before
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            _ = self
                .store
                .update_user(
                    &c.user.id,
                    alibi::UpdateUser {
                        name: Some("Stored New Name".into()),
                        ..Default::default()
                    },
                )
                .await?;
            _ = self
                .store
                .update_member_role(&c.member.id, "member")
                .await?;
            Ok(None)
        }
        async fn after_update(&self, c: &OrganizationUpdatedContext) -> AuthResult<()> {
            self.after.lock().unwrap().push(c.clone());
            Ok(())
        }
    }
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let hooks = Arc::new(Hooks {
        store: Arc::new(store),
        after: Mutex::new(Vec::new()),
        before: std::sync::atomic::AtomicUsize::new(0),
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            update_hooks: Some(hooks.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let org = body(
        &call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"Original","slug":"owned"})),
                &cookies(&owner),
            ),
            200,
        )
        .await,
    );
    let sessions = db.table("sessions").await?;
    let updated = body(
        &call(
            &auth,
            request(
                "/organization/update",
                Some(json!({"organizationId":org["id"],"data":{"name":"Submitted update"}})),
                &cookies(&owner),
            ),
            200,
        )
        .await,
    );
    assert_eq!(updated["name"], "Submitted update");
    let after = hooks.after.lock().unwrap()[0].clone();
    assert_eq!(
        after.user.name.as_deref(),
        body(&owner)["user"]["name"].as_str()
    );
    assert_eq!(after.member.role, "owner");
    assert_eq!(after.organization.unwrap().name, "Submitted update");
    assert_eq!(
        db.text("SELECT name FROM users WHERE id=$1", &[&after.user.id])
            .await?
            .as_deref(),
        Some("Stored New Name")
    );
    assert_eq!(
        db.text("SELECT role FROM member WHERE id=$1", &[&after.member.id])
            .await?
            .as_deref(),
        Some("member")
    );
    assert_eq!(db.table("sessions").await?, sessions);
    let before = db
        .tables(&["users", "accounts", "sessions", "organization", "member"])
        .await?;
    let denied = call(
        &auth,
        request(
            "/organization/update",
            Some(json!({"organizationId":org["id"],"data":{"name":"must-not-write"}})),
            &cookies(&owner),
        ),
        403,
    )
    .await;
    assert_eq!(
        body(&denied)["code"],
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION"
    );
    assert_eq!(hooks.before.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(hooks.after.lock().unwrap().len(), 1);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "organization", "member"])
            .await?,
        before
    );
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn organization_update_hook_deleted_row_returns_null_and_original_authority<B: Backend>(
    db: Db,
) -> TestResult {
    struct Hooks<S: AuthSchema> {
        store: Arc<dyn alibi::AuthStore<S>>,
        after: Mutex<Vec<OrganizationUpdatedContext>>,
    }
    impl<S: AuthSchema> std::fmt::Debug for Hooks<S> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("DeletingUpdateCallback")
        }
    }
    #[async_trait]
    impl<S: AuthSchema> OrganizationUpdateHooks for Hooks<S> {
        async fn before_update(
            &self,
            c: &OrganizationUpdateContext,
        ) -> AuthResult<Option<OrganizationUpdatePatch>> {
            self.store
                .delete_organization(&c.member.organization_id)
                .await?;
            Ok(None)
        }
        async fn after_update(&self, c: &OrganizationUpdatedContext) -> AuthResult<()> {
            self.after.lock().unwrap().push(c.clone());
            Ok(())
        }
    }
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let hooks = Arc::new(Hooks {
        store: Arc::new(store),
        after: Mutex::new(Vec::new()),
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            update_hooks: Some(hooks.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let org = body(
        &call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"Original","slug":"owned"})),
                &cookies(&owner),
            ),
            200,
        )
        .await,
    );
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let response = call(
        &auth,
        request(
            "/organization/update",
            Some(json!({"organizationId":org["id"],"data":{"name":"Submitted update"}})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert!(body(&response).is_null());
    let after = hooks.after.lock().unwrap()[0].clone();
    assert!(after.organization.is_none());
    assert_eq!(after.user.id, body(&owner)["user"]["id"]);
    assert_eq!(after.member.organization_id, org["id"]);
    assert_eq!(after.member.role, "owner");
    assert_eq!(db.count("organization").await?, 0);
    assert_eq!(db.count("member").await?, 0);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn organization_update_hooks_preserve_empty_values_and_input_field_fallback<B: Backend>(
    db: Db,
) -> TestResult {
    #[derive(Debug, Default)]
    struct Hooks {
        mode: Mutex<usize>,
        after: Mutex<Vec<OrganizationUpdatedContext>>,
    }
    #[async_trait]
    impl OrganizationUpdateHooks for Hooks {
        async fn before_update(
            &self,
            _: &OrganizationUpdateContext,
        ) -> AuthResult<Option<OrganizationUpdatePatch>> {
            Ok(Some(match *self.mode.lock().unwrap() {
                0 => OrganizationUpdatePatch {
                    name: Some(String::new()),
                    ..Default::default()
                },
                1 => OrganizationUpdatePatch {
                    metadata: Some(Some(Default::default())),
                    ..Default::default()
                },
                _ => OrganizationUpdatePatch {
                    name: Some("Patched Without Metadata".into()),
                    ..Default::default()
                },
            }))
        }
        async fn after_update(&self, c: &OrganizationUpdatedContext) -> AuthResult<()> {
            self.after.lock().unwrap().push(c.clone());
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let hooks = Arc::new(Hooks::default());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            update_hooks: Some(hooks.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let org = body(
        &call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"Original","slug":"owned"})),
                &cookies(&owner),
            ),
            200,
        )
        .await,
    );
    let stable = db
        .tables(&["users", "accounts", "sessions", "member"])
        .await?;
    for mode in 0..3 {
        *hooks.mode.lock().unwrap() = mode;
        let result=body(&call(&auth,request("/organization/update",Some(json!({"organizationId":org["id"],"data":{"name":"Submitted","metadata":{"requested":true}}})),&cookies(&owner)),200).await);
        let expected_name = match mode {
            0 => "",
            1 => "Submitted",
            _ => "Patched Without Metadata",
        };
        let expected_meta = if mode == 1 {
            json!({})
        } else {
            json!({"requested":true})
        };
        assert_eq!(result["name"], expected_name);
        assert_eq!(result["metadata"], expected_meta);
        let after = hooks.after.lock().unwrap().last().unwrap().clone();
        assert_eq!(after.organization.unwrap().name, expected_name);
        assert_eq!(
            db.text(
                "SELECT name FROM organization WHERE id=$1",
                &[org["id"].as_str().unwrap()]
            )
            .await?
            .as_deref(),
            Some(expected_name)
        );
        let stored = db
            .text(
                "SELECT CAST(metadata AS TEXT) FROM organization WHERE id=$1",
                &[org["id"].as_str().unwrap()],
            )
            .await?
            .unwrap();
        assert_eq!(serde_json::from_str::<Value>(&stored)?, expected_meta);
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "member"])
                .await?,
            stable
        );
    }
    B::close(connection).await
}

async fn organization_creation_hooks_preserve_trusted_empty_values_and_omitted_fields<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    #[derive(Debug, Default)]
    struct Hooks(Mutex<usize>);
    #[async_trait]
    impl OrganizationCreationHooks for Hooks {
        async fn before_create(
            &self,
            _: &OrganizationDraftContext,
        ) -> AuthResult<Option<OrganizationCreatePatch>> {
            Ok(match *self.0.lock().unwrap() {
                0 => Some(OrganizationCreatePatch {
                    name: Some(String::new()),
                    ..Default::default()
                }),
                1 => Some(OrganizationCreatePatch {
                    metadata: Some(Some(Default::default())),
                    ..Default::default()
                }),
                2 => Some(OrganizationCreatePatch {
                    name: Some("Patched Without Metadata".into()),
                    ..Default::default()
                }),
                _ => None,
            })
        }
        async fn before_add_member(
            &self,
            _: &OrganizationMemberDraftContext,
        ) -> AuthResult<Option<OrganizationMemberCreatePatch>> {
            Ok(
                (*self.0.lock().unwrap() == 3).then(|| OrganizationMemberCreatePatch {
                    role: Some(String::new()),
                    ..Default::default()
                }),
            )
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let hooks = Arc::new(Hooks::default());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            creation_hooks: Some(hooks.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let foreign_token = body(&foreign)["token"].as_str().unwrap().to_owned();
    let foreign_selection = db
        .text(
            "SELECT active_organization_id FROM sessions WHERE token=$1",
            &[&foreign_token],
        )
        .await?;
    for mode in 0..4 {
        *hooks.0.lock().unwrap() = mode;
        let result=body(&call(&auth,request("/organization/create",Some(json!({"name":"Submitted","slug":format!("trusted-{mode}"),"metadata":{"requested":true}})),&cookies(&owner)),200).await);
        let expected_name = match mode {
            0 => "",
            2 => "Patched Without Metadata",
            _ => "Submitted",
        };
        let expected_meta = if mode == 1 {
            json!({})
        } else {
            json!({"requested":true})
        };
        let expected_role = if mode == 3 { "" } else { "owner" };
        assert_eq!(result["name"], expected_name);
        assert_eq!(result["metadata"], expected_meta);
        assert_eq!(result["members"][0]["role"], expected_role);
        assert_eq!(
            db.text(
                "SELECT role FROM member WHERE organization_id=$1",
                &[result["id"].as_str().unwrap()]
            )
            .await?
            .as_deref(),
            Some(expected_role)
        );
        assert_eq!(
            db.text(
                "SELECT name FROM organization WHERE id=$1",
                &[result["id"].as_str().unwrap()]
            )
            .await?
            .as_deref(),
            Some(expected_name)
        );
        let stored = db
            .text(
                "SELECT CAST(metadata AS TEXT) FROM organization WHERE id=$1",
                &[result["id"].as_str().unwrap()],
            )
            .await?
            .unwrap();
        assert_eq!(serde_json::from_str::<Value>(&stored)?, expected_meta);
        assert_eq!(
            db.text(
                "SELECT active_organization_id FROM sessions WHERE token=$1",
                &[&foreign_token]
            )
            .await?,
            foreign_selection
        );
    }
    assert_eq!(db.count("member").await?, 4);
    assert_eq!(db.count("sessions").await?, 2);
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}

async fn organization_creation_retains_original_member_after_independent_role_write<B: Backend>(
    db: Db,
) -> TestResult {
    struct Hooks<S: AuthSchema> {
        store: Arc<dyn alibi::AuthStore<S>>,
        roles: Mutex<Vec<String>>,
    }
    impl<S: AuthSchema> std::fmt::Debug for Hooks<S> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("CreatorRoleWrite")
        }
    }
    #[async_trait]
    impl<S: AuthSchema> OrganizationCreationHooks for Hooks<S> {
        async fn after_add_member(&self, c: &OrganizationCreatedContext) -> AuthResult<()> {
            self.roles.lock().unwrap().push(c.member.role.clone());
            _ = self.store.update_member_role(&c.member.id, "admin").await?;
            Ok(())
        }
        async fn after_create(&self, c: &OrganizationCreatedContext) -> AuthResult<()> {
            self.roles.lock().unwrap().push(c.member.role.clone());
            Ok(())
        }
    }
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let hooks = Arc::new(Hooks {
        store: Arc::new(store),
        roles: Mutex::new(Vec::new()),
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            creation_hooks: Some(hooks.clone()),
            teams: TeamsConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let result = body(
        &call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"Created","slug":"created"})),
                &cookies(&owner),
            ),
            200,
        )
        .await,
    );
    assert_eq!(result["members"][0]["role"], "owner");
    assert_eq!(*hooks.roles.lock().unwrap(), vec!["owner", "owner"]);
    let member_id = result["members"][0]["id"].as_str().unwrap();
    assert_eq!(
        db.text("SELECT role FROM member WHERE id=$1", &[member_id])
            .await?
            .as_deref(),
        Some("admin")
    );
    assert_eq!(db.count("team").await?, 1);
    assert_eq!(db.count("team_member").await?, 1);
    let token = body(&owner)["token"].as_str().unwrap().to_owned();
    assert_eq!(
        db.text(
            "SELECT active_organization_id FROM sessions WHERE token=$1",
            &[&token]
        )
        .await?
        .as_deref(),
        result["id"].as_str()
    );
    assert_eq!(
        db.text(
            "SELECT active_team_id FROM sessions WHERE token=$1",
            &[&token]
        )
        .await?,
        db.text("SELECT id FROM team", &[]).await?
    );
    assert_eq!(db.count("sessions").await?, 1);
    B::close(connection).await
}

async fn organization_creator_patch_retargeting_keeps_team_and_selection_actor<B: Backend>(
    db: Db,
) -> TestResult {
    #[derive(Debug, Default)]
    struct Hooks {
        target: Mutex<Option<(String, String)>>,
        actors: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl OrganizationCreationHooks for Hooks {
        async fn before_add_member(
            &self,
            c: &OrganizationMemberDraftContext,
        ) -> AuthResult<Option<OrganizationMemberCreatePatch>> {
            self.actors.lock().unwrap().push(c.user.id.clone());
            Ok(self.target.lock().unwrap().as_ref().map(|(org, user)| {
                OrganizationMemberCreatePatch {
                    organization_id: Some(org.clone()),
                    user_id: Some(user.clone()),
                    role: Some("member".into()),
                }
            }))
        }
        async fn after_create(&self, c: &OrganizationCreatedContext) -> AuthResult<()> {
            self.actors.lock().unwrap().push(c.user.id.clone());
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let hooks = Arc::new(Hooks::default());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            creation_hooks: Some(hooks.clone()),
            teams: TeamsConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let foreign = signup(&auth, "foreign@example.test").await;
    let actor = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let prior = body(
        &call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"Prior","slug":"prior"})),
                &cookies(&owner),
            ),
            200,
        )
        .await,
    );
    let prior_id = prior["id"].as_str().unwrap().to_owned();
    *hooks.target.lock().unwrap() = Some((prior_id.clone(), foreign_id.clone()));
    hooks.actors.lock().unwrap().clear();
    let foreign_token = body(&foreign)["token"].as_str().unwrap().to_owned();
    let before = db
        .text(
            "SELECT active_organization_id FROM sessions WHERE token=$1",
            &[&foreign_token],
        )
        .await?;
    let created = body(
        &call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"New","slug":"new"})),
                &cookies(&owner),
            ),
            200,
        )
        .await,
    );
    let id = created["id"].as_str().unwrap();
    assert_eq!(created["members"][0]["organizationId"], prior_id);
    assert_eq!(created["members"][0]["userId"], foreign_id);
    assert_eq!(
        *hooks.actors.lock().unwrap(),
        vec![actor.clone(), actor.clone()]
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM member WHERE organization_id=$1",
            &[id]
        )
        .await?,
        0
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM member WHERE organization_id=$1",
            &[&prior_id]
        )
        .await?,
        2
    );
    let team = db
        .text("SELECT id FROM team WHERE organization_id=$1", &[id])
        .await?
        .unwrap();
    assert_eq!(
        db.text("SELECT user_id FROM team_member WHERE team_id=$1", &[&team])
            .await?
            .as_deref(),
        Some(actor.as_str())
    );
    let token = body(&owner)["token"].as_str().unwrap().to_owned();
    assert_eq!(
        db.text(
            "SELECT active_organization_id FROM sessions WHERE token=$1",
            &[&token]
        )
        .await?
        .as_deref(),
        Some(id)
    );
    assert_eq!(
        db.text(
            "SELECT active_team_id FROM sessions WHERE token=$1",
            &[&token]
        )
        .await?
        .as_deref(),
        Some(team.as_str())
    );
    assert_eq!(
        db.text(
            "SELECT active_organization_id FROM sessions WHERE token=$1",
            &[&foreign_token]
        )
        .await?,
        before
    );
    B::close(connection).await
}

async fn organization_addition_after_hook_keeps_original_target_after_user_write<B: Backend>(
    db: Db,
) -> TestResult {
    struct Hooks<S: AuthSchema> {
        store: Arc<dyn alibi::AuthStore<S>>,
        before: Mutex<Vec<OrganizationMemberAdditionContext>>,
        after: Mutex<Vec<OrganizationMemberAddedContext>>,
    }
    impl<S: AuthSchema> std::fmt::Debug for Hooks<S> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("AdditionTargetWrite")
        }
    }
    #[async_trait]
    impl<S: AuthSchema> OrganizationMemberAdditionHooks for Hooks<S> {
        async fn before_add_member(
            &self,
            c: &OrganizationMemberAdditionContext,
        ) -> AuthResult<Option<OrganizationMemberCreatePatch>> {
            self.before.lock().unwrap().push(c.clone());
            _ = self
                .store
                .update_user(
                    &c.user.id,
                    alibi::UpdateUser {
                        name: Some("Stored Addition Target".into()),
                        ..Default::default()
                    },
                )
                .await?;
            Ok(None)
        }
        async fn after_add_member(&self, c: &OrganizationMemberAddedContext) -> AuthResult<()> {
            self.after.lock().unwrap().push(c.clone());
            Ok(())
        }
    }
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let hooks = Arc::new(Hooks {
        store: Arc::new(store),
        before: Mutex::new(Vec::new()),
        after: Mutex::new(Vec::new()),
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            member_addition_hooks: Some(hooks.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let target = signup(&auth, "target@example.test").await;
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
    let stable = db.tables(&["accounts", "sessions", "organization"]).await?;
    let target_id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let result = auth
        .dispatch_endpoint(
            OrganizationPlugin::add_member_endpoint(&serde_json::from_value(
                json!({"organizationId":org["id"],"userId":target_id,"role":"member"}),
            )?)?,
            alibi::endpoint::EndpointOptions::default(),
        )
        .await?
        .decode()?;
    let before = hooks.before.lock().unwrap()[0].clone();
    let after = hooks.after.lock().unwrap()[0].clone();
    assert_eq!(
        before.user.name.as_deref(),
        body(&target)["user"]["name"].as_str()
    );
    assert_eq!(after.user.name, before.user.name);
    assert_eq!(after.user.email, before.user.email);
    assert_eq!(after.user.id, target_id);
    assert_eq!(after.member.id, result.id);
    assert_eq!(
        db.text("SELECT name FROM users WHERE id=$1", &[&target_id])
            .await?
            .as_deref(),
        Some("Stored Addition Target")
    );
    assert_eq!(
        db.tables(&["accounts", "sessions", "organization"]).await?,
        stable
    );
    assert_eq!(db.count("member").await?, 2);
    authenticated(&auth, &cookies(&owner), "owner@example.test").await;
    B::close(connection).await
}

async fn organization_self_removal_after_rejection_clears_only_current_org_selection<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::AuthSession;
    struct Hooks<S: AuthSchema> {
        store: Arc<dyn alibi::AuthStore<S>>,
        token: Mutex<String>,
        after: Mutex<Vec<OrganizationMemberRemovalContext>>,
        observed: Mutex<Vec<(Option<String>, Option<String>)>>,
    }
    impl<S: AuthSchema> std::fmt::Debug for Hooks<S> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("SelfRemovalAfterVeto")
        }
    }
    #[async_trait]
    impl<S: AuthSchema> OrganizationMemberRemovalHooks for Hooks<S> {
        async fn after_remove(&self, c: &OrganizationMemberRemovalContext) -> AuthResult<()> {
            self.after.lock().unwrap().push(c.clone());
            let token = self.token.lock().unwrap().clone();
            let session = self.store.get_session(&token).await?.unwrap();
            self.observed.lock().unwrap().push((
                session.active_organization_id().map(str::to_owned),
                session.active_team_id().map(str::to_owned),
            ));
            Err(AuthError::Api {
                status: 400,
                code: Some("MEMBER_REMOVAL_HOOK_REJECTED".into()),
                message: "after removal rejected".into(),
            })
        }
    }
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let hooks = Arc::new(Hooks {
        store: Arc::new(store),
        token: Mutex::new(String::new()),
        after: Mutex::new(Vec::new()),
        observed: Mutex::new(Vec::new()),
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            member_removal_hooks: Some(hooks.clone()),
            teams: TeamsConfig {
                enabled: true,
                create_default_team: false,
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "owner@example.test").await;
    let target = signup(&auth, "target@example.test").await;
    let sibling = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"target@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
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
    let target_id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let member = auth
        .dispatch_endpoint(
            OrganizationPlugin::add_member_endpoint(&serde_json::from_value(
                json!({"organizationId":org["id"],"userId":target_id,"role":"owner"}),
            )?)?,
            alibi::endpoint::EndpointOptions::default(),
        )
        .await?
        .decode()?;
    let team = body(
        &call(
            &auth,
            request(
                "/organization/create-team",
                Some(json!({"organizationId":org["id"],"name":"Selected team"})),
                &cookies(&owner),
            ),
            200,
        )
        .await,
    );
    _ = call(
        &auth,
        request(
            "/organization/add-team-member",
            Some(json!({"organizationId":org["id"],"teamId":team["id"],"userId":target_id})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    for browser in [&target, &sibling] {
        _ = call(
            &auth,
            request(
                "/organization/set-active",
                Some(json!({"organizationId":org["id"]})),
                &cookies(browser),
            ),
            200,
        )
        .await;
        _ = call(
            &auth,
            request(
                "/organization/set-active-team",
                Some(json!({"teamId":team["id"]})),
                &cookies(browser),
            ),
            200,
        )
        .await;
    }
    let token = body(&target)["token"].as_str().unwrap().to_owned();
    let sibling_token = body(&sibling)["token"].as_str().unwrap().to_owned();
    *hooks.token.lock().unwrap() = token.clone();
    let stable = db.tables(&["users", "accounts", "organization"]).await?;
    let mut expected_team: Value = serde_json::from_str(&db.table("team").await?)?;
    expected_team[0]["member_count"] = json!(0);
    let denied = call(
        &auth,
        request(
            "/organization/remove-member",
            Some(json!({"organizationId":org["id"],"memberIdOrEmail":member.id})),
            &cookies(&target),
        ),
        400,
    )
    .await;
    assert_eq!(body(&denied)["code"], "MEMBER_REMOVAL_HOOK_REJECTED");
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM member WHERE id=$1", &[&member.id])
            .await?,
        0
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM team_member WHERE user_id=$1",
            &[&target_id]
        )
        .await?,
        0
    );
    assert_eq!(
        db.text(
            "SELECT active_organization_id FROM sessions WHERE token=$1",
            &[&token]
        )
        .await?,
        None
    );
    assert_eq!(
        db.text(
            "SELECT active_team_id FROM sessions WHERE token=$1",
            &[&token]
        )
        .await?
        .as_deref(),
        team["id"].as_str()
    );
    assert_eq!(
        db.text(
            "SELECT active_organization_id FROM sessions WHERE token=$1",
            &[&sibling_token]
        )
        .await?
        .as_deref(),
        org["id"].as_str()
    );
    assert_eq!(
        db.text(
            "SELECT active_team_id FROM sessions WHERE token=$1",
            &[&sibling_token]
        )
        .await?
        .as_deref(),
        team["id"].as_str()
    );
    assert_eq!(
        hooks.observed.lock().unwrap()[0],
        (None, Some(team["id"].as_str().unwrap().into()))
    );
    assert_eq!(hooks.after.lock().unwrap()[0].user.id, target_id);
    assert_eq!(
        db.tables(&["users", "accounts", "organization"]).await?,
        stable
    );
    assert_eq!(
        serde_json::from_str::<Value>(&db.table("team").await?)?,
        expected_team
    );
    authenticated(&auth, &cookies(&owner), "owner@example.test").await;
    B::close(connection).await
}

async fn organization_removal_callback_500_identity<B: Backend>(db: Db) -> TestResult {
    struct Hooks<S: AuthSchema> {
        store: Arc<dyn alibi::AuthStore<S>>,
        after: bool,
        database: bool,
        events: Mutex<Vec<&'static str>>,
    }
    impl<S: AuthSchema> std::fmt::Debug for Hooks<S> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("RemovalErrorIdentity")
        }
    }
    impl<S: AuthSchema> Hooks<S> {
        async fn phase(
            &self,
            c: &OrganizationMemberRemovalContext,
            phase: &'static str,
            fail: bool,
        ) -> AuthResult<()> {
            self.events.lock().unwrap().push(phase);
            if !fail {
                return Ok(());
            }
            if self.database {
                _ = self
                    .store
                    .update_user(
                        &c.user.id,
                        alibi::UpdateUser {
                            name: Some("Vetoed Write".into()),
                            ..Default::default()
                        },
                    )
                    .await?;
                Ok(())
            } else {
                Err(AuthError::Api {
                    status: 500,
                    code: Some("PUBLIC_REMOVAL_500".into()),
                    message: format!("{phase} explicit failure"),
                })
            }
        }
    }
    #[async_trait]
    impl<S: AuthSchema> OrganizationMemberRemovalHooks for Hooks<S> {
        async fn before_remove(&self, c: &OrganizationMemberRemovalContext) -> AuthResult<()> {
            self.phase(c, "before", !self.after).await
        }
        async fn after_remove(&self, c: &OrganizationMemberRemovalContext) -> AuthResult<()> {
            self.phase(c, "after", self.after).await
        }
    }
    for after in [false, true] {
        for database in [false, true] {
            let db = db.fresh().await?;
            let (connection, store) = db.migrated::<B>(SECRET).await?;
            let hooks = Arc::new(Hooks {
                store: Arc::new(store),
                after,
                database,
                events: Mutex::new(Vec::new()),
            });
            let auth = super::auth_probe::fast_builder::<B>(&connection)
                .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                    member_removal_hooks: Some(hooks.clone()),
                    teams: TeamsConfig {
                        enabled: true,
                        create_default_team: false,
                        ..Default::default()
                    },
                    ..Default::default()
                }))
                .build()
                .await?;

            let owner = signup(&auth, "owner@example.test").await;
            let target = signup(&auth, "target@example.test").await;
            let foreign = signup(&auth, "foreign@example.test").await;
            let target_id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
            let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
            let org=body(&call(&auth,request("/organization/create",Some(json!({"name":"Original Organization","slug":"owned","metadata":{"original":true}})),&cookies(&owner)),200).await);
            let other = body(
                &call(
                    &auth,
                    request(
                        "/organization/create",
                        Some(json!({"name":"Foreign Organization","slug":"foreign"})),
                        &cookies(&foreign),
                    ),
                    200,
                )
                .await,
            );
            let mut members = Vec::new();
            let mut teams = Vec::new();
            for (organization, actor) in [(&org, &owner), (&other, &foreign)] {
                let member=auth.dispatch_endpoint(OrganizationPlugin::add_member_endpoint(&serde_json::from_value(json!({"organizationId":organization["id"],"userId":target_id,"role":"member"}))?)?,alibi::endpoint::EndpointOptions::default()).await?.decode()?;
                members.push(member);
                let team = body(
                    &call(
                        &auth,
                        request(
                            "/organization/create-team",
                            Some(json!({"organizationId":organization["id"],"name":"Seat"})),
                            &cookies(actor),
                        ),
                        200,
                    )
                    .await,
                );
                let _=call(&auth,request("/organization/add-team-member",Some(json!({"organizationId":organization["id"],"teamId":team["id"],"userId":target_id})),&cookies(actor)),200).await;
                teams.push(team);
            }
            let original = members.first().unwrap();
            let own_team = teams.first().unwrap()["id"].as_str().unwrap().to_owned();
            let foreign_team = teams.last().unwrap()["id"].as_str().unwrap().to_owned();

            if database {
                _=db.execute(&format!("CREATE TRIGGER veto_target_name BEFORE UPDATE OF name ON users WHEN NEW.id='{}' BEGIN SELECT RAISE(ABORT,'application callback database failure'); END",target_id),&[]).await?;
            }
            let stable = db
                .tables(&["users", "accounts", "sessions", "organization"])
                .await?;
            let failed = call(
                &auth,
                request(
                    "/organization/remove-member",
                    Some(json!({"organizationId":org["id"],"memberIdOrEmail":original.id})),
                    &cookies(&owner),
                ),
                500,
            )
            .await;
            assert_eq!(failed.headers.get_all("set-cookie").count(), 0);
            if database {
                assert!(failed.body.is_empty());
                assert!(failed.headers.get("content-type").is_none());
            } else {
                assert_eq!(
                    body(&failed),
                    json!({"code":"PUBLIC_REMOVAL_500","message":format!("{} explicit failure",if after {"after"} else {"before"})})
                );
                assert!(
                    failed
                        .headers
                        .get("content-type")
                        .unwrap()
                        .contains("application/json")
                );
            }
            assert_eq!(
                *hooks.events.lock().unwrap(),
                if after {
                    vec!["before", "after"]
                } else {
                    vec!["before"]
                }
            );
            assert_eq!(
                db.count_where("SELECT COUNT(*) FROM member WHERE id=$1", &[&original.id])
                    .await?,
                i64::from(!after)
            );
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM team_member WHERE team_id=$1",
                    &[&own_team]
                )
                .await?,
                i64::from(!after)
            );
            assert_eq!(
                db.count_where("SELECT member_count FROM team WHERE id=$1", &[&own_team])
                    .await?,
                i64::from(!after)
            );
            assert_eq!(
                db.count_where(
                    "SELECT member_count FROM team WHERE id=$1",
                    &[&foreign_team]
                )
                .await?,
                1
            );
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "organization"])
                    .await?,
                stable
            );
            let _ = owner_id;
            B::close(connection).await?;
        }
    }
    Ok(())
}
