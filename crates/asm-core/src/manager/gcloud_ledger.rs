//! Local-only inventory and retirement of journaled Google service accounts.

use std::collections::HashSet;
use std::sync::Arc;

use asm_proto::wire::LeaseMode;
use serde_json::json;

use super::activity::{Category, Event};
use super::{Core, TOPIC_GCLOUD_ACCOUNTS, TOPIC_LEASES, TOPIC_REQUESTS, lock, to_system_time};
use crate::error::{CoreError, Result};
use crate::ffi::{GcloudOwnedAccount, GcloudOwnedAccountDelete, GcloudOwnedAccountLease, GcloudOwnedAccountState};
use crate::generator::{GeneratorClient, GeneratorConfig, GeneratorEntry};
use crate::store::{GcloudAccountDeletion, GcloudManagedAccount, GcloudProfilePhase, gcloud_profile_email};

fn stale_confirmation() -> CoreError {
    CoreError::invalid("Google service account, connection, or dependent leases changed; review the current account and confirm again")
}

fn verified_uid(account: &GcloudManagedAccount) -> Result<&str> {
    account.profile.unique_id.as_deref().filter(|uid| {
        !uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit())
    }).filter(|_| account.profile.phase != GcloudProfilePhase::Creating)
        .ok_or_else(|| CoreError::invalid("ASM never received an immutable Google service account ID; verify ownership in Google Cloud before manual cleanup"))
}

fn deletion_client(account: &GcloudManagedAccount, entry: Option<&GeneratorEntry>) -> Result<Arc<GeneratorClient>> {
    if account.deletion == GcloudAccountDeletion::Deleted {
        return Err(CoreError::invalid("this service account has already been deleted"));
    }
    if account.superseded {
        return Err(CoreError::invalid("this superseded creation attempt is not safe to delete automatically"));
    }
    verified_uid(account)?;
    let entry = entry.ok_or_else(|| CoreError::invalid("the original Google Cloud connection is no longer configured"))?;
    let GeneratorConfig::GcloudConnection(config) = &entry.record.config else {
        return Err(stale_confirmation());
    };
    if entry.record.id != account.key.generator_id || config.account_subject != account.key.account_subject
        || config.account_email != account.profile.admin_email
    {
        return Err(CoreError::invalid("the saved Google identity does not match the original account creator"));
    }
    let client = entry.client()?;
    if !client.matches_config(&entry.record.config) {
        return Err(stale_confirmation());
    }
    Ok(client)
}

impl Core {
    pub(crate) fn has_recorded_gcloud_accounts(&self) -> Result<bool> {
        self.store.has_recorded_gcloud_accounts()
    }

    pub(crate) fn list_gcloud_owned_accounts(&self) -> Result<Vec<GcloudOwnedAccount>> {
        let _authority = lock(&self.authorization);
        let accounts = self.store.list_gcloud_managed_accounts()?;
        let now = self.generation_now();
        let mut host_names = self.host_names();
        Ok(accounts.into_iter().map(|account| {
            let entry = self.generators.get(&account.key.generator_id);
            let blocked = deletion_client(&account, entry.as_ref()).err();
            let state = match (account.deletion, account.profile.phase) {
                (GcloudAccountDeletion::Pending, _) => GcloudOwnedAccountState::DeletionPending,
                (GcloudAccountDeletion::Deleted, _) => GcloudOwnedAccountState::Deleted,
                (_, GcloudProfilePhase::Creating) => GcloudOwnedAccountState::Creating,
                (_, GcloudProfilePhase::Created) => GcloudOwnedAccountState::Created,
                (_, GcloudProfilePhase::ProjectBound) => GcloudOwnedAccountState::ProjectBound,
                (_, GcloudProfilePhase::TokenCreatorBound) => GcloudOwnedAccountState::TokenCreatorBound,
                (_, GcloudProfilePhase::Ready) => GcloudOwnedAccountState::Ready,
            };
            let project = &account.key.access.project_id;
            let email = gcloud_profile_email(project, &account.profile.account_id);
            GcloudOwnedAccount {
                id: account.id, generator_id: account.key.generator_id,
                generator_name: entry.as_ref().map(|entry| entry.record.name.clone()),
                generator_revision: entry.as_ref().map(|entry| entry.record.revision),
                generator_status: entry.as_ref().map(|entry| entry.status().into()),
                project_id: account.key.access.project_id, account_name: account.profile.account_id,
                account_email: email, account_unique_id: account.profile.unique_id,
                operator_email: account.profile.admin_email,
                permissions: account.key.access.permissions.into_iter().map(Into::into).collect(),
                state, superseded: account.superseded, deletable: blocked.is_none(),
                blocking_reason: blocked.map(|error| error.message),
                leases: account.leases.into_iter().map(|lease| {
                    let status = lease.status(now).into();
                    let host_label = host_names.get(&lease.host_id)
                        .map_or_else(|| lease.host_id.clone(), |(label, _)| label.clone());
                    GcloudOwnedAccountLease { id: lease.id, host_label, agent_label: lease.agent,
                        status, deadline: lease.expires_at.map(to_system_time) }
                }).collect(),
            }
        }).collect())
    }

    pub(super) fn check_gcloud_account_not_retired(&self, unique_id: &str) -> Result<()> {
        if self.store.gcloud_account_is_retired(unique_id)? {
            return Err(CoreError::vault_unavailable("the immutable Google service account has been retired"));
        }
        Ok(())
    }

    /// The native confirmation names the exact immutable account, saved connection
    /// revision and lease set. Persist the retirement and remove local authority in
    /// one transaction before using any provider credential or endpoint.
    pub(crate) fn delete_gcloud_owned_account(&self, target: GcloudOwnedAccountDelete) -> Result<()> {
        if !target.confirmed {
            return Err(CoreError::invalid("explicit local confirmation is required to delete a Google service account"));
        }
        let uid = target.account_unique_id.as_str();
        let (account, pending, entry, client, flight, tokens, cutover, request_cleanup) = {
            let authority = lock(&self.authorization);
            self.check_gcloud_delete_shutdown()?;
            let account = self.store.gcloud_managed_account(target.profile_id)?.ok_or_else(stale_confirmation)?;
            let email = gcloud_profile_email(&account.key.access.project_id, &account.profile.account_id);
            let actual: HashSet<_> = account.leases.iter().map(|lease| lease.id.as_str()).collect();
            let expected: HashSet<_> = target.expected_lease_ids.iter().map(String::as_str).collect();
            if target.generator_id != account.key.generator_id || target.project_id != account.key.access.project_id
                || target.account_name != account.profile.account_id || target.account_email != email
                || verified_uid(&account)? != uid || expected.len() != target.expected_lease_ids.len() || expected != actual
            {
                return Err(stale_confirmation());
            }
            let (entry, client) = self.gcloud_delete_connection(&account, target.generator_revision)?;
            let flight = self.gcloud_profiles.start_delete(&account.key, uid)?;
            let pending = self.store.begin_gcloud_account_deletion(&account, target.generator_revision)?;
            self.gcloud_profiles.invalidate_deleted_profile_plans(&account.key);
            let mut tokens = Vec::new();
            let mut request_cleanup = Ok(());
            lock(&self.book).done.retain(|id, done| {
                if done.generated.as_ref().is_some_and(|d| actual.contains(d.lease_id.as_str())) {
                    if let Err(error) = self.delete_book_row(id) {
                        request_cleanup = Err(error);
                    }
                    false
                } else {
                    true
                }
            });
            for lease in &account.leases {
                tokens.extend(self.evict_generated_locked(lease, &authority));
            }
            lock(&self.last_active).retain(|id| !actual.contains(id.as_str()));
            let cutover = if account.leases.iter().any(|lease| lease.mode == LeaseMode::Sentinel) {
                self.publish_proxy_account_retirement_locked(&authority, account.id)
            } else if lock(&self.proxy_state).account_cutovers.contains(&account.id) {
                // A failed first publication stopped the old process but may not
                // have written the reduced desired set. Retry it before cloud work.
                self.publish_proxy_locked(&authority)
            } else {
                Ok(())
            };
            (account, pending, entry, client, flight, tokens, cutover, request_cleanup)
        };

        self.log_gcloud_account_retirement("gcloud_account_deletion_started", "Google service account retirement recorded; local leases removed", &account, &target, None);
        self.revoke_tokens(tokens);
        self.notify_proxy_changed();
        self.notify(TOPIC_LEASES);
        self.bump();
        self.notify(TOPIC_REQUESTS);
        self.notify(TOPIC_GCLOUD_ACCOUNTS);
        request_cleanup?;

        let gate = || {
            let _authority = lock(&self.authorization);
            self.check_gcloud_delete_shutdown()?;
            let (_, live) = self.gcloud_delete_connection(&pending, target.generator_revision)?;
            if !Arc::ptr_eq(&client, &live) || self.store.gcloud_managed_account(pending.id)?.as_ref() != Some(&pending) {
                return Err(stale_confirmation());
            }
            Ok(())
        };
        let outcome = (|| {
            cutover.map_err(|_| CoreError::vault_unavailable("local leases were removed and the old proxy was stopped, but its reduced configuration could not be published; restore proxy health and retry"))?;
            gate()?;
            self.with_gcloud_connection_parent(&entry, |http, token, identity| {
                if identity.subject != pending.key.account_subject || identity.email != pending.profile.admin_email {
                    return Err(CoreError::unauthorized("verified Google identity does not match the original account creator"));
                }
                gate()?;
                http.delete_profile_account(token, &pending.key.access, uid, &target.account_email, identity, gate)
            })?;
            // A successful provider response is durable cleanup evidence, even when
            // shutdown was requested while waiting. The flight keeps the journal open.
            let _authority = lock(&self.authorization);
            self.store.finish_gcloud_account_deletion(&pending)
        })();
        let outcome = match outcome {
            Ok(()) => {
                self.log_gcloud_account_retirement("gcloud_account_deleted", "Google service account deletion confirmed", &account, &target, None);
                Ok(())
            }
            Err(error) => {
                self.log_gcloud_account_retirement("gcloud_account_deletion_pending", "Google service account deletion not completed; local delivery remains stopped", &account, &target, Some(&error.message));
                Err(CoreError::new(error.code, format!("{}. The local leases are gone. Review and retry deletion for the same immutable Google account.", error.message.trim_end_matches('.'))))
            }
        };
        drop(flight);
        self.notify(TOPIC_GCLOUD_ACCOUNTS);
        outcome
    }

    fn check_gcloud_delete_shutdown(&self) -> Result<()> {
        if lock(&self.generation).shutting_down {
            return Err(CoreError::vault_unavailable("manager is shutting down"));
        }
        Ok(())
    }

    fn gcloud_delete_connection(&self, account: &GcloudManagedAccount, revision: u64) -> Result<(GeneratorEntry, Arc<GeneratorClient>)> {
        let entry = self.generators.get(&account.key.generator_id);
        let client = deletion_client(account, entry.as_ref())?;
        let entry = entry.ok_or_else(stale_confirmation)?;
        if entry.record.revision != revision || self.store.get_generator(&entry.record.id)?.as_ref() != Some(&entry.record) {
            return Err(stale_confirmation());
        }
        Ok((entry, client))
    }

    fn log_gcloud_account_retirement(&self, kind: &'static str, summary: &str, account: &GcloudManagedAccount,
        target: &GcloudOwnedAccountDelete, status: Option<&str>,
    ) {
        self.log(Event::new(Category::Generators, kind, format!("{summary}: {}", target.account_email))
            .detail(json!({ "profile_id": account.id, "generator_id": target.generator_id,
                "generator_revision": target.generator_revision, "project": target.project_id,
                "service_account_email": target.account_email, "service_account_unique_id": target.account_unique_id,
                "operator_email": account.profile.admin_email, "lease_ids": target.expected_lease_ids, "status": status,
            })));
    }
}
