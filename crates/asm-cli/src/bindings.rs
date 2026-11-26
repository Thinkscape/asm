//! Shared catalog and capability checks for file and environment delivery.

use crate::api::Api;
use crate::error::CliError;
use asm_proto::bindings::SecretBinding;
use asm_proto::generators::GenerationRequest;
use asm_proto::names::resolve_catalog_name;
use asm_proto::wire::{
    CAPABILITY_BROADER_LEASE_REUSE_V1, CAPABILITY_GCLOUD_ACCESS_V1, CAPABILITY_GENERATED_CREDENTIALS_V1,
    CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1, CAPABILITY_OPERATOR_SELECTED_GRANT_V1,
    CAPABILITY_OPERATOR_SELECTED_PROJECT_V1, CAPABILITY_SECRET_FIELDS_V1,
    HealthResponse, SecretEntry, SecretsResponse,
};

#[derive(Clone, Copy, Default)]
pub(crate) struct GetCapabilities {
    pub(crate) operator_selected_grant: bool,
    pub(crate) operator_selected_project: bool,
    pub(crate) broader_lease_reuse: bool,
}

pub(crate) fn require_capabilities(
    api: &Api, generated: bool, fields: bool, provider: Option<&str>,
) -> Result<GetCapabilities, CliError> {
    if !generated && !fields && provider.is_none() {
        return Ok(GetCapabilities::default());
    }
    let health: HealthResponse = api.get("/health")?;
    for capability in [
        generated.then_some(CAPABILITY_GENERATED_CREDENTIALS_V1),
        fields.then_some(CAPABILITY_SECRET_FIELDS_V1),
        provider,
    ].into_iter().flatten() {
        health.require_capability(capability)?;
    }
    Ok(GetCapabilities {
        operator_selected_grant: health.capabilities.iter().any(|c| c == CAPABILITY_OPERATOR_SELECTED_GRANT_V1),
        operator_selected_project: health.capabilities.iter().any(|c| c == CAPABILITY_OPERATOR_SELECTED_PROJECT_V1),
        broader_lease_reuse: health.capabilities.iter().any(|c| c == CAPABILITY_BROADER_LEASE_REUSE_V1),
    })
}

impl GetCapabilities {
    pub(crate) fn client_capabilities(
        self, generation: Option<&GenerationRequest>, pinned: bool, new_lease: bool,
    ) -> Vec<String> {
        let project = (self.operator_selected_project && !pinned
            && matches!(generation, Some(GenerationRequest::GcloudAccess(_))))
            .then_some(CAPABILITY_OPERATOR_SELECTED_PROJECT_V1);
        let reuse = (self.broader_lease_reuse && generation.is_some() && !pinned && !new_lease)
            .then_some(CAPABILITY_BROADER_LEASE_REUSE_V1);
        [
            CAPABILITY_GENERATED_CREDENTIALS_V1,
            CAPABILITY_SECRET_FIELDS_V1,
            CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1,
            CAPABILITY_GCLOUD_ACCESS_V1,
            CAPABILITY_OPERATOR_SELECTED_GRANT_V1,
        ].into_iter().chain(project).chain(reuse).map(str::to_owned).collect()
    }
}

pub(crate) fn catalog(api: &Api) -> Result<Vec<SecretEntry>, CliError> {
    let response: SecretsResponse = api.get("/secrets")?;
    Ok(response.secrets)
}

pub(crate) struct ResolvedBinding {
    pub binding: SecretBinding,
    pub request_name: String,
    pub canonical_key: String,
    pub generated_output: Option<&'static str>,
    pub available_fields: Vec<String>,
}

pub(crate) fn resolve(binding: SecretBinding, entries: &[SecretEntry]) -> Result<ResolvedBinding, CliError> {
    let resolved = resolve_catalog_name(&binding.source, entries)?;
    let entry = &entries[resolved.entry_index];
    if let Some(field) = &binding.field {
        if !entry.fields.contains(field) {
            return Err(CliError::invalid(format!("unknown field {field}; available fields: {}", entry.fields.join(", "))));
        }
    }
    if binding.destination.is_some() && binding.field.is_none() && entry.fields.len() != 1 {
        return Err(CliError::invalid(format!("select a field with DEST=SOURCE::FIELD; available fields: {}", entry.fields.join(", "))));
    }
    Ok(ResolvedBinding {
        binding,
        request_name: resolved.request_name,
        canonical_key: resolved.canonical_key,
        generated_output: resolved.generated_output,
        available_fields: entry.fields.clone(),
    })
}

pub(crate) fn environment_name(name: &str) -> bool {
    let mut chars = name.bytes();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}


pub(crate) fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Quote a catalog name for the binding grammar, before shell quoting it.
pub(crate) fn binding_escape(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if matches!(c, '\\' | '=' | ',' | ':') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
