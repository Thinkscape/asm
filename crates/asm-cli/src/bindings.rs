//! Shared catalog and capability checks for file and environment delivery.

use crate::api::Api;
use crate::error::CliError;
use asm_proto::bindings::SecretBinding;
use asm_proto::generators::SourceKind;
use asm_proto::names::resolve_catalog_name;
use asm_proto::wire::{
    HealthResponse, SecretEntry, SecretsResponse, CAPABILITY_GENERATED_CREDENTIALS_V1,
    CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1, CAPABILITY_SECRET_FIELDS_V1,
};

pub(crate) fn require_capabilities(api: &Api, generated: bool, fields: bool, github_scope: bool) -> Result<(), CliError> {
    if !generated && !fields && !github_scope {
        return Ok(());
    }
    let health: HealthResponse = api.get("/health")?;
    for (needed, capability) in [
        (generated, CAPABILITY_GENERATED_CREDENTIALS_V1),
        (fields, CAPABILITY_SECRET_FIELDS_V1),
        (github_scope, CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1),
    ] {
        if needed && !health.capabilities.iter().any(|c| c == capability) {
            return Err(CliError::invalid(format!("this operation requires {capability}; upgrade the manager")));
        }
    }
    Ok(())
}

pub(crate) fn capabilities() -> Vec<String> {
    vec![
        CAPABILITY_GENERATED_CREDENTIALS_V1.into(),
        CAPABILITY_SECRET_FIELDS_V1.into(),
        CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1.into(),
    ]
}

pub(crate) fn catalog(api: &Api) -> Result<Vec<SecretEntry>, CliError> {
    let response: SecretsResponse = api.get("/secrets")?;
    Ok(response.secrets)
}

pub(crate) struct ResolvedBinding {
    pub binding: SecretBinding,
    pub request_name: String,
    pub canonical_key: String,
    pub generated: bool,
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
        generated: entry.source_kind == SourceKind::Generator,
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
