//! File-free acquisition followed by direct process replacement. No Session/reaper path.

use crate::api::Api;
use crate::bindings;
use crate::delivery::Delivery;
use crate::error::CliError;
use crate::requests::{self, GenerationArgs, submit_get};
use crate::state;
use asm_proto::generators::{
    CREDENTIAL_REFRESH_MARGIN_SECS, GCLOUD_TOKEN_NAME, GITHUB_TOKEN_ALIAS, GITHUB_TOKEN_NAME, GenerationRequest,
    generated_output_names,
};
use asm_proto::wire::{
    GetResult, LeaseInfo, LeaseStatus, LeasesResponse, RequestBody, RequestedMode,
};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

#[derive(clap::Args)]
pub struct ExecArgs {
    #[arg(long, conflicts_with = "sentinel")]
    raw: bool,
    /// Require substitution for static bindings. Cannot be combined with generated bindings.
    #[arg(long, conflicts_with = "raw")]
    sentinel: bool,
    /// Proxy destination restrictions for static bindings only.
    #[arg(long, value_delimiter = ',')]
    hosts: Vec<String>,
    #[arg(long)]
    reason: Option<String>,
    #[command(flatten)]
    generation_args: GenerationArgs,
    /// Explicit OAuth scope URI for a legacy bound Google generator; repeat or separate with commas.
    #[arg(long = "gcloud-scope", value_name = "URI", value_delimiter = ',')]
    gcloud_scopes: Vec<String>,
    /// Overall acquisition budget, excluding discovery, proxy preparation and the child.
    #[arg(long)]
    wait: Option<u64>,
    /// Comma-separated [DEST=]SOURCE[::FIELD] bindings.
    bindings: String,
    /// Exact executable and arguments, following a required literal -- separator.
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<OsString>,
}

struct Acquisition {
    key: String,
    name: String,
    generated_output: Option<&'static str>,
    fields: Vec<String>,
    result: Option<GetResult>,
}

struct Destination {
    name: String,
    group: usize,
    field: String,
}

fn plan(input: &str, entries: &[asm_proto::wire::SecretEntry]) -> Result<(Vec<Acquisition>, Vec<Destination>), CliError> {
    let mut groups: Vec<Acquisition> = Vec::new();
    let mut destinations: Vec<Destination> = Vec::new();
    let mut assigned: HashMap<String, (usize, String)> = HashMap::new();
    for binding in asm_proto::bindings::parse_bindings(input)? {
        let resolved = bindings::resolve(binding, entries)?;
        let field = match &resolved.binding.field {
            Some(field) => field.clone(),
            None if resolved.available_fields.len() == 1 => resolved.available_fields[0].clone(),
            None => return Err(CliError::invalid(format!("use DEST=SOURCE::FIELD; available fields: {}", resolved.available_fields.join(", ")))),
        };
        if resolved.available_fields.len() > 1 && resolved.binding.destination.is_none() {
            return Err(CliError::invalid(format!("structured fields require DEST=SOURCE::FIELD; available fields: {}", resolved.available_fields.join(", "))));
        }
        let single_name;
        let names = match (&resolved.binding.destination, resolved.generated_output) {
            (Some(destination), _) => {
                single_name = [destination.as_str()];
                &single_name[..]
            }
            (None, Some(output)) => generated_output_names(output).expect("resolved generator output"),
            (None, None) => {
                let leaf = resolved.binding.source.rsplit('/').next().unwrap_or("");
                if !bindings::environment_name(leaf) {
                    return Err(CliError::invalid("this source needs an explicit DEST= binding"));
                }
                single_name = [leaf];
                &single_name[..]
            }
        };
        let group = groups.iter().position(|g| g.key == resolved.canonical_key).unwrap_or_else(|| {
            let index = groups.len();
            groups.push(Acquisition {
                key: resolved.canonical_key,
                name: resolved.request_name,
                generated_output: resolved.generated_output,
                fields: Vec::new(),
                result: None,
            });
            index
        });
        if !groups[group].fields.contains(&field) {
            groups[group].fields.push(field.clone());
        }
        for &name in names {
            if crate::proxy::ENV_NAMES.iter().any(|key| name.eq_ignore_ascii_case(key)) {
                return Err(CliError::invalid(format!("{name} is reserved for proxy/CA settings")));
            }
            if let Some((old_group, old_field)) = assigned.get(name) {
                if *old_group != group || old_field != &field {
                    return Err(CliError::invalid(format!("conflicting bindings for {name}")));
                }
                continue;
            }
            assigned.insert(name.to_owned(), (group, field.clone()));
            destinations.push(Destination { name: name.to_owned(), group, field: field.clone() });
        }
    }
    if let (Some(a), Some(b)) = (assigned.get(GITHUB_TOKEN_NAME), assigned.get(GITHUB_TOKEN_ALIAS)) {
        if [a, b].iter().any(|binding| groups[binding.0].generated_output == Some(GITHUB_TOKEN_NAME)) && a != b {
            return Err(CliError::invalid("GH_TOKEN and GITHUB_TOKEN must identify the same generated credential; use custom destinations for different apps"));
        }
    }
    for group in &mut groups {
        group.fields.sort();
    }
    Ok((groups, destinations))
}

fn body(
    name: String,
    fields: Vec<String>,
    mode: RequestedMode,
    hosts: Vec<String>,
    reason: String,
    lease_id: Option<String>,
    generation: Option<GenerationRequest>,
    capabilities: bindings::GetCapabilities,
) -> RequestBody {
    let client_capabilities = capabilities.client_capabilities(generation.as_ref(), lease_id.is_some());
    RequestBody::Get {
        name, fields: Some(fields), raw: mode == RequestedMode::Raw,
        sentinel: mode == RequestedMode::Sentinel, hosts, reason, lease_id,
        generation, refresh: false, refresh_from_version: None, new_lease: false,
        client_capabilities, agent: crate::hostinfo::agent_label(),
    }
}

fn changed() -> CliError {
    CliError::failure("credentials changed before launch; rerun asm exec")
}

fn authority<'a>(leases: &'a LeasesResponse, group: &Acquisition) -> Result<&'a LeaseInfo, CliError> {
    let result = group.result.as_ref().expect("acquired");
    let lease = leases.leases.iter().find(|l| l.lease_id == result.lease_id).ok_or_else(changed)?;
    if lease.status != LeaseStatus::Active
        || lease.mode != result.mode
        || lease.expires_at.as_deref().is_some_and(|t| asm_proto::time::parse_unix(t).is_none_or(|t| t <= requests::unix_now()))
        || group.fields.iter().any(|field| !lease.fields.contains(field))
        || lease.generation != result.generation
        || (group.generated_output.is_some() && lease.generation.is_none())
    {
        return Err(changed());
    }
    Ok(lease)
}

fn headroom(expiry: Option<&str>) -> bool {
    expiry.and_then(asm_proto::time::parse_unix).is_some_and(|t| t > requests::unix_now() + CREDENTIAL_REFRESH_MARGIN_SECS)
}

fn default_reason(command: &std::ffi::OsStr) -> String {
    let basename = Path::new(command).file_name().and_then(|s| s.to_str());
    if let Some(name) = basename.filter(|name| !name.is_empty()) {
        let candidate = format!("Run {name} with approved credentials");
        if asm_proto::rules::validate_reason(&candidate).is_ok() {
            return candidate;
        }
    }
    "Run command with approved credentials".into()
}

pub fn run(args: ExecArgs) -> Result<(), CliError> {
    let executable = args.command.first().filter(|s| !s.is_empty()).ok_or_else(|| CliError::invalid("a command is required after --"))?;
    let hosts = requests::parse_hosts(&args.hosts)?;
    let default_reason = default_reason(executable);
    let reason = asm_proto::rules::validate_reason(args.reason.as_deref().unwrap_or(&default_reason))?;
    let mode = RequestedMode::from_flags(args.raw, args.sentinel)?;
    let mut selectors = args.generation_args.into_selectors(args.gcloud_scopes)?;
    let host = state::require()?;
    let api = Api::for_host(&host)?;
    bindings::require_capabilities(&api, false, true, None)?;
    let entries = bindings::catalog(&api)?;
    let (mut groups, destinations) = plan(&args.bindings, &entries)?;
    let mut github_groups = groups.iter().filter(|g| g.generated_output == Some(GITHUB_TOKEN_NAME)).count();
    let mut google_groups = groups.iter().filter(|g| g.generated_output == Some(GCLOUD_TOKEN_NAME)).count();
    let generated_groups = github_groups + google_groups;
    let generated = generated_groups != 0;
    let has_static = generated_groups < groups.len();
    let generated_mode = if generated {
        mode.for_new_generated(if has_static { &[] } else { &hosts })?
    } else {
        mode
    };
    if github_groups != 0 && matches!(&selectors.google, Some(GenerationRequest::GcloudAccess(_))) {
        return Err(CliError::invalid("managed Google Cloud and GitHub credentials require separate asm exec commands; --permissions cannot select both"));
    }
    match (github_groups, selectors.github.is_some()) {
        (0, true) => return Err(CliError::invalid("--repositories and --permissions require a generated GitHub binding")),
        (1.., false) => return Err(requests::github_repositories_required()),
        _ => {}
    }
    match (google_groups, selectors.google.is_some()) {
        (0, true) => return Err(CliError::invalid("Google Cloud generation flags require a generated Google Cloud binding")),
        (1.., false) => return Err(requests::gcloud_access_required()),
        _ => {}
    }
    let capabilities = bindings::require_capabilities(&api, generated, true, selectors.capability())?;

    let mut deadline = requests::deadline(args.wait);
    for group in &mut groups {
        let generation = match group.generated_output {
            Some(GITHUB_TOKEN_NAME) => {
                github_groups -= 1;
                if github_groups == 0 { selectors.github.take() } else { selectors.github.clone() }
            }
            Some(GCLOUD_TOKEN_NAME) => {
                google_groups -= 1;
                if google_groups == 0 { selectors.google.take() } else { selectors.google.clone() }
            }
            _ => None,
        };
        let (mode, hosts) = if group.generated_output.is_some() {
            (generated_mode, Vec::new())
        } else {
            (mode, hosts.clone())
        };
        let mut request = body(group.name.clone(), group.fields.clone(), mode, hosts, reason.clone(), None, generation, capabilities);
        request.canonicalize()?;
        group.result = Some(submit_get(&api, &request, deadline, None, capabilities)?);
    }
    // Inspect current authority without reconciling any local get files.
    let leases: LeasesResponse = api.get_until("/leases", deadline)?;
    for group in &mut groups {
        let lease = authority(&leases, group)?;
        let result = group.result.as_ref().expect("acquired");
        if group.generated_output.is_some() && (lease.credential_version != result.credential_version || !headroom(result.credential_expires_at.as_deref()) || !headroom(lease.credential_expires_at.as_deref())) {
            let request = body(lease.name.clone(), group.fields.clone(), RequestedMode::Raw, Vec::new(), reason.clone(), Some(lease.lease_id.clone()), requests::replay_managed_claims(lease.generation.as_ref()), capabilities);
            group.result = Some(submit_get(&api, &request, deadline, Some(lease), capabilities)?);
        }
    }
    let needs_proxy = groups.iter().any(|g| {
        let result = g.result.as_ref().expect("acquired");
        result.files.iter().any(|f| Delivery::from_field(result.mode, f.substituted) != Delivery::Raw)
    });
    let preparation = Instant::now();
    let proxy_env = if needs_proxy { crate::proxy::environment(&host, &api)? } else { Vec::new() };
    // Proxy/CA preparation is deliberately outside the acquisition wait budget.
    if let Some(until) = &mut deadline {
        *until += preparation.elapsed();
    }
    let leases: LeasesResponse = api.get_until("/leases", deadline)?;
    for group in &groups {
        let lease = authority(&leases, group)?;
        let result = group.result.as_ref().expect("acquired");
        if group.generated_output.is_some() && (lease.credential_version != result.credential_version || !headroom(result.credential_expires_at.as_deref()) || !headroom(lease.credential_expires_at.as_deref())) {
            return Err(changed());
        }
    }
    let mut command = Command::new(executable);
    command.args(&args.command[1..]);
    for destination in destinations {
        let result = groups[destination.group].result.as_ref().expect("acquired");
        let file = result.files.iter().find(|f| f.field == destination.field).ok_or_else(changed)?;
        if file.content.contains('\0') {
            return Err(CliError::failure("a credential contains NUL and cannot be placed in the child environment"));
        }
        Delivery::from_field(result.mode, file.substituted).report(&destination.name);
        command.env(destination.name, &file.content);
    }
    if needs_proxy {
        eprintln!("asm exec configured the proxy and CA for this command.");
        crate::delivery::proxy_hint();
    }
    for (key, value) in proxy_env {
        command.env_remove(key.to_ascii_lowercase());
        command.env(key, value);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = command.exec();
        let code = if error.kind() == std::io::ErrorKind::NotFound { 127 } else { 126 };
        Err(CliError::new(code, format!("could not execute command: {}", error.kind())))
    }
    #[cfg(not(unix))]
    {
        Err(CliError::failure("direct command execution is unsupported on this platform"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entries() -> Vec<asm_proto::wire::SecretEntry> {
        serde_json::from_value(json!([
            {"name":"GH_TOKEN","aliases":["GITHUB_TOKEN"],"source_kind":"generator","generators":[{"generator_id":"app","name":"release-bot"}],"vault":"GitHub App","kind":"single","fields":["value"],"lease":null},
            {"name":"CLOUDSDK_AUTH_ACCESS_TOKEN","source_kind":"generator","generators":[{"generator_id":"gcp","name":"gcloud-dev"}],"vault":"gcloud-dev","kind":"single","fields":["value"],"lease":null},
            {"name":"work/login","vault":"work","kind":"login","fields":["username","password"],"lease":null}
        ])).unwrap()
    }

    #[test]
    fn aliases_coalesce_and_fields_union() {
        let (groups, destinations) = plan("GH_TOKEN,GITHUB_TOKEN,U=work/login::username,P=work/login::password", &entries()).unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[1].fields, ["password", "username"]);
        assert_eq!(destinations.len(), 4);
    }

    #[test]
    fn mixed_providers_use_distinct_acquisitions_and_native_environment_names() {
        let (groups, destinations) = plan("GITHUB_TOKEN,CLOUDSDK_AUTH_ACCESS_TOKEN,SECOND=CLOUDSDK_AUTH_ACCESS_TOKEN", &entries()).unwrap();
        assert_eq!(groups.iter().map(|g| g.name.as_str()).collect::<Vec<_>>(), ["GITHUB_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN"]);
        assert_eq!(
            destinations.iter().map(|d| (d.name.as_str(), d.group, d.field.as_str())).collect::<Vec<_>>(),
            [("GH_TOKEN", 0, "value"), ("GITHUB_TOKEN", 0, "value"), ("CLOUDSDK_AUTH_ACCESS_TOKEN", 1, "value"), ("SECOND", 1, "value")],
        );
    }

    #[test]
    fn qualified_google_binding_defaults_only_to_gcloud_token_environment() {
        let (groups, destinations) = plan("gcloud-dev/CLOUDSDK_AUTH_ACCESS_TOKEN", &entries()).unwrap();
        assert_eq!(groups[0].name, "gcloud-dev/CLOUDSDK_AUTH_ACCESS_TOKEN");
        assert_eq!(destinations.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), ["CLOUDSDK_AUTH_ACCESS_TOKEN"]);
        assert!(plan("gcloud-dev/GH_TOKEN", &entries()).is_err());
        assert!(plan("release-bot/CLOUDSDK_AUTH_ACCESS_TOKEN", &entries()).is_err());
    }

    #[test]
    fn conflicts_are_identity_based() {
        assert!(plan("X=GH_TOKEN,X=work/login::username", &entries()).is_err());
        assert!(plan("GH_TOKEN=GH_TOKEN,GITHUB_TOKEN=work/login::username", &entries()).is_err());
        assert!(plan("HTTPS_PROXY=GH_TOKEN", &entries()).is_err());
        assert!(plan("work/login", &entries()).is_err());
        assert!(plan("work/login::username", &entries()).is_err());
    }

    #[test]
    fn reason_never_includes_arguments() {
        assert_eq!(default_reason(std::ffi::OsStr::new("/usr/bin/gh")), "Run gh with approved credentials");
        assert_eq!(default_reason(std::ffi::OsStr::new("bad\nname")), "Run command with approved credentials");
    }
}
