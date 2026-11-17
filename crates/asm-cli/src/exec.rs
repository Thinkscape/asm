//! File-free acquisition followed by direct process replacement. No Session/reaper path.

use crate::api::Api;
use crate::bindings;
use crate::error::CliError;
use crate::requests::{self, submit_get};
use crate::state;
use asm_proto::generators::CREDENTIAL_REFRESH_MARGIN_SECS;
use asm_proto::wire::{GetResult, LeaseInfo, LeaseMode, LeaseStatus, LeasesResponse, RequestBody};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

#[derive(clap::Args)]
pub struct ExecArgs {
    #[arg(long, conflicts_with = "sentinel")]
    raw: bool,
    #[arg(long, conflicts_with = "raw")]
    sentinel: bool,
    #[arg(long, value_delimiter = ',')]
    hosts: Vec<String>,
    #[arg(long)]
    reason: Option<String>,
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
    generated: bool,
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
        let names = match &resolved.binding.destination {
            Some(destination) => vec![destination.clone()],
            None if resolved.generated => vec!["GH_TOKEN".into(), "GITHUB_TOKEN".into()],
            None => {
                let leaf = resolved.binding.source.rsplit('/').next().unwrap_or("");
                if !bindings::environment_name(leaf) {
                    return Err(CliError::invalid("this source needs an explicit DEST= binding"));
                }
                vec![leaf.to_owned()]
            }
        };
        let group = groups.iter().position(|g| g.key == resolved.canonical_key).unwrap_or_else(|| {
            let index = groups.len();
            groups.push(Acquisition {
                key: resolved.canonical_key,
                name: resolved.request_name,
                generated: resolved.generated,
                fields: Vec::new(),
                result: None,
            });
            index
        });
        if !groups[group].fields.contains(&field) {
            groups[group].fields.push(field.clone());
        }
        for name in names {
            if crate::proxy::ENV_NAMES.iter().any(|key| name.eq_ignore_ascii_case(key)) {
                return Err(CliError::invalid(format!("{name} is reserved for proxy/CA settings")));
            }
            if let Some((old_group, old_field)) = assigned.get(&name) {
                if *old_group != group || old_field != &field {
                    return Err(CliError::invalid(format!("conflicting bindings for {name}")));
                }
                continue;
            }
            assigned.insert(name.clone(), (group, field.clone()));
            destinations.push(Destination { name, group, field: field.clone() });
        }
    }
    if let (Some(a), Some(b)) = (assigned.get("GH_TOKEN"), assigned.get("GITHUB_TOKEN")) {
        if (groups[a.0].generated || groups[b.0].generated) && a != b {
            return Err(CliError::invalid("GH_TOKEN and GITHUB_TOKEN must identify the same generated credential; use custom destinations for different apps"));
        }
    }
    for group in &mut groups {
        group.fields.sort();
    }
    Ok((groups, destinations))
}

fn body(name: String, fields: Vec<String>, raw: bool, sentinel: bool, hosts: Vec<String>, reason: String, lease_id: Option<String>) -> RequestBody {
    RequestBody::Get {
        name, fields: Some(fields), raw, sentinel, hosts, reason, lease_id,
        generation: None, refresh: false, refresh_from_version: None, new_lease: false,
        client_capabilities: bindings::capabilities(), agent: crate::hostinfo::agent_label(),
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
        || (group.generated && lease.generation.is_none())
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
    let host = state::require()?;
    let api = Api::for_host(&host)?;
    bindings::require_capabilities(&api, false, true)?;
    let entries = bindings::catalog(&api)?;
    let (mut groups, destinations) = plan(&args.bindings, &entries)?;
    bindings::require_capabilities(&api, groups.iter().any(|g| g.generated), true)?;
    let mut deadline = requests::deadline(args.wait);
    for group in &mut groups {
        let mut request = body(group.name.clone(), group.fields.clone(), args.raw, args.sentinel, hosts.clone(), reason.clone(), None);
        request.canonicalize()?;
        group.result = Some(submit_get(&api, &request, deadline)?);
        if group.generated && group.result.as_ref().is_none_or(|r| r.generation.is_none()) {
            return Err(CliError::failure("the manager omitted generated credential metadata"));
        }
    }
    // Inspect current authority without reconciling any local get files.
    let leases: LeasesResponse = api.get_until("/leases", deadline)?;
    for group in &mut groups {
        let lease = authority(&leases, group)?;
        let result = group.result.as_ref().expect("acquired");
        if group.generated && (lease.credential_version != result.credential_version || !headroom(result.credential_expires_at.as_deref()) || !headroom(lease.credential_expires_at.as_deref())) {
            let request = body(lease.name.clone(), group.fields.clone(), lease.mode == LeaseMode::Raw, lease.mode == LeaseMode::Sentinel, lease.hosts.clone(), reason.clone(), Some(lease.lease_id.clone()));
            group.result = Some(submit_get(&api, &request, deadline)?);
        }
    }
    let needs_proxy = groups.iter().any(|g| g.result.as_ref().expect("acquired").files.iter().any(|f| f.substituted));
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
        if group.generated && (lease.credential_version != result.credential_version || !headroom(result.credential_expires_at.as_deref()) || !headroom(lease.credential_expires_at.as_deref())) {
            return Err(changed());
        }
    }
    let mut command = Command::new(executable);
    command.args(&args.command[1..]);
    for destination in destinations {
        let result = groups[destination.group].result.as_ref().expect("acquired");
        let value = &result.files.iter().find(|f| f.field == destination.field).ok_or_else(changed)?.content;
        if value.contains('\0') {
            return Err(CliError::failure("a credential contains NUL and cannot be placed in the child environment"));
        }
        command.env(destination.name, value);
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
            {"name":"GH_TOKEN","aliases":["GITHUB_TOKEN"],"source_kind":"generator","generators":[{"generator_id":"app","name":"release-bot","available":true}],"vault":"GitHub App","kind":"single","fields":["value"],"lease":null},
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
