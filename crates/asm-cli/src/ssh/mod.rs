//! `asm ssh`: SSH leases on the operator's hosts. The local files live in
//! `<config_dir>/ssh/` (see `store`).

mod agent;
mod extend;
mod install;
mod request;
mod store;

use crate::api::Api;
use crate::error::CliError;
use crate::requests::unix_now;
use crate::state;
use asm_proto::ssh::SshTargetsResponse;
use asm_proto::time::fmt_unix;
use asm_proto::wire::{CAPABILITY_SSH_LEASES_V2, HealthResponse};
use clap::Subcommand;
use std::io::Write as _;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum SshCommand {
    /// Request SSH access to hosts; with a command after --, run it on the host
    Request(request::RequestArgs),
    /// List the SSH hosts you can request
    Hosts {
        #[arg(long)]
        json: bool,
    },
    /// List this machine's SSH leases
    Leases {
        #[arg(long)]
        json: bool,
    },
    /// Ask to extend one of this machine's SSH leases
    Extend(extend::ExtendArgs),
    /// Let ssh, scp, git and Ansible use active leases by host name (edits ~/.ssh/config once)
    Install,
    /// Remove what asm ssh install added to ~/.ssh/config
    Uninstall,
    /// Serve SSH lease certificates to ssh (started by asm ssh request).
    #[command(hide = true)]
    Agent {
        /// SSH state directory (default: <config dir>/ssh).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

pub fn run(cmd: SshCommand) -> Result<(), CliError> {
    match cmd {
        SshCommand::Request(args) => request::request(args),
        SshCommand::Hosts { json } => hosts(json),
        SshCommand::Leases { json } => leases(json),
        SshCommand::Extend(args) => extend::extend(args),
        SshCommand::Install => install::install(),
        SshCommand::Uninstall => install::uninstall(),
        SshCommand::Agent { dir } => agent::run(dir),
    }
}

/// `<config_dir>/ssh`.
pub fn ssh_dir() -> Result<PathBuf, CliError> {
    Ok(state::config_dir()?.join("ssh"))
}

/// Fail with exit 2 unless the manager advertises SSH leases.
fn require_ssh(api: &Api) -> Result<(), CliError> {
    let health: HealthResponse = api.get("/health")?;
    health.require_capability(CAPABILITY_SSH_LEASES_V2).map_err(|_| {
        CliError::invalid("the manager does not support SSH leases; upgrade Agents Secrets Manager")
    })
}

/// `asm ssh hosts [--json]`.
fn hosts(json: bool) -> Result<(), CliError> {
    let host = state::require()?;
    let api = Api::for_host(&host)?;
    require_ssh(&api)?;
    let resp: SshTargetsResponse = api.get("/ssh/targets")?;
    let mut out = std::io::stdout().lock();
    if json {
        let _ = serde_json::to_writer(&mut out, &resp);
        let _ = out.write_all(b"\n");
    } else {
        for t in &resp.targets {
            let _ = writeln!(
                out,
                "{}\tprivileged:{}\tusers:{}\tgrants:{}",
                t.name,
                t.privileged_login.as_deref().unwrap_or("-"),
                if t.users.is_empty() { "-".to_owned() } else { t.users.join(",") },
                t.grants.join(",")
            );
        }
    }
    Ok(())
}

/// `asm ssh leases [--json]`: this machine's unexpired SSH leases, from `leases.json`
/// only (a lease revoked on the Mac stays listed until its end).
fn leases(json: bool) -> Result<(), CliError> {
    let dir = ssh_dir()?;
    let now = unix_now();
    let leases: Vec<_> = store::read_leases(&dir)
        .map_err(CliError::failure)?
        .into_iter()
        .filter(|l| l.expires_at > now)
        .collect();
    let mut out = std::io::stdout().lock();
    let config = |id: &str| store::lease_dir(&dir, id).join(store::CONFIG_FILE);
    if json {
        let doc: Vec<_> = leases
            .iter()
            .map(|l| {
                serde_json::json!({
                    "lease_id": l.lease_id,
                    "expires_at": fmt_unix(l.expires_at),
                    "config": config(&l.lease_id).to_string_lossy(),
                    "targets": l.targets.iter().map(request::target_json).collect::<Vec<_>>(),
                })
            })
            .collect();
        let _ = writeln!(out, "{}", serde_json::Value::Array(doc));
    } else {
        for l in &leases {
            let targets: Vec<String> = l
                .targets
                .iter()
                .map(|t| format!("{} ({})", t.name, request::access_text(t)))
                .collect();
            let _ = writeln!(
                out,
                "{}\tuntil {}\t{}\t{}",
                l.lease_id,
                fmt_unix(l.expires_at),
                targets.join(", "),
                config(&l.lease_id).display()
            );
        }
    }
    Ok(())
}
