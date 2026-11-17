//! `asm`: the Agents Secrets Manager CLI for agent machines.

mod api;
mod error;
mod files;
mod hostinfo;
mod pair;
mod proxy;
mod reaper;
mod requests;
mod skill;
mod state;
mod tls;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "asm",
    version,
    about = "Agents Secrets Manager: request secrets from the operator's manager"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Pair this machine with a manager (default port 7411). While the manager still
    /// accepts this machine's pairing, prints "already paired" and does nothing.
    Pair {
        /// Pair again even though the current pairing still works (the manager keeps the
        /// same host record and issues a new token).
        #[arg(long)]
        force: bool,
        /// Manager address: <hostname>[:port].
        manager: String,
        /// Unattended pairing code (asm-…); also read from $ASM_PAIRING_CODE.
        pairing_code: Option<String>,
    },
    /// List the secrets you can request.
    List {
        /// Print the manager's JSON answer.
        #[arg(long)]
        json: bool,
    },
    /// Request a lease on a secret and write its files.
    Get {
        /// Ask for the real value instead of a sentinel.
        #[arg(long)]
        raw: bool,
        /// Hosts the sentinel will be used with (comma-separated patterns).
        #[arg(long, value_delimiter = ',')]
        hosts: Vec<String>,
        /// Stop waiting for the operator after this many seconds (exit 4 while still
        /// pending). Default: until the request expires on the manager (typically 10 min).
        #[arg(long)]
        wait: Option<u64>,
        /// Print the result as JSON.
        #[arg(long)]
        json: bool,
        /// Do not start the background process that deletes the files when the lease
        /// ends (also `ASM_NO_REAPER=1`); later asm commands still delete them.
        #[arg(long)]
        no_reaper: bool,
        /// Secret name as shown by `asm list`.
        name: String,
        /// Why you need it (shown to the operator; at most 250 characters).
        reason: String,
    },
    /// Change a secret; the new value is read from stdin.
    Update {
        /// Field to change (default: password for logins, the only field otherwise).
        #[arg(long)]
        field: Option<String>,
        /// Stop waiting for the operator after this many seconds (exit 4 while still
        /// pending). Default: until the request expires on the manager (typically 10 min).
        #[arg(long)]
        wait: Option<u64>,
        name: String,
    },
    /// Add a new secret; the value is read from stdin.
    Add {
        /// Stop waiting for the operator after this many seconds (exit 4 while still
        /// pending). Default: until the request expires on the manager (typically 10 min).
        #[arg(long)]
        wait: Option<u64>,
        name: String,
    },
    /// Show the proxy addresses, which one is reachable, and the CA files (information only).
    ProxyInfo {
        #[arg(long)]
        json: bool,
    },
    /// Print shell code that points HTTP clients at the proxy: eval "$(asm proxy-env)".
    /// Prints nothing on stdout (and exits 1) when no proxy address is reachable.
    ProxyEnv {
        /// Output syntax.
        #[arg(long, value_enum, default_value = "posix")]
        shell: proxy::Shell,
        /// Print code that removes the variables instead.
        #[arg(long)]
        unset: bool,
    },
    /// Check pairing, connectivity, files and the proxy.
    Doctor {
        /// HTTPS URL fetched through the proxy.
        #[arg(long, default_value = "https://example.com/")]
        probe_url: String,
    },
    /// Install the agent skill shipped with this CLI into agents' skill folders.
    #[command(subcommand)]
    Skill(skill::SkillCommand),
    /// Delete the files of ended leases in the background (started by other commands).
    #[command(hide = true)]
    Reap {
        /// Secrets directory (default: as for the other commands).
        #[arg(long)]
        dir: Option<std::path::PathBuf>,
    },
}

fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Pair {
            force,
            manager,
            pairing_code,
        } => pair::run(&manager, pairing_code, force),
        Command::List { json } => requests::list(json),
        Command::Get {
            raw,
            hosts,
            wait,
            json,
            no_reaper,
            name,
            reason,
        } => {
            if no_reaper {
                reaper::disable();
            }
            requests::get(requests::GetArgs {
                raw,
                hosts,
                wait,
                json,
                name,
                reason,
            })
        }
        Command::Update { field, wait, name } => requests::update(field, wait, name),
        Command::Add { wait, name } => requests::add(wait, name),
        Command::ProxyInfo { json } => proxy::proxy_info(json),
        Command::ProxyEnv { shell, unset } => proxy::proxy_env(shell, unset),
        Command::Doctor { probe_url } => proxy::doctor(&probe_url),
        Command::Reap { dir } => reaper::run(dir),
        Command::Skill(cmd) => skill::run(cmd),
    };
    if let Err(e) = result {
        if !e.message.is_empty() {
            eprintln!("{}", e.message);
        }
        std::process::exit(e.exit);
    }
}
