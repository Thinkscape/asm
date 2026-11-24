//! `asm`: the Agents Secrets Manager CLI for agent machines.

mod api;
mod bindings;
mod browser;
mod delivery;
mod error;
mod exec;
mod files;
mod gh;
mod hostinfo;
mod login;
mod pair;
mod proxy;
mod reaper;
mod requests;
mod router;
mod service;
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
        /// Print the secret catalog as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Request a lease on a secret and write its files.
    Get(requests::GetArgs),
    /// Run a command with approved credentials in its environment, without token files.
    Exec(exec::ExecArgs),
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
    /// Sign in to a website on the manager's Mac (the operator approves and the manager
    /// fills the vault login there) and receive the browser storage state.
    Login(login::LoginArgs),
    /// Set up browsers for login grants: route their HTTPS through asm's proxy router and
    /// trust the asm browser CA.
    #[command(subcommand)]
    Browser(browser::BrowserCommand),
    /// Local HTTPS proxy for browsers: routes sites with an active login grant through
    /// the manager's proxy (installed by asm browser install).
    #[command(hide = true, name = "proxy-router", subcommand)]
    ProxyRouter(router::RouterCommand),
    /// Use the GitHub CLI (gh) through the manager: a gh shim that adds GitHub App tokens
    /// for the repositories you add.
    #[command(subcommand)]
    Gh(gh::GhCommand),
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
        Command::Get(args) => {
            if args.no_reaper {
                reaper::disable();
            }
            requests::get(args)
        }
        Command::Exec(args) => exec::run(args),
        Command::Update { field, wait, name } => requests::update(field, wait, name),
        Command::Add { wait, name } => requests::add(wait, name),
        Command::ProxyInfo { json } => proxy::proxy_info(json),
        Command::ProxyEnv { shell, unset } => proxy::proxy_env(shell, unset),
        Command::Doctor { probe_url } => proxy::doctor(&probe_url),
        Command::Reap { dir } => reaper::run(dir),
        Command::Skill(cmd) => skill::run(cmd),
        Command::ProxyRouter(cmd) => router::run(cmd),
        Command::Login(args) => login::run(args),
        Command::Browser(cmd) => browser::run(cmd),
        Command::Gh(cmd) => gh::run(cmd),
    };
    if let Err(e) = result {
        if !e.message.is_empty() {
            eprintln!("{}", e.message);
        }
        std::process::exit(e.exit);
    }
}
