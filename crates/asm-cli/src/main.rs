//! `asm`: the Agents Secrets Manager CLI for agent machines.

mod api;
mod error;
mod files;
mod hostinfo;
mod pair;
mod proxy;
mod requests;
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
    /// Pair this machine with a manager (default port 7411).
    Pair {
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
        /// Seconds to wait for the operator.
        #[arg(long, default_value_t = 120)]
        wait: u64,
        /// Print the result as JSON.
        #[arg(long)]
        json: bool,
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
        /// Seconds to wait for the operator.
        #[arg(long, default_value_t = 120)]
        wait: u64,
        name: String,
    },
    /// Add a new secret; the value is read from stdin.
    Add {
        /// Seconds to wait for the operator.
        #[arg(long, default_value_t = 120)]
        wait: u64,
        name: String,
    },
    /// Show proxy addresses and the environment for using them.
    ProxyInfo {
        #[arg(long)]
        json: bool,
    },
    /// Check pairing, connectivity, files and the proxy.
    Doctor {
        /// HTTPS URL fetched through the proxy.
        #[arg(long, default_value = "https://example.com/")]
        probe_url: String,
    },
}

fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Pair {
            manager,
            pairing_code,
        } => pair::run(&manager, pairing_code),
        Command::List { json } => requests::list(json),
        Command::Get {
            raw,
            hosts,
            wait,
            json,
            name,
            reason,
        } => requests::get(requests::GetArgs {
            raw,
            hosts,
            wait,
            json,
            name,
            reason,
        }),
        Command::Update { field, wait, name } => requests::update(field, wait, name),
        Command::Add { wait, name } => requests::add(wait, name),
        Command::ProxyInfo { json } => proxy::proxy_info(json),
        Command::Doctor { probe_url } => proxy::doctor(&probe_url),
    };
    if let Err(e) = result {
        if !e.message.is_empty() {
            eprintln!("{}", e.message);
        }
        std::process::exit(e.exit);
    }
}
