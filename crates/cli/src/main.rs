use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use loops::{
    find_team, hostname, human_bytes, print_pull_report, print_push_report, print_report,
    print_rotation_report, print_wrap_report, workspace_name, LoopControl,
};
use pear_core::relay::{RelayClient, RelayError};

// Shared with `peard`: the loop bodies (loops) and the daemon IPC surface
// (daemon). Each binary uses part of these modules, hence the allows.
#[allow(dead_code)]
mod daemon;
#[allow(dead_code)]
mod loops;

#[derive(Parser)]
#[command(
    name = "pear",
    version,
    about = "pear — your working context, everywhere"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Relay TLS flags shared by every command that talks to a relay (§17).
#[derive(clap::Args)]
struct RelayTls {
    /// PEM certificate of a private CA to trust for the relay's TLS
    /// (self-signed deployments); defaults to the PEAR_TLS_CA env var.
    /// Replaces the default root set for this connection — there is no
    /// skip-verify mode.
    #[arg(long, env = "PEAR_TLS_CA")]
    tls_ca_cert: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage relay users (admin token).
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Manage teams and their members.
    Team {
        #[command(subcommand)]
        command: TeamCommand,
    },
    /// Attach the local workspace to a team (§13: workspace owner).
    Share {
        path: PathBuf,
        /// Team name.
        #[arg(long)]
        team: String,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        #[command(flatten)]
        tls: RelayTls,
    },
    /// Re-pin a user's identity to the key bundle the relay currently
    /// serves (§19): the explicit, operator-visible answer to a
    /// `pin_changed` wrap report. Only run this after verifying the new
    /// fingerprint out-of-band — a pin is never updated implicitly.
    Trust {
        /// User name to trust.
        user: String,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        #[command(flatten)]
        tls: RelayTls,
    },
    /// Rotate the workspace keyring to a fresh generation and re-wrap it
    /// for the current team (§20) — the operator-initiated compromise
    /// response. Nothing is re-uploaded; the next push encrypts under the
    /// new generation automatically.
    Rekey {
        path: PathBuf,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        #[command(flatten)]
        tls: RelayTls,
    },
    /// Initialize a directory as a pear workspace.
    Init { path: PathBuf },
    /// Run one sync cycle from SOURCE into TARGET.
    Sync { source: PathBuf, target: PathBuf },
    /// Local mode: initial sync, then watch SOURCE and keep TARGET converged.
    /// Writer mode (--relay): hold the workspace lease and push every cycle.
    /// With --daemon, register with the running peard instead (§16).
    Watch {
        source: PathBuf,
        target: Option<PathBuf>,
        /// Relay base URL; switches watch into multi-device writer mode.
        #[arg(long)]
        relay: Option<String>,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long, requires = "relay")]
        token: Option<String>,
        /// Device id for the lease; defaults to the hostname.
        #[arg(long, requires = "relay")]
        device: Option<String>,
        /// Writer mode only: take the lease by force and make this tree the
        /// head, even if that strands another writer's changes.
        #[arg(long, requires = "relay")]
        force: bool,
        /// Writer mode only: attach the workspace to this team at register.
        #[arg(long, requires = "relay")]
        team: Option<String>,
        /// Writer mode only: register and push the workspace end-to-end
        /// encrypted (§17) — the workspace key never leaves your devices;
        /// immutable once registered.
        #[arg(long, requires = "relay")]
        e2e: bool,
        /// Register with the running peard daemon instead of watching in
        /// the foreground.
        #[arg(long)]
        daemon: bool,
        #[command(flatten)]
        tls: RelayTls,
    },
    /// Mirror a relay workspace into PATH, applying the writer's changes.
    /// With --daemon, register with the running peard instead (§16).
    Mirror {
        path: PathBuf,
        /// Id of the workspace to mirror.
        #[arg(long)]
        workspace: String,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        /// Your user name (the one you enrolled with `pear user keygen`) —
        /// needed the first time you mirror an e2e workspace, so pear can
        /// fetch and unwrap your wrapped workspace key (§17).
        #[arg(long)]
        name: Option<String>,
        /// Register with the running peard daemon instead of mirroring in
        /// the foreground.
        #[arg(long)]
        daemon: bool,
        #[command(flatten)]
        tls: RelayTls,
    },
    /// Query peard for per-workspace sync state (§16).
    Status {
        /// Limit the report to one registered workspace path.
        path: Option<PathBuf>,
    },
    /// Control the peard daemon (§16).
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    /// Move the workspace lease to this device (writer handoff).
    Checkout {
        path: PathBuf,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        /// Device id for the lease; defaults to the hostname.
        #[arg(long)]
        device: Option<String>,
        /// Revoke the current lease instead of asking for a transfer.
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        tls: RelayTls,
    },
    /// Preserve the local tree as a snapshot on the relay — head-synced or
    /// not. This is how unsynced state survives a mirror/force decision.
    Snapshot {
        path: PathBuf,
        /// Snapshot name/message.
        #[arg(short = 'm')]
        message: Option<String>,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        /// Device id recorded on the snapshot; defaults to the hostname.
        #[arg(long)]
        device: Option<String>,
        #[command(flatten)]
        tls: RelayTls,
    },
    /// List the local workspace's snapshots, newest first.
    Snapshots {
        path: PathBuf,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        #[command(flatten)]
        tls: RelayTls,
    },
    /// With --snapshot: clone the snapshot into PATH as a NEW workspace
    /// (forked lineage; never registers, mirrors, or pushes). Without it:
    /// mirror the head once — the onboarding command (§13). WORKSPACE is a
    /// hex id or a `team/name` ref, resolved on the relay.
    Clone {
        path: PathBuf,
        /// Workspace ref: a hex id or `team/name`.
        #[arg(long)]
        workspace: String,
        /// Snapshot id to fork-clone; without it, mirror the head once.
        #[arg(long)]
        snapshot: Option<u64>,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        /// Your user name (the one you enrolled with `pear user keygen`) —
        /// needed to clone an e2e workspace, so pear can fetch and unwrap
        /// your wrapped workspace key (§17).
        #[arg(long)]
        name: Option<String>,
        #[command(flatten)]
        tls: RelayTls,
    },
}

#[derive(Subcommand)]
enum UserCommand {
    /// Create a user and print their token once (admin only).
    Create {
        name: String,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Admin bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        #[command(flatten)]
        tls: RelayTls,
    },
    /// Generate (or load) your identity halves at
    /// ~/.pear/keys/<name>.{x25519,ed25519} — creating only the MISSING
    /// ones, so an existing x25519 key keeps old wraps unwrapping — sign
    /// the key bundle, and register it on the relay (§17/§19). Required
    /// before an e2e workspace can wrap its key for you.
    Keygen {
        /// Your user name, as created by the admin (`pear user create`).
        #[arg(long)]
        name: String,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        #[command(flatten)]
        tls: RelayTls,
    },
    /// Print your ed25519 identity fingerprint (full hex) from the local
    /// key (§19) — the out-of-band comparison aid for first-sight pins.
    Id {
        /// Your user name.
        #[arg(long)]
        name: String,
    },
    /// Print the local identity's secret bytes as hex (the FULL identity:
    /// x25519 + ed25519 halves) for moving to another machine; import it
    /// there with `pear user import`. Guard the output like a password.
    Export {
        /// Your user name.
        #[arg(long)]
        name: String,
    },
    /// Install an exported identity hex under --name (0600 key files).
    /// Refuses to overwrite an existing identity.
    Import {
        /// Your user name.
        #[arg(long)]
        name: String,
        /// The hex printed by `pear user export` (64 or 128 chars).
        hex: String,
    },
}

#[derive(Subcommand)]
enum TeamCommand {
    /// Create a team; you become its first owner.
    Create {
        team: String,
        /// Forbid `.env*` sync in this team's workspaces (§28): plaintext
        /// commits containing `.env*` paths are rejected, and writers
        /// refuse to watch trees that capture them. Reversible later with
        /// `pear team policy <team> --env on`.
        #[arg(long)]
        no_env: bool,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        #[command(flatten)]
        tls: RelayTls,
    },
    /// Add a member to a team (team owner only).
    Add {
        team: String,
        /// User name to add.
        #[arg(long)]
        user: String,
        /// Role to grant.
        #[arg(long)]
        role: TeamRole,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        #[command(flatten)]
        tls: RelayTls,
    },
    /// Remove a member from a team (§20): team owner, or yourself to
    /// leave. Idempotent — removing a non-member is a no-op. The departed
    /// member's wrapped workspace keys die with the membership; the crypto
    /// cutoff (key rotation) follows at the writer's next watch start.
    Remove {
        team: String,
        /// User name to remove.
        #[arg(long)]
        user: String,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        #[command(flatten)]
        tls: RelayTls,
    },
    /// List a team's members.
    Members {
        team: String,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        #[command(flatten)]
        tls: RelayTls,
    },
    /// Change a team's `.env` policy (§28, team owner only). `--env off`
    /// forbids `.env*` sync in the team's workspaces (relay rejects
    /// plaintext `.env*` commits; writers refuse to watch trees that
    /// capture `.env*` files); `--env on` restores the product promise.
    Policy {
        team: String,
        /// Allow (`on`, the default everywhere) or forbid (`off`) `.env*`
        /// sync for this team.
        #[arg(long)]
        env: EnvToggle,
        /// Relay base URL.
        #[arg(long)]
        relay: String,
        /// Bearer token; defaults to the PEAR_TOKEN env var.
        #[arg(long)]
        token: Option<String>,
        #[command(flatten)]
        tls: RelayTls,
    },
}

#[derive(Subcommand)]
enum DaemonCommand {
    /// Ask peard to shut down cleanly: loops finish their current cycle,
    /// leases are left to expire (§16).
    Stop,
}

/// Team roles (§13); the value is sent to the relay verbatim.
#[derive(Clone, clap::ValueEnum)]
enum TeamRole {
    Owner,
    Writer,
    Reader,
}

impl TeamRole {
    fn as_str(&self) -> &'static str {
        match self {
            TeamRole::Owner => "owner",
            TeamRole::Writer => "writer",
            TeamRole::Reader => "reader",
        }
    }
}

/// `pear team policy --env on|off` (§28): the kill switch positions.
#[derive(Clone, clap::ValueEnum)]
enum EnvToggle {
    On,
    Off,
}

impl EnvToggle {
    fn sync_env(&self) -> bool {
        match self {
            EnvToggle::On => true,
            EnvToggle::Off => false,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::User { command } => match command {
            UserCommand::Create {
                name,
                relay,
                token,
                tls,
            } => user_create(&name, &relay, token, &tls)?,
            UserCommand::Keygen {
                name,
                relay,
                token,
                tls,
            } => user_keygen(&name, &relay, token, &tls)?,
            UserCommand::Id { name } => user_id(&name)?,
            UserCommand::Export { name } => user_export(&name)?,
            UserCommand::Import { name, hex } => user_import(&name, &hex)?,
        },
        Commands::Team { command } => match command {
            TeamCommand::Create {
                team,
                no_env,
                relay,
                token,
                tls,
            } => team_create(&team, no_env, &relay, token, &tls)?,
            TeamCommand::Add {
                team,
                user,
                role,
                relay,
                token,
                tls,
            } => team_add(&team, &user, role, &relay, token, &tls)?,
            TeamCommand::Remove {
                team,
                user,
                relay,
                token,
                tls,
            } => team_remove(&team, &user, &relay, token, &tls)?,
            TeamCommand::Members {
                team,
                relay,
                token,
                tls,
            } => team_members(&team, &relay, token, &tls)?,
            TeamCommand::Policy {
                team,
                env,
                relay,
                token,
                tls,
            } => team_policy(&team, env, &relay, token, &tls)?,
        },
        Commands::Share {
            path,
            team,
            relay,
            token,
            tls,
        } => share(&path, &team, &relay, token, &tls)?,
        Commands::Trust {
            user,
            relay,
            token,
            tls,
        } => trust(&user, &relay, token, &tls)?,
        Commands::Rekey {
            path,
            relay,
            token,
            tls,
        } => rekey(&path, &relay, token, &tls)?,
        Commands::Init { path } => {
            let (meta, created) = pear_core::init_workspace(&path, None)?;
            if created {
                println!("initialized workspace {} at {}", meta.id, path.display());
            } else {
                println!("workspace already initialized (id {})", meta.id);
            }
        }
        Commands::Sync { source, target } => {
            let report = pear_core::sync::sync_cycle(&source, &target)?;
            print_report(&report);
        }
        Commands::Watch {
            source,
            target,
            relay,
            token,
            device,
            force,
            team,
            e2e,
            daemon: as_daemon,
            tls,
        } => match (target, relay) {
            (Some(target), None) => {
                if as_daemon {
                    register_watch(
                        &source,
                        Some(&target),
                        None,
                        token,
                        device,
                        force,
                        team,
                        e2e,
                        &tls,
                    )?;
                } else {
                    println!(
                        "watching {} -> {} (ctrl-c to stop)",
                        source.display(),
                        target.display()
                    );
                    loops::watch_local(&source, &target, &LoopControl::foreground(), print_report)?;
                }
            }
            (None, Some(relay)) => {
                if as_daemon {
                    register_watch(
                        &source,
                        None,
                        Some(relay),
                        token,
                        device,
                        force,
                        team,
                        e2e,
                        &tls,
                    )?;
                } else {
                    watch_writer(&source, &relay, token, device, force, team, e2e, &tls)?;
                }
            }
            (Some(_), Some(_)) => {
                bail!("`pear watch` takes either a TARGET (local sync) or --relay (writer mode), not both")
            }
            (None, None) => {
                bail!(
                    "`pear watch` needs a TARGET for local sync, or --relay <url> for writer mode"
                )
            }
        },
        Commands::Mirror {
            path,
            workspace,
            relay,
            token,
            name,
            daemon: as_daemon,
            tls,
        } => {
            if as_daemon {
                register_mirror(&path, &workspace, &relay, token, name, &tls)?;
            } else {
                mirror(&path, &workspace, &relay, token, name, &tls)?;
            }
        }
        Commands::Status { path } => status(path)?,
        Commands::Daemon { command } => match command {
            DaemonCommand::Stop => daemon_stop()?,
        },
        Commands::Checkout {
            path,
            relay,
            token,
            device,
            force,
            tls,
        } => checkout(&path, &relay, token, device, force, &tls)?,
        Commands::Snapshot {
            path,
            message,
            relay,
            token,
            device,
            tls,
        } => snapshot(&path, message, &relay, token, device, &tls)?,
        Commands::Snapshots {
            path,
            relay,
            token,
            tls,
        } => snapshots(&path, &relay, token, &tls)?,
        Commands::Clone {
            path,
            workspace,
            snapshot,
            relay,
            token,
            name,
            tls,
        } => clone(&path, &workspace, snapshot, &relay, token, name, &tls)?,
    }
    Ok(())
}

impl RelayTls {
    /// The PEM bytes of --tls-ca-cert / PEAR_TLS_CA (§17), if given.
    fn ca_pem(&self) -> Result<Option<Vec<u8>>> {
        loops::resolve_tls_ca(self.tls_ca_cert.as_deref())
    }

    /// The CA path made absolute for handing to peard (its CWD is not
    /// ours), validated readable so a bad file fails at registration
    /// instead of inside the daemon's loop thread.
    fn absolutized_ca(&self) -> Result<Option<PathBuf>> {
        let Some(path) = &self.tls_ca_cert else {
            return Ok(None);
        };
        let path =
            std::path::absolute(path).with_context(|| format!("absolutize {}", path.display()))?;
        let _ = loops::resolve_tls_ca(Some(&path))?;
        Ok(Some(path))
    }
}

/// `pear user create` (§13): mint a user and print their token once.
fn user_create(name: &str, relay: &str, token: Option<String>, tls: &RelayTls) -> Result<()> {
    let token = resolve_token(token)?;
    let client =
        RelayClient::unbound_with_tls_ca(relay, &token, &hostname(), tls.ca_pem()?.as_deref())?;
    let created = client.create_user(name)?;
    println!(
        "created user {} — token (shown once): {}",
        created.name, created.token
    );
    Ok(())
}

/// `pear user keygen` (§17+§19): create only the MISSING identity halves
/// at `$PEAR_HOME/keys/<name>.{x25519,ed25519}` — an existing `.x25519` is
/// signed AS-IS so wraps made to it keep unwrapping, and an existing
/// `.ed25519` keeps the identity stable while a missing `.x25519` is
/// minted fresh — then register the signed bundle on the relay (self
/// only — the relay 403s if the token's user is not --name). Idempotent.
fn user_keygen(name: &str, relay: &str, token: Option<String>, tls: &RelayTls) -> Result<()> {
    let token = resolve_token(token)?;
    let keys_dir = keys_dir()?;
    let keypair = pear_core::crypto::user_keypair_load_or_create(&keys_dir, name)?;
    let ed = pear_core::crypto::ed_keypair_load_or_create(&keys_dir, name)?;
    let x_hex = pear_core::crypto::hex_encode(&keypair.public);
    let ed_hex = pear_core::crypto::hex_encode(&ed.public);
    let sig_hex = pear_core::crypto::hex_encode(
        &ed.sign(&pear_core::crypto::bundle_statement(name, &keypair.public)),
    );
    let client =
        RelayClient::unbound_with_tls_ca(relay, &token, &hostname(), tls.ca_pem()?.as_deref())?;
    client.put_key_bundle(name, &x_hex, &ed_hex, &sig_hex)?;
    println!("registered signed key bundle for {name}:");
    println!("  identity (ed25519): {ed_hex}");
    println!("  encryption key (x25519): {x_hex}");
    println!(
        "private keys (keep them safe): {}",
        keys_dir.join(format!("{name}.x25519")).display()
    );
    println!("                               {}", keys_dir.join(format!("{name}.ed25519")).display());
    Ok(())
}

/// `pear user id` (§19): print the ed25519 fingerprint (the full hex of
/// the identity public key) from the local key — what teammates compare
/// against the pins their wrap pass printed.
fn user_id(name: &str) -> Result<()> {
    let keys_dir = keys_dir()?;
    if !keys_dir.join(format!("{name}.ed25519")).exists() {
        bail!(
            "no ed25519 identity for {name:?} at {} — run `pear user keygen --name {name} --relay <url>` first",
            keys_dir.join(format!("{name}.ed25519")).display()
        );
    }
    let ed = pear_core::crypto::ed_keypair_load_or_create(&keys_dir, name)?;
    println!("{}", pear_core::crypto::hex_encode(&ed.public));
    Ok(())
}

/// `pear user export` (§19): print the FULL identity's secret bytes as
/// hex — `x25519_secret ‖ ed25519_seed` (128 hex) when both halves exist,
/// the legacy 64-hex x25519-only export otherwise.
fn user_export(name: &str) -> Result<()> {
    let keys_dir = keys_dir()?;
    let bytes = pear_core::crypto::user_identity_export(&keys_dir, name)?;
    println!("{}", pear_core::crypto::hex_encode(&bytes));
    Ok(())
}

/// `pear user import` (§19): install an exported identity under --name,
/// refusing to overwrite any existing identity file for the name.
fn user_import(name: &str, hex: &str) -> Result<()> {
    let keys_dir = keys_dir()?;
    let bytes = pear_core::crypto::hex_decode(hex.trim())
        .context("the identity export is not valid hex")?;
    pear_core::crypto::user_identity_import(&keys_dir, name, &bytes)?;
    if bytes.len() == 64 {
        println!("imported the full identity (x25519 + ed25519) for {name}");
    } else {
        println!(
            "imported the x25519 half of {name}'s identity; run `pear user keygen --name {name} --relay <url>` to mint and register its ed25519 half"
        );
    }
    Ok(())
}

/// `pear trust` (§19): fetch the user's current bundle from the relay,
/// verify its signature HERE (the pins are only worth anything if what
/// they pin verified writer-side), and re-pin known_keys to it — the only
/// way a pin is updated on mismatch. Prints the fingerprint for
/// out-of-band comparison.
fn trust(user: &str, relay: &str, token: Option<String>, tls: &RelayTls) -> Result<()> {
    let token = resolve_token(token)?;
    let client =
        RelayClient::unbound_with_tls_ca(relay, &token, &hostname(), tls.ca_pem()?.as_deref())?;
    let bundle = client.get_key(user)?;
    let (Some(x_hex), Some(ed_hex), Some(sig_hex)) =
        (&bundle.pubkey, &bundle.ed25519, &bundle.sig)
    else {
        bail!(
            "{user:?} has no signed key bundle on the relay (legacy unsigned key, or none at all); \
             ask them to run `pear user keygen --name {user} --relay <url>` — refusing to pin"
        );
    };
    let x = hex_field::<32>("x25519", x_hex)?;
    let ed = hex_field::<32>("ed25519", ed_hex)?;
    let sig = hex_field::<64>("sig", sig_hex)?;
    if !pear_core::crypto::ed_verify(&ed, &pear_core::crypto::bundle_statement(user, &x), &sig) {
        bail!(
            "the bundle the relay serves for {user:?} does not verify (possible relay/key \
             tampering) — refusing to pin; do NOT trust this identity"
        );
    }
    let path = daemon::pear_home()?.join("known_keys");
    let mut pins = pear_core::known_keys::load(&path)?;
    pear_core::known_keys::pin(&mut pins, user, ed_hex);
    pear_core::known_keys::save(&path, &pins)?;
    println!("pinned {user}: {ed_hex}");
    println!(
        "compare this fingerprint with {user} out-of-band (`pear user id --name {user}` on their device) before relying on it"
    );
    Ok(())
}

/// Decode a fixed-size hex field served by the relay, with context —
/// relay-held data is hostile by default.
fn hex_field<const N: usize>(field: &str, value: &str) -> Result<[u8; N]> {
    let bytes = pear_core::crypto::hex_decode(value)
        .with_context(|| format!("{field} from the relay is not hex"))?;
    bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!("{field} from the relay is {} bytes, expected {N}", bytes.len())
    })
}

/// The directory holding local user keypairs (`pear user keygen`, §17).
fn keys_dir() -> Result<PathBuf> {
    Ok(daemon::pear_home()?.join("keys"))
}

/// `pear team create` (§13): the caller becomes the team's first owner.
/// §28: `--no-env` creates the team with the `.env` kill switch engaged.
fn team_create(
    team: &str,
    no_env: bool,
    relay: &str,
    token: Option<String>,
    tls: &RelayTls,
) -> Result<()> {
    let token = resolve_token(token)?;
    let client =
        RelayClient::unbound_with_tls_ca(relay, &token, &hostname(), tls.ca_pem()?.as_deref())?;
    let created = client.create_team_with_policy(team, !no_env)?;
    println!("created team {} ({})", created.name, created.id);
    if no_env {
        println!(
            "team {team} forbids .env sync (sync_env=false) — lift it with `pear team policy {team} --env on`"
        );
    }
    Ok(())
}

/// `pear team policy` (§28): flip a team's `.env` kill switch. The relay
/// gates this to team owners; the line echoes the policy now in effect.
fn team_policy(
    team: &str,
    env: EnvToggle,
    relay: &str,
    token: Option<String>,
    tls: &RelayTls,
) -> Result<()> {
    let token = resolve_token(token)?;
    let client =
        RelayClient::unbound_with_tls_ca(relay, &token, &hostname(), tls.ca_pem()?.as_deref())?;
    let team_info = find_team(&client, team)?;
    let updated = client.set_team_policy(&team_info.id, env.sync_env())?;
    if updated.sync_env {
        println!("team {team} now allows .env sync (sync_env=true)");
    } else {
        println!(
            "team {team} now forbids .env sync (sync_env=false) — writers stop on .env* files and plaintext .env commits are rejected"
        );
    }
    Ok(())
}

/// `pear team add` (§13): grant a user a role in a team (team owner only).
fn team_add(
    team: &str,
    user: &str,
    role: TeamRole,
    relay: &str,
    token: Option<String>,
    tls: &RelayTls,
) -> Result<()> {
    let token = resolve_token(token)?;
    let client =
        RelayClient::unbound_with_tls_ca(relay, &token, &hostname(), tls.ca_pem()?.as_deref())?;
    let team_info = find_team(&client, team)?;
    client.team_add_member(&team_info.id, user, role.as_str())?;
    println!("added {user} to team {team} as {}", role.as_str());
    Ok(())
}

/// `pear team remove` (§20): drop a member from a team — team owner, or
/// yourself to leave. Idempotent: the relay answers 204 whether or not
/// the user was a member, so the removed/was-not-a-member line comes
/// from a membership read just before the delete. The departed member's
/// wrapped workspace keys die with the membership (their `keys/me` 404s
/// at once); the crypto cutoff is the writer's next watch-start pass.
fn team_remove(
    team: &str,
    user: &str,
    relay: &str,
    token: Option<String>,
    tls: &RelayTls,
) -> Result<()> {
    let token = resolve_token(token)?;
    let client =
        RelayClient::unbound_with_tls_ca(relay, &token, &hostname(), tls.ca_pem()?.as_deref())?;
    let team_info = find_team(&client, team)?;
    let was_member = client
        .team_members(&team_info.id)?
        .iter()
        .any(|m| m.user == user);
    client.team_remove_member(&team_info.id, user)?;
    if was_member {
        println!("removed {user} from team {team}");
    } else {
        println!("{user} was not a member of team {team} (nothing to do)");
    }
    Ok(())
}

/// `pear team members` (§13): list a team's members.
fn team_members(team: &str, relay: &str, token: Option<String>, tls: &RelayTls) -> Result<()> {
    let token = resolve_token(token)?;
    let client =
        RelayClient::unbound_with_tls_ca(relay, &token, &hostname(), tls.ca_pem()?.as_deref())?;
    let team_info = find_team(&client, team)?;
    let members = client.team_members(&team_info.id)?;
    println!("{:<24} ROLE", "USER");
    for m in members {
        println!("{:<24} {}", m.user, m.role);
    }
    Ok(())
}

/// `pear rekey` (§20): force one keyring rotation and re-wrap for the
/// current team — the operator's compromise response. No push is needed:
/// the writer's next push encrypts under the newest generation
/// automatically, and unchanged content keeps its ciphertext. Errors when
/// the workspace is not e2e (nothing to rotate) or has no attached team
/// (nobody to re-wrap for; rotating would only orphan readers).
fn rekey(path: &Path, relay: &str, token: Option<String>, tls: &RelayTls) -> Result<()> {
    let token = resolve_token(token)?;
    let Some(meta) = pear_core::load_workspace(path)? else {
        bail!(
            "{} is not a pear workspace; run `pear init` first",
            path.display()
        );
    };
    let client = RelayClient::with_tls_ca(
        relay,
        &token,
        &meta.id,
        &hostname(),
        tls.ca_pem()?.as_deref(),
    )?;
    let ws = client.get_workspace()?;
    if !ws.e2e {
        bail!(
            "workspace {} is not end-to-end encrypted; rekey only applies to e2e workspaces",
            meta.id
        );
    }
    if ws.team_id.is_none() {
        bail!(
            "workspace {} has no attached team; `pear share --team <team>` first",
            meta.id
        );
    }
    // Only the writer holds the keyring — refuse to invent one here (a
    // fresh key could never decrypt the existing head).
    let mut keyring = pear_core::e2e::load_workspace_keyring(path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "workspace {} is end-to-end encrypted but this device has no workspace key; \
             run `pear watch --relay --e2e` on the writer first",
            meta.id
        )
    })?;
    let rotation =
        pear_core::e2e::rotation_maintenance(&client, path, &mut keyring, &known_keys_path()?, true)?;
    print_rotation_report(&rotation);
    println!(
        "workspace keyring is now at generation {}; the next push encrypts under it",
        rotation.generation
    );
    Ok(())
}

/// `pear share` (§13): attach the local workspace to a team. The caller
/// must own the workspace and be owner/writer in the team. On an e2e
/// workspace the attach is followed by wrap-maintenance (§17/§19): every
/// member whose signed bundle verifies and matches the known_keys pin gets
/// the workspace key wrapped to them. §20: `share` never rotates — it
/// wraps whatever the current keyring is, full history included.
fn share(
    path: &Path,
    team: &str,
    relay: &str,
    token: Option<String>,
    tls: &RelayTls,
) -> Result<()> {
    let token = resolve_token(token)?;
    let Some(meta) = pear_core::load_workspace(path)? else {
        bail!(
            "{} is not a pear workspace; run `pear init` first",
            path.display()
        );
    };
    let client = RelayClient::with_tls_ca(
        relay,
        &token,
        &meta.id,
        &hostname(),
        tls.ca_pem()?.as_deref(),
    )?;
    let team_info = find_team(&client, team)?;
    // Register idempotently so sharing works before the first watch too.
    // An existing workspace keeps its registered flavor (the e2e flag is
    // immutable relay-side); only a fresh one is created here — plain,
    // since an e2e workspace only ever exists after `watch --e2e`.
    let e2e = match client.get_workspace() {
        Ok(ws) => ws.e2e,
        Err(RelayError::NotFound(_)) => {
            client.create_workspace(&workspace_name(path))?;
            false
        }
        Err(e) => return Err(e.into()),
    };
    client.attach_team(&team_info.id)?;
    println!(
        "workspace {} ({}) attached to team {team}",
        meta.id,
        workspace_name(path)
    );
    if e2e {
        // §17 wrap-maintenance after share. Only the writer holds the
        // workspace keyring — refuse to invent one here (a fresh key could
        // never decrypt the existing head). §20: wrapping never rotates;
        // new members receive the full keyring, history included.
        let keyring = pear_core::e2e::load_workspace_keyring(path)?.ok_or_else(|| {
            anyhow::anyhow!(
                "workspace {} is end-to-end encrypted but this device has no workspace key; \
                 run `pear watch --relay --e2e` on the writer first",
                meta.id
            )
        })?;
        let wrap = pear_core::e2e::wrap_maintenance(&client, &keyring, &known_keys_path()?)?;
        print_wrap_report(&wrap);
    }
    Ok(())
}

/// `$PEAR_HOME/known_keys` — the writer-side identity pins (§19).
fn known_keys_path() -> Result<PathBuf> {
    Ok(daemon::pear_home()?.join("known_keys"))
}

/// Writer flow (§11): the shared loop body in `loops` with foreground
/// control (fatal fencing exits with EXIT_LOST_LEASE, as before).
/// `--e2e` registers and pushes the workspace end-to-end encrypted (§17).
#[allow(clippy::too_many_arguments)]
fn watch_writer(
    source: &Path,
    relay: &str,
    token: Option<String>,
    device: Option<String>,
    force: bool,
    team: Option<String>,
    e2e: bool,
    tls: &RelayTls,
) -> Result<()> {
    let token = resolve_token(token)?;
    loops::watch_writer(
        source,
        relay,
        &token,
        device,
        force,
        team,
        e2e,
        tls.tls_ca_cert.as_deref(),
        &LoopControl::foreground(),
        print_push_report,
    )
}

/// Mirror flow (§11/§14): the shared loop body in `loops` with foreground
/// control. On an e2e workspace, `name` selects the local keypair that
/// unwraps the fetched workspace key (§17).
fn mirror(
    path: &Path,
    workspace: &str,
    relay: &str,
    token: Option<String>,
    name: Option<String>,
    tls: &RelayTls,
) -> Result<()> {
    let token = resolve_token(token)?;
    loops::mirror(
        path,
        workspace,
        relay,
        &token,
        name.as_deref(),
        tls.tls_ca_cert.as_deref(),
        &LoopControl::foreground(),
        print_pull_report,
    )
}

/// `pear watch --daemon` (§16): register the watch with the running daemon
/// instead of running the loop here. The daemon holds the token in memory
/// only; it is resolved here so a missing token fails before the socket
/// round-trip. Fails cleanly when no daemon is up — never spawns one.
/// The §17 CA path is absolutized (peard's CWD is not ours) and validated
/// here, so an unreadable file fails at registration.
#[allow(clippy::too_many_arguments)]
fn register_watch(
    source: &Path,
    target: Option<&Path>,
    relay: Option<String>,
    token: Option<String>,
    device: Option<String>,
    force: bool,
    team: Option<String>,
    e2e: bool,
    tls: &RelayTls,
) -> Result<()> {
    let source = source
        .canonicalize()
        .with_context(|| format!("canonicalize {}", source.display()))?;
    let target = match target {
        Some(t) => {
            Some(std::path::absolute(t).with_context(|| format!("absolutize {}", t.display()))?)
        }
        None => None,
    };
    let token = match relay.is_some() {
        true => Some(resolve_token(token)?),
        false => None,
    };
    let tls_ca_cert = tls.absolutized_ca()?;
    let request = daemon::Request::AddWatch {
        path: source,
        target,
        relay,
        token,
        device,
        force,
        team,
        e2e,
        tls_ca_cert,
    };
    let result = daemon::send(&daemon::pear_home()?, &request)?.into_result()?;
    println!(
        "registered with peard: {}",
        daemon::EntryInfo::from_json(&result)?.summary()
    );
    Ok(())
}

/// `pear mirror --daemon` (§16): register the mirror with the running
/// daemon instead of running the loop here.
fn register_mirror(
    path: &Path,
    workspace: &str,
    relay: &str,
    token: Option<String>,
    name: Option<String>,
    tls: &RelayTls,
) -> Result<()> {
    let path = path
        .canonicalize()
        .with_context(|| format!("canonicalize {}", path.display()))?;
    let request = daemon::Request::AddMirror {
        path,
        workspace: workspace.to_string(),
        relay: relay.to_string(),
        token: resolve_token(token)?,
        name,
        tls_ca_cert: tls.absolutized_ca()?,
    };
    let result = daemon::send(&daemon::pear_home()?, &request)?.into_result()?;
    println!(
        "registered with peard: {}",
        daemon::EntryInfo::from_json(&result)?.summary()
    );
    Ok(())
}

/// `pear status` (§16): per-workspace state from the daemon — role
/// (watch/mirror), relay, head seq, and the last error if a loop failed.
fn status(path: Option<PathBuf>) -> Result<()> {
    let path = path.map(|p| {
        p.canonicalize()
            .or_else(|_| std::path::absolute(&p))
            .unwrap_or(p)
    });
    let request = daemon::Request::Status { path };
    let result = daemon::send(&daemon::pear_home()?, &request)?.into_result()?;
    let entries = daemon::EntryInfo::list_from_json(&result)?;
    if entries.is_empty() {
        println!("no workspaces registered with peard");
        return Ok(());
    }
    for entry in &entries {
        let relay = entry.relay.as_deref().unwrap_or("-");
        let head = match entry.head_seq {
            0 => "-".to_string(),
            seq => seq.to_string(),
        };
        println!(
            "{}  {}  relay={relay}  head={head}  {}",
            entry.path.display(),
            entry.role,
            entry.state
        );
        if let Some(error) = &entry.error {
            println!("  error: {error}");
        }
    }
    Ok(())
}

/// `pear daemon stop` (§16): ask the daemon to shut down cleanly.
fn daemon_stop() -> Result<()> {
    daemon::send(&daemon::pear_home()?, &daemon::Request::Shutdown)?.into_result()?;
    println!("peard: shutdown requested");
    Ok(())
}

/// Handoff (§5/§11): transfer the lease to this device — or force-take it,
/// fencing the current writer — and print the new generation.
fn checkout(
    path: &Path,
    relay: &str,
    token: Option<String>,
    device: Option<String>,
    force: bool,
    tls: &RelayTls,
) -> Result<()> {
    let token = resolve_token(token)?;
    let device = device.unwrap_or_else(hostname);
    // Checkout must target an existing workspace — minting a fresh id here
    // would just 404 against the relay and strand a stray `.pear`.
    let Some(meta) = pear_core::load_workspace(path)? else {
        bail!(
            "{} is not a pear workspace; run `pear mirror --workspace <id> --relay <url>` first",
            path.display()
        );
    };
    let client =
        RelayClient::with_tls_ca(relay, &token, &meta.id, &device, tls.ca_pem()?.as_deref())?;
    let generation = if force {
        client.force()?
    } else {
        // The synced-to-head proof is what THIS device has applied locally
        // (`.pear/remote.json`), not the relay's own head — sending the
        // relay's seq would make the transfer check a tautology and let a
        // stale tree overwrite the writer's newer commits.
        let applied = pear_core::sync::last_applied_seq(path).unwrap_or(0);
        client.transfer(applied).map_err(|e| match e {
            e @ RelayError::TransferRejected { .. } => anyhow::anyhow!(
                "{e}. Run `pear mirror` to reach the current head first \
                 (or --force, which can strand the writer's unsynced changes)"
            ),
            other => anyhow::Error::new(other),
        })?
    };
    println!(
        "lease held by {device}: workspace {}, generation {generation}",
        meta.id
    );
    Ok(())
}

/// `pear snapshot` (§12): preserve the local tree as a named snapshot on
/// the relay. Works head-synced or not — the writer pipeline minus the
/// head commit.
fn snapshot(
    path: &Path,
    message: Option<String>,
    relay: &str,
    token: Option<String>,
    device: Option<String>,
    tls: &RelayTls,
) -> Result<()> {
    let token = resolve_token(token)?;
    let device = device.unwrap_or_else(hostname);
    let Some(meta) = pear_core::load_workspace(path)? else {
        bail!(
            "{} is not a pear workspace; run `pear init` first",
            path.display()
        );
    };
    let client =
        RelayClient::with_tls_ca(relay, &token, &meta.id, &device, tls.ca_pem()?.as_deref())?;
    // Snapshots live under the workspace on the relay; register it
    // idempotently so snapshotting works before the first watch too. An
    // existing workspace keeps its registered flavor (§17: e2e is
    // immutable relay-side); only a fresh one is created here — plain.
    let e2e = match client.get_workspace() {
        Ok(ws) => ws.e2e,
        Err(RelayError::NotFound(_)) => {
            client.create_workspace(&workspace_name(path))?;
            false
        }
        Err(e) => return Err(e.into()),
    };
    let report = if e2e {
        // §17: the snapshot commits the encrypted manifest. Only the
        // writer holds the workspace keyring — never invent one here.
        let keyring = pear_core::e2e::load_workspace_keyring(path)?.ok_or_else(|| {
            anyhow::anyhow!(
                "workspace {} is end-to-end encrypted but this device has no workspace key; \
                 run `pear watch --relay --e2e` on the writer first",
                meta.id
            )
        })?;
        pear_core::snapshot::push_snapshot_e2e(path, &client, message.as_deref(), &keyring)?
    } else {
        pear_core::snapshot::push_snapshot(path, &client, message.as_deref())?
    };
    println!(
        "snapshot {} created: {} files, {} chunks uploaded ({})",
        report.id,
        report.files,
        report.chunks_uploaded,
        human_bytes(report.bytes_uploaded)
    );
    if !report.excluded.is_empty() {
        println!(
            "note: excluded by name and NOT captured: {}",
            report.excluded.join(", ")
        );
    }
    Ok(())
}

/// `pear snapshots` (§12): list the local workspace's snapshots.
fn snapshots(path: &Path, relay: &str, token: Option<String>, tls: &RelayTls) -> Result<()> {
    let token = resolve_token(token)?;
    let Some(meta) = pear_core::load_workspace(path)? else {
        bail!(
            "{} is not a pear workspace; run `pear init` first",
            path.display()
        );
    };
    let client = RelayClient::with_tls_ca(
        relay,
        &token,
        &meta.id,
        &hostname(),
        tls.ca_pem()?.as_deref(),
    )?;
    let list = client.list_snapshots()?;
    if list.is_empty() {
        println!("no snapshots for workspace {}", meta.id);
        return Ok(());
    }
    println!("{:<5} {:<11} {:<12} NAME", "ID", "KIND", "CREATED_AT");
    for s in list {
        println!(
            "{:<5} {:<11} {:<12} {}",
            s.id,
            s.kind,
            s.created_at,
            s.name.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

/// `pear clone` (§12/§13): with `--snapshot`, materialize a snapshot into a
/// fresh directory as a NEW workspace (forked lineage, origin.json
/// provenance). Without it — the onboarding command — mirror the head once:
/// adopt the shared workspace id and pull. WORKSPACE is a hex id or a
/// `team/name` ref resolved on the relay.
fn clone(
    path: &Path,
    workspace_ref: &str,
    snapshot: Option<u64>,
    relay: &str,
    token: Option<String>,
    name: Option<String>,
    tls: &RelayTls,
) -> Result<()> {
    let token = resolve_token(token)?;
    let tls_ca = tls.ca_pem()?;
    // A `team/name` ref resolves to the shared workspace id first (§13
    // name resolution); anything else is used as the id verbatim.
    let workspace = if workspace_ref.contains('/') {
        let Some((team, name)) = workspace_ref
            .split_once('/')
            .filter(|(team, name)| !team.is_empty() && !name.is_empty() && !name.contains('/'))
        else {
            bail!("workspace ref {workspace_ref:?} is neither a hex id nor <team>/<name>");
        };
        let resolver =
            RelayClient::unbound_with_tls_ca(relay, &token, &hostname(), tls_ca.as_deref())?;
        resolver
            .resolve_workspace(team, name)
            .map_err(|e| match e {
                RelayError::NotFound(_) => anyhow::anyhow!(
                    "no workspace {team}/{name} — it does not exist or you have no role on it"
                ),
                other => anyhow::Error::new(other),
            })?
            .id
    } else {
        workspace_ref.to_string()
    };
    let client =
        RelayClient::with_tls_ca(relay, &token, &workspace, &hostname(), tls_ca.as_deref())?;
    // Verify the workspace exists and is readable (a 404 means no such
    // workspace OR no role on it) — and learn its flavor (§17) before any
    // filesystem side effect.
    let ws_record = client.get_workspace().map_err(|e| match e {
        RelayError::NotFound(_) => anyhow::anyhow!(
            "no workspace {workspace} — it does not exist or you have no role on it"
        ),
        other => anyhow::Error::new(other),
    })?;
    let Some(snapshot) = snapshot else {
        // Mirror-once: adopt the shared id and pull the current head.
        // Same guards as the fork-clone path: never into a non-empty or
        // already-initialized directory.
        if pear_core::load_workspace(path)?.is_some() {
            bail!(
                "{} is already a pear workspace; clone needs a fresh directory",
                path.display()
            );
        }
        std::fs::create_dir_all(path)?;
        if std::fs::read_dir(path)?.next().is_some() {
            bail!(
                "{} is not empty; clone needs a fresh directory",
                path.display()
            );
        }
        pear_core::init_workspace(path, Some(&workspace))?;
        let onboard = || -> anyhow::Result<pear_core::sync::PullReport> {
            // §17: on an e2e workspace, resolve the keyring AFTER init —
            // local file when this device already onboarded, else fetch
            // the caller's wrap and unwrap it with the `--name` identity's
            // keypair.
            let e2e_keyring = if ws_record.e2e {
                Some(pear_core::e2e::workspace_key_for_reader(
                    path,
                    &client,
                    &keys_dir()?,
                    name.as_deref(),
                )?)
            } else {
                None
            };
            Ok(match &e2e_keyring {
                Some(keyring) => pear_core::sync::pull_once_e2e(path, &client, keyring)?,
                None => pear_core::sync::pull_once(path, &client)?,
            })
        };
        let report = onboard().inspect_err(|_| {
            // The directory was verified empty before init, so everything
            // in it now is ours — including a failed key fetch, which must
            // not block the retry: clear it all (same cleanup as the
            // fork-clone path).
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    let _ = if p.is_dir() {
                        std::fs::remove_dir_all(&p)
                    } else {
                        std::fs::remove_file(&p)
                    };
                }
            }
        })?;
        println!(
            "cloned workspace {workspace_ref} ({workspace}) into {}",
            path.display()
        );
        println!(
            "head seq {}: {} files written, {} deleted, {} chunks fetched ({})",
            report.head_seq,
            report.written.len(),
            report.deleted.len(),
            report.chunks_fetched,
            human_bytes(report.bytes_fetched)
        );
        println!("run `pear mirror --workspace {workspace} --relay {relay}` to keep following this workspace");
        return Ok(());
    };
    // Fork-clone. On an e2e workspace the keyring is fetched+unwrapped
    // here WITHOUT touching the target (a refused clone leaves no side
    // effects); the clone stores it itself after init.
    let report = if ws_record.e2e {
        let keyring = pear_core::e2e::fetch_and_unwrap_workspace_key(
            &client,
            &keys_dir()?,
            name.as_deref(),
        )?;
        pear_core::snapshot::clone_from_snapshot_e2e(path, &client, snapshot, &keyring)?
    } else {
        pear_core::snapshot::clone_from_snapshot(path, &client, snapshot)?
    };
    println!(
        "cloned snapshot {snapshot} of workspace {workspace} into {}",
        path.display()
    );
    println!(
        "new workspace {} (forked lineage): {} files written, {} chunks fetched ({})",
        report.workspace_id,
        report.files_written,
        report.chunks_fetched,
        human_bytes(report.bytes_fetched)
    );
    println!(
        "origin recorded in {}",
        path.join(".pear").join("origin.json").display()
    );
    Ok(())
}

fn resolve_token(token: Option<String>) -> Result<String> {
    match token.or_else(|| std::env::var("PEAR_TOKEN").ok()) {
        Some(token) if !token.is_empty() => Ok(token),
        _ => bail!("no relay token — pass --token or set PEAR_TOKEN"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Writer-mode flags must not be silently accepted in local mode: a
    /// no-op `--force` would let a user believe a takeover happened.
    #[test]
    fn watch_rejects_writer_flags_without_relay() {
        for args in [
            vec!["pear", "watch", "a", "b", "--force"],
            vec!["pear", "watch", "a", "b", "--device", "x"],
            vec!["pear", "watch", "a", "b", "--team", "t"],
            vec!["pear", "watch", "a", "b", "--token", "t"],
            vec!["pear", "watch", "a", "b", "--e2e"],
        ] {
            assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
        }
        assert!(
            Cli::try_parse_from(["pear", "watch", "a", "--relay", "http://x", "--force"]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["pear", "watch", "a", "--relay", "http://x", "--e2e"]).is_ok()
        );
        assert!(Cli::try_parse_from(["pear", "watch", "a", "b"]).is_ok());
    }

    /// §17 surfaces: keygen requires --name (there is no local user
    /// concept); mirror/clone take an optional --name for e2e onboarding.
    /// §19 adds the local identity surfaces (id/export/import) and the
    /// explicit re-pin command (trust).
    #[test]
    fn e2e_surface_parses() {
        assert!(Cli::try_parse_from(["pear", "user", "keygen", "--relay", "http://x"]).is_err());
        assert!(Cli::try_parse_from([
            "pear", "user", "keygen", "--name", "jane", "--relay", "http://x"
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["pear", "user", "id", "--name", "jane"]).is_ok());
        assert!(Cli::try_parse_from(["pear", "user", "export", "--name", "jane"]).is_ok());
        assert!(Cli::try_parse_from(["pear", "user", "import", "--name", "jane", "ab12"]).is_ok());
        assert!(Cli::try_parse_from(["pear", "user", "import", "--name", "jane"]).is_err());
        assert!(Cli::try_parse_from(["pear", "trust", "jane", "--relay", "http://x"]).is_ok());
        assert!(Cli::try_parse_from(["pear", "trust", "jane"]).is_err());
        assert!(Cli::try_parse_from([
            "pear",
            "mirror",
            "p",
            "--workspace",
            "w",
            "--relay",
            "http://x",
            "--name",
            "jane"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "pear",
            "clone",
            "p",
            "--workspace",
            "w",
            "--relay",
            "http://x",
            "--name",
            "jane"
        ])
        .is_ok());
        // --name stays optional: plain workspaces need no identity.
        assert!(Cli::try_parse_from([
            "pear",
            "mirror",
            "p",
            "--workspace",
            "w",
            "--relay",
            "http://x"
        ])
        .is_ok());
        // §20: the manual rotation surface requires --relay (it re-wraps
        // on the relay) and a path.
        assert!(Cli::try_parse_from(["pear", "rekey", "p", "--relay", "http://x"]).is_ok());
        assert!(Cli::try_parse_from(["pear", "rekey", "p"]).is_err());
        assert!(Cli::try_parse_from(["pear", "rekey", "--relay", "http://x"]).is_err());
        // §20: member removal mirrors `team add` — team + --user + --relay.
        assert!(Cli::try_parse_from([
            "pear", "team", "remove", "t", "--user", "u", "--relay", "http://x"
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["pear", "team", "remove", "t", "--relay", "http://x"]).is_err());
        assert!(Cli::try_parse_from(["pear", "team", "remove", "t", "--user", "u"]).is_err());
        assert!(Cli::try_parse_from([
            "pear", "watch", "a", "--relay", "http://x", "--e2e", "--daemon"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "pear",
            "mirror",
            "p",
            "--workspace",
            "w",
            "--relay",
            "http://x",
            "--name",
            "j",
            "--daemon"
        ])
        .is_ok());
    }

    /// The daemon surface (§16): --daemon on watch/mirror, status, daemon stop.
    #[test]
    fn daemon_surface_parses() {
        assert!(Cli::try_parse_from(["pear", "watch", "a", "b", "--daemon"]).is_ok());
        assert!(
            Cli::try_parse_from(["pear", "watch", "a", "--relay", "http://x", "--daemon"]).is_ok()
        );
        assert!(Cli::try_parse_from([
            "pear",
            "mirror",
            "a",
            "--workspace",
            "w",
            "--relay",
            "http://x",
            "--daemon"
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["pear", "status"]).is_ok());
        assert!(Cli::try_parse_from(["pear", "status", "some/path"]).is_ok());
        assert!(Cli::try_parse_from(["pear", "daemon", "stop"]).is_ok());
    }

    /// §28: the `.env` kill switch surfaces — `team create --no-env` and
    /// `team policy <team> --env on|off` (the value is required, and only
    /// on/off parse).
    #[test]
    fn team_env_policy_surface_parses() {
        assert!(
            Cli::try_parse_from(["pear", "team", "create", "t", "--relay", "http://x"]).is_ok()
        );
        assert!(Cli::try_parse_from([
            "pear", "team", "create", "t", "--no-env", "--relay", "http://x"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "pear", "team", "policy", "t", "--env", "off", "--relay", "http://x"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "pear", "team", "policy", "t", "--env", "on", "--relay", "http://x"
        ])
        .is_ok());
        // --env is required, and only on|off are values.
        assert!(
            Cli::try_parse_from(["pear", "team", "policy", "t", "--relay", "http://x"]).is_err()
        );
        assert!(Cli::try_parse_from([
            "pear", "team", "policy", "t", "--env", "maybe", "--relay", "http://x"
        ])
        .is_err());
    }

    /// §17/§19: every relay-talking surface accepts --tls-ca-cert.
    #[test]
    fn tls_ca_cert_parses_on_all_relay_surfaces() {
        for args in [
            vec!["pear", "user", "create", "n", "--relay", "http://x"],
            vec![
                "pear", "user", "keygen", "--name", "n", "--relay", "http://x",
            ],
            vec!["pear", "trust", "n", "--relay", "http://x"],
            vec!["pear", "team", "create", "t", "--relay", "http://x"],
            vec![
                "pear", "team", "add", "t", "--user", "u", "--role", "writer", "--relay",
                "http://x",
            ],
            vec!["pear", "team", "remove", "t", "--user", "u", "--relay", "http://x"],
            vec!["pear", "team", "members", "t", "--relay", "http://x"],
            vec![
                "pear", "team", "policy", "t", "--env", "off", "--relay", "http://x",
            ],
            vec!["pear", "share", "p", "--team", "t", "--relay", "http://x"],
            vec!["pear", "rekey", "p", "--relay", "http://x"],
            vec!["pear", "watch", "a", "--relay", "http://x"],
            vec![
                "pear",
                "mirror",
                "p",
                "--workspace",
                "w",
                "--relay",
                "http://x",
            ],
            vec!["pear", "checkout", "p", "--relay", "http://x"],
            vec!["pear", "snapshot", "p", "--relay", "http://x"],
            vec!["pear", "snapshots", "p", "--relay", "http://x"],
            vec![
                "pear",
                "clone",
                "p",
                "--workspace",
                "w",
                "--relay",
                "http://x",
            ],
        ] {
            let mut with_ca = args.clone();
            with_ca.extend(["--tls-ca-cert", "ca.pem"]);
            assert!(
                Cli::try_parse_from(&with_ca).is_ok(),
                "--tls-ca-cert rejected: {with_ca:?}"
            );
        }
    }

    /// §20 at the CLI surface: `pear rekey` forces one rotation, re-wraps
    /// the current team, and persists the member record — while a plain
    /// workspace and a team-less e2e workspace are operator errors, not
    /// silent no-ops. Runs against a real relay on a background runtime;
    /// the test body is synchronous (RelayClient is blocking).
    #[test]
    fn rekey_rotates_rewraps_and_errors_where_it_must() {
        const TOKEN: &str = "rekey-test-token";
        let tmp = tempfile::tempdir().unwrap();
        // `pear rekey` resolves known_keys under $PEAR_HOME: keep it out
        // of the operator's real home. No other test in this binary reads
        // the environment, so the process-wide set is race-free here.
        let pear_home = tmp.path().join("pear-home");
        std::env::set_var("PEAR_HOME", &pear_home);

        // The relay on a background multi-thread runtime.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let relay_dir = tmp.path().join("relay");
        let url = rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                pear_relay::serve_on(listener, TOKEN, &relay_dir, 300)
                    .await
                    .expect("relay serve failed");
            });
            format!("http://{addr}")
        });
        let probe = RelayClient::new(&url, TOKEN, "rekey-probe", "probe");
        for _ in 0..100 {
            if probe.create_workspace("probe").is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // Users, and signed key bundles for both (what `pear user keygen`
        // mints and registers).
        let admin = RelayClient::unbound(&url, TOKEN, "operator");
        let alice_tok = admin.create_user("alice").unwrap().token;
        let bob_tok = admin.create_user("bob").unwrap().token;
        let keys_dir = pear_home.join("keys");
        for (name, token) in [("alice", &alice_tok), ("bob", &bob_tok)] {
            let x = pear_core::crypto::user_keypair_load_or_create(&keys_dir, name).unwrap();
            let ed = pear_core::crypto::ed_keypair_load_or_create(&keys_dir, name).unwrap();
            let sig = ed.sign(&pear_core::crypto::bundle_statement(name, &x.public));
            RelayClient::unbound(&url, token, name)
                .put_key_bundle(
                    name,
                    &pear_core::crypto::hex_encode(&x.public),
                    &pear_core::crypto::hex_encode(&ed.public),
                    &pear_core::crypto::hex_encode(&sig),
                )
                .unwrap();
        }
        let alice_admin = RelayClient::unbound(&url, &alice_tok, "alice-laptop");
        let team = alice_admin.create_team("acme").unwrap();
        alice_admin
            .team_add_member(&team.id, "bob", "reader")
            .unwrap();

        // The e2e workspace: pushed once at generation 1, wrapped to
        // alice+bob, record persisted — what `pear watch --e2e` sets up.
        let dir_a = tmp.path().join("a");
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::write(dir_a.join("f.txt"), b"v1\n").unwrap();
        let (meta, _) = pear_core::init_workspace(&dir_a, None).unwrap();
        let alice = RelayClient::new(&url, &alice_tok, &meta.id, "alice-laptop");
        alice.create_workspace_e2e("api", Some(&team.id)).unwrap();
        alice.acquire().unwrap();
        let mut keyring = pear_core::e2e::load_or_create_workspace_keyring(&dir_a).unwrap();
        pear_core::sync::push_cycle_e2e(&dir_a, &alice, 0, false, &keyring).unwrap();
        let known_keys = pear_home.join("known_keys");
        pear_core::e2e::rotation_maintenance(&alice, &dir_a, &mut keyring, &known_keys, false)
            .unwrap();
        assert_eq!(keyring.newest().0, 1, "setup: still generation 1");

        // Happy path: one forced rotation, gen 1 -> 2, team re-wrapped,
        // record updated. (The test's `keyring` var still holds gen 1:
        // `rekey` loads and rotates its own copy from disk.)
        let tls = RelayTls { tls_ca_cert: None };
        rekey(&dir_a, &url, Some(alice_tok.clone()), &tls).unwrap();
        let reloaded = pear_core::e2e::load_workspace_keyring(&dir_a)
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.newest().0, 2, "rekey forced exactly one rotation");
        // ...and generation 1 is retained: pre-rekey ciphertext still
        // decrypts under the stored ring (no history loss, §20).
        let gen1_blob = pear_core::crypto::encrypt_chunk(keyring.newest().1, b"old content");
        assert!(
            reloaded
                .decrypt("chunk", |k| pear_core::crypto::decrypt_chunk(k, &gen1_blob))
                .is_ok(),
            "the rotated ring kept generation 1"
        );
        let recorded = pear_core::e2e::load_wrapped_members(&dir_a)
            .unwrap()
            .expect("rekey persists the wrapped member set");
        assert_eq!(
            recorded,
            ["alice", "bob"].into_iter().map(String::from).collect()
        );
        // Bob's wrap now unwraps the FULL two-generation ring (an addition
        // or a re-wrap always hands over the whole history). `keys/me` is
        // per-token, so the fetch goes out as bob.
        let bob = RelayClient::new(&url, &bob_tok, &meta.id, "bob-laptop");
        let bob_ring =
            pear_core::e2e::fetch_and_unwrap_workspace_key(&bob, &keys_dir, Some("bob")).unwrap();
        assert_eq!(bob_ring, reloaded);

        // A plain (not e2e) workspace is an operator error...
        let dir_p = tmp.path().join("plain");
        std::fs::create_dir_all(&dir_p).unwrap();
        let (pmeta, _) = pear_core::init_workspace(&dir_p, None).unwrap();
        RelayClient::new(&url, &alice_tok, &pmeta.id, "alice-laptop")
            .create_workspace("plain")
            .unwrap();
        let err = rekey(&dir_p, &url, Some(alice_tok.clone()), &tls).unwrap_err();
        assert!(
            format!("{err:#}").contains("not end-to-end encrypted"),
            "{err:#}"
        );

        // ...and so is an e2e workspace with no attached team.
        let dir_s = tmp.path().join("solo");
        std::fs::create_dir_all(&dir_s).unwrap();
        let (smeta, _) = pear_core::init_workspace(&dir_s, None).unwrap();
        RelayClient::new(&url, &alice_tok, &smeta.id, "alice-laptop")
            .create_workspace_e2e("solo", None)
            .unwrap();
        let err = rekey(&dir_s, &url, Some(alice_tok), &tls).unwrap_err();
        assert!(format!("{err:#}").contains("no attached team"), "{err:#}");
    }

    /// §20 at the CLI surface: `pear team remove` drops a member and their
    /// wrapped-key access dies with the membership (their `keys/me` 404s
    /// at once); the last-owner removal is refused; and a non-owner member
    /// removes THEMSELVES (leaving) without any owner. Runs against a real
    /// relay on a background runtime, like the rekey test above.
    #[test]
    fn team_remove_cuts_wrap_access_and_guards_last_owner() {
        const TOKEN: &str = "team-remove-test-token";
        let tmp = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let relay_dir = tmp.path().join("relay");
        let url = rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                pear_relay::serve_on(listener, TOKEN, &relay_dir, 300)
                    .await
                    .expect("relay serve failed");
            });
            format!("http://{addr}")
        });
        let probe = RelayClient::new(&url, TOKEN, "team-remove-probe", "probe");
        for _ in 0..100 {
            if probe.create_workspace("probe").is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // Users with signed bundles, a team, and an e2e workspace wrapped
        // for both (wrap-maintenance needs no workspace files — client,
        // keyring, and a known_keys path are enough).
        let admin = RelayClient::unbound(&url, TOKEN, "operator");
        let alice_tok = admin.create_user("alice").unwrap().token;
        let bob_tok = admin.create_user("bob").unwrap().token;
        let keys_dir = tmp.path().join("keys");
        for (name, token) in [("alice", &alice_tok), ("bob", &bob_tok)] {
            let x = pear_core::crypto::user_keypair_load_or_create(&keys_dir, name).unwrap();
            let ed = pear_core::crypto::ed_keypair_load_or_create(&keys_dir, name).unwrap();
            let sig = ed.sign(&pear_core::crypto::bundle_statement(name, &x.public));
            RelayClient::unbound(&url, token, name)
                .put_key_bundle(
                    name,
                    &pear_core::crypto::hex_encode(&x.public),
                    &pear_core::crypto::hex_encode(&ed.public),
                    &pear_core::crypto::hex_encode(&sig),
                )
                .unwrap();
        }
        let alice_admin = RelayClient::unbound(&url, &alice_tok, "alice-laptop");
        let team = alice_admin.create_team("acme").unwrap();
        alice_admin
            .team_add_member(&team.id, "bob", "reader")
            .unwrap();
        let (meta, _) = pear_core::init_workspace(&tmp.path().join("a"), None).unwrap();
        let alice = RelayClient::new(&url, &alice_tok, &meta.id, "alice-laptop");
        alice.create_workspace_e2e("api", Some(&team.id)).unwrap();
        // A real generation-1 ring, minted on disk like the writer's.
        let keyring = pear_core::e2e::load_or_create_workspace_keyring(&tmp.path().join("a")).unwrap();
        let known_keys = tmp.path().join("known_keys");
        pear_core::e2e::wrap_maintenance(&alice, &keyring, &known_keys).unwrap();
        // Setup check: bob's wrap unwraps for him before the removal.
        let bob = RelayClient::new(&url, &bob_tok, &meta.id, "bob-laptop");
        assert!(
            pear_core::e2e::fetch_and_unwrap_workspace_key(&bob, &keys_dir, Some("bob")).is_ok()
        );

        // `pear team remove`: bob's access dies with the membership —
        // his keys/me 404s immediately, before any writer rotation pass.
        let tls = RelayTls { tls_ca_cert: None };
        team_remove("acme", "bob", &url, Some(alice_tok.clone()), &tls).unwrap();
        let err = bob.get_my_wrapped_key().unwrap_err();
        assert!(
            matches!(err, pear_core::relay::RelayError::NotFound(_)),
            "bob's keys/me died with the membership: {err:?}"
        );
        // Idempotent at the CLI too: removing a non-member is a quiet no-op.
        team_remove("acme", "bob", &url, Some(alice_tok.clone()), &tls).unwrap();

        // Removing the team's LAST owner is refused with the operator
        // message, whoever asks.
        let err = team_remove("acme", "alice", &url, Some(alice_tok.clone()), &tls).unwrap_err();
        assert!(format!("{err:#}").contains("last owner"), "{err:#}");

        // Leaving needs no owner: bob (a plain reader) removes himself.
        alice_admin
            .team_add_member(&team.id, "bob", "reader")
            .unwrap();
        team_remove("acme", "bob", &url, Some(bob_tok), &tls).unwrap();
        let members = alice_admin.team_members(&team.id).unwrap();
        assert!(
            !members.iter().any(|m| m.user == "bob"),
            "bob actually left the team"
        );
    }
}
