//! Thin binary wrapper around `pear_relay::serve` (DESIGN.md §11).

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

/// pear relay server: bearer-token auth, workspace registry, global chunk
/// pool, and the head log with CAS (§32: multi-writer, no leases).
#[derive(Parser)]
#[command(name = "pear-relay", version, about)]
struct Args {
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:7700")]
    addr: SocketAddr,

    /// Shared bearer token required on all routes.
    #[arg(long, env = "PEAR_TOKEN")]
    token: String,

    /// Data directory for the chunk pool and metadata database.
    #[arg(long, default_value = "./.pear-relay")]
    data_dir: PathBuf,

    /// Serve HTTPS with this PEM certificate chain instead of plain HTTP
    /// (§17); requires --tls-key.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// PEM private key matching --tls-cert.
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // Key material is validated here so a bad pair fails at startup, not
    // at the first handshake.
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => Some(pear_relay::ServerTls::from_pem_files(cert, key)?),
        _ => None,
    };
    match tls {
        Some(tls) => {
            pear_relay::serve_tls(args.addr, &args.token, &args.data_dir, tls).await
        }
        None => pear_relay::serve(args.addr, &args.token, &args.data_dir).await,
    }
}
