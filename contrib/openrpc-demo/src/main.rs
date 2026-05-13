mod codegen;
mod openrpc;

use anyhow::Context as _;
use clap::Parser;
use openrpc::OpenRpcDoc;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(about = "Generate a type-safe Rust client from Bitcoin Core's getopenrpcinfo RPC")]
struct Args {
    /// Bitcoin Core RPC host
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// RPC port [default: auto-derived from chain]
    #[arg(long)]
    port: Option<u16>,

    /// Bitcoin data directory [default: ~/.bitcoin]
    #[arg(long)]
    datadir: Option<PathBuf>,

    /// Network: main | signet | testnet | testnet4 | regtest
    /// [default: read from bitcoin.conf, fallback to main]
    #[arg(long)]
    chain: Option<String>,

    /// RPC username — reads the .cookie file if omitted
    #[arg(long)]
    rpc_user: Option<String>,

    /// RPC password — reads the .cookie file if omitted
    #[arg(long)]
    rpc_pass: Option<String>,

    /// Read OpenRPC JSON from a file instead of a live node
    #[arg(long, short)]
    input: Option<PathBuf>,

    /// Write generated Rust to this file.
    /// Defaults to $OUT_DIR/bitcoin_client.rs if OUT_DIR is set (Cargo build
    /// script), otherwise ./bitcoin_client.rs in the current directory.
    #[arg(long, short)]
    output: Option<PathBuf>,
}

// ── Data-directory helpers ────────────────────────────────────────────────────

fn default_datadir() -> PathBuf {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".bitcoin"))
        .unwrap_or_else(|| PathBuf::from(".bitcoin"))
}

/// Parse `chain=<value>` from bitcoin.conf, returning `"main"` if absent.
fn chain_from_conf(datadir: &Path) -> String {
    let Ok(text) = std::fs::read_to_string(datadir.join("bitcoin.conf")) else {
        return "main".to_string();
    };
    for line in text.lines() {
        if let Some(val) = line.trim().strip_prefix("chain=") {
            return val.trim().to_string();
        }
    }
    "main".to_string()
}

fn default_port(chain: &str) -> u16 {
    match chain {
        "signet"   => 38332,
        "testnet"  => 18332,
        "testnet4" => 48332,
        "regtest"  => 18443,
        _          => 8332,   // main
    }
}

/// Cookie lives at `{datadir}/.cookie` for mainnet and
/// `{datadir}/{chain}/.cookie` for every other network.
fn cookie_path(datadir: &Path, chain: &str) -> PathBuf {
    match chain {
        "main" => datadir.join(".cookie"),
        other  => datadir.join(other).join(".cookie"),
    }
}

fn read_cookie(datadir: &Path, chain: &str) -> anyhow::Result<(String, String)> {
    let path = cookie_path(datadir, chain);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading cookie from {}", path.display()))?;
    let (user, pass) = text
        .trim()
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("malformed cookie file at {}", path.display()))?;
    Ok((user.to_string(), pass.to_string()))
}

// ── RPC fetch ─────────────────────────────────────────────────────────────────

fn basic_auth(user: &str, pass: &str) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    format!("Basic {encoded}")
}

fn fetch_openrpc(host: &str, port: u16, user: &str, pass: &str) -> anyhow::Result<OpenRpcDoc> {
    let url  = format!("http://{host}:{port}/");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id":      "openrpc-demo",
        "method":  "getopenrpcinfo",
        "params":  [],
    });

    // Bitcoin Core returns HTTP 500 for RPC-level errors but still sends a
    // valid JSON body, so handle both the Ok and Status arms.
    let response: serde_json::Value = match ureq::post(&url)
        .set("Authorization", &basic_auth(user, pass))
        .send_json(body)
    {
        Ok(resp)                          => resp.into_json()?,
        Err(ureq::Error::Status(_, resp)) => resp.into_json()?,
        Err(e)                            => anyhow::bail!("HTTP error: {e}"),
    };

    if let Some(err) = response.get("error").filter(|e| !e.is_null()) {
        anyhow::bail!("RPC error: {err}");
    }

    Ok(serde_json::from_value(response["result"].clone())?)
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let doc: OpenRpcDoc = if let Some(path) = &args.input {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text)?
    } else {
        let datadir = args.datadir.unwrap_or_else(default_datadir);
        let chain   = args.chain.unwrap_or_else(|| chain_from_conf(&datadir));
        let port    = args.port.unwrap_or_else(|| default_port(&chain));

        let (user, pass) = match (args.rpc_user, args.rpc_pass) {
            (Some(u), Some(p)) => (u, p),
            _ => read_cookie(&datadir, &chain)?,
        };

        eprintln!("Connecting to {}:{} (chain: {chain}) …", args.host, port);
        fetch_openrpc(&args.host, port, &user, &pass)?
    };

    eprintln!(
        "Generating client for {} {} ({} methods) …",
        doc.info.title,
        doc.info.version,
        doc.methods.len()
    );

    let code = codegen::generate(&doc);

    let out_path: PathBuf = args.output.unwrap_or_else(|| {
        std::env::var_os("OUT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("bitcoin_client.rs")
    });

    std::fs::write(&out_path, &code)?;
    eprintln!("Written to {}", out_path.display());

    Ok(())
}
