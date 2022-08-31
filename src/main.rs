mod tls;
use crate::tls::make_tls_config;
use anyhow::Result;
use clap::Parser;
use crowdstrike_cloudproto::framing::CloudProtoSocket;
use crowdstrike_cloudproto::services::lfo::{LfoClient, LfoRequest};
use lfo_client::channel::Channel;
use std::ffi::OsString;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io;
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};
use tracing::{debug, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const DEFAULT_LFO_DOMAIN: &str = "lfodown01-lanner-lion.cloudsink.net";
const DEFAULT_LFO_PORT: u16 = 443;

// For use with local servers. If you are unsure, leave this to false.
const INSECURE_NO_VERIFY_SERVER_CERT: bool = false;

#[derive(Parser)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Download a file from an LFO server
    Download(Download),
    /// Parse a "channel file" and try to show any download records inside
    ParseChannel { path: String },
}

#[derive(Parser)]
struct Download {
    remote_name: String,
    #[clap(long)]
    host: Option<String>,
    #[clap(long)]
    port: Option<u16>,
    #[clap(short, long)]
    local_name: Option<String>,
    #[clap(short, long)]
    download_folder: Option<PathBuf>,
    #[clap(short, long)]
    save_raw_lfo: bool,
}

async fn lfo_tls_connect(host: &str, port: u16) -> Result<TlsStream<TcpStream>> {
    let tls_config = make_tls_config().await?;
    let connector = TlsConnector::from(Arc::new(tls_config));

    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let domain = rustls::ServerName::try_from(host)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;
    let stream = TcpStream::connect(&addr).await?;
    debug!("TCP connected to LFO port 443");

    let stream = connector.connect(domain, stream).await?;
    info!("LFO TLS session established");

    Ok(stream)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "lfo_client=debug,rustls=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Args::parse();
    match cli.command {
        Command::ParseChannel { path } => {
            let data = std::fs::read(path)?;
            let chan = Channel::try_from(&data)?;
            info!("Channel ID {:#x}", chan.channel_id);
            info!(
                "Channel ver0 {:#x}, ver1 {:#x}",
                chan.version0, chan.version1
            );
            if let Some(meta) = chan.download_metadata {
                info!("Channel contains {} download records", meta.records.len());
                for (i, record) in meta.records.into_iter().enumerate() {
                    info!("Record {i}: {record:#}")
                }
            }
        }
        Command::Download(args @ Download { .. }) => {
            let host = args.host.as_deref().unwrap_or(DEFAULT_LFO_DOMAIN);
            let port = args.port.unwrap_or(DEFAULT_LFO_PORT);
            let stream = lfo_tls_connect(host, port).await?;
            let mut client = LfoClient::new(CloudProtoSocket::new(stream));
            let lfo = client
                .get(&LfoRequest::new_simple(args.remote_name.clone()))
                .await?;
            info!(
                "Received successful response ({:#x} bytes)",
                lfo.raw_lfo_payload().len(),
            );

            let mut save_path = if let Some(folder) = args.download_folder {
                folder
            } else {
                std::env::current_dir()?
            };
            let local_name = if let Some(name) = args.local_name {
                name
            } else if let Some(slash_idx) = args.remote_name.rfind('/') {
                args.remote_name[slash_idx + 1..].to_owned()
            } else {
                args.remote_name
            };
            save_path.push(local_name);

            if args.save_raw_lfo {
                let lfo_ext: OsString = match save_path.extension() {
                    None => "lfo".into(),
                    Some(ext) => {
                        let mut ext = ext.to_owned();
                        ext.push(".lfo");
                        ext
                    }
                };
                let raw_save_path = save_path.with_extension(lfo_ext);
                std::fs::write(&raw_save_path, lfo.raw_lfo_payload())?;
                info!(
                    "Saved {} (0x{:x} bytes)",
                    &raw_save_path.display(),
                    lfo.raw_lfo_payload().len()
                );
            }

            let data = lfo.data()?;
            std::fs::write(&save_path, data.as_ref())?;
            info!("Saved {} (0x{:x} bytes)", &save_path.display(), data.len());
        }
    }

    Ok(())
}
