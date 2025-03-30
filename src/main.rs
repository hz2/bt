use clap::Parser;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use bt::session::Session;
use bt::torrent::Torrent;
use bt::tracker::{peers::SocketType, TrackerRequest};
use bt::util::init_logging;
#[derive(Parser, Debug)]
#[command(name = "bt", about = "jd's BitTorrent client", author, version)]
struct Args {
    /// Path to the .torrent file
    #[arg(short, long)]
    torrent: PathBuf,

    /// Output file destination
    #[arg(short, long)]
    output: PathBuf,

    /// Optional peer ID (20 bytes); otherwise randomly generated
    #[arg(long)]
    peer_id: Option<String>,

    /// Enable compact mode (default: true)
    #[arg(long)]
    compact: u8,

    /// Optional port number (default: 6881)
    #[arg(short, long)]
    port: Option<u16>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();
    init_logging();

    let torrent_bytes = fs::read(&args.torrent).expect("could not read .torrent file");
    let torrent: Torrent =
        serde_bencode::from_bytes(&torrent_bytes).expect("invalid .torrent file");

    let peer_id = args.peer_id.map_or_else(
        || {
            let mut id = [0u8; 20];
            id[..8].copy_from_slice(b"-RU0001-");
            let random: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
            id[8..].copy_from_slice(&random);
            id
        },
        |s| {
            let bytes = s.as_bytes();
            assert_eq!(bytes.len(), 20, "peer_id must be 20 bytes");
            let mut id = [0u8; 20];
            id.copy_from_slice(bytes);
            id
        },
    );

    let tracker_req = TrackerRequest {
        info_hash: torrent.info_hash(),
        peer_id,
        port: args.port.unwrap_or(6969), // nice
        uploaded: 0,
        downloaded: 0,
        left: torrent.total_length(),
        compact: args.compact,
    };

    let tracker_resp =
        TrackerRequest::announce(&tracker_req, &torrent).expect("failed to contact tracker");

    let peers: Vec<SocketAddr> = tracker_resp
        .peers
        .iter()
        .filter(|p| matches!(p, SocketType::IPv4(_))) // restrict at runtime
        .map(|p| match p {
            SocketType::IPv4(addr) => SocketAddr::V4(*addr),
            SocketType::IPv6(addr) => SocketAddr::V6(*addr), // won't happen unless filter logic changes
        })
        .collect();

    if peers.is_empty() {
        eprintln!("No usable peers found.");
        std::process::exit(1);
    }

    let session = Session::new(torrent, peers, peer_id, args.output);
    let stats = session.start();

    println!(
        "Download finished: {} / {} pieces completed. {} peers succeeded, {} failed.",
        stats.completed_pieces, stats.total_pieces, stats.successful_peers, stats.failed_peers
    );
}
