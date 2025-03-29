pub mod bitfield;
pub mod download;
pub mod http;
pub mod peer;
pub mod session;
pub mod torrent;
pub mod tracker;
pub mod util;

#[allow(dead_code)]
const SAMPLE_PATH: &str = "samples/debian-12.10.0-arm64-netinst.iso.torrent";
#[allow(dead_code)]
const TARGET_PATH: &str = "target/debian-12.10.0-arm64-netinst.iso";
