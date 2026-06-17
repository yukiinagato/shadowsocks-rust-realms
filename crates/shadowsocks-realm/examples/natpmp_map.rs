//! Testbed helper: request a NAT-PMP TCP port mapping using this crate's real
//! NAT-PMP client (`portmap::natpmp::map_tcp`). Used by
//! `testing/natpmp-sim/run.sh` to drive a real NAT-PMP gateway.
//!
//! usage: natpmp_map <gateway-ipv4> <internal-port> <external-port>

use std::net::Ipv4Addr;
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: natpmp_map <gateway-ipv4> <internal-port> <external-port>");
        std::process::exit(2);
    }
    let gateway: Ipv4Addr = args[1].parse().expect("gateway ipv4");
    let internal: u16 = args[2].parse().expect("internal port");
    let external: u16 = args[3].parse().expect("external port");

    match shadowsocks_realm::portmap::natpmp::map_tcp(
        gateway,
        internal,
        external,
        7200,
        Duration::from_millis(800),
        5,
    )
    .await
    {
        Ok(m) => println!("MAPPED external={} internal_port={}", m.external, m.internal_port),
        Err(e) => {
            eprintln!("MAP_FAILED {e}");
            std::process::exit(1);
        }
    }
}
