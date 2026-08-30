//! Three peers on one socket each, every one dialling the others.
//!
//! ```bash
//! cargo run -p fectp --example mesh
//! ```
//!
//! No node is a server. Each binds one port, dials the others from that same
//! port, and answers dials on it — which is what a node behind a NAT needs, and
//! what "peer to peer" means beyond the marketing.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use fectp::{Endpoint, Event, PayloadType, PeerId};

const NODES: usize = 3;
const SECRET: &[u8] = b"mesh-demo-secret";

struct Node {
    name: char,
    endpoint: Endpoint,
    addr: SocketAddr,
    /// Sessions this node has, and whether it started each one.
    peers: HashMap<PeerId, bool>,
    heard: Vec<String>,
}

fn main() -> fectp::Result<()> {
    // A pre-shared key suits a mesh: every node holds one secret, and nobody
    // has to ship anyone's public key around.
    let mut nodes: Vec<Node> = ('A'..)
        .take(NODES)
        .map(|name| {
            let endpoint = Endpoint::bind_psk("127.0.0.1:0", SECRET)?;
            let addr = endpoint.local_addr()?;
            Ok(Node {
                name,
                endpoint,
                addr,
                peers: HashMap::new(),
                heard: Vec::new(),
            })
        })
        .collect::<fectp::Result<_>>()?;

    for node in &nodes {
        println!("node {} on {}", node.name, node.addr);
    }

    // Every node dials every node after it, so each pair gets one session.
    let addresses: Vec<SocketAddr> = nodes.iter().map(|n| n.addr).collect();
    for (index, node) in nodes.iter_mut().enumerate() {
        for address in addresses.iter().skip(index + 1) {
            node.endpoint.connect(*address, None)?;
        }
    }

    // One loop drives every node. A real deployment runs one of these per
    // process; here they share a thread so the example stays readable.
    let expected_sessions = NODES * (NODES - 1) / 2 * 2;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut sessions = 0;
    while sessions < expected_sessions && Instant::now() < deadline {
        sessions = 0;
        for node in nodes.iter_mut() {
            if let Ok(Event::Connected {
                peer, initiated, ..
            }) = node.endpoint.poll(Some(Duration::from_millis(20)))
            {
                node.peers.insert(peer, initiated);
            }
            sessions += node.peers.len();
        }
    }

    for node in &nodes {
        let dialled = node.peers.values().filter(|started| **started).count();
        println!(
            "node {}: {} session(s) — {dialled} dialled, {} accepted",
            node.name,
            node.peers.len(),
            node.peers.len() - dialled
        );
    }

    // Everyone greets everyone.
    for node in nodes.iter_mut() {
        let greeting = format!("hello from {}", node.name);
        let peers: Vec<PeerId> = node.peers.keys().copied().collect();
        for peer in peers {
            node.endpoint.send(peer, greeting.as_bytes(), PayloadType::Opaque)?;
        }
    }

    let expected_messages = NODES * (NODES - 1);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut delivered = 0;
    while delivered < expected_messages && Instant::now() < deadline {
        delivered = 0;
        for node in nodes.iter_mut() {
            if let Ok(Event::Message { data, .. }) = node.endpoint.poll(Some(Duration::from_millis(20)))
            {
                node.heard.push(String::from_utf8_lossy(&data).into_owned());
            }
            delivered += node.heard.len();
        }
    }

    for node in &nodes {
        let mut heard = node.heard.clone();
        heard.sort();
        println!("node {} heard: {heard:?}", node.name);
    }

    assert_eq!(delivered, expected_messages, "every greeting arrived");
    println!("\n{NODES} peers, {sessions} sessions, one socket each");
    Ok(())
}
