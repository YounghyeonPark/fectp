//! A round trip over a real socket, in one process.
//!
//! ```bash
//! cargo run -p fectp --example echo
//! ```

use std::thread;
use std::time::{Duration, Instant};

use fectp::{Connection, Endpoint, Event, Identity, PayloadType};

fn main() -> fectp::Result<()> {
    let identity = Identity::generate();
    let server_public = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity)?;
    let addr = server.local_addr()?.to_string();
    println!("server listening on {addr}");

    let server = thread::spawn(move || -> fectp::Result<()> {
        let mut echoed = 0;
        while echoed < 5 {
            match server.poll(Some(Duration::from_secs(5)))? {
                Event::Connected { peer, zero_rtt, .. } => println!(
                    "accepted {:?}, 0-RTT payload: {:?}",
                    server.peer_addr(peer),
                    String::from_utf8_lossy(&zero_rtt)
                ),
                Event::Message { peer, data } => {
                    server.send(peer, &data, PayloadType::Opaque)?;
                    echoed += 1;
                }
                _ => {}
            }
        }
        Ok(())
    });

    // The 0-RTT payload rides along in the first handshake message, so it
    // reaches the server before the handshake has finished.
    let client = Connection::connect_and_send(
        &addr,
        &server_public,
        &Identity::generate(),
        b"hello before the handshake finished",
    )?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    println!("connected, max payload {} bytes", client.max_payload());

    let mut buf = vec![0u8; 2048];
    for i in 0..5 {
        let message = format!("message {i}");
        let start = Instant::now();
        client.send(message.as_bytes(), PayloadType::Opaque)?;
        let n = client.recv(&mut buf)?;
        println!(
            "  {:>10} -> echoed in {:?}",
            String::from_utf8_lossy(&buf[..n]),
            start.elapsed()
        );
    }

    server.join().expect("server thread")?;
    Ok(())
}
