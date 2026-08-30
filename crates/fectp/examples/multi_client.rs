//! Several clients against one server socket, in one process.
//!
//! ```bash
//! cargo run -p fectp --example multi_client
//! ```

use std::thread;
use std::time::{Duration, Instant};

use fectp::{Connection, Event, Identity, Endpoint};

const CLIENTS: usize = 6;
const ROUNDS: usize = 3;

fn main() -> fectp::Result<()> {
    let identity = Identity::generate();
    let server_public = *identity.public();
    let mut server = Endpoint::bind("127.0.0.1:0", identity)?;
    let addr = server.local_addr()?;
    println!("server on {addr}, expecting {CLIENTS} clients");

    let clients = thread::spawn(move || -> fectp::Result<()> {
        // Connect everyone first so their traffic genuinely interleaves.
        let mut conns: Vec<Connection> = (0..CLIENTS)
            .map(|_| {
                let c = Connection::connect(addr, &server_public, &Identity::generate())?;
                c.set_read_timeout(Some(Duration::from_secs(5)))?;
                Ok(c)
            })
            .collect::<fectp::Result<_>>()?;

        let mut buf = vec![0u8; 4096];
        for round in 0..ROUNDS {
            for (index, conn) in conns.iter_mut().enumerate() {
                let message = format!("client {index}, round {round}");
                let start = Instant::now();
                conn.send(message.as_bytes())?;
                let n = conn.recv(&mut buf)?;
                assert_eq!(&buf[..n], message.as_bytes(), "crossed wires");
                if round == 0 {
                    println!("  client {index} round-trip {:?}", start.elapsed());
                }
            }
        }
        Ok(())
    });

    let expected = CLIENTS * ROUNDS;
    let mut echoed = 0;
    let deadline = Instant::now() + Duration::from_secs(10);
    while echoed < expected && Instant::now() < deadline {
        match server.poll(Some(Duration::from_millis(100)))? {
            Event::Connected { peer, resumed, .. } => {
                println!(
                    "  {peer:?} connected ({}), {} peer(s) now",
                    if resumed { "resumed" } else { "full handshake" },
                    server.peer_count()
                );
            }
            Event::Message { peer, data } => {
                server.send(peer, &data)?;
                echoed += 1;
            }
            Event::Idle => {}
            _ => {}
        }
    }

    clients.join().expect("client thread")?;
    println!("echoed {echoed}/{expected} messages across {} peers", server.peer_count());
    Ok(())
}
