//! Public-key identities, end to end: making one, keeping it, handing out the
//! public half, and deciding who is allowed in.
//!
//! ```bash
//! cargo run -p fectp --example keys
//! ```
//!
//! The other examples call `Identity::generate()` and pass the key straight to
//! the peer as a variable, which skips the only part that is actually awkward
//! in a real deployment: the two sides are different machines, started at
//! different times, and the only thing that travels between them beforehand is
//! a string somebody copied.
//!
//! Four things this shows, in order:
//!
//! 1. An identity is generated **once** and stored. Generating a fresh one on
//!    every start would change the server's public key every restart, and every
//!    client would stop trusting it.
//! 2. The **secret never leaves the machine**. Only the public half is copied.
//! 3. A public key is 32 raw bytes, which is not something you can paste into a
//!    config file, so it is printed as hex and parsed back.
//! 4. **Authentication is not authorisation.** The handshake proves *which* key
//!    a peer holds. Deciding whether that key may do anything is your job, and
//!    here it is an allow-list.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

// `PeerKey` is the public name for a 32-byte X25519 public key. Method
// signatures spell the underlying type `PublicKey`; this is the name to
// import when you want to store one.
use fectp::{Connection, Endpoint, Error, Event, Identity, PayloadType, PeerKey};

fn main() -> fectp::Result<()> {
    // Somewhere to keep the key files. A real deployment uses a fixed path the
    // service owns — /etc/myservice/identity.key, or a flash partition.
    let dir = std::env::temp_dir().join("fectp-keys-example");
    fs::create_dir_all(&dir).map_err(Error::Io)?;

    // ── 1. The server's identity ─────────────────────────────────────────
    //
    // Created on first run, loaded on every run after. The public key stays
    // the same across restarts because the secret does.
    let server_identity = load_or_create(&dir.join("server.key"))?;
    let server_public = *server_identity.public();

    println!("server identity: {}", dir.join("server.key").display());
    println!("  public key  : {}", to_hex(&server_public));
    println!("  ^ this is the line you put in a client's configuration\n");

    // ── 2. Who is allowed to connect ─────────────────────────────────────
    //
    // Each client has its own identity, exactly as the server does. The server
    // keeps the public halves of the ones it will accept. This is a plain file
    // here; a real service might read a directory, a database, or a config.
    let known_client = load_or_create(&dir.join("client.key"))?;
    let allow_list: HashSet<PeerKey> = [*known_client.public()].into_iter().collect();

    println!("allow-list ({} entry):", allow_list.len());
    println!("  {}\n", to_hex(known_client.public()));

    let mut server = Endpoint::bind("127.0.0.1:0", server_identity)?;
    let addr = server.local_addr()?;

    // ── 3. The client side ───────────────────────────────────────────────
    //
    // A client does not have the server's `Identity` — only the hex string
    // above, out of its configuration file. That string is all it needs, and
    // it is the only thing that had to travel between the two machines.
    let configured = to_hex(&server_public);
    assert_eq!(from_hex(&configured), Some(server_public), "hex must round-trip");
    assert!(from_hex("nonsense").is_none(), "a bad string must not become a zero key");

    let client = thread::spawn(move || -> fectp::Result<()> {
        let server_public = from_hex(&configured).expect("a valid key in the config");

        // The known client: on the allow-list, so it gets an answer.
        let conn = Connection::connect(addr, &server_public, &known_client)?;
        conn.set_read_timeout(Some(Duration::from_secs(5)))?;
        conn.send(b"reading: 23.5", PayloadType::Opaque)?;

        let mut buf = vec![0u8; 1024];
        let n = conn.recv(&mut buf)?;
        println!("known client   <- {}", String::from_utf8_lossy(&buf[..n]));

        // A stranger: a perfectly valid identity that nobody put on the list.
        // Its handshake succeeds — it is a real key, and the server can prove
        // it — and then the server drops it anyway.
        let stranger = Identity::generate();
        let conn = Connection::connect(addr, &server_public, &stranger)?;
        conn.set_read_timeout(Some(Duration::from_millis(500)))?;
        conn.send(b"let me in", PayloadType::Opaque)?;
        match conn.recv(&mut buf) {
            Ok(n) => println!("stranger       <- {}", String::from_utf8_lossy(&buf[..n])),
            Err(_) => println!("stranger       <- nothing; it was not on the list"),
        }
        Ok(())
    });

    // ── 4. The server loop ───────────────────────────────────────────────
    let mut accepted = 0;
    let mut refused = 0;
    while accepted + refused < 2 {
        match server.poll(Some(Duration::from_millis(200)))? {
            Event::Connected { peer, .. } => {
                // The handshake authenticated this peer from its first message,
                // so by the time we get here the key is proven. What remains is
                // the decision: is this key one of ours?
                let key = server.peer_public_key(peer).copied();
                match key {
                    Some(key) if allow_list.contains(&key) => {
                        accepted += 1;
                        println!("server: accepted {}…", &to_hex(&key)[..16]);
                    }
                    Some(key) => {
                        refused += 1;
                        println!("server: refused  {}… — not on the allow-list", &to_hex(&key)[..16]);
                        server.disconnect(peer);
                    }
                    // Only reachable in the modes that have no identities.
                    None => {
                        refused += 1;
                        server.disconnect(peer);
                    }
                }
            }
            Event::Message { peer, data } => {
                let reply = format!("received {} bytes", data.len());
                server.send(peer, reply.as_bytes(), PayloadType::Opaque)?;
            }
            _ => {}
        }
    }

    client.join().expect("client thread")?;

    println!("\n{accepted} accepted, {refused} refused");
    println!("run it again: the server's public key above is unchanged, because");
    println!("its secret was loaded from disk rather than generated afresh.");
    Ok(())
}

/// Loads an identity from `path`, creating and storing one if it is not there.
///
/// This is the whole lifecycle. The secret is 32 bytes and it is the only thing
/// that must stay private — the public half is derived from it, so nothing else
/// needs storing.
fn load_or_create(path: &Path) -> fectp::Result<Identity> {
    match fs::read(path) {
        Ok(bytes) => {
            let secret: [u8; 32] = bytes
                .try_into()
                .map_err(|_| Error::Io(std::io::Error::other("key file is not 32 bytes")))?;
            Ok(Identity::from_secret(secret))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let identity = Identity::generate();
            write_secret(path, identity.secret())?;
            Ok(identity)
        }
        Err(e) => Err(Error::Io(e)),
    }
}

/// Writes a secret key, readable only by its owner where the platform allows.
fn write_secret(path: &Path, secret: &[u8; 32]) -> fectp::Result<()> {
    fs::write(path, secret).map_err(Error::Io)?;
    // A key file the whole machine can read is not much of a secret. Unix has
    // a mode for that; on Windows the equivalent is an ACL, which is beyond
    // what an example should be doing.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(Error::Io)?;
    }
    Ok(())
}

/// 32 bytes as 64 hex characters — something a person can paste into a config.
fn to_hex(key: &PeerKey) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Reverses [`to_hex`], rejecting anything that is not exactly one key.
fn from_hex(text: &str) -> Option<PeerKey> {
    let text = text.trim();
    if text.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(key)
}
