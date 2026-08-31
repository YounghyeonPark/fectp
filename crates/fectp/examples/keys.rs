//! Public-key identities, end to end — as **two separate processes**, because
//! that is the only part of this that is actually awkward.
//!
//! ```bash
//! cargo run -p fectp --example keys -- serve
//! # prints the server's public key; copy it, then in another terminal:
//! cargo run -p fectp --example keys -- connect <that key>
//! ```
//!
//! Run `serve` with no other arguments and it tells you what to do next.
//!
//! The point of splitting it is that a public key has to *travel*, and every
//! way of faking that inside one process — a shared variable, a channel, a
//! moved `String` — quietly skips the step you actually have to get right. Here
//! the key reaches the client the way it reaches a real one: as text somebody
//! copied, parsed from `argv`.
//!
//! What it shows, in order:
//!
//! 1. An identity is generated **once** and stored. Generating a fresh one each
//!    start would change the public key every restart and every client would
//!    stop trusting it.
//! 2. The **secret never moves.** Only the public half is copied, and it is
//!    printed as hex because 32 raw bytes do not go in a config file.
//! 3. **Authentication is not authorisation.** The handshake proves *which* key
//!    a peer holds. Whether that key may do anything is your decision, and here
//!    it is a file of permitted keys — so the first `connect` is refused, and
//!    you have to add the client before it works.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

// `PeerKey` is the public name for a 32-byte X25519 public key. Method
// signatures spell the underlying type `PublicKey`; this is the name to import
// when you want to store one.
use fectp::{Connection, Endpoint, Error, Event, Identity, PayloadType, PeerKey};

const ADDR: &str = "127.0.0.1:4433";

fn main() -> fectp::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => serve(),
        Some("connect") => match args.get(1) {
            Some(key) => connect(key),
            None => {
                eprintln!("usage: keys connect <server public key, 64 hex characters>");
                eprintln!("start the server first; it prints the key to use.");
                Ok(())
            }
        },
        _ => {
            println!("Public-key identities across two processes.\n");
            println!("  1. cargo run -p fectp --example keys -- serve");
            println!("     Creates an identity if there is not one, and prints its public key.\n");
            println!("  2. cargo run -p fectp --example keys -- connect <that key>");
            println!("     In another terminal. It will be REFUSED the first time —");
            println!("     the server has no reason to trust it yet, and says so.\n");
            println!("  3. Add the client's key to the allow-list, as the output tells you.");
            println!("     Run step 2 again and it works.\n");
            println!("Files live in {}", dir().display());
            Ok(())
        }
    }
}

/// The server: holds an identity, and a list of clients it will talk to.
fn serve() -> fectp::Result<()> {
    let identity = load_or_create(&dir().join("server.key"))?;
    let public = *identity.public();

    println!("server listening on {ADDR}");
    println!("public key: {}", to_hex(&public));
    println!("\nrun this in another terminal:");
    println!("  cargo run -p fectp --example keys -- connect {}\n", to_hex(&public));

    let allowed = load_allow_list()?;
    match allowed.len() {
        0 => println!("allow-list is empty — every client will be refused until you add one."),
        n => println!("allow-list: {n} client(s)."),
    }
    println!("(editing {} takes effect on the next connection)\n", allow_list_path().display());

    let mut server = Endpoint::bind(ADDR, identity)?;
    loop {
        // Re-read each time round rather than caching, so adding a key does not
        // mean restarting the server. A real service would watch the file or
        // reload on a signal; the point is that the list is data, not code.
        let allowed = load_allow_list()?;

        match server.poll(Some(Duration::from_millis(200)))? {
            Event::Connected { peer, .. } => {
                // The handshake already authenticated this peer from its very
                // first message, so the key below is proven, not claimed. All
                // that is left is the decision.
                let Some(key) = server.peer_public_key(peer).copied() else {
                    server.disconnect(peer);
                    continue;
                };
                if allowed.contains(&key) {
                    println!("accepted {}…", &to_hex(&key)[..16]);
                } else {
                    println!("REFUSED  {}", to_hex(&key));
                    println!("  ^ to let this client in, append that line to");
                    println!("    {}", allow_list_path().display());
                    server.disconnect(peer);
                }
            }
            Event::Message { peer, data } => {
                println!("  {} bytes from {peer:?}", data.len());
                let reply = format!("server received {} bytes", data.len());
                server.send(peer, reply.as_bytes(), PayloadType::Opaque)?;
            }
            _ => {}
        }
    }
}

/// The client: has its own identity, and the server's key as text.
///
/// It never sees the server's `Identity` — only these 64 characters, which is
/// the whole of what had to be distributed.
fn connect(server_key: &str) -> fectp::Result<()> {
    let Some(server_public) = from_hex(server_key) else {
        eprintln!("that is not a public key: expected 64 hex characters, got {}", server_key.len());
        return Ok(());
    };

    let identity = load_or_create(&dir().join("client.key"))?;
    println!("client public key: {}", to_hex(identity.public()));
    println!("connecting to {ADDR}\n");

    let conn = Connection::connect(ADDR, &server_public, &identity)?;
    conn.set_read_timeout(Some(Duration::from_secs(2)))?;
    conn.send(b"reading: 23.5", PayloadType::Opaque)?;

    let mut buf = vec![0u8; 1024];
    match conn.recv(&mut buf) {
        Ok(n) => println!("reply: {}", String::from_utf8_lossy(&buf[..n])),
        Err(_) => {
            println!("no reply — the server refused this client.");
            println!("it printed the line to add to its allow-list; do that and try again.");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- storage ---

fn dir() -> PathBuf {
    std::env::temp_dir().join("fectp-keys-example")
}

fn allow_list_path() -> PathBuf {
    dir().join("allowed-clients.txt")
}

/// Reads the permitted client keys: one 64-character hex line each.
///
/// A missing file means an empty list, which refuses everyone. That is the
/// right default — the alternative, admitting anyone until told otherwise, is
/// the kind of thing that ships by accident.
fn load_allow_list() -> fectp::Result<HashSet<PeerKey>> {
    let text = match fs::read_to_string(allow_list_path()) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(e) => return Err(Error::Io(e)),
    };
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(from_hex)
        .collect())
}

/// Loads an identity from `path`, creating and storing one if it is not there.
///
/// The secret is 32 bytes and is the only thing that must stay private — the
/// public half is derived from it, so nothing else needs storing.
fn load_or_create(path: &Path) -> fectp::Result<Identity> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(Error::Io)?;
    }
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
            println!("created {}", path.display());
            Ok(identity)
        }
        Err(e) => Err(Error::Io(e)),
    }
}

/// Writes a secret key, readable only by its owner where the platform allows.
fn write_secret(path: &Path, secret: &[u8; 32]) -> fectp::Result<()> {
    fs::write(path, secret).map_err(Error::Io)?;
    // A key file the whole machine can read is not much of a secret. Unix has a
    // mode for that; the Windows equivalent is an ACL, which is more than an
    // example should be doing.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(Error::Io)?;
    }
    Ok(())
}

// ------------------------------------------------------------------- hex ---

/// 32 bytes as 64 hex characters — something a person can paste.
fn to_hex(key: &PeerKey) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Reverses [`to_hex`].
///
/// Returns `None` rather than a zero key for anything malformed: a typo that
/// silently became a valid-looking key would be authenticated against the wrong
/// peer, which is the one failure here that must never be quiet.
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
