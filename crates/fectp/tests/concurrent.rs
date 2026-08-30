//! Sending and receiving from different threads.
//!
//! Every `Connection` method takes `&self`, so this needs no wrapper, no
//! conversion and no clone — a shared reference is enough. These check that the
//! claim holds and that the two directions do not block each other.

use std::time::Duration;

mod common;

use common::Echo;
use fectp::{Connection, Identity, PayloadType};

const TIMEOUT: Duration = Duration::from_secs(5);

fn client(echo: &Echo) -> Connection {
    let conn =
        Connection::connect(echo.addr(), &echo.public(), &Identity::generate()).expect("connect");
    conn.set_read_timeout(Some(TIMEOUT)).expect("timeout");
    conn
}

#[test]
fn a_connection_is_shareable_between_threads() {
    fn assert_sync<T: Sync + Send>() {}
    assert_sync::<Connection>();
}

#[test]
fn sending_works_while_another_thread_is_blocked_reading() {
    let echo = Echo::start();
    let conn = client(&echo);

    std::thread::scope(|s| {
        // Blocked in `recv` with nothing to read. With `&mut self` methods this
        // thread would own the connection and the send below could not compile,
        // let alone run.
        let reader = s.spawn(|| {
            let mut buf = [0u8; 2048];
            conn.recv(&mut buf).map(|n| buf[..n].to_vec())
        });

        std::thread::sleep(Duration::from_millis(50));
        conn.send(b"sent while the reader waits", PayloadType::Opaque).expect("send");

        let message = reader.join().expect("reader thread").expect("recv");
        assert_eq!(message, b"sent while the reader waits");
    });
}

#[test]
fn both_directions_run_at_once() {
    let echo = Echo::start();
    let conn = client(&echo);

    const MESSAGES: usize = 100;
    std::thread::scope(|s| {
        s.spawn(|| {
            for i in 0..MESSAGES {
                conn.send(&(i as u32).to_le_bytes(), PayloadType::Opaque).expect("send");
            }
        });

        let mut seen = Vec::new();
        let mut buf = [0u8; 2048];
        while seen.len() < MESSAGES {
            let n = conn.recv(&mut buf).expect("recv");
            seen.push(buf[..n].to_vec());
        }

        seen.sort();
        let mut expected: Vec<Vec<u8>> = (0..MESSAGES as u32)
            .map(|i| i.to_le_bytes().to_vec())
            .collect();
        expected.sort();
        assert_eq!(seen, expected);
    });
}

#[test]
fn a_blocked_read_does_not_hold_up_a_send() {
    let echo = Echo::collector();
    let conn = client(&echo);

    std::thread::scope(|s| {
        // This reader will wait the whole timeout, because the collector never
        // answers. The send must not queue behind it.
        s.spawn(|| {
            let mut buf = [0u8; 2048];
            let _ = conn.recv(&mut buf);
        });
        std::thread::sleep(Duration::from_millis(50));

        let start = std::time::Instant::now();
        conn.send(b"not waiting for the reader", PayloadType::Opaque).expect("send");
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(500),
            "the send took {elapsed:?}, so it was waiting behind the blocked read"
        );
    });

    assert_eq!(
        echo.messages(1, TIMEOUT),
        vec![b"not waiting for the reader".to_vec()]
    );
}

#[test]
fn reliable_delivery_works_across_threads() {
    let echo = Echo::collector();
    let conn = client(&echo);

    std::thread::scope(|s| {
        s.spawn(|| {
            for i in 0..20u32 {
                // The congestion window starts small and widens as
                // acknowledgements arrive, so a sender has to be prepared to
                // wait rather than assuming the memory bound is the limit.
                while conn.send_reliable(&i.to_le_bytes(), PayloadType::Opaque).is_err() {
                    conn.flush(TIMEOUT).expect("flush to make room");
                }
            }
            conn.flush(TIMEOUT).expect("flush");
        });
    });

    assert_eq!(echo.messages(20, TIMEOUT).len(), 20);
    assert_eq!(conn.unacknowledged(), 0);
}
