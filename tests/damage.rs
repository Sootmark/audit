//! Damaged input: arbitrary bytes, and every fixture damaged anywhere,
//! give events or problems, never a panic.

use std::fs;
use std::path::Path;

use audit::{classify, parse};
use proptest::prelude::*;

const FIXTURES: [&str; 6] = [
    "plaso/audit.log",
    "plaso/audit_enriched.log",
    "plaso/selinux.log",
    "go-libaudit/audit-rhel7.log",
    "go-libaudit/normal.log",
    "lab/audit.log",
];

fn read(fixture: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture),
    )
    .unwrap()
}

/// Everything a reader would ask of every event.
fn read_all(data: &[u8]) {
    for event in &parse(data).events {
        let _ = (
            event.command_line(),
            event.syscall(),
            event.socket_address(),
        );
        let _ = classify(event);
    }
}

proptest! {
    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..2_000)) {
        read_all(&data);
    }

    /// Record-shaped text with arbitrary values.
    #[test]
    fn arbitrary_records(body in "[ -~\u{1d}]{0,200}", kind in "[A-Z_]{1,12}") {
        read_all(format!("type={kind} msg=audit(1.000:1): {body}\ntype=EXECVE msg=audit(1.000:1): {body}").as_bytes());
    }

    /// A fixture with bytes overwritten anywhere, then cut anywhere.
    #[test]
    fn damaged_fixtures(
        fixture in 0..FIXTURES.len(),
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40),
        cut in any::<usize>(),
    ) {
        let mut data = read(FIXTURES[fixture]);
        let len = data.len();
        for (at, byte) in flips {
            data[at % len] = byte;
        }
        data.truncate(cut % (len + 1));
        read_all(&data);
    }
}
