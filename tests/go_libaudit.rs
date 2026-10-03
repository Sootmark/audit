//! Elastic go-libaudit's test logs (Apache-2.0, `tests/fixtures/go-libaudit/`):
//! records from RHEL 6 and 7 and Ubuntu 14 to 17, interleaved events, a
//! serial number wrapping around, and older formats.

use std::fs;
use std::path::Path;

use audit::{classify, parse, Event, Log};

fn read(name: &str) -> Log {
    parse(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/go-libaudit")
                .join(name),
        )
        .unwrap(),
    )
}

fn event(log: &Log, serial: u64) -> &Event {
    log.events.iter().find(|e| e.serial == serial).unwrap()
}

#[test]
fn interleaved_events() {
    let log = read("test3.log");
    assert!(log.problems.is_empty(), "{:?}", log.problems);
    // Seven events written at once, their records out of order.
    let sshd = event(&log, 194_435);
    let lines: Vec<usize> = sshd.records.iter().map(|r| r.line).collect();
    assert_eq!(lines, [1, 4]);
    assert_eq!(sshd.proctitle(), Some("sshd: burn [priv]"));
    assert_eq!(sshd.syscall().unwrap().comm, Some("sshd"));
}

#[test]
fn serials_wrapping_around() {
    let log = read("rollover.log");
    let serials: Vec<u64> = log.events.iter().map(|e| e.serial).collect();
    assert_eq!(serials, [4_294_967_294, 4_294_967_295, 0, 1, 2]);
}

#[test]
fn hex_encoded_values() {
    let rhel6 = read("audit-rhel6.log");
    assert_eq!(
        event(&rhel6, 20_614_537).syscall().unwrap().exe,
        Some("/usr/libexec/strongswan/charon (deleted)")
    );
    let ubuntu14 = read("audit-ubuntu14.log");
    assert_eq!(
        event(&ubuntu14, 1_428_931).paths().collect::<Vec<_>>(),
        ["/share/general/path_redacted"]
    );
    let rhel7 = read("audit-rhel7.log");
    assert_eq!(event(&rhel7, 1_208_725).cwd(), Some("/tmp/a b c"));
    // Keystrokes (pam_tty_audit): control characters escaped.
    let keys = event(&rhel7, 1_065_565).field("data").unwrap();
    assert!(keys.starts_with("eh\\x{7f}\\x{7f}echo test\\x{0d}vim /etc/pam.d/"));
    // `msg=?`: a record without a stamp.
    assert_eq!(rhel7.problems, ["line 31: no msg=audit(…) stamp"]);
}

#[test]
fn connections_and_logins() {
    let normal = read("normal.log");
    let connect = classify(event(&normal, 58)).unwrap();
    assert_eq!(
        (
            connect.action,
            connect.success,
            connect.destination_ip.as_deref(),
            connect.destination_port
        ),
        (
            "network connect",
            Some(false),
            Some("169.254.169.254"),
            Some(80)
        )
    );
    assert_eq!(event(&normal, 58).syscall().unwrap().exit, Some(-115));
    let ubuntu16 = read("audit-ubuntu16.log");
    let login = classify(event(&ubuntu16, 12_651)).unwrap();
    assert_eq!(
        (
            login.action,
            login.source_ip.as_deref(),
            login.terminal.as_deref()
        ),
        ("ssh login", Some("72.83.230.100"), Some("/dev/pts/1"))
    );
    assert_eq!(login.account.and_then(|a| a.id), Some(1001));
}

#[test]
fn old_pam_records() {
    let log = read("test2.log");
    let start = event(&log, 297).record("USER_START").unwrap();
    assert_eq!(
        ["acct", "exe", "hostname", "addr", "terminal", "res"].map(|f| start.get(f)),
        ["root", "/usr/sbin/crond", "?", "?", "cron", "success"].map(Some)
    );
    let session = classify(event(&log, 297)).unwrap();
    assert_eq!(
        (session.action, session.terminal.as_deref(), session.success),
        ("session opened", Some("cron"), Some(true))
    );
    // The access decision and its system call: one event.
    let pickup = event(&log, 293);
    let kinds: Vec<&str> = pickup.records.iter().map(|r| r.kind.as_str()).collect();
    assert_eq!(kinds, ["AVC", "SYSCALL", "CWD", "PATH"]);
    assert_eq!(pickup.cwd(), Some("/var/spool/postfix"));
}
