//! A log recorded on a Debian 13 lab machine (`tests/fixtures/lab/`, made by
//! `gen.sh` and `activity.sh` with auditd 4.0.2, enriched format): an
//! account and a group created, changed and deleted, commands with spaces,
//! accents and an argument long enough to be split, sudo, connections over
//! IPv4 and IPv6, an ssh login with a key and a failed one, all under login
//! uid 1000 (`analyst`).

use std::fs;
use std::path::Path;

use audit::{classify, parse, Account, Activity, Event, Log, SocketAddress};

fn log() -> Log {
    parse(
        &fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/lab/audit.log"))
            .unwrap(),
    )
}

fn activities(log: &Log) -> Vec<(&Event, Activity)> {
    log.events
        .iter()
        .filter_map(|e| classify(e).map(|a| (e, a)))
        .collect()
}

fn name(account: Option<&Account>) -> Option<&str> {
    account.and_then(|a| a.name.as_deref())
}

fn command_run(log: &Log, command: &str) -> Activity {
    activities(log)
        .into_iter()
        .map(|(_, a)| a)
        .find(|a| a.action == "command executed" && a.command.as_deref() == Some(command))
        .unwrap_or_else(|| panic!("{command}"))
}

#[test]
fn read_whole() {
    let log = log();
    assert!(log.problems.is_empty(), "{:?}", log.problems);
    assert_eq!(log.events.len(), 489);
    let first = &log.events[0];
    assert_eq!(first.records[0].kind, "DAEMON_ROTATE");
}

#[test]
fn commands_as_typed() {
    let log = log();
    let echo = command_run(&log, "/bin/echo café naïve résumé it's");
    let event = log
        .events
        .iter()
        .find(|e| e.command_line().as_deref() == echo.command.as_deref())
        .unwrap();
    assert_eq!(
        event.arguments.as_deref(),
        Some(&["/bin/echo", "café", "naïve résumé", "it's"].map(str::to_owned)[..])
    );
    // The login user survives sudo; the user is whoever runs the command.
    assert_eq!(
        echo.login_user,
        Some(Account {
            id: Some(1000),
            name: Some("analyst".to_owned())
        })
    );
    assert_eq!(echo.cwd.as_deref(), Some("/tmp"));
    let moved = command_run(&log, "mv /tmp/sootmark/a.txt /tmp/sootmark/b c.txt");
    assert_eq!(moved.exe.as_deref(), Some("/usr/bin/mv"));
    let as_other = command_run(&log, "/usr/bin/id");
    assert_eq!(
        (
            name(as_other.user.as_ref()),
            name(as_other.login_user.as_ref())
        ),
        (Some("sootmarktest"), Some("analyst"))
    );
    // 9 005 bytes, hex-encoded and split across three EXECVE records.
    let split = log
        .events
        .iter()
        .find(|e| e.records.iter().filter(|r| r.kind == "EXECVE").count() == 3)
        .unwrap();
    let arguments = split.arguments.as_deref().unwrap();
    assert_eq!(arguments.len(), 2);
    assert_eq!(arguments[1], format!("{} tail", "x".repeat(9_000)));
    assert_eq!(split.record("EXECVE").unwrap().get("a1_len"), Some("18010"));
    // A failed exec: what it tried to run.
    let nscd = activities(&log)
        .into_iter()
        .map(|(_, a)| a)
        .find(|a| a.success == Some(false))
        .unwrap();
    assert_eq!(
        (nscd.action, nscd.command.as_deref(), nscd.exe.as_deref()),
        (
            "command executed",
            Some("/usr/sbin/nscd"),
            Some("/usr/sbin/groupadd")
        )
    );
}

#[test]
fn sudo() {
    let log = log();
    let commands: Vec<(Option<String>, Option<String>)> = activities(&log)
        .into_iter()
        .filter(|(_, a)| a.action == "sudo" && a.login_user.is_some())
        .map(|(_, a)| (a.command, a.cwd))
        .collect();
    let tmp = Some("/tmp".to_owned());
    for command in ["/usr/bin/id", "/usr/bin/cat /etc/hostname"] {
        assert!(
            commands.contains(&(Some(command.to_owned()), tmp.clone())),
            "{command}: {commands:?}"
        );
    }
}

#[test]
fn logins() {
    let log = log();
    let logins: Vec<Activity> = activities(&log)
        .into_iter()
        .map(|(_, a)| a)
        .filter(|a| a.action.contains("login"))
        .collect();
    assert_eq!(logins.len(), 3);
    let ok = &logins[0];
    assert_eq!(
        (
            ok.action,
            ok.success,
            ok.source_ip.as_deref(),
            ok.terminal.as_deref()
        ),
        (
            "ssh login",
            Some(true),
            Some("127.0.0.1"),
            Some("/dev/pts/11")
        )
    );
    let sootmarktest = Some(Account {
        id: Some(1001),
        name: Some("sootmarktest".to_owned()),
    });
    assert_eq!(
        (&ok.account, &ok.login_user),
        (&sootmarktest, &sootmarktest)
    );
    for failed in &logins[1..] {
        assert_eq!(
            (
                failed.action,
                failed.invalid_user,
                failed.account.as_ref(),
                failed.source_ip.as_deref()
            ),
            ("ssh failed login", true, None, Some("127.0.0.1"))
        );
    }
    // The commands run in the session: under the new login uid.
    let remote = command_run(&log, "/bin/echo remote cmd");
    assert_eq!(remote.login_user, sootmarktest);
}

#[test]
fn account_changes() {
    let log = log();
    let all = activities(&log);
    let changes: Vec<(&str, Option<&str>, Option<&str>)> = all
        .iter()
        .filter(|(_, a)| {
            a.action.starts_with("user")
                || a.action.starts_with("group")
                || a.action == "password changed"
        })
        .map(|(_, a)| (a.action, name(a.account.as_ref()), name(a.group.as_ref())))
        .collect();
    for expected in [
        ("group added", None, Some("sootmarkops")),
        ("user added", Some("sootmarktest"), None),
        ("user changed", Some("sootmarktest"), Some("sootmarkops")),
        ("password changed", Some("sootmarktest"), None),
        ("user changed", Some("sootmarktest"), Some("adm")),
        ("user deleted", Some("sootmarktest"), None),
        ("group deleted", None, Some("sootmarktest")),
    ] {
        assert!(changes.contains(&expected), "{expected:?} in {changes:?}");
    }
}

#[test]
fn connections() {
    let log = log();
    let connections: Vec<(String, u16, Option<u32>)> = activities(&log)
        .into_iter()
        .filter(|(_, a)| a.action == "network connect")
        .map(|(_, a)| {
            (
                a.destination_ip.unwrap(),
                a.destination_port.unwrap(),
                a.login_user.and_then(|u| u.id),
            )
        })
        .collect();
    assert_eq!(
        connections,
        [
            ("127.0.0.1".to_owned(), 22, Some(1000)),
            ("::1".to_owned(), 22, Some(1000)),
            ("127.0.0.1".to_owned(), 2222, Some(1000)),
            ("127.0.0.1".to_owned(), 2222, Some(1000)),
        ]
    );
    // Local sockets are read too, but aren't the network.
    let local: Vec<SocketAddress> = log
        .events
        .iter()
        .filter_map(Event::socket_address)
        .collect();
    assert!(local.contains(&SocketAddress::Unix("/var/run/nscd/socket".to_owned())));
    assert!(local.contains(&SocketAddress::Netlink));
}
