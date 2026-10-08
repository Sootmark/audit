//! plaso's audit log test files (Apache-2.0, `tests/fixtures/plaso/`, see
//! `NOTICE`), read as plaso's own tests
//! (`tests/parsers/text_plugins/selinux.py`) expect, and as plaso itself
//! reads them (`tests/oracle/plaso.tsv`). plaso counts records; here
//! records are gathered into events, so the counts are of both.

use std::fs;
use std::path::Path;

use audit::{classify, parse, Event, Log};

fn read(name: &str) -> Log {
    parse(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/plaso")
                .join(name),
        )
        .unwrap(),
    )
}

fn event(log: &Log, serial: u64) -> &Event {
    log.events.iter().find(|e| e.serial == serial).unwrap()
}

fn time(event: &Event) -> String {
    event.time.to_iso8601().unwrap()
}

#[test]
fn counts_as_plaso() {
    for (name, records, events, problems) in [
        ("audit.log", 34, 11, 0),
        ("audit_enriched.log", 34, 14, 0),
        ("audit_avc.log", 6, 6, 0),
        // Odd hex digits; an unreadable argc. plaso also warns of an invalid
        // mode, a result that is neither success nor failure, and bytes that
        // aren't UTF-8: here the mode is kept as written, the result unknown,
        // the bytes escaped.
        ("audit_corrupted.log", 6, 6, 2),
        // Two unreadable stamps, a record without a type, a line that isn't
        // a record; AVC and SYSCALL 101 are one event.
        ("selinux.log", 7, 6, 4),
    ] {
        let log = read(name);
        let count: usize = log.events.iter().map(|e| e.records.len()).sum();
        assert_eq!(
            (count, log.events.len(), log.problems.len()),
            (records, events, problems),
            "{name}: {:?}",
            log.problems
        );
    }
}

#[test]
fn raw_log() {
    let log = read("audit.log");
    let exec = event(&log, 500);
    assert_eq!(time(exec), "2026-07-08T02:49:34.7130000Z");
    let syscall = exec.syscall().unwrap();
    assert_eq!(
        (syscall.arch, syscall.number, syscall.name),
        (Some("x86_64"), Some(59), Some("execve"))
    );
    assert_eq!(syscall.keys, ["specimen_exec"]);
    assert_eq!(exec.cwd(), Some("/home/ubuntu"));
    assert_eq!(
        event(&log, 505).arguments.as_deref(),
        Some(&["/bin/cat".to_owned(), "/tmp/my report.txt".to_owned()][..])
    );
    let chkpwd = event(&log, 522);
    assert_eq!(
        chkpwd.proctitle(),
        Some("/usr/sbin/unix_chkpwd specimenuser chkexpiry")
    );
    let path = chkpwd.record("PATH").unwrap();
    assert_eq!(
        ["name", "mode", "ouid", "ogid", "nametype"].map(|f| path.get(f)),
        ["/etc/shadow", "0100640", "0", "42", "NORMAL"].map(Some)
    );
    let auth = event(&log, 520).record("USER_AUTH").unwrap();
    assert_eq!(
        ["acct", "exe", "op", "res", "terminal", "addr"].map(|f| auth.get(f)),
        [
            "specimenuser",
            "/usr/bin/su",
            "PAM:authentication",
            "success",
            "?",
            "?"
        ]
        .map(Some)
    );
    let deleted = classify(event(&log, 508)).unwrap();
    assert_eq!(
        (deleted.action, deleted.success),
        ("user deleted", Some(false))
    );
    assert_eq!(
        deleted.account.and_then(|a| a.name).as_deref(),
        Some("specimenuser")
    );
}

#[test]
fn enriched_log() {
    let log = read("audit_enriched.log");
    let exec = event(&log, 485);
    let syscall = exec.syscall().unwrap();
    assert_eq!(
        (syscall.arch, syscall.name, syscall.session),
        (Some("x86_64"), Some("execve"), Some(8))
    );
    assert_eq!(syscall.keys, ["specimen_exec"]);
    assert!(exec
        .records
        .iter()
        .all(|r| r.fields.iter().all(|(_, v)| !v.contains('\x1d'))));
    assert_eq!(
        exec.record("SYSCALL").unwrap().interpretation("AUID"),
        Some("root")
    );
    // Several rule keys, hex-encoded and separated by 0x01.
    let chmod = event(&log, 371);
    assert_eq!(chmod.syscall().unwrap().keys, ["alpha", "beta"]);
    assert_eq!(chmod.paths().collect::<Vec<_>>(), ["/tmp/keytest"]);
    assert_eq!(chmod.record("PATH").unwrap().get("ouid"), Some("1000"));
    assert_eq!(
        event(&log, 487).command_line().as_deref(),
        Some("/bin/sh -c grep -c . /etc/hostname")
    );
    // The login record, its result a number.
    let login = event(&log, 447).record("LOGIN").unwrap();
    assert_eq!(
        (login.get("res"), login.get("auid")),
        (Some("1"), Some("0"))
    );
    // A service's executable and name are in the nested message.
    let service = event(&log, 260).record("SERVICE_START").unwrap();
    assert_eq!(
        (service.get("exe"), service.get("comm"), service.get("res")),
        (
            Some("/usr/lib/systemd/systemd"),
            Some("systemd"),
            Some("success")
        )
    );
    // A failed public key authentication from a remote address, before the
    // login uid is set.
    let pubkey = classify(event(&log, 441)).unwrap();
    assert_eq!(
        (
            pubkey.action,
            pubkey.source_ip.as_deref(),
            pubkey.login_user,
            pubkey.session
        ),
        ("failed authentication", Some("172.23.112.1"), None, None)
    );
    assert_eq!(event(&log, 441).field("op"), Some("pubkey"));
    let account = event(&log, 444).record("USER_ACCT").unwrap();
    assert_eq!(
        ["acct", "op", "addr", "hostname", "terminal", "res"].map(|f| account.get(f)),
        [
            "root",
            "PAM:accounting",
            "172.23.112.1",
            "172.23.112.1",
            "ssh",
            "success"
        ]
        .map(Some)
    );
}

#[test]
fn access_decisions() {
    let log = read("audit_avc.log");
    let enforcing = event(&log, 767).record("AVC").unwrap();
    assert_eq!(
        [
            "seresult",
            "seperms",
            "pid",
            "comm",
            "name",
            "scontext",
            "tcontext",
            "tclass",
            "permissive"
        ]
        .map(|f| enforcing.get(f)),
        [
            "denied",
            "write",
            "2197",
            "rpm",
            ".rpm.lock",
            "system_u:system_r:setroubleshootd_t:s0",
            "system_u:object_r:rpm_var_lib_t:s0",
            "file",
            "0"
        ]
        .map(Some)
    );
    let permissive = event(&log, 833).record("AVC").unwrap();
    assert_eq!(
        ["seperms", "comm", "tclass", "permissive"].map(|f| permissive.get(f)),
        ["siginh", "bash", "process", "1"].map(Some)
    );
    let path = event(&log, 476).record("AVC").unwrap();
    assert_eq!(
        (path.get("seperms"), path.get("path")),
        (Some("entrypoint"), Some("/usr/bin/cat"))
    );
}

#[test]
fn damaged_values() {
    let log = read("audit_corrupted.log");
    assert_eq!(
        log.problems,
        [
            "line 1: proctitle isn't whole hex bytes, kept as written",
            "line 4: EXECVE without a readable argc",
        ]
    );
    assert_eq!(event(&log, 900).proctitle(), Some("2F62696E2F6361F"));
    assert_eq!(
        event(&log, 901).arguments.as_deref(),
        Some(&["/bin/cat".to_owned(), "\\x{ff}\\x{fe}".to_owned()][..])
    );
    let path = event(&log, 902).record("PATH").unwrap();
    assert_eq!(
        (path.get("name"), path.get("mode")),
        (Some("/etc/shadow"), Some("abc"))
    );
    assert_eq!(event(&log, 903).arguments, None);
    let auth = classify(event(&log, 904)).unwrap();
    assert_eq!((auth.action, auth.success), ("authentication", None));
    assert_eq!(auth.account.and_then(|a| a.name).as_deref(), Some("root"));
    let avc = event(&log, 905).record("AVC").unwrap();
    assert_eq!((avc.get("seperms"), avc.get("comm")), (None, Some("x")));
}

#[test]
fn old_and_odd_lines() {
    let log = read("selinux.log");
    let login = event(&log, 94983);
    assert_eq!(time(login), "2012-05-24T07:40:01.1740000Z");
    assert_eq!(login.records[0].get("pid"), Some("25443"));
    // `.0`: no milliseconds.
    let short = event(&log, 0);
    assert_eq!(
        (time(short).as_str(), short.records[0].kind.as_str()),
        ("2012-05-24T07:40:01.0000000Z", "SHORTDATE")
    );
    let serial_94984: Vec<(&str, usize)> = log
        .events
        .iter()
        .filter(|e| e.serial == 94984)
        .map(|e| (e.records[0].kind.as_str(), e.records[0].fields.len()))
        .collect();
    // The same serial at two times: two events.
    assert_eq!(serial_94984, [("NOMSG", 0), ("UNDER_SCORE", 6)]);
    // `old auid=4294967295 new auid=54321`: both kept, in order.
    let under_score = &log
        .events
        .iter()
        .find(|e| e.records[0].kind == "UNDER_SCORE")
        .unwrap()
        .records[0];
    let auids: Vec<&str> = under_score
        .fields
        .iter()
        .filter(|(name, _)| name == "auid")
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(auids, ["4294967295", "54321"]);
    let ls = event(&log, 101);
    let syscall = ls.syscall().unwrap();
    assert_eq!(
        (
            syscall.arch,
            syscall.number,
            syscall.name,
            syscall.exit,
            syscall.ppid,
            syscall.comm,
            syscall.exe,
            syscall.tty
        ),
        (
            Some("i386"),
            Some(197),
            None,
            Some(0),
            Some(2671),
            Some("ls"),
            Some("/bin/ls"),
            Some("pts1")
        )
    );
    assert!(syscall.keys.is_empty());
    assert_eq!(
        ls.record("AVC").unwrap().get("path"),
        Some("/usr/lib/locale/locale-archive")
    );
    assert_eq!(event(&log, 2159).records[0].kind, "UNKNOWN[1323]");
}

/// What plaso's `text/selinux` parser reads of a record: its names, and
/// the fields they come from.
const PLASO_FIELDS: [(&str, &str); 12] = [
    ("auid", "audit_login_identifier"),
    ("ses", "audit_session_identifier"),
    ("exe", "executable"),
    ("exit", "exit_code"),
    ("gid", "group_identifier"),
    ("ppid", "parent_process_identifier"),
    ("pid", "pid"),
    ("comm", "process_name"),
    ("subj", "security_context"),
    ("success", "success"),
    ("syscall", "system_call"),
    ("uid", "user_identifier"),
];

/// The values `plaso.tsv` identifies a record by.
const KEYS: [&str; 3] = ["audit_serial=", "audit_type=", "message_body="];

/// A record as `plaso.tsv` identifies it (file, time, serial, type, its
/// text as written: the line it was read from) and its values under
/// plaso's names.
fn plaso_record(
    name: &str,
    text: &str,
    event: &Event,
    record: &audit::Record,
) -> (String, Vec<String>) {
    let line = text.split('\n').nth(record.line - 1).unwrap_or_default();
    let body = line.split_once("): ").map_or("", |(_, body)| body);
    let body = body.split('\x1d').next().unwrap_or_default().trim();
    let mut key = vec![
        name.to_owned(),
        time(event).trim_end_matches('Z').to_owned(),
        format!("audit_serial={}", event.serial),
        format!("audit_type={}", record.kind),
    ];
    if !body.is_empty() {
        key.push(format!("message_body={body}"));
    }
    let values = PLASO_FIELDS
        .iter()
        .filter_map(|(ours, plaso)| Some(format!("{plaso}={}", record.get(ours)?)))
        .collect();
    (key.join("\t"), values)
}

/// `plaso.tsv`'s records, as `plaso_record` gives them.
fn plaso_records() -> Vec<(String, Vec<String>)> {
    include_str!("oracle/plaso.tsv")
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            let (keys, values): (Vec<&str>, Vec<&str>) = fields[4..]
                .iter()
                .partition(|field| KEYS.iter().any(|key| field.starts_with(key)));
            let key = [&fields[..2], &keys[..]].concat().join("\t");
            (key, values.into_iter().map(str::to_owned).collect())
        })
        .collect()
}

/// What plaso (the log2timeline/plaso:20260720 image) reads from the same
/// files with log2timeline (`tests/oracle/plaso.tsv`, see
/// `tests/oracle/README`): every one of its 53 records found here, at the
/// same time, with the same serial, type and text, and every value it
/// reads read the same. plaso reads no record of `audit_enriched.log`: it
/// takes the file's `0x1d` separators for binary. And it stops reading a
/// record's values at the first word that isn't `name=value`: an `AVC`'s
/// (`avc: denied { … } for pid=…`), and `LOGIN`'s after `old`; here those
/// are read too.
#[test]
fn every_record_as_plaso_log2timeline_reads_it() {
    let mut expected = plaso_records();
    let mut beyond: Vec<String> = Vec::new();
    for name in [
        "audit.log",
        "audit_avc.log",
        "audit_corrupted.log",
        "selinux.log",
    ] {
        let data = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/plaso")
                .join(name),
        )
        .unwrap();
        let text = String::from_utf8_lossy(&data);
        for event in &parse(&data).events {
            for record in &event.records {
                let (key, ours) = plaso_record(name, &text, event, record);
                let at = expected
                    .iter()
                    .position(|(k, _)| *k == key)
                    .unwrap_or_else(|| panic!("not one of plaso's: {key}"));
                let (_, theirs) = expected.remove(at);
                for value in &theirs {
                    assert!(ours.contains(value), "{key}: {value} read as {ours:?}");
                }
                beyond.extend(
                    ours.iter()
                        .filter(|v| !theirs.contains(v))
                        .filter_map(|v| Some(format!("{}:{}", record.kind, v.split_once('=')?.0))),
                );
            }
        }
    }
    assert!(expected.is_empty(), "plaso's, not read: {expected:#?}");
    beyond.sort();
    beyond.dedup();
    assert_eq!(
        beyond,
        [
            "AVC:pid",
            "AVC:process_name",
            "LOGIN:audit_login_identifier",
            "LOGIN:audit_session_identifier",
            "UNDER_SCORE:audit_login_identifier",
            "UNDER_SCORE:audit_session_identifier",
        ]
    );
}
