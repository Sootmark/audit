//! Every fixture against what audit-userspace's own tools make of it
//! (`tests/oracle/`, written by `regenerate.sh` with audit 4.0.2):
//!
//! - `ausearch --interpret`: the same events (time to the millisecond and
//!   serial), the same record types in each, and the same decoded values:
//!   process titles, `EXECVE` arguments (pieces of long ones too), paths,
//!   executables, commands, accounts, addresses, rule keys, system call
//!   names and socket addresses;
//! - `aureport`: the same logins, authentications, account changes and
//!   system call names.
//!
//! Where this crate and ausearch read a damaged line differently, the
//! difference is listed with its reason.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use audit::{classify, parse, Event, Log, SocketAddress};

const FIXTURES: [&str; 15] = [
    "plaso/audit.log",
    "plaso/audit_enriched.log",
    "plaso/audit_avc.log",
    "plaso/audit_corrupted.log",
    "plaso/selinux.log",
    "go-libaudit/audit-rhel6.log",
    "go-libaudit/audit-rhel7.log",
    "go-libaudit/audit-ubuntu14.log",
    "go-libaudit/audit-ubuntu16.log",
    "go-libaudit/audit-ubuntu17.log",
    "go-libaudit/test2.log",
    "go-libaudit/test3.log",
    "go-libaudit/normal.log",
    "go-libaudit/rollover.log",
    "lab/audit.log",
];

/// Records ausearch reads and this crate reports as damaged, by
/// (fixture, serial, type).
const ONLY_AUSEARCH: [(&str, u64, &str); 2] = [
    // `msg=audit(1337845201)`: no milliseconds, no serial. ausearch reads
    // it as `.000:0`; here the stamp is unreadable.
    ("plaso/selinux.log", 0, "WRONGDATE"),
    // `type= msg=…`: ausearch keeps a record without a type.
    ("plaso/selinux.log", 94984, ""),
];

/// Records read here that ausearch 4.0.2 leaves out: access decisions it
/// can't interpret.
const ONLY_HERE: [(&str, u64, &str); 2] = [
    // No permissions: `avc:  denied  pid=1 comm="x"`.
    ("plaso/audit_corrupted.log", 905, "AVC"),
    // AppArmor's: `apparmor="DENIED" operation="ptrace" …`.
    ("go-libaudit/audit-ubuntu16.log", 61207, "AVC"),
];

/// Types auditd didn't know when it wrote the record (a newer kernel's),
/// written by number: kept as written here, named by ausearch.
const NUMBERED_TYPES: [(&str, &str); 1] = [("UNKNOWN[1323]", "MMAP")];

/// Values read differently, by fixture, lines and fields.
const READ_DIFFERENTLY: [(&str, &[usize], &[&str]); 2] = [
    // Odd hex digits: kept as written here (and reported); ausearch decodes
    // what makes whole bytes, then a stray digit.
    ("plaso/audit_corrupted.log", &[1], &["proctitle"]),
    // Old PAM records, `(hostname=?, addr=?, terminal=cron res=success)`:
    // read as fields here, printed as written by ausearch.
    (
        "go-libaudit/test2.log",
        &[8, 9, 10],
        &["hostname", "addr", "terminal"],
    ),
];

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(fixture: &str) -> Log {
    parse(&fs::read(root().join("tests/fixtures").join(fixture)).unwrap())
}

fn oracle(fixture: &str, extension: &str) -> String {
    let name = fixture.trim_end_matches(".log").replace('/', "-");
    let bytes = fs::read(root().join(format!("tests/oracle/{name}.{extension}"))).unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// An event as ausearch prints it: `MM/DD/YY HH:MM:SS.mmm` (UTC) and the
/// serial.
type Key = (String, u64);

/// ausearch's records: type, and what follows `:`.
fn ausearch(fixture: &str) -> BTreeMap<Key, Vec<(String, String)>> {
    let mut events: BTreeMap<Key, Vec<(String, String)>> = BTreeMap::new();
    for line in oracle(fixture, "ausearch").lines() {
        let Some(rest) = line.strip_prefix("type=") else {
            continue;
        };
        let (kind, rest) = rest.split_once(" msg=audit(").unwrap();
        let (stamp, body) = rest.split_once(')').unwrap();
        let body = body.strip_prefix(" :").unwrap_or(body);
        let (time, serial) = stamp.rsplit_once(':').unwrap();
        events
            .entry((time.to_owned(), serial.parse().unwrap()))
            .or_default()
            .push((kind.to_owned(), body.to_owned()));
    }
    events
}

/// `2026-07-08T02:49:34.7130000Z` as ausearch prints it in UTC.
fn key(event: &Event) -> Key {
    let iso = event.time.to_iso8601().unwrap();
    let time = format!(
        "{}/{}/{} {}",
        &iso[5..7],
        &iso[8..10],
        &iso[2..4],
        &iso[11..23]
    );
    (time, event.serial)
}

/// Values ausearch prints decoded, as this crate decodes them; ids,
/// modes and flags it turns into names are left out.
const COMPARED: [&str; 14] = [
    "proctitle",
    "cwd",
    "name",
    "exe",
    "comm",
    "acct",
    "cmd",
    "op",
    "hostname",
    "addr",
    "terminal",
    "grantors",
    "path",
    "key",
];

/// ` key=value ` in ausearch's line, or ` key="value" ` for a field it
/// doesn't interpret (quotes of a nested `msg='…'` as spaces, on both
/// sides).
fn shows(body: &str, key: &str, value: &str) -> bool {
    let body = format!(" {} ", body.replace('\'', " "));
    let value = value.replace('\'', " ");
    body.contains(&format!(" {key}={value} ")) || body.contains(&format!(" {key}=\"{value}\" "))
}

fn compared(kind: &str, name: &str) -> bool {
    COMPARED.contains(&name)
        || kind == "EXECVE" && name.starts_with('a') && name != "argc" && !name.ends_with("_len")
}

/// ausearch's view of what `event` says, beyond its fields.
fn interpretations(event: &Event) -> Vec<(&'static str, &'static str, String)> {
    let mut out = Vec::new();
    if let Some(syscall) = event.syscall() {
        if let Some(name) = syscall.name {
            out.push(("SYSCALL", "syscall", name.to_owned()));
        }
        if let Some(arch) = syscall.arch {
            out.push(("SYSCALL", "arch", arch.to_owned()));
        }
        if let Some(success) = syscall.success {
            let yes_no = if success { "yes" } else { "no" };
            out.push(("SYSCALL", "success", yes_no.to_owned()));
        }
    }
    let address = match event.socket_address() {
        Some(SocketAddress::Inet(a)) if a.is_ipv4() => {
            format!("{{ saddr_fam=inet laddr={} lport={} }}", a.ip(), a.port())
        }
        Some(SocketAddress::Inet(a)) => {
            format!("{{ saddr_fam=inet6 laddr={} lport={} }}", a.ip(), a.port())
        }
        Some(SocketAddress::Unix(path)) => format!("{{ saddr_fam=local path={path} }}"),
        _ => String::new(),
    };
    if !address.is_empty() {
        out.push(("SOCKADDR", "saddr", address));
    }
    out
}

fn read_differently(fixture: &str, line: usize, field: &str) -> bool {
    READ_DIFFERENTLY
        .iter()
        .any(|(f, lines, fields)| *f == fixture && lines.contains(&line) && fields.contains(&field))
}

fn named(kind: &str) -> &str {
    NUMBERED_TYPES
        .iter()
        .find_map(|&(number, name)| (number == kind).then_some(name))
        .unwrap_or(kind)
}

fn excused<'a>(
    list: &'a [(&str, u64, &str)],
    fixture: &str,
    serial: u64,
) -> impl Fn(&&str) -> bool + 'a {
    let fixture = fixture.to_owned();
    move |kind| !list.contains(&(fixture.as_str(), serial, kind))
}

#[test]
fn events_times_and_values_as_ausearch() {
    let mut checked = 0;
    for fixture in FIXTURES {
        let log = read(fixture);
        let theirs = ausearch(fixture);
        let ours: BTreeMap<Key, &Event> = log.events.iter().map(|e| (key(e), e)).collect();
        assert_eq!(
            ours.len(),
            log.events.len(),
            "{fixture}: two events, one key"
        );
        let keys: BTreeSet<&Key> = ours.keys().chain(theirs.keys()).collect();
        for key in keys {
            let mut our_kinds: Vec<&str> = ours
                .get(key)
                .map(|e| e.records.iter().map(|r| named(&r.kind)).collect())
                .unwrap_or_default();
            our_kinds.retain(excused(&ONLY_HERE, fixture, key.1));
            let mut their_kinds: Vec<&str> = theirs
                .get(key)
                .map(|records| records.iter().map(|(k, _)| k.as_str()).collect())
                .unwrap_or_default();
            their_kinds.retain(excused(&ONLY_AUSEARCH, fixture, key.1));
            our_kinds.sort_unstable();
            their_kinds.sort_unstable();
            assert_eq!(our_kinds, their_kinds, "{fixture} {key:?}: record types");
        }
        for (key, event) in &ours {
            let Some(records) = theirs.get(key) else {
                continue;
            };
            for record in &event.records {
                let pairs: Vec<(&str, String)> = record
                    .fields
                    .iter()
                    .filter(|(name, value)| {
                        compared(&record.kind, name)
                            && !value.contains("\\x{")
                            && !read_differently(fixture, record.line, name)
                    })
                    .flat_map(|(name, value)| {
                        // Several rule keys: ausearch prints `key=` for each.
                        value
                            .split("\\x{01}")
                            .map(move |v| (name.as_str(), v.to_owned()))
                    })
                    .chain(
                        interpretations(event)
                            .into_iter()
                            .filter(|(kind, ..)| *kind == record.kind)
                            .map(|(_, name, value)| (name, value)),
                    )
                    .collect();
                let found = records.iter().any(|(kind, body)| {
                    kind == named(&record.kind) && pairs.iter().all(|(n, v)| shows(body, n, v))
                });
                assert!(
                    found,
                    "{fixture} line {}: no {} record in ausearch's event shows {pairs:?}",
                    record.line, record.kind
                );
                checked += pairs.len();
            }
        }
    }
    assert!(checked > 5_000, "{checked} values compared");
}

/// The rows of one of aureport's reports, as words.
fn report(fixture: &str, option: &str) -> Vec<Vec<String>> {
    let text = oracle(fixture, "aureport");
    let start = format!("### aureport {option}\n");
    let section = text.split_once(&start).map_or("", |(_, s)| s);
    let section = section.split("### ").next().unwrap_or("");
    section
        .lines()
        .filter(|l| {
            l.split_once(". ")
                .is_some_and(|(n, _)| n.parse::<u32>().is_ok())
        })
        .map(|l| l.split_whitespace().map(str::to_owned).collect())
        .collect()
}

/// A report row's event, success, and executable (`exe_from_end` words
/// from the end).
fn event_success_exe(row: &[String], exe_from_end: usize) -> (u64, bool, String) {
    let n = row.len();
    (
        row[n - 1].parse().unwrap(),
        row[n - 2] == "yes",
        row[n - exe_from_end].clone(),
    )
}

fn activities(log: &Log, actions: &[&str]) -> BTreeSet<(u64, bool, String)> {
    log.events
        .iter()
        .filter_map(|e| classify(e).map(|a| (e.serial, a)))
        .filter(|(_, a)| actions.contains(&a.action))
        // aureport counts what didn't fail as a success, and prints a
        // missing executable as `(null)`.
        .map(|(serial, a)| {
            let exe = a.exe.unwrap_or_else(|| "(null)".to_owned());
            (serial, a.success != Some(false), exe)
        })
        .collect()
}

#[test]
fn logins_authentications_and_changes_as_aureport() {
    let mut rows = 0;
    for fixture in FIXTURES {
        let log = read(fixture);
        // `… exe success event`; `… exe acct success event`.
        for (option, exe_from_end, actions) in [
            (
                "--login",
                3,
                &["ssh login", "ssh failed login", "login", "failed login"][..],
            ),
            (
                "--auth",
                3,
                &["authentication", "failed authentication"][..],
            ),
            (
                "--mods",
                4,
                &[
                    "user added",
                    "user deleted",
                    "user changed",
                    "group added",
                    "group deleted",
                    "group changed",
                    "password changed",
                ][..],
            ),
        ] {
            let theirs: BTreeSet<(u64, bool, String)> = report(fixture, option)
                .iter()
                .map(|row| event_success_exe(row, exe_from_end))
                .collect();
            rows += theirs.len();
            assert_eq!(activities(&log, actions), theirs, "{fixture} {option}");
        }
    }
    assert!(rows > 30, "{rows} rows compared");
}

#[test]
fn system_call_names_as_aureport() {
    let mut named = 0;
    for fixture in FIXTURES {
        let log = read(fixture);
        // `N. date time syscall pid comm auid event`.
        let theirs: BTreeMap<u64, String> = report(fixture, "--syscall")
            .into_iter()
            .map(|row| (row[row.len() - 1].parse().unwrap(), row[3].clone()))
            .collect();
        for event in &log.events {
            if let Some(name) = event.syscall().and_then(|s| s.name) {
                assert_eq!(
                    theirs.get(&event.serial).map(String::as_str),
                    Some(name),
                    "{fixture} {}",
                    event.serial
                );
                named += 1;
            }
        }
    }
    assert!(named > 250, "{named} system calls named");
}
