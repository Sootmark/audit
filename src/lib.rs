//! Linux audit logs: `/var/log/audit/audit.log` and its rotations
//! (`audit.log.1`, …), as auditd writes them, raw or enriched.
//!
//! Each line is a record: `type=SYSCALL msg=audit(1783478974.713:500):
//! arch=c000003e syscall=59 success=yes …`, maybe after `node=<host> `. The
//! kernel and programs write several records for one event (a `SYSCALL`
//! with its `EXECVE`, `CWD`, `PATH`s and `PROCTITLE`), all stamped with the
//! same time and serial number; they are gathered here into [`Event`]s,
//! even when other records come between them.
//!
//! Values are decoded. Quotes are taken off; values auditd hex-encodes
//! (those with spaces, quotes or bytes outside printable ASCII:
//! `proctitle`, `EXECVE`'s arguments, `cmd`, `exe`, `name`, …) are turned
//! back into text, what isn't text escaped as `\x{ff}`; the nested
//! `msg='…'` of a program's record is read as the record's own fields. An
//! enriched log's interpretations (after `\x1d`: `AUID="alice"`) are kept
//! apart, in [`Record::interpreted`].
//!
//! An [`Event`] tells its program's arguments (long ones, split across
//! fields, joined), its command line, the [system call](Event::syscall) and
//! the [socket address](Event::socket_address). [`classify`] tells what it
//! records: a command run, a login, a sudo command, an account change, a
//! connection.
//!
//! A line that isn't a record, or a value that can't be decoded, is
//! reported in `problems`, never fatal.

use std::collections::{BTreeMap, HashMap};

use common::time::Ts;

use crate::decode::{Argument, Value};
use crate::line::{Line, Raw, Stamp};

mod activity;
mod decode;
mod line;
mod syscall;

pub use activity::{classify, Account, Activity};
pub use syscall::{SocketAddress, Syscall};

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A log's events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    /// Events in the order their first record was written.
    pub events: Vec<Event>,
    /// Lines that aren't records, and values that can't be decoded.
    pub problems: Vec<String>,
}

/// The records written for one event: one time, one serial number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// When it happened (UTC, to the millisecond).
    pub time: Ts,
    /// Its serial number: with the time, what ties its records together.
    pub serial: u64,
    /// The host, in logs gathered from several (`node=`).
    pub node: Option<String>,
    /// Its records, in file order.
    pub records: Vec<Record>,
    /// The program's arguments, from the `EXECVE` records: `None` without
    /// them or without a readable `argc`.
    pub arguments: Option<Vec<String>>,
}

/// One line: a record of an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Its type: `SYSCALL`, `EXECVE`, `USER_LOGIN`, `UNKNOWN[1323]`, …
    pub kind: String,
    /// Its line number, from 1.
    pub line: usize,
    /// Its fields, in order, values decoded: those of a nested `msg='…'`
    /// in its place. A name can come twice (`old auid=… new auid=…`).
    pub fields: Vec<(String, String)>,
    /// An enriched log's interpretations: `UID="root"` as `("UID", "root")`.
    pub interpreted: Vec<(String, String)>,
}

impl Record {
    /// The first field called `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        lookup(&self.fields, name)
    }

    /// The enriched log's interpretation called `name` (`AUID`, `SYSCALL`).
    #[must_use]
    pub fn interpretation(&self, name: &str) -> Option<&str> {
        lookup(&self.interpreted, name)
    }
}

fn lookup<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find_map(|(n, value)| (n == name).then_some(value.as_str()))
}

impl Event {
    /// The first record of type `kind`.
    #[must_use]
    pub fn record(&self, kind: &str) -> Option<&Record> {
        self.records.iter().find(|r| r.kind == kind)
    }

    /// The first field called `name`, in any record.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.records.iter().find_map(|r| r.get(name))
    }

    /// The command line: the arguments joined with spaces, or the process
    /// title (`PROCTITLE`, cut by the kernel at 128 bytes) without them.
    #[must_use]
    pub fn command_line(&self) -> Option<String> {
        match &self.arguments {
            Some(arguments) if !arguments.is_empty() => Some(arguments.join(" ")),
            _ => self.proctitle().map(str::to_owned),
        }
    }

    /// The process title, its arguments separated by spaces.
    #[must_use]
    pub fn proctitle(&self) -> Option<&str> {
        self.record("PROCTITLE")?.get("proctitle")
    }

    /// The working directory (`CWD`).
    #[must_use]
    pub fn cwd(&self) -> Option<&str> {
        self.record("CWD")?.get("cwd")
    }

    /// The paths of the `PATH` records, in order.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.records
            .iter()
            .filter(|r| r.kind == "PATH")
            .filter_map(|r| r.get("name"))
    }
}

/// Read an audit log.
#[must_use]
pub fn parse(data: &[u8]) -> Log {
    let mut pending: Vec<Pending> = Vec::new();
    let mut by_stamp: HashMap<(Option<String>, Stamp), usize> = HashMap::new();
    let mut problems = Vec::new();
    for (index, raw) in data.split(|&b| b == b'\n').enumerate() {
        let number = index + 1;
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        if raw.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let line = match line::read(&String::from_utf8_lossy(raw)) {
            Ok(line) => line,
            Err(why) => {
                problems.push(format!("line {number}: {why}"));
                continue;
            }
        };
        problems.extend(line.issues.iter().map(|i| format!("line {number}: {i}")));
        let at = *by_stamp
            .entry((line.node.clone(), line.stamp))
            .or_insert_with(|| {
                pending.push(Pending {
                    node: line.node.clone(),
                    stamp: line.stamp,
                    lines: Vec::new(),
                });
                pending.len() - 1
            });
        pending[at].lines.push((number, line));
    }
    let events = pending
        .into_iter()
        .map(|p| p.finish(&mut problems))
        .collect();
    Log { events, problems }
}

/// An event's lines (with their numbers), read but not yet decoded.
struct Pending {
    node: Option<String>,
    stamp: Stamp,
    lines: Vec<(usize, Line)>,
}

impl Pending {
    fn finish(self, problems: &mut Vec<String>) -> Event {
        let Self { node, stamp, lines } = self;
        let arguments = arguments(&lines, problems);
        let records = lines
            .into_iter()
            .map(|(number, line)| record(number, line, problems))
            .collect();
        Event {
            time: Ts::from_unix_millis(stamp.seconds * 1_000 + i64::from(stamp.millis)),
            serial: stamp.serial,
            node,
            records,
            arguments,
        }
    }
}

fn record(number: usize, line: Line, problems: &mut Vec<String>) -> Record {
    let kind = line.kind;
    let fields = line
        .fields
        .into_iter()
        .map(|raw| match decode::value(&kind, &raw) {
            Value::AsWritten => (raw.name, raw.value),
            Value::Decoded(text) => (raw.name, text),
            Value::Damaged => {
                problems.push(format!(
                    "line {number}: {} isn't whole hex bytes, kept as written",
                    raw.name
                ));
                (raw.name, raw.value)
            }
        })
        .collect();
    Record {
        kind,
        line: number,
        fields,
        interpreted: line.interpreted,
    }
}

/// The program's arguments, from `argc` and `a0`, `a1`, … in the `EXECVE`
/// records. An argument too long for one field is split into `aN[0]`,
/// `aN[1]`, … after `aN_len` (the length as written): the pieces are
/// joined as bytes, then decoded.
fn arguments(lines: &[(usize, Line)], problems: &mut Vec<String>) -> Option<Vec<String>> {
    let execve = lines.iter().filter(|(_, line)| line.kind == "EXECVE");
    let (number, _) = execve.clone().next()?;
    let fields: Vec<&Raw> = execve.flat_map(|(_, line)| &line.fields).collect();
    let argc = fields.iter().find(|r| r.name == "argc");
    let Some(argc) = argc.and_then(|r| r.value.parse::<usize>().ok()) else {
        problems.push(format!("line {number}: EXECVE without a readable argc"));
        return None;
    };
    let mut whole: HashMap<usize, &Raw> = HashMap::new();
    let mut pieces: BTreeMap<(usize, usize), &Raw> = BTreeMap::new();
    let mut lengths: HashMap<usize, usize> = HashMap::new();
    for raw in &fields {
        match decode::argument(&raw.name) {
            Some(Argument { index, piece: None }) => {
                whole.entry(index).or_insert(raw);
            }
            Some(Argument {
                index,
                piece: Some(piece),
            }) => {
                pieces.insert((index, piece), raw);
            }
            None => {
                if let (Some(index), Ok(length)) = (written_length_of(&raw.name), raw.value.parse())
                {
                    lengths.insert(index, length);
                }
            }
        }
    }
    let mut arguments = Vec::new();
    // Stops at the first missing argument: a damaged argc can't run long.
    for index in 0..argc {
        let bytes = if let Some(raw) = whole.get(&index) {
            decode::bytes(raw)
        } else if let Some(split) = Split::of(&pieces, index) {
            if !split.complete(lengths.get(&index).copied()) {
                problems.push(format!(
                    "line {number}: EXECVE argument a{index} is missing pieces"
                ));
            }
            split.bytes()
        } else {
            problems.push(format!(
                "line {number}: EXECVE argument a{index} of {argc} missing"
            ));
            break;
        };
        arguments.push(decode::text(&bytes));
    }
    Some(arguments)
}

/// The pieces of a long argument, in order: `aN[0]`, `aN[1]`, …
struct Split<'a> {
    pieces: Vec<(usize, &'a Raw)>,
}

impl<'a> Split<'a> {
    fn of(pieces: &BTreeMap<(usize, usize), &'a Raw>, index: usize) -> Option<Self> {
        let pieces: Vec<(usize, &Raw)> = pieces
            .range((index, 0)..=(index, usize::MAX))
            .map(|(&(_, piece), raw)| (piece, *raw))
            .collect();
        (!pieces.is_empty()).then_some(Self { pieces })
    }

    /// Numbered from 0 without a gap, as long as `aN_len` says.
    fn complete(&self, length: Option<usize>) -> bool {
        let written: usize = self.pieces.iter().map(|(_, raw)| raw.value.len()).sum();
        let numbered = self
            .pieces
            .iter()
            .enumerate()
            .all(|(i, (piece, _))| i == *piece);
        numbered && length.map_or(true, |length| length == written)
    }

    fn bytes(&self) -> Vec<u8> {
        self.pieces
            .iter()
            .flat_map(|(_, raw)| decode::bytes(raw))
            .collect()
    }
}

/// `a3_len` → 3.
fn written_length_of(name: &str) -> Option<usize> {
    decode::number(name.strip_prefix('a')?.strip_suffix("_len")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaved_records_and_nodes() {
        let log = parse(
            b"type=SYSCALL msg=audit(1.001:7): syscall=59\n\
              node=b type=CWD msg=audit(1.001:7): cwd=\"/b\"\n\
              type=SYSCALL msg=audit(1.002:8): syscall=1\r\n\
              \n\
              type=CWD msg=audit(1.001:7): cwd=\"/a\"\n",
        );
        assert!(log.problems.is_empty(), "{:?}", log.problems);
        let shape: Vec<(Option<&str>, u64, Vec<usize>)> = log
            .events
            .iter()
            .map(|e| {
                (
                    e.node.as_deref(),
                    e.serial,
                    e.records.iter().map(|r| r.line).collect(),
                )
            })
            .collect();
        assert_eq!(
            shape,
            [
                (None, 7, vec![1, 5]),
                (Some("b"), 7, vec![2]),
                (None, 8, vec![3])
            ]
        );
        assert_eq!(
            log.events[0].time.to_iso8601().as_deref(),
            Some("1970-01-01T00:00:01.0010000Z")
        );
        assert_eq!(log.events[0].cwd(), Some("/a"));
    }

    #[test]
    fn split_arguments_joined_as_bytes() {
        // `café` split inside its `é`, across two EXECVE records.
        let log = parse(
            b"type=EXECVE msg=audit(1.000:1): argc=3 a0=\"echo\" a1_len=10 a1[0]=636166C3\n\
              type=EXECVE msg=audit(1.000:1): a1[1]=A9 a2=\"x\"\n",
        );
        assert!(log.problems.is_empty(), "{:?}", log.problems);
        let event = &log.events[0];
        assert_eq!(
            event.arguments.as_deref(),
            Some(&["echo".to_owned(), "café".to_owned(), "x".to_owned()][..])
        );
        assert_eq!(event.command_line().as_deref(), Some("echo café x"));
    }

    #[test]
    fn damaged_arguments() {
        let log = parse(
            b"type=EXECVE msg=audit(1.000:1): argc=4294967295 a0=\"ls\" a1_len=8 a1[1]=6C73\n\
              type=EXECVE msg=audit(1.000:2): argc=x a0=\"ls\"\n",
        );
        assert_eq!(
            log.events[0].arguments.as_deref(),
            Some(&["ls".to_owned(), "ls".to_owned()][..])
        );
        assert_eq!(log.events[1].arguments, None);
        assert_eq!(
            log.problems,
            [
                "line 1: EXECVE argument a1 is missing pieces",
                "line 1: EXECVE argument a2 of 4294967295 missing",
                "line 2: EXECVE without a readable argc",
            ]
        );
    }
}
