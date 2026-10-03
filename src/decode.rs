//! Values back to text. auditd writes a value that may hold spaces, quotes
//! or bytes outside printable ASCII either quoted or, when it does hold
//! them, as unquoted hex: `a1=2F746D702F6D79207265706F72742E747874` is
//! `/tmp/my report.txt`.

use std::fmt::Write;

use crate::line::Raw;

/// Fields whose values auditd hex-encodes when needed (auparse's escaped
/// fields), besides `EXECVE`'s arguments.
const ENCODED: [&str; 21] = [
    "acct",
    "cgroup",
    "cmd",
    "comm",
    "cwd",
    "data",
    "device",
    "dir",
    "exe",
    "file",
    "grp",
    "key",
    "name",
    "new_group",
    "ocomm",
    "path",
    "proctitle",
    "root_dir",
    "sw",
    "vm",
    "watch",
];

/// What decoding made of a value.
pub(crate) enum Value {
    /// Nothing to decode: the value is as written.
    AsWritten,
    /// Hex turned back into text.
    Decoded(String),
    /// Hex digits that don't make whole bytes: kept as written.
    Damaged,
}

/// `raw`, in a `kind` record, as text.
pub(crate) fn value(kind: &str, raw: &Raw) -> Value {
    if raw.quoted || !may_be_encoded(kind, &raw.name) {
        return Value::AsWritten;
    }
    match hex(&raw.value) {
        Hex::Bytes(bytes) if raw.name == "proctitle" => Value::Decoded(proctitle(&bytes)),
        Hex::Bytes(bytes) => Value::Decoded(text(&bytes)),
        Hex::OddDigits => Value::Damaged,
        // `(null)`, `?`, and old records' unquoted names.
        Hex::Other => Value::AsWritten,
    }
}

/// `raw`'s bytes: decoded when hex, as written otherwise.
pub(crate) fn bytes(raw: &Raw) -> Vec<u8> {
    match hex(&raw.value) {
        Hex::Bytes(bytes) if !raw.quoted => bytes,
        _ => raw.value.as_bytes().to_vec(),
    }
}

fn may_be_encoded(kind: &str, name: &str) -> bool {
    ENCODED.contains(&name) || kind == "EXECVE" && argument(name).is_some()
}

/// An `EXECVE` argument's name: `a3`, or `a3[0]` for a piece of a long
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Argument {
    pub index: usize,
    pub piece: Option<usize>,
}

/// `a3`, `a3[0]`; not `a3_len`, nor `argc`.
pub(crate) fn argument(name: &str) -> Option<Argument> {
    let rest = name.strip_prefix('a')?;
    let (index, piece) = match rest.split_once('[') {
        Some((index, piece)) => (index, Some(number(piece.strip_suffix(']')?)?)),
        None => (rest, None),
    };
    Some(Argument {
        index: number(index)?,
        piece,
    })
}

/// Decimal digits only: no sign, no space.
pub(crate) fn number(digits: &str) -> Option<usize> {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Hex digits as bytes, when they make whole bytes.
pub(crate) fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    match hex(text) {
        Hex::Bytes(bytes) => Some(bytes),
        Hex::OddDigits | Hex::Other => None,
    }
}

enum Hex {
    Bytes(Vec<u8>),
    OddDigits,
    Other,
}

fn hex(text: &str) -> Hex {
    let digits = text.as_bytes();
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_hexdigit) {
        return Hex::Other;
    }
    if digits.len() % 2 == 1 {
        return Hex::OddDigits;
    }
    Hex::Bytes(
        digits
            .chunks_exact(2)
            .map(|pair| nibble(pair[0]) << 4 | nibble(pair[1]))
            .collect(),
    )
}

fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => digit - b'A' + 10,
    }
}

/// A process title: its arguments separated by NULs, shown with spaces as
/// ausearch does.
fn proctitle(bytes: &[u8]) -> String {
    let spaced: Vec<u8> = bytes
        .iter()
        .map(|&b| if b == 0 { b' ' } else { b })
        .collect();
    text(&spaced).trim_end_matches(' ').to_owned()
}

/// Bytes as text: UTF-8 kept, control characters and bytes that aren't
/// UTF-8 escaped as `\x{ff}`, as Sootmark escapes what isn't text.
pub(crate) fn text(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            if c.is_ascii_control() {
                let _ = write!(out, "\\x{{{:02x}}}", c as u32);
            } else {
                out.push(c);
            }
        }
        for byte in chunk.invalid() {
            let _ = write!(out, "\\x{{{byte:02x}}}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(name: &str, value: &str, quoted: bool) -> Raw {
        Raw {
            name: name.to_owned(),
            value: value.to_owned(),
            quoted,
        }
    }

    /// The value as read, and whether it was damaged.
    fn decoded(kind: &str, name: &str, value: &str) -> (String, bool) {
        match super::value(kind, &raw(name, value, false)) {
            Value::AsWritten => (value.to_owned(), false),
            Value::Decoded(text) => (text, false),
            Value::Damaged => (value.to_owned(), true),
        }
    }

    #[test]
    fn hex_where_auditd_writes_it() {
        assert_eq!(
            decoded("EXECVE", "a1", "2F746D702F6D79207265706F72742E747874").0,
            "/tmp/my report.txt"
        );
        assert_eq!(decoded("EXECVE", "a1[2]", "636166C3A9").0, "café");
        assert_eq!(
            decoded("PROCTITLE", "proctitle", "2F62696E2F636174002F746D70").0,
            "/bin/cat /tmp"
        );
        // A system call's arguments are numbers in hex, not text.
        assert_eq!(decoded("SYSCALL", "a1", "7ffd484083e0").0, "7ffd484083e0");
        assert_eq!(
            decoded("SYSCALL", "key", "(null)"),
            ("(null)".into(), false)
        );
        // Two keys, separated by 0x01.
        assert_eq!(
            decoded("SYSCALL", "key", "616C7068610162657461").0,
            "alpha\\x{01}beta"
        );
        assert_eq!(
            decoded("PROCTITLE", "proctitle", "2F62696E2F6361F"),
            ("2F62696E2F6361F".into(), true)
        );
        assert_eq!(decoded("EXECVE", "a1", "FFFE").0, "\\x{ff}\\x{fe}");
        assert!(matches!(
            super::value("CWD", &raw("cwd", "2F", true)),
            Value::AsWritten
        ));
    }

    #[test]
    fn argument_names() {
        let at = |index, piece| Some(Argument { index, piece });
        assert_eq!(argument("a0"), at(0, None));
        assert_eq!(argument("a12[3]"), at(12, Some(3)));
        for name in ["a1_len", "argc", "a", "a1[x", "a1[]", "a[0]", "auid"] {
            assert_eq!(argument(name), None, "{name}");
        }
    }
}
