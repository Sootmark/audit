//! One line of an audit log, read into a record whose values are still as
//! written: `[node=<host> ]type=<TYPE> msg=audit(<seconds>.<ms>:<serial>):
//! key=value …[\x1d KEY=value …]`.

/// Separates an enriched record's interpretations from the record (GS).
const ENRICHED: char = '\x1d';
/// Digits of the seconds since 1970: enough until the year 33658.
const MAX_SECONDS_DIGITS: usize = 12;

/// A line read, its values not yet decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Line {
    pub node: Option<String>,
    pub kind: String,
    pub stamp: Stamp,
    pub fields: Vec<Raw>,
    pub interpreted: Vec<(String, String)>,
    /// What was odd but not fatal (an unterminated quote).
    pub issues: Vec<String>,
}

/// `msg=audit(<seconds>.<ms>:<serial>)`: with the node, what ties an
/// event's records together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Stamp {
    pub seconds: i64,
    pub millis: u16,
    pub serial: u64,
}

/// A value as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Raw {
    pub name: String,
    /// Without its quotes.
    pub value: String,
    /// Whether it was quoted: a quoted value is never hex-encoded.
    pub quoted: bool,
}

/// Read a line, or say why it isn't a record.
pub(crate) fn read(line: &str) -> Result<Line, &'static str> {
    let (record, enriched) = line.split_once(ENRICHED).unwrap_or((line, ""));
    let mut rest = record.trim_start();
    let mut node = None;
    if let Some(after) = rest.strip_prefix("node=") {
        let (name, after) = after.split_once(' ').ok_or("a node and nothing else")?;
        node = Some(name.to_owned());
        rest = after.trim_start();
    }
    let rest = rest.strip_prefix("type=").ok_or("not an audit record")?;
    let (kind, rest) = rest.split_once(' ').ok_or("no msg=audit(…) stamp")?;
    if kind.is_empty() {
        return Err("no record type");
    }
    let rest = rest
        .trim_start()
        .strip_prefix("msg=audit(")
        .ok_or("no msg=audit(…) stamp")?;
    let (stamp, rest) = rest
        .split_once(')')
        .ok_or("unterminated msg=audit(…) stamp")?;
    let stamp = read_stamp(stamp).ok_or("unreadable msg=audit(…) stamp")?;
    // auditd 2.4 wrote `DAEMON_CONFIG msg=audit(…) config changed, …`.
    let body = rest.strip_prefix(':').unwrap_or(rest);
    let mut issues = Vec::new();
    let mut fields = Vec::new();
    read_fields(body, true, &mut fields, &mut issues);
    let mut interpreted = Vec::new();
    read_fields(enriched, false, &mut interpreted, &mut issues);
    Ok(Line {
        node,
        kind: kind.to_owned(),
        stamp,
        fields,
        interpreted: interpreted.into_iter().map(|r| (r.name, r.value)).collect(),
        issues,
    })
}

/// `<seconds>.<ms>:<serial>`. The milliseconds are a number, as auparse
/// reads them: auditd always writes three digits.
fn read_stamp(text: &str) -> Option<Stamp> {
    let (time, serial) = text.split_once(':')?;
    let (seconds, millis) = time.split_once('.')?;
    Some(Stamp {
        seconds: digits(seconds, MAX_SECONDS_DIGITS)?,
        millis: digits(millis, 3)?,
        serial: digits(serial, 20)?,
    })
}

/// At most `max` decimal digits, and nothing else.
fn digits<T: std::str::FromStr>(text: &str, max: usize) -> Option<T> {
    if text.is_empty() || text.len() > max || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// `key=value` pairs separated by spaces, values plain, `"quoted"`,
/// `'quoted'` or, in enriched socket addresses, `{ braced }`. A program's
/// record nests its own fields in `msg='…'`; they are read as the record's
/// (`nested`). Words that aren't pairs are skipped, except SELinux's access
/// decision (`avc: denied { read } for`), kept as `seresult` and
/// `seperms`, auparse's names.
fn read_fields(text: &str, nested: bool, out: &mut Vec<Raw>, issues: &mut Vec<String>) {
    let mut rest = text;
    loop {
        rest = rest.trim_start_matches([' ', '\t']);
        if rest.is_empty() {
            return;
        }
        let word_end = rest.find([' ', '\t', '=']).unwrap_or(rest.len());
        let word = &rest[..word_end];
        // Old PAM records: `(hostname=?, addr=?, terminal=cron res=success)`.
        let key = word.trim_start_matches('(');
        if !rest[word_end..].starts_with('=') || key.is_empty() {
            rest = &rest[word_end..];
            if word == "{" {
                let (permissions, after) = rest.split_once('}').unwrap_or((rest, ""));
                out.push(plain("seperms", permissions.trim()));
                rest = after;
            } else if word == "denied" || word == "granted" {
                out.push(plain("seresult", word));
            } else if word_end == 0 {
                rest = &rest[1..]; // a lone `=`
            }
            continue;
        }
        let after = &rest[word_end + 1..];
        let (value, quote, after) = split_value(after);
        rest = after;
        if let Quote::Unterminated(q) = quote {
            issues.push(format!("{key}: no closing {q}, value read to the end"));
        }
        match quote {
            Quote::Single | Quote::Unterminated('\'') if nested && key == "msg" => {
                read_fields(value, false, out, issues);
            }
            Quote::Single | Quote::Double | Quote::Unterminated(_) => {
                out.push(quoted(key, value));
            }
            Quote::Brace => out.push(quoted(key, value.trim())),
            Quote::None => match value.strip_suffix('"') {
                Some(value) => {
                    issues.push(format!("{key}: a closing \" without an opening one"));
                    out.push(plain(key, value));
                }
                None => out.push(plain(key, trim_old_pam(value))),
            },
        }
    }
}

enum Quote {
    None,
    Double,
    Single,
    Brace,
    Unterminated(char),
}

/// A value at the start of `text`: the value, how it was quoted, the rest.
fn split_value(text: &str) -> (&str, Quote, &str) {
    for (open, close, quote) in [
        ('"', '"', Quote::Double),
        ('\'', '\'', Quote::Single),
        ('{', '}', Quote::Brace),
    ] {
        if let Some(inner) = text.strip_prefix(open) {
            return match inner.split_once(close) {
                Some((value, rest)) => (value, quote, rest),
                None => (inner, Quote::Unterminated(close), ""),
            };
        }
    }
    let end = text.find([' ', '\t']).unwrap_or(text.len());
    (&text[..end], Quote::None, &text[end..])
}

/// `?,` and `success)` in old PAM records; `(none)` is left alone.
fn trim_old_pam(value: &str) -> &str {
    let value = value.strip_suffix(',').unwrap_or(value);
    match value.strip_suffix(')') {
        Some(trimmed) if !value.contains('(') => trimmed,
        _ => value,
    }
}

fn plain(name: &str, value: &str) -> Raw {
    Raw {
        name: name.to_owned(),
        value: value.to_owned(),
        quoted: false,
    }
}

fn quoted(name: &str, value: &str) -> Raw {
    Raw {
        quoted: true,
        ..plain(name, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(line: &Line) -> Vec<(&str, &str)> {
        line.fields
            .iter()
            .map(|r| (r.name.as_str(), r.value.as_str()))
            .collect()
    }

    #[test]
    fn header_and_nested_message() {
        let line = read("node=web1 type=USER_LOGIN msg=audit(1492896301.818:19955): pid=12635 uid=0 msg='op=login acct=28696E76616C6964207573657229 exe=\"/usr/sbin/sshd\" hostname=? addr=179.38.151.221 terminal=sshd res=failed'\x1dUID=\"root\" AUID=\"unset\"").unwrap();
        assert_eq!(line.node.as_deref(), Some("web1"));
        assert_eq!(line.kind, "USER_LOGIN");
        assert_eq!(
            line.stamp,
            Stamp {
                seconds: 1_492_896_301,
                millis: 818,
                serial: 19955
            }
        );
        assert_eq!(
            pairs(&line),
            [
                ("pid", "12635"),
                ("uid", "0"),
                ("op", "login"),
                ("acct", "28696E76616C6964207573657229"),
                ("exe", "/usr/sbin/sshd"),
                ("hostname", "?"),
                ("addr", "179.38.151.221"),
                ("terminal", "sshd"),
                ("res", "failed"),
            ]
        );
        assert!(line.fields[4].quoted && !line.fields[3].quoted);
        assert_eq!(
            line.interpreted,
            [
                ("UID".to_owned(), "root".to_owned()),
                ("AUID".to_owned(), "unset".to_owned())
            ]
        );
    }

    #[test]
    fn access_decisions_and_old_records() {
        let avc = read("type=AVC msg=audit(1243332701.744:101): avc:  denied  { getattr read } for  pid=2714 comm=\"ls\"").unwrap();
        assert_eq!(
            pairs(&avc),
            [
                ("seresult", "denied"),
                ("seperms", "getattr read"),
                ("pid", "2714"),
                ("comm", "ls")
            ]
        );
        let pam = read("type=USER_START msg=audit(1170021601.344:297): user pid=13015 msg='PAM: session open acct=root : exe=\"/usr/sbin/crond\" (hostname=?, addr=?, terminal=cron res=success)'").unwrap();
        assert_eq!(
            pairs(&pam),
            [
                ("pid", "13015"),
                ("acct", "root"),
                ("exe", "/usr/sbin/crond"),
                ("hostname", "?"),
                ("addr", "?"),
                ("terminal", "cron"),
                ("res", "success")
            ]
        );
        let tty = read("type=SYSCALL msg=audit(1.000:1): tty=(none) key=(null)").unwrap();
        assert_eq!(pairs(&tty), [("tty", "(none)"), ("key", "(null)")]);
        let sockaddr = read("type=SOCKADDR msg=audit(1.000:1): saddr=0200\x1dSADDR={ saddr_fam=inet laddr=127.0.0.1 lport=22 }").unwrap();
        assert_eq!(
            sockaddr.interpreted,
            [(
                "SADDR".to_owned(),
                "saddr_fam=inet laddr=127.0.0.1 lport=22".to_owned()
            )]
        );
    }

    #[test]
    fn damaged_lines() {
        for (line, why) in [
            ("msg=audit(1337845201.174:94984): x", "not an audit record"),
            ("type= msg=audit(1337845333.174:94984): x", "no record type"),
            (
                "type=WRONGDATE msg=audit(1337845201): x",
                "unreadable msg=audit(…) stamp",
            ),
            (
                "type=EMPTYDATE msg=audit(): x",
                "unreadable msg=audit(…) stamp",
            ),
            (
                "type=CUT msg=audit(1337845201.17",
                "unterminated msg=audit(…) stamp",
            ),
            ("node=", "a node and nothing else"),
        ] {
            assert_eq!(read(line), Err(why), "{line}");
        }
        let cut = read("type=EXECVE msg=audit(1.000:1): argc=2 a0=\"/bin/ca").unwrap();
        assert_eq!(pairs(&cut), [("argc", "2"), ("a0", "/bin/ca")]);
        assert_eq!(cut.issues, ["a0: no closing \", value read to the end"]);
        let stray = read("type=SYSCALL msg=audit(1.000:1): key=6578656301\"").unwrap();
        assert_eq!(pairs(&stray), [("key", "6578656301")]);
        assert_eq!(stray.issues, ["key: a closing \" without an opening one"]);
        let cut =
            read("type=USER_LOGIN msg=audit(1.000:1): pid=1 msg='op=login acct=\"root\" res=fai")
                .unwrap();
        assert_eq!(
            pairs(&cut),
            [
                ("pid", "1"),
                ("op", "login"),
                ("acct", "root"),
                ("res", "fai")
            ]
        );
        let nomsg = read("type=NOMSG msg=audit(1337845222.174:94984):").unwrap();
        assert!(nomsg.fields.is_empty());
    }
}
